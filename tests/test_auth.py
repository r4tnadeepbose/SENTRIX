"""Auth primitives: hashing, rate limiting, account guards, sessions, tokens."""
from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from keysentry.auth import AuthError, AuthManager, hash_password
from keysentry.config import load_config
from keysentry.core.extensions import ExtStorage

PASSWORD = "unit-test-pass-123"
SALT = "fixed-salt-for-tests"


class AuthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.cfg = load_config()
        self.cfg["auth"]["login_rate_limit"] = 5
        self.storage = ExtStorage(Path(self._tmp.name) / "auth.db")
        self.addCleanup(self.storage.close)
        self.auth = AuthManager(self.storage, self.cfg)
        self.storage.add_user(
            "alice", hash_password(PASSWORD, SALT), SALT, "analyst")

    def test_hash_password_deterministic_with_same_salt(self):
        first = hash_password(PASSWORD, SALT)
        second = hash_password(PASSWORD, SALT)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)  # sha256 hex digest
        self.assertNotEqual(first, hash_password(PASSWORD, "another-salt"))
        self.assertNotEqual(first, hash_password("different-pass-123", SALT))

    def test_login_rate_limit_after_five_bad_attempts(self):
        for _ in range(5):
            with self.assertRaises(AuthError) as ctx:
                self.auth.login("alice", "wrong-password", "10.0.0.1")
            self.assertIn("Invalid credentials", str(ctx.exception))
        # The sixth attempt inside the window is throttled outright.
        with self.assertRaises(AuthError) as ctx:
            self.auth.login("alice", "wrong-password", "10.0.0.1")
        self.assertIn("Too many attempts", str(ctx.exception))
        # A different client IP is unaffected, and correct credentials work.
        token, user = self.auth.login("alice", PASSWORD, "10.0.0.2")
        self.assertTrue(token)
        self.assertEqual(user["username"], "alice")

    def test_change_password_wrong_old_raises(self):
        with self.assertRaises(AuthError):
            self.auth.change_password("alice", "not-the-old-pass", "new-pass-12345")
        # The original password still works afterwards.
        token, user = self.auth.login("alice", PASSWORD, "10.0.0.3")
        self.assertTrue(token)
        self.assertEqual(user["role"], "analyst")

    def test_change_password_updates_credentials(self):
        self.auth.change_password("alice", PASSWORD, "brand-new-pass-123")
        with self.assertRaises(AuthError):
            self.auth.login("alice", PASSWORD, "10.0.0.4")
        token, user = self.auth.login("alice", "brand-new-pass-123", "10.0.0.4")
        self.assertTrue(token)
        self.assertEqual(user["username"], "alice")

    def test_add_user_duplicate_raises(self):
        self.auth.add_user("admin", "bob", "bob-password-123", "viewer")
        with self.assertRaises(AuthError):
            self.auth.add_user("admin", "bob", "other-password-123", "analyst")
        users = {u["username"] for u in self.storage.list_users()}
        self.assertEqual(users, {"alice", "bob"})
        self.assertEqual(self.storage.get_user("bob")["role"], "viewer")

    def test_add_user_rejects_bad_role_and_short_password(self):
        with self.assertRaises(AuthError):
            self.auth.add_user("admin", "carol", "carol-pass-123", "superuser")
        with self.assertRaises(AuthError):
            self.auth.add_user("admin", "carol", "short", "viewer")
        self.assertIsNone(self.storage.get_user("carol"))

    def test_set_disabled_self_raises(self):
        with self.assertRaises(AuthError):
            self.auth.set_disabled("alice", "alice", True)
        self.assertEqual(self.storage.get_user("alice")["disabled"], 0)

    def test_set_disabled_other_blocks_login(self):
        self.auth.add_user("admin", "bob", "bob-password-123", "viewer")
        self.auth.set_disabled("alice", "bob", True)
        self.assertEqual(self.storage.get_user("bob")["disabled"], 1)
        with self.assertRaises(AuthError):
            self.auth.login("bob", "bob-password-123", "10.0.0.5")

    def test_session_expiry_returns_none(self):
        # An already-expired session must never identify a user.
        self.storage.add_session("expired-token", "alice", "analyst",
                                 time.time() - 3600)
        self.assertIsNone(self.auth.session_user("expired-token"))
        # A live session works; unknown and empty tokens do not.
        self.storage.add_session("live-token", "alice", "analyst",
                                 time.time() + 3600)
        self.assertEqual(self.auth.session_user("live-token"),
                         {"username": "alice", "role": "analyst"})
        self.assertIsNone(self.auth.session_user("missing-token"))
        self.assertIsNone(self.auth.session_user(""))

    def test_session_expiry_checked_even_if_row_survives(self):
        # Insert an expired row directly so the expiry branch in session_user
        # is exercised (add_session normally purges expired rows on insert).
        self.storage._db.execute(
            "INSERT OR REPLACE INTO sessions VALUES (?,?,?,?)",
            ("stale-row", "alice", "analyst", time.time() - 10))
        self.storage._db.commit()
        self.assertIsNotNone(self.storage.get_session("stale-row"))
        self.assertIsNone(self.auth.session_user("stale-row"))

    def test_logout_invalidates_session(self):
        token, _ = self.auth.login("alice", PASSWORD, "10.0.0.6")
        self.assertIsNotNone(self.auth.session_user(token))
        self.auth.logout(token)
        self.assertIsNone(self.auth.session_user(token))

    def test_bearer_token_lifecycle(self):
        raw = self.auth.create_token("alice", "ci", "analyst")
        self.assertTrue(raw.startswith("kst_"))
        self.assertEqual(self.auth.bearer_user(f"Bearer {raw}"),
                         {"username": "token:ci", "role": "analyst"})
        self.assertIsNone(self.auth.bearer_user(raw))  # missing scheme
        self.assertIsNone(self.auth.bearer_user(f"Bearer {raw}tampered"))
        tid = self.storage.list_tokens()[0]["id"]
        self.auth.revoke_token("alice", tid)
        self.assertIsNone(self.auth.bearer_user(f"Bearer {raw}"))


if __name__ == "__main__":
    unittest.main()