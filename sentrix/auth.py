"""Authentication, sessions, RBAC, API tokens and audit logging."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from collections import defaultdict, deque

from sentrix.config import cfg_get, resolve_path

ITERATIONS = 200_000
ROLES = ("super_admin", "security_admin", "security_analyst", "appsec_engineer",
         "devsecops_engineer", "developer", "auditor", "viewer")
WRITE_ROLES = ROLES[:5]
ADMIN_ROLES = ROLES[:2]
TEAM = (
    ("s.chen", "appsec_engineer", "Security Engineer"),
    ("m.ross", "security_analyst", "SOC Analyst"),
    ("i.kumar", "devsecops_engineer", "Incident Responder"),
    ("a.diaz", "auditor", "Compliance Officer"),
    ("j.lee", "developer", "Software Developer"),
)


class AuthError(Exception):
    pass


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), ITERATIONS).hex()


class AuthManager:
    def __init__(self, storage, cfg: dict):
        self.storage = storage
        self.cfg = cfg
        self._attempts: dict[str, deque] = defaultdict(deque)
        self.session_hours = cfg_get(cfg, "auth.session_hours", 12)

    def ensure_admin(self):
        if not self.storage.list_users():
            password = os.environ.get("SENTRIX_ADMIN_PASSWORD")
            generated = not password
            if not password:
                if cfg_get(self.cfg, "auth.demo_mode", False):
                    password = cfg_get(self.cfg, "auth.demo_password", "sentrix-demo")
                else:
                    password = secrets.token_urlsafe(9)
            salt = secrets.token_hex(16)
            self.storage.add_user("admin", hash_password(password, salt), salt, "super_admin",
                                  title="Platform Administrator")
            if generated:
                target = resolve_path(self.cfg, "data/INITIAL_ADMIN_PASSWORD.txt")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(
                    f"username: admin\npassword: {password}\n"
                    "Change this password in Settings after first login.\n", encoding="utf-8")
            self.log("warn", "auth", "Initial admin account created")
        self.seed_team()

    def seed_team(self):
        """A full company roster so the console behaves like a real team tool."""
        if not cfg_get(self.cfg, "auth.demo_mode", False):
            return
        for username, role, title in TEAM:
            existing = self.storage.get_user(username)
            if existing:
                if existing["role"] != role or existing.get("title", "") != title:
                    self.storage.update_user(username, role=role, title=title)
                continue
            password = f"{username}-demo"
            salt = secrets.token_hex(16)
            self.storage.add_user(username, hash_password(password, salt), salt, role,
                                  title=title)
        self.log("info", "auth", "Company demo roster ready (6 accounts)")

    def demo_accounts(self) -> list[dict]:
        accounts = []
        admin = self.storage.get_user("admin")
        demo_password = cfg_get(self.cfg, "auth.demo_password", "sentrix-demo")
        if admin and not admin["disabled"] and hmac.compare_digest(
                admin["pw_hash"], hash_password(demo_password, admin["salt"])):
            accounts.append({"username": "admin", "password": demo_password,
                             "role": admin["role"], "title": admin.get("title", "")})
        for username, role, title in TEAM:
            user = self.storage.get_user(username)
            password = f"{username}-demo"
            if user and not user["disabled"] and hmac.compare_digest(
                    user["pw_hash"], hash_password(password, user["salt"])):
                accounts.append({"username": username, "password": password,
                                 "role": user["role"], "title": user.get("title", title)})
        return accounts

    def login(self, username: str, password: str, ip: str,
              remember: bool = False) -> tuple[str, dict]:
        now = time.time()
        window = self._attempts[ip]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= cfg_get(self.cfg, "auth.login_rate_limit", 5):
            self.log("warn", "auth", f"Login rate limit hit for {ip}")
            raise AuthError("Too many failed attempts; wait a minute.")
        user = self.storage.get_user(username)
        if not user or user["disabled"]:
            window.append(now)
            self.audit("login.failed", username, "unknown or disabled account")
            raise AuthError("Invalid credentials.")
        candidate = hash_password(password, user["salt"])
        if not hmac.compare_digest(candidate, user["pw_hash"]):
            window.append(now)
            self.audit("login.failed", username, "bad password")
            raise AuthError("Invalid credentials.")
        token = secrets.token_hex(24)
        hours = 24 * 30 if remember else self.session_hours
        expires = now + hours * 3600
        self.storage.add_session(token, username, user["role"], expires)
        self.audit("login.ok", username, f"session issued for {hours}h")
        self.log("info", "auth", f"{username} signed in")
        return token, {"username": username, "role": user["role"],
                       "title": user.get("title", "")}

    def logout(self, token: str):
        session = self.storage.get_session(token)
        if session:
            self.storage.delete_session(token)
            self.audit("logout", session["username"], "")

    def session_user(self, token: str) -> dict | None:
        if not token:
            return None
        session = self.storage.get_session(token)
        if not session or session["expires_at"] < time.time():
            return None
        user = self.storage.get_user(session["username"])
        if not user or user["disabled"]:
            return None
        return {"username": user["username"], "role": user["role"],
                "title": user.get("title", "")}

    def bearer_user(self, header: str) -> dict | None:
        if not header.startswith("Bearer sxt_"):
            return None
        raw = header[len("Bearer "):]
        token = self.storage.get_token_by_hash(hashlib.sha256(raw.encode()).hexdigest())
        if not token or token["revoked"]:
            return None
        return {"username": f"token:{token['name']}", "role": token["role"]}

    def change_password(self, username: str, old: str, new: str):
        user = self.storage.get_user(username)
        if not user or not hmac.compare_digest(
                hash_password(old, user["salt"]), user["pw_hash"]):
            raise AuthError("Current password is incorrect.")
        if len(new) < 10:
            raise AuthError("New password must be at least 10 characters.")
        salt = secrets.token_hex(16)
        self.storage.update_user(username, pw_hash=hash_password(new, salt), salt=salt)
        self.audit("password.changed", username, "")
        self.log("info", "auth", f"{username} changed their password")

    def add_user(self, by: str, username: str, password: str, role: str, title: str = ""):
        if role not in ROLES:
            raise AuthError(f"role must be one of {ROLES}")
        if self.storage.get_user(username):
            raise AuthError("User already exists.")
        if len(password) < 10:
            raise AuthError("Password must be at least 10 characters.")
        salt = secrets.token_hex(16)
        self.storage.add_user(username, hash_password(password, salt), salt, role, title=title)
        self.audit("user.added", by, f"{username} ({role})")

    def set_role(self, by: str, username: str, role: str):
        if role not in ROLES:
            raise AuthError(f"role must be one of {ROLES}")
        self.storage.update_user(username, role=role)
        self.audit("user.role", by, f"{username} -> {role}")

    def set_disabled(self, by: str, username: str, disabled: bool):
        if username == by:
            raise AuthError("You cannot disable your own account.")
        self.storage.update_user(username, disabled=1 if disabled else 0)
        self.audit("user.disabled" if disabled else "user.enabled", by, username)

    def create_token(self, by: str, name: str, role: str) -> str:
        if role not in ROLES:
            raise AuthError(f"role must be one of {ROLES}")
        raw = "sxt_" + secrets.token_hex(20)
        self.storage.add_token(
            secrets.token_hex(6), name, hashlib.sha256(raw.encode()).hexdigest(), role, by)
        self.audit("token.created", by, f"{name} ({role})")
        return raw

    def revoke_token(self, by: str, token_id: str):
        self.storage.revoke_token(token_id)
        self.audit("token.revoked", by, token_id)

    def audit(self, action: str, username: str = "", detail: str = ""):
        self.storage.add_audit(action, username, detail)

    def log(self, level: str, source: str, message: str):
        self.storage.add_log(level, source, message)