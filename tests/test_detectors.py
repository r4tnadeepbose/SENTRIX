"""Positive detector samples, masking, and allowlist behavior."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wintermute.core.allowlist import Allowlist
from wintermute.core.engine import scan_text
from wintermute.core.util import fingerprint

# (sample text, expected detector id, sensitive substring that must be masked)
SAMPLES = [
    ('AWS_KEY = "AWS_KEY_REDACTED"', "aws-access-key-id", "AWS_KEY_REDACTED"),
    ('GITHUB_TOKEN = "GITHUB_TOKEN_REDACTED"',
     "github-token", "GITHUB_TOKEN_REDACTED"),
    ('STRIPE_KEY = "STRIPE_KEY_REDACTED"',
     "stripe-key", "STRIPE_KEY_REDACTED"),
    ('bot token SLACK_TOKEN_REDACTED',
     "slack-token", "SLACK_TOKEN_REDACTED"),
    ('postgres://admin:Sup3rSecretPass@db.internal:5432/prod',
     "postgres-uri", "Sup3rSecretPass"),
    ('-----BEGIN RSA PRIVATE KEY-----', "private-key", "-----BEGIN RSA PRIVATE KEY-----"),
    ('API_TOKEN="tok_9f8e7d6c5b4a39281706f5e4d3c2b1a0"',
     "env-secret", "tok_9f8e7d6c5b4a39281706f5e4d3c2b1a0"),
    ('password = "PASSWORD_REDACTED"', "generic-secret-assignment", "PASSWORD_REDACTED"),
]


class DetectorPositiveTests(unittest.TestCase):
    def test_each_family_detected_and_masked(self):
        for text, detector_id, sensitive in SAMPLES:
            with self.subTest(detector=detector_id):
                findings = scan_text(text, "sample.py", "filesystem")
                matches = [f for f in findings if f.detector_id == detector_id]
                self.assertTrue(matches, f"{detector_id} not detected in {text!r}")
                for finding in matches:
                    self.assertIn("*", finding.secret_masked)
                    self.assertNotIn(sensitive, finding.secret_masked)
                    self.assertEqual(finding.surface, "filesystem")
                    self.assertEqual(finding.path, "sample.py")
                    self.assertTrue(finding.fingerprint)

    def test_fingerprint_stable(self):
        text = 'AWS_KEY = "AWS_KEY_REDACTED"'
        first = scan_text(text, "a.py", "filesystem")
        second = scan_text(text, "b.py", "filesystem")
        self.assertEqual(first[0].fingerprint, second[0].fingerprint)
        self.assertEqual(
            first[0].fingerprint,
            fingerprint("aws-access-key-id", "AWS_KEY_REDACTED"),
        )


class AllowlistTests(unittest.TestCase):
    def test_builtin_example_key_blocked(self):
        findings = scan_text(
            'key = "AKIAIOSFODNN7EXAMPLE"', "x.py", "filesystem", Allowlist())
        self.assertFalse(
            any(f.detector_id == "aws-access-key-id" for f in findings))

    def test_is_allowed_by_fingerprint(self):
        fp = fingerprint("aws-access-key-id", "AWS_KEY_REDACTED")
        allow = Allowlist(fingerprints={fp})
        self.assertTrue(allow.is_allowed(fp, "AWS_KEY_REDACTED", "x.py"))
        self.assertFalse(allow.is_allowed("other", "AWS_KEY_REDACTED", "x.py"))

    def test_is_allowed_builtin_safe_value(self):
        allow = Allowlist()
        self.assertTrue(allow.is_allowed("fp", "AKIAIOSFODNN7EXAMPLE", "x.py"))
        self.assertTrue(allow.is_allowed("fp", "changeme", "x.py"))

    def test_extra_pattern_blocks(self):
        allow = Allowlist(extra_patterns=[r"^tok_"])
        self.assertTrue(allow.is_allowed("fp", "tok_9f8e7d6c5b4a39281706", "x.py"))
        findings = scan_text(
            'API_TOKEN="tok_9f8e7d6c5b4a39281706f5e4d3c2b1a0"',
            "x.py", "filesystem", allow)
        self.assertFalse(any(f.detector_id == "env-secret" for f in findings))


if __name__ == "__main__":
    unittest.main()