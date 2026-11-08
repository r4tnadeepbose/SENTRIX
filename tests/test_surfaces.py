"""Surface adapters: SaaS exports, Lambda artifacts, and git diffs."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentrix.config import load_config
from sentrix.surfaces import cloud, confluence, git, jira, postman, slack

AWS = "AWS_KEY_REDACTED"


class ExportSurfaceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def _write(self, name, data):
        path = self.root / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return str(path)

    def test_slack_export(self):
        path = self._write("slack.json", [
            {"channel": "eng", "ts": "1.0", "user": "u1", "text": f"leaked {AWS}"},
        ])
        findings = slack.scan_export(path)
        self.assertTrue(findings)
        self.assertTrue(all(f.surface == "slack" for f in findings))
        self.assertTrue(any(f.detector_id == "aws-access-key-id" for f in findings))
        self.assertEqual(findings[0].owner, "u1")

    def test_confluence_export(self):
        path = self._write("confluence.json", {"pages": [
            {"title": "Runbook", "owner": "alice", "body": f"<p>key {AWS}</p>"},
        ]})
        findings = confluence.scan_export(path)
        self.assertTrue(findings)
        self.assertTrue(all(f.surface == "confluence" for f in findings))
        self.assertTrue(any(f.detector_id == "aws-access-key-id" for f in findings))

    def test_jira_export(self):
        path = self._write("jira.json", {"issues": [
            {"key": "SEC-1", "fields": {"summary": "Leak", "description": f"AWS {AWS}"}},
        ]})
        findings = jira.scan_export(path)
        self.assertTrue(findings)
        self.assertTrue(all(f.surface == "jira" for f in findings))
        self.assertTrue(any(f.detector_id == "aws-access-key-id" for f in findings))

    def test_postman_collection(self):
        path = self._write("collection.json", {
            "info": {"name": "Payments"},
            "item": [{"request": {"header": [
                {"key": "Authorization", "value": f"Bearer {AWS}"},
            ]}}],
        })
        findings = postman.scan_collection(path)
        self.assertTrue(findings)
        self.assertTrue(all(f.surface == "postman" for f in findings))
        self.assertTrue(any(f.detector_id == "aws-access-key-id" for f in findings))
        self.assertTrue(any(f.meta.get("json_path") for f in findings))

    def test_postman_environment(self):
        path = self._write("environment.json", {
            "name": "Prod",
            "values": [{"key": "AWS_KEY", "value": AWS}],
        })
        findings = postman.scan_environment(path)
        self.assertTrue(findings)
        self.assertTrue(all(f.surface == "postman" for f in findings))
        self.assertTrue(any(f.detector_id == "aws-access-key-id" for f in findings))
        self.assertTrue(any(f.meta.get("env_key") == "AWS_KEY" for f in findings))

    def test_lambda_dir(self):
        cfg = load_config()
        fn_dir = self.root / "payments"
        fn_dir.mkdir()
        (fn_dir / "config.json").write_text(json.dumps({
            "FunctionName": "payments",
            "Environment": {"Variables": {
                "STRIPE_KEY": "STRIPE_KEY_REDACTED",
            }},
        }), encoding="utf-8")
        (fn_dir / "function.py").write_text(f'AWS_KEY = "{AWS}"\n', encoding="utf-8")
        findings = cloud.scan_lambda_dir(self.root, cfg)
        self.assertTrue(findings)
        self.assertTrue(all(f.surface == "cloud" for f in findings))
        ids = {f.detector_id for f in findings}
        self.assertIn("stripe-key", ids)
        self.assertIn("aws-access-key-id", ids)


DIFF = (
    "diff --git a/src/app.py b/src/app.py\n"
    "--- a/src/app.py\n"
    "+++ b/src/app.py\n"
    "@@ -1,3 +1,3 @@\n"
    " import os\n"
    '-AWS_KEY = "AWS_KEY_REDACTED"\n'
    '+GITHUB_TOKEN = "GITHUB_TOKEN_REDACTED"\n'
    ' print("hi")\n'
)


class GitSurfaceTests(unittest.TestCase):
    def test_parse_added_lines(self):
        added = list(git.parse_added_lines(DIFF))
        self.assertEqual(len(added), 1)
        path, line_no, content = added[0]
        self.assertEqual(path, "src/app.py")
        self.assertEqual(line_no, 2)
        self.assertEqual(
            content, 'GITHUB_TOKEN = "GITHUB_TOKEN_REDACTED"')

    def test_scan_diff_added_only(self):
        findings = git.scan_diff(DIFF, "pre_push")
        ids = {f.detector_id for f in findings}
        self.assertIn("github-token", ids)
        # The removed line carried an AWS key; it must not be reported.
        self.assertNotIn("aws-access-key-id", ids)
        self.assertTrue(all(f.surface == "pre_push" for f in findings))
        self.assertTrue(all(f.line == 2 for f in findings))


if __name__ == "__main__":
    unittest.main()