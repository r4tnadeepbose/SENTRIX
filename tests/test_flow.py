"""Reference-workflow parity: provenance, confirm/ignore branch, auto tickets, mentions."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wintermute.alerting.router import AlertRouter
from wintermute.config import load_config
from wintermute.core.engine import scan_text
from wintermute.core.extensions import ExtStorage
from wintermute.core.models import Finding
from wintermute.core.pipeline import Pipeline


class FlowTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.cfg = load_config()
        self.cfg["storage"]["path"] = str(Path(self._tmp.name) / "flow.db")
        self.cfg["alerting"]["channels"] = ["outbox"]
        self.storage = ExtStorage(Path(self.cfg["storage"]["path"]))
        self.pipeline = Pipeline(self.cfg, self.storage)

    def tearDown(self):
        self.storage.close()

    def test_provenance_recorded_on_ingest(self):
        findings = scan_text('AWS_KEY = "AWS_KEY_REDACTED"', "src/a.py", "ci")
        self.pipeline.ingest(findings, kind="gate.blocked", provenance={"range": "a..b", "author": "dev@x"})
        stored = self.storage.get_finding(findings[0].id)
        origin = stored.meta["origin"]
        self.assertEqual(origin["range"], "a..b")
        self.assertEqual(origin["author"], "dev@x")
        self.assertEqual(origin["surface"], "ci")
        self.assertEqual(origin["event"], "gate.blocked")

    def test_saas_unconfirmed_finding_ignored_for_audit(self):
        findings = scan_text('password = "yourvalue123456"', "tests/fixtures/x.py", "slack")
        self.assertTrue(findings)
        self.pipeline.ingest(findings, kind="ingest.slack")
        stored = self.storage.get_finding(findings[0].id)
        self.assertEqual(stored.status, "false_positive")
        logs = self.storage.list_logs(limit=50)
        self.assertTrue(any("logged for audit" in l["message"] for l in logs))

    def test_saas_confirmed_finding_stays_open(self):
        findings = scan_text('bot token SLACK_TOKEN_REDACTED',
                             "slack:#eng/1.2", "slack")
        self.pipeline.ingest(findings, kind="ingest.slack")
        stored = self.storage.get_finding(findings[0].id)
        self.assertEqual(stored.status, "open")
        self.assertIn("triage", stored.meta)

    def test_critical_finding_auto_tickets_from_store(self):
        findings = scan_text('token = "GITHUB_TOKEN_REDACTED"', "a.py", "git")
        self.pipeline.ingest(findings, kind="scan.job")
        critical = next(f for f in findings if f.severity == "critical")
        remediations = self.storage.list_remediations(critical.id)
        self.assertTrue(any(r["action"] == "auto-ticket" for r in remediations))

    def test_slack_payload_mentions_responsible_user(self):
        finding = Finding(detector_id="x", title="t", severity="high", surface="slack",
                          path="p", line=1, secret_masked="m", entropy=4.0,
                          fingerprint="f" * 64, owner="U12345678")
        self.assertIn("<@U12345678>", AlertRouter.slack_payload(finding, "msg")["text"])
        finding.owner = "alice"
        self.assertIn("@alice", AlertRouter.slack_payload(finding, "msg")["text"])


if __name__ == "__main__":
    unittest.main()