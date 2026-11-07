"""Pipeline ingest dedupe, alert routing, and allowlist skipping."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from keysentry.alerting.router import AlertRouter
from keysentry.config import load_config
from keysentry.core.engine import scan_text
from keysentry.core.pipeline import Pipeline
from keysentry.core.storage import Storage


def aws_findings():
    return scan_text('AWS_KEY = "AWS_KEY_REDACTED"', "src/a.py", "filesystem")


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.cfg = load_config()
        self.cfg["storage"]["path"] = str(Path(self._tmp.name) / "pipe.db")
        self.cfg["alerting"]["channels"] = ["outbox"]
        self.storage = Storage(Path(self.cfg["storage"]["path"]))
        self.addCleanup(self.storage.close)

    def test_ingest_new_then_known(self):
        pipeline = Pipeline(self.cfg, self.storage)
        findings = aws_findings()
        first = pipeline.ingest(findings, kind="scan.completed")
        self.assertEqual(len(first["new"]), 1)
        self.assertEqual(len(first["known"]), 0)
        second = pipeline.ingest(aws_findings(), kind="scan.completed")
        self.assertEqual(len(second["new"]), 0)
        self.assertEqual(len(second["known"]), 1)
        self.assertEqual(self.storage.stats()["total"], 1)

    def test_router_receives_alerts_for_new(self):
        router = AlertRouter(self.cfg, self.storage)
        pipeline = Pipeline(self.cfg, self.storage, router)
        result = pipeline.ingest(aws_findings(), kind="scan.completed")
        self.assertEqual(len(result["new"]), 1)
        alerts = self.storage.list_alerts()
        self.assertTrue(alerts)
        self.assertTrue(all(a["channel"] == "outbox" for a in alerts))
        self.assertEqual(alerts[0]["finding_id"], result["new"][0].id)
        # A second ingest produces no new findings, hence no new alerts.
        pipeline.ingest(aws_findings(), kind="scan.completed")
        self.assertEqual(len(self.storage.list_alerts()), len(alerts))

    def test_allowlisted_fingerprint_skipped(self):
        findings = aws_findings()
        self.storage.allowlist_add(findings[0].fingerprint, "false positive")
        pipeline = Pipeline(self.cfg, self.storage)
        result = pipeline.ingest(findings, kind="scan.completed")
        self.assertEqual(result["new"], [])
        self.assertEqual(result["known"], [])
        self.assertEqual(self.storage.stats()["total"], 0)
        self.assertIsNone(self.storage.get_finding(findings[0].id))

    def test_ingest_records_event(self):
        pipeline = Pipeline(self.cfg, self.storage)
        pipeline.ingest(aws_findings(), kind="scan.custom")
        events = self.storage.list_events()
        self.assertTrue(any(e["kind"] == "scan.custom" for e in events))


if __name__ == "__main__":
    unittest.main()