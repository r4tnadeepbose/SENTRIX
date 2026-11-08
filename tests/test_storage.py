"""SQLite persistence: findings, status, stats, allowlist, remediation, events."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentrix.core.engine import scan_text
from sentrix.core.models import Alert, Event, Remediation
from sentrix.core.storage import Storage


def make_finding(path="src/a.py", line=1):
    return scan_text('AWS_KEY = "AWS_KEY_REDACTED"', path, "filesystem")[0]


class StorageTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db_path = Path(self._tmp.name) / "store.db"
        self.storage = Storage(self.db_path)
        self.addCleanup(self.storage.close)

    def test_upsert_new_then_duplicate(self):
        finding = make_finding()
        self.assertTrue(self.storage.upsert_finding(finding))
        duplicate = make_finding()
        self.assertFalse(self.storage.upsert_finding(duplicate))
        self.assertEqual(duplicate.id, finding.id)
        self.assertEqual(len(self.storage.list_findings()), 1)

    def test_set_status_and_get(self):
        finding = make_finding()
        self.storage.upsert_finding(finding)
        updated = self.storage.set_status(finding.id, "triaged")
        self.assertIsNotNone(updated)
        self.assertEqual(updated.status, "triaged")
        self.assertEqual(self.storage.get_finding(finding.id).status, "triaged")
        self.assertIsNone(self.storage.get_finding("does-not-exist"))

    def test_stats_counts(self):
        finding = make_finding()
        self.storage.upsert_finding(finding)
        stats = self.storage.stats()
        self.assertEqual(stats["total"], 1)
        self.assertEqual(stats["open"], 1)
        self.assertEqual(stats["by_severity"].get("high"), 1)
        self.assertEqual(stats["by_surface"].get("filesystem"), 1)
        self.storage.set_status(finding.id, "remediated")
        stats = self.storage.stats()
        self.assertEqual(stats["open"], 0)
        self.assertEqual(stats["by_status"].get("remediated"), 1)

    def test_list_findings_filters(self):
        self.storage.upsert_finding(make_finding("src/a.py"))
        self.storage.upsert_finding(make_finding("src/b.py"))
        self.assertEqual(len(self.storage.list_findings(surface="filesystem")), 2)
        self.assertEqual(len(self.storage.list_findings(q="src/a.py")), 1)
        self.assertEqual(len(self.storage.list_findings(status="open")), 2)
        self.assertEqual(len(self.storage.list_findings(status="triaged")), 0)

    def test_allowlist_add_and_list(self):
        self.storage.allowlist_add("fp-1", "confirmed placeholder")
        entries = self.storage.allowlist_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["fingerprint"], "fp-1")
        self.assertEqual(entries[0]["reason"], "confirmed placeholder")
        self.assertEqual(self.storage.allowlist_fingerprints(), {"fp-1"})

    def test_remediation_add_and_list(self):
        finding = make_finding()
        self.storage.upsert_finding(finding)
        self.storage.add_remediation(
            Remediation(finding_id=finding.id, action="redact", detail="done"))
        rows = self.storage.list_remediations(finding.id)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["action"], "redact")
        self.assertEqual(rows[0]["detail"], "done")
        self.assertEqual(self.storage.list_remediations("other"), [])

    def test_events_add_and_list(self):
        self.storage.add_event(
            Event(kind="scan.completed", surface="filesystem", payload={"new": 2}))
        events = self.storage.list_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["kind"], "scan.completed")
        self.assertEqual(events[0]["payload"], {"new": 2})

    def test_alerts_add_and_list(self):
        finding = make_finding()
        self.storage.upsert_finding(finding)
        self.storage.add_alert(
            Alert(finding_id=finding.id, channel="outbox", message="hello"))
        alerts = self.storage.list_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["channel"], "outbox")
        self.assertEqual(self.storage.stats()["alerts_sent"], 1)

    def test_set_meta(self):
        finding = make_finding()
        self.storage.upsert_finding(finding)
        self.storage.set_meta(finding.id, {"triage": {"verdict": "needs_review"}})
        stored = self.storage.get_finding(finding.id)
        self.assertEqual(stored.meta["triage"]["verdict"], "needs_review")


if __name__ == "__main__":
    unittest.main()