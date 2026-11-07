"""ExtStorage: extras, notes, history, checklists, retention, dump/import, backup."""
from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from keysentry.core.engine import scan_text
from keysentry.core.extensions import ExtStorage

AWS_TEXT = 'AWS_KEY = "AWS_KEY_REDACTED"'
EXTRA_DEFAULTS = {
    "assignee": "", "tags": [], "severity_override": "", "pinned": 0,
    "muted": 0, "occurrences": 1, "first_seen": "", "last_seen": "",
}


def make_finding(path="src/a.py"):
    return scan_text(AWS_TEXT, path, "filesystem")[0]


class ExtStorageTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.storage = ExtStorage(self.root / "ext.db")
        self.addCleanup(self.storage.close)

    def test_extra_defaults_for_unknown_finding(self):
        self.assertEqual(self.storage.get_extra("missing"), EXTRA_DEFAULTS)

    def test_update_extra_tags_roundtrip(self):
        finding = make_finding()
        self.storage.upsert_finding(finding)
        self.storage.update_extra(
            finding.id, tags=["prod", "aws"], assignee="alice", pinned=1)
        extra = self.storage.get_extra(finding.id)
        self.assertEqual(extra["tags"], ["prod", "aws"])
        self.assertEqual(extra["assignee"], "alice")
        self.assertEqual(extra["pinned"], 1)
        self.assertTrue(extra["first_seen"])
        self.storage.update_extra(finding.id, tags=[])
        self.assertEqual(self.storage.get_extra(finding.id)["tags"], [])

    def test_upsert_increments_occurrences(self):
        finding = make_finding()
        self.assertTrue(self.storage.upsert_finding(finding))
        self.assertEqual(self.storage.get_extra(finding.id)["occurrences"], 1)
        duplicate = make_finding()
        self.assertFalse(self.storage.upsert_finding(duplicate))
        extra = self.storage.get_extra(finding.id)
        self.assertEqual(extra["occurrences"], 2)
        self.assertTrue(extra["last_seen"])
        self.assertFalse(self.storage.upsert_finding(make_finding()))
        self.assertEqual(self.storage.get_extra(finding.id)["occurrences"], 3)
        self.assertEqual(len(self.storage.list_findings()), 1)

    def test_set_status_writes_history(self):
        finding = make_finding()
        self.storage.upsert_finding(finding)
        self.storage.set_status(finding.id, "triaged", "alice")
        history = self.storage.list_history(finding.id)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["old"], "open")
        self.assertEqual(history[0]["new"], "triaged")
        self.assertEqual(history[0]["username"], "alice")
        self.assertTrue(history[0]["ts"])
        # Setting the same status again adds no history entry.
        self.storage.set_status(finding.id, "triaged", "bob")
        self.assertEqual(len(self.storage.list_history(finding.id)), 1)
        self.storage.set_status(finding.id, "remediated", "bob")
        history = self.storage.list_history(finding.id)
        self.assertEqual(len(history), 2)
        self.assertEqual(history[-1]["new"], "remediated")

    def test_notes_add_and_list(self):
        finding = make_finding()
        self.storage.upsert_finding(finding)
        self.storage.add_note(finding.id, "alice", "first note")
        self.storage.add_note(finding.id, "bob", "second note")
        notes = self.storage.list_notes(finding.id)
        self.assertEqual([n["body"] for n in notes], ["first note", "second note"])
        self.assertEqual([n["username"] for n in notes], ["alice", "bob"])
        self.assertEqual(self.storage.list_notes("other"), [])

    def test_checklist_set_and_get(self):
        finding = make_finding()
        self.storage.upsert_finding(finding)
        self.storage.set_checklist_step(finding.id, 0, True, "alice")
        self.storage.set_checklist_step(finding.id, 1, False, "bob")
        checklist = self.storage.get_checklist(finding.id)
        self.assertEqual(set(checklist), {0, 1})
        self.assertEqual(checklist[0]["done"], 1)
        self.assertEqual(checklist[0]["username"], "alice")
        self.assertEqual(checklist[1]["done"], 0)
        # Updating a step replaces it instead of adding a row.
        self.storage.set_checklist_step(finding.id, 0, False, "bob")
        checklist = self.storage.get_checklist(finding.id)
        self.assertEqual(len(checklist), 2)
        self.assertEqual(checklist[0]["done"], 0)
        self.assertEqual(checklist[0]["username"], "bob")
        self.assertEqual(self.storage.get_checklist("other"), {})

    def test_purge_retention_removes_old_remediated(self):
        old_remediated = make_finding("src/old_remediated.py")
        old_open = make_finding("src/old_open.py")
        recent_remediated = make_finding("src/recent.py")
        for finding in (old_remediated, old_open, recent_remediated):
            self.storage.upsert_finding(finding)
        self.storage.set_status(old_remediated.id, "remediated", "alice")
        self.storage.set_status(recent_remediated.id, "remediated", "alice")
        self.storage.add_note(old_remediated.id, "alice", "done")
        self.storage.update_extra(old_remediated.id, tags=["stale"])
        self.storage.set_checklist_step(old_remediated.id, 0, True, "alice")
        # Backdate two findings well beyond the retention window.
        self.storage._db.execute(
            "UPDATE findings SET updated_at=? WHERE id IN (?,?)",
            ("2000-01-01T00:00:00", old_remediated.id, old_open.id))
        self.storage._db.commit()

        removed = self.storage.purge_retention(90)
        self.assertEqual(removed, 1)
        self.assertIsNone(self.storage.get_finding(old_remediated.id))
        self.assertEqual(self.storage.list_notes(old_remediated.id), [])
        self.assertEqual(self.storage.list_history(old_remediated.id), [])
        self.assertEqual(self.storage.get_checklist(old_remediated.id), {})
        self.assertEqual(self.storage.get_extra(old_remediated.id), EXTRA_DEFAULTS)
        # Open findings and recent remediations survive the purge.
        self.assertIsNotNone(self.storage.get_finding(old_open.id))
        self.assertIsNotNone(self.storage.get_finding(recent_remediated.id))

    def test_dump_json_import_json_roundtrip(self):
        finding = make_finding()
        self.storage.upsert_finding(finding)
        self.storage.add_note(finding.id, "alice", "roundtrip")
        self.storage.update_extra(finding.id, tags=["aws"], assignee="alice")
        self.storage.add_filter("flt-1", "alice", "saved", {"severity": "high"})
        self.storage.add_schedule("sch-1", ".", "filesystem", 3600)
        self.storage.add_rule("rule-1", "outbox", "high")
        self.storage.allowlist_add("fp-x", "test")

        dump = self.storage.dump_json()
        for table in ("findings", "events", "alerts", "allowlist", "remediations",
                      "notes", "finding_extra", "saved_filters", "schedules",
                      "alert_rules"):
            self.assertIn(table, dump)

        other = ExtStorage(self.root / "import.db")
        self.addCleanup(other.close)
        imported = other.import_json(dump)
        # import_json only restores the tables it accepts.
        restorable = ("findings", "allowlist", "notes", "finding_extra",
                      "saved_filters", "schedules", "alert_rules")
        self.assertEqual(imported, sum(len(dump[t]) for t in restorable))
        self.assertEqual([f.to_dict() for f in other.list_findings()],
                         [f.to_dict() for f in self.storage.list_findings()])
        self.assertEqual(other.list_notes(finding.id),
                         self.storage.list_notes(finding.id))
        self.assertEqual(other.get_extra(finding.id),
                         self.storage.get_extra(finding.id))
        self.assertEqual(other.list_filters("alice"),
                         self.storage.list_filters("alice"))
        self.assertEqual(other.list_schedules(), self.storage.list_schedules())
        self.assertEqual(other.list_rules(), self.storage.list_rules())
        self.assertEqual(other.allowlist_entries(),
                         self.storage.allowlist_entries())

    def test_backup_creates_file(self):
        finding = make_finding()
        self.storage.upsert_finding(finding)
        dest = self.root / "backups" / "copy.db"
        self.storage.backup(dest)
        self.assertTrue(dest.is_file())
        self.assertGreater(dest.stat().st_size, 0)
        conn = sqlite3.connect(str(dest))
        try:
            count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()