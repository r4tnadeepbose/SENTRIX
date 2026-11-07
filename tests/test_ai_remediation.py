"""Heuristic triage bounds, rotation guides, and redact/rotate-guide playbooks."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wintermute.ai.triage import heuristic_triage
from wintermute.config import load_config, resolve_path
from wintermute.core.engine import scan_text
from wintermute.core.models import Finding
from wintermute.core.storage import Storage
from wintermute.remediation.playbooks import execute, rotation_guide

VERDICTS = {"likely_true_positive", "likely_false_positive", "needs_review"}
AWS_TEXT = 'AWS_KEY = "AWS_KEY_REDACTED"'


class HeuristicTriageTests(unittest.TestCase):
    def test_valid_verdict_and_confidence_bounds(self):
        finding = scan_text(AWS_TEXT, "src/a.py", "filesystem")[0]
        result = heuristic_triage(finding)
        self.assertEqual(result["source"], "heuristic")
        self.assertIn(result["verdict"], VERDICTS)
        self.assertGreaterEqual(result["confidence"], 0.05)
        self.assertLessEqual(result["confidence"], 0.95)
        self.assertIsInstance(result["reasons"], list)
        self.assertTrue(result["reasons"])
        self.assertIsInstance(result["recommendation"], str)

    def test_placeholder_path_is_false_positive(self):
        finding = Finding(
            detector_id="aws-access-key-id", title="AWS Access Key ID",
            severity="low", surface="filesystem", path="tests/example_fixture.py",
            line=1, secret_masked="AKIA********MPLE", entropy=2.0,
            fingerprint="placeholder-fp")
        result = heuristic_triage(finding)
        self.assertEqual(result["verdict"], "likely_false_positive")
        self.assertLessEqual(result["confidence"], 0.35)


class PlaybookTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.cfg = load_config()
        self.cfg["storage"]["path"] = str(self.root / "rem.db")
        self.storage = Storage(Path(self.cfg["storage"]["path"]))
        self.addCleanup(self.storage.close)

    def test_rotation_guide_has_numbered_steps(self):
        finding = scan_text(AWS_TEXT, "src/a.py", "filesystem")[0]
        guide = rotation_guide(finding)
        self.assertIn(finding.title, guide)
        self.assertIn("1. ", guide)
        self.assertIn("2. ", guide)
        self.assertIn("5. ", guide)

    def test_execute_rotate_guide_writes_file_and_triages(self):
        finding = scan_text(AWS_TEXT, "src/a.py", "filesystem")[0]
        self.storage.upsert_finding(finding)
        target = resolve_path(self.cfg, f"data/remediation/{finding.id}.md")
        self.addCleanup(lambda: target.unlink(missing_ok=True))
        detail = execute("rotate-guide", finding, self.cfg, self.storage)
        self.assertTrue(target.is_file())
        self.assertIn(str(target), detail)
        self.assertEqual(self.storage.get_finding(finding.id).status, "triaged")
        rows = self.storage.list_remediations(finding.id)
        self.assertTrue(any(r["action"] == "rotate-guide" for r in rows))

    def test_execute_redact_rewrites_file_and_remediates(self):
        source = self.root / "leak.py"
        source.write_text(AWS_TEXT + "\n", encoding="utf-8")
        finding = scan_text(source.read_text(encoding="utf-8"),
                            str(source), "filesystem")[0]
        self.assertEqual(finding.detector_id, "aws-access-key-id")
        self.storage.upsert_finding(finding)
        execute("redact", finding, self.cfg, self.storage)
        contents = source.read_text(encoding="utf-8")
        self.assertIn("<REDACTED:aws-access-key-id>", contents)
        self.assertNotIn("AWS_KEY_REDACTED", contents)
        self.assertEqual(self.storage.get_finding(finding.id).status, "remediated")

    def test_execute_unknown_action_raises(self):
        finding = scan_text(AWS_TEXT, "src/a.py", "filesystem")[0]
        self.storage.upsert_finding(finding)
        with self.assertRaises(ValueError):
            execute("not-an-action", finding, self.cfg, self.storage)


if __name__ == "__main__":
    unittest.main()