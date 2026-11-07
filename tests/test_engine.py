"""Engine line numbering, tree walking, binary and oversize skipping."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from keysentry.config import load_config
from keysentry.core.engine import scan_file, scan_text, scan_tree

AWS_LINE = 'AWS_KEY = "AWS_KEY_REDACTED"'
GH_LINE = 'GITHUB_TOKEN = "GITHUB_TOKEN_REDACTED"'


class ScanTextTests(unittest.TestCase):
    def test_line_numbers_multiline(self):
        text = "\n".join(["first", AWS_LINE, "third", GH_LINE, ""])
        findings = scan_text(text, "multi.py", "filesystem")
        by_detector = {f.detector_id: f for f in findings}
        self.assertIn("aws-access-key-id", by_detector)
        self.assertIn("github-token", by_detector)
        self.assertEqual(by_detector["aws-access-key-id"].line, 2)
        self.assertEqual(by_detector["github-token"].line, 4)

    def test_single_line_is_line_one(self):
        findings = scan_text(AWS_LINE, "one.py", "filesystem")
        self.assertEqual(findings[0].line, 1)


class ScanTreeTests(unittest.TestCase):
    def setUp(self):
        self.cfg = load_config()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def test_ignore_dirs_pruned(self):
        ignored = self.root / "node_modules"
        ignored.mkdir()
        (ignored / "x.py").write_text(AWS_LINE + "\n", encoding="utf-8")
        src = self.root / "src"
        src.mkdir()
        (src / "y.py").write_text(AWS_LINE + "\n", encoding="utf-8")

        findings, count = scan_tree(self.root, "filesystem", self.cfg)
        self.assertEqual(count, 1)
        self.assertTrue(findings)
        for finding in findings:
            self.assertIn("src", Path(finding.path).parts)
            self.assertNotIn("node_modules", Path(finding.path).parts)

    def test_binary_file_skipped(self):
        path = self.root / "blob.bin"
        path.write_bytes(b"\0\0binary" + AWS_LINE.encode())
        self.assertEqual(scan_file(path, "filesystem", self.cfg), [])

    def test_oversize_file_skipped(self):
        self.cfg["scan"]["max_file_bytes"] = 8
        path = self.root / "big.py"
        path.write_text(AWS_LINE + "\n", encoding="utf-8")
        self.assertGreater(path.stat().st_size, 8)
        self.assertEqual(scan_file(path, "filesystem", self.cfg), [])

    def test_scan_tree_on_single_file(self):
        path = self.root / "solo.py"
        path.write_text(AWS_LINE + "\n", encoding="utf-8")
        findings, count = scan_tree(path, "filesystem", self.cfg)
        self.assertEqual(count, 1)
        self.assertTrue(any(f.detector_id == "aws-access-key-id" for f in findings))


if __name__ == "__main__":
    unittest.main()