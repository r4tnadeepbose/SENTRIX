"""CLI entry point: selftest, scan --json --no-store, and gate outside a repo."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from keysentry.config import ROOT as PROJECT_ROOT

RUN_PY = str(PROJECT_ROOT / "run.py")
AWS_TEXT = 'AWS_KEY = "AWS_KEY_REDACTED"'


def run_cli(args, cwd=None, env=None):
    return subprocess.run(
        [sys.executable, RUN_PY, *args],
        cwd=str(cwd) if cwd else str(PROJECT_ROOT),
        env=env, capture_output=True, text=True, timeout=120)


class CliTests(unittest.TestCase):
    def test_selftest_exits_zero(self):
        proc = run_cli(["selftest"])
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("PASS", proc.stdout)

    def test_scan_json_no_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "leak.py"
            target.write_text(AWS_TEXT + "\n", encoding="utf-8")
            proc = run_cli(["scan", str(target), "--json", "--no-store"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertIsInstance(data, list)
        self.assertTrue(data)
        self.assertTrue(
            any(f["detector_id"] == "aws-access-key-id" for f in data))

    def test_gate_staged_outside_repo_exits_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            # Prevent git from discovering a repository above the temp dir.
            env["GIT_CEILING_DIRECTORIES"] = str(Path(tmp).resolve())
            proc = run_cli(["gate", "--staged"], cwd=tmp, env=env)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("Not inside a git repository", proc.stderr)


if __name__ == "__main__":
    unittest.main()