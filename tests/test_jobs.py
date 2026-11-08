"""JobRunner: background scans, incremental cache reuse, deterministic cancel."""
from __future__ import annotations

import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentrix.config import load_config
from sentrix.core.engine import scan_file
from sentrix.core.extensions import ExtStorage
from sentrix.core.jobs import JobRunner
from sentrix.core.pipeline import Pipeline

AWS_TEXT = 'AWS_KEY = "' + "AKIA" + "QRSTUVWXYZ123456" + '"'
TERMINAL = ("done", "failed", "cancelled")


class JobRunnerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.cfg = load_config()
        self.cfg["storage"]["path"] = str(self.root / "jobs.db")
        self.cfg["alerting"]["channels"] = ["outbox"]
        self.storage = ExtStorage(Path(self.cfg["storage"]["path"]))
        self.addCleanup(self.storage.close)
        # No router: jobs stay offline and write no alert outbox entries.
        self.pipeline = Pipeline(self.cfg, self.storage)
        self.runner = JobRunner(self.storage, self.pipeline, self.cfg)
        self.target = self.root / "target"
        self.target.mkdir()
        self.leak = self.target / "leak.py"
        self.leak.write_text(AWS_TEXT + "\n", encoding="utf-8")

    def _wait(self, jid, timeout=10.0):
        # Poll over a separate read connection: the worker thread must be the
        # only user of the shared storage connection while the job runs, or
        # concurrent cursors on one connection can stall the worker.
        deadline = time.monotonic() + timeout
        conn = sqlite3.connect(self.cfg["storage"]["path"])
        conn.row_factory = sqlite3.Row
        try:
            while time.monotonic() < deadline:
                row = conn.execute(
                    "SELECT * FROM scan_jobs WHERE id=?", (jid,)).fetchone()
                job = dict(row) if row else None
                if job and job["status"] in TERMINAL:
                    return job
                time.sleep(0.05)
        finally:
            conn.close()
        self.fail(f"job {jid} did not finish within {timeout}s")

    def test_submit_scans_secret_file_to_completion(self):
        jid = self.runner.submit(str(self.target), "filesystem", "tester")
        job = self._wait(jid)
        self.assertEqual(job["status"], "done", job["error"])
        self.assertEqual(job["files"], 1)
        self.assertGreaterEqual(job["findings"], 1)
        self.assertTrue(job["finished"])
        self.assertEqual(self.storage.stats()["total"], 1)
        cached = self.storage.cache_get(str(self.leak))
        self.assertIsNotNone(cached)
        self.assertEqual(cached["mtime"], self.leak.stat().st_mtime)
        self.assertEqual(cached["size"], self.leak.stat().st_size)

    def test_second_run_reuses_cache_and_dedupes(self):
        first = self._wait(
            self.runner.submit(str(self.target), "filesystem", "tester"))
        self.assertEqual(first["status"], "done", first["error"])
        self.assertGreaterEqual(first["findings"], 1)
        before = self.storage.cache_get(str(self.leak))
        self.assertIsNotNone(before)

        with mock.patch("sentrix.core.jobs.scan_file",
                        wraps=scan_file) as scan_spy:
            second = self._wait(
                self.runner.submit(str(self.target), "filesystem", "tester"))
        # The unchanged file is served from cache: no rescan, no cache rewrite.
        scan_spy.assert_not_called()
        self.assertEqual(second["status"], "done", second["error"])
        # Cached findings are re-ingested but deduped by the pipeline.
        self.assertEqual(second["findings"], 0)
        after = self.storage.cache_get(str(self.leak))
        self.assertEqual(after["mtime"], before["mtime"])
        self.assertEqual(after, before)
        self.assertEqual(self.storage.stats()["total"], 1)

    def test_cancel_before_run_marks_cancelled(self):
        # Drive _run synchronously: submit-then-cancel would race the worker
        # thread, so queue the job and cancel it before any scan can start.
        jid = "job-cancelled-unit"
        self.storage.add_job(jid, str(self.target), "filesystem", "tester")
        self.runner.cancel(jid)
        self.runner._run(jid)
        job = self.storage.get_job(jid)
        self.assertEqual(job["status"], "cancelled")
        self.assertTrue(job["finished"])
        self.assertEqual(self.storage.stats()["total"], 0)
        self.assertIsNone(self.storage.cache_get(str(self.leak)))


if __name__ == "__main__":
    unittest.main()