"""SENTRIX enterprise layer: risk, lifecycle, reports, integrations, hardening."""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentrix.config import load_config
from sentrix.core import risk
from sentrix.core.engine import scan_text
from sentrix.core.extensions import ExtStorage
from sentrix.core.models import Finding
from sentrix.core.pipeline import Pipeline
from sentrix.core import reports, integrations
from sentrix.server import make_server


def make_finding(**kw):
    base = dict(detector_id="aws-access-key-id", title="AWS Access Key ID",
                severity="critical", surface="ci", path="repo/app.py", line=1,
                secret_masked="AKIA********3456", entropy=4.2,
                fingerprint="a" * 64, meta={"family": "cloud", "confidence": 0.9,
                                            "validation": "format_validated"})
    base.update(kw)
    return Finding(**base)


class EnterpriseTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.cfg = load_config()
        self.cfg["storage"]["path"] = str(Path(self._tmp.name) / "t.db")
        self.cfg["alerting"]["channels"] = ["outbox"]
        self.storage = ExtStorage(Path(self.cfg["storage"]["path"]))
        self.pipeline = Pipeline(self.cfg, self.storage)

    def tearDown(self):
        self.storage.close()

    def test_risk_score_explainable_and_bounded(self):
        result = risk.score(make_finding())
        self.assertTrue(0 <= result["score"] <= 100)
        self.assertTrue(result["factors"])
        self.assertIn(result["band"], ("critical", "high", "medium", "low", "info"))
        self.assertFalse(result["confirmed_validity"])

    def test_lifecycle_transitions_recorded(self):
        f = make_finding()
        self.pipeline.ingest([f], kind="test")
        self.storage.set_status(f.id, "assigned", "p.patel")
        self.storage.set_status(f.id, "in_progress", "p.patel")
        history = self.storage.list_history(f.id)
        self.assertEqual([h["new"] for h in history], ["assigned", "in_progress"])

    def test_reports_generate_and_history(self):
        self.pipeline.ingest([make_finding()], kind="test")
        result = reports.generate("critical", "csv", self.storage, "admin")
        self.assertIn("id,severity", result["body"])
        self.assertEqual(len(self.storage.list_reports()), 1)
        self.assertTrue(self.storage.get_report(result["id"])["body"])

    def test_integration_states_honest(self):
        inv = integrations.inventory(self.cfg, self.storage, demo=True)
        self.assertEqual(len(inv), 9)
        self.assertTrue(all(i["status"] == "demo" for i in inv))
        os.environ["SENTRIX_SLACK_TOKEN"] = "x"
        self.addCleanup(os.environ.pop, "SENTRIX_SLACK_TOKEN", None)
        inv = integrations.inventory(self.cfg, self.storage, demo=True)
        slack = next(i for i in inv if i["id"] == "slack")
        self.assertEqual(slack["status"], "connected")

    def test_legacy_database_migrates(self):
        legacy = Path(self._tmp.name) / "wintermute.db"
        conn = sqlite3.connect(str(legacy))
        conn.execute("CREATE TABLE marker (x TEXT)")
        conn.execute("INSERT INTO marker VALUES ('preserved')")
        conn.commit()
        conn.close()
        target = Path(self._tmp.name) / "sentrix.db"
        store = ExtStorage(target)
        self.assertTrue(target.exists())
        self.assertFalse(legacy.exists())
        self.assertEqual(store._db.execute("SELECT x FROM marker").fetchone()[0], "preserved")
        store.close()

    def test_exceptions_record_reason(self):
        f = make_finding()
        self.pipeline.ingest([f], kind="test")
        self.storage.set_status(f.id, "accepted_risk", "n.singh")
        self.storage.add_note(f.id, "n.singh", "Exception accepted_risk: sandbox only")
        self.assertEqual(self.storage.get_finding(f.id).status, "accepted_risk")
        self.assertTrue(self.storage.list_notes(f.id))


class ServerHardeningTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        cfg = load_config()
        cfg["storage"]["path"] = str(Path(self._tmp.name) / "s.db")
        cfg["server"]["port"] = 0
        cfg["alerting"]["channels"] = ["outbox"]
        os.environ["SENTRIX_ADMIN_PASSWORD"] = "test-admin-pass-123"
        self.addCleanup(os.environ.pop, "SENTRIX_ADMIN_PASSWORD", None)
        self.server = make_server(cfg)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.cookie = self._login()["cookie"]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.server.state.storage.close()

    def _login(self, remember=False):
        req = urllib.request.Request(
            self.base + "/api/auth/login",
            data=json.dumps({"username": "admin", "password": "test-admin-pass-123",
                             "remember": remember}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {"cookie": resp.headers["Set-Cookie"].split(";")[0],
                    "body": json.loads(resp.read().decode())}

    def _post(self, path, payload, headers=None):
        merged = {"Content-Type": "application/json", "Cookie": self.cookie}
        merged.update(headers or {})
        req = urllib.request.Request(self.base + path, data=json.dumps(payload).encode(),
                                     headers=merged, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.getcode(), json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_csrf_origin_rejected(self):
        code, _ = self._post("/api/allowlist", {"fingerprint": "b" * 64},
                             {"Origin": "https://evil.example"})
        self.assertEqual(code, 403)

    def test_remember_me_extends_session(self):
        info = self._login(remember=True)
        session = self.server.state.storage.get_session(info["cookie"].split("=", 1)[1])
        self.assertGreater(session["expires_at"], time.time() + 29 * 86400)

    def test_detection_rules_validate_pattern(self):
        code, body = self._post("/api/detection-rules",
                                {"id": "corp-key", "title": "Corp key", "pattern": "corp_[A-Z0-9]{16}"})
        self.assertEqual(code, 200)
        code, _ = self._post("/api/detection-rules", {"pattern": "["})
        self.assertEqual(code, 400)

    def test_enterprise_endpoints_live(self):
        for path in ("/api/overview", "/api/pipeline", "/api/posture", "/api/intelligence",
                     "/api/sources", "/api/assets", "/api/integrations", "/api/remediation",
                     "/api/investigations", "/api/exceptions", "/api/compliance",
                     "/api/system/health", "/api/reports"):
            req = urllib.request.Request(self.base + path, headers={"Cookie": self.cookie})
            with urllib.request.urlopen(req, timeout=10) as resp:
                self.assertEqual(resp.getcode(), 200, path)
                json.loads(resp.read().decode())


if __name__ == "__main__":
    unittest.main()