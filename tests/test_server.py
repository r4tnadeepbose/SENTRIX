"""HTTP API: health, scan (no persist), demo, triage, status, allowlist, stats."""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from keysentry.config import load_config
from keysentry.server import make_server

AWS_TEXT = 'AWS_KEY = "AWS_KEY_REDACTED"'
VERDICTS = {"likely_true_positive", "likely_false_positive", "needs_review"}


class ServerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        cfg = load_config()
        cfg["storage"]["path"] = str(Path(self._tmp.name) / "server.db")
        cfg["server"]["port"] = 0
        cfg["alerting"]["channels"] = ["outbox"]
        self.server = make_server(cfg)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.server.state.storage.close()

    def _request(self, path, payload=None):
        url = self.base + path
        if payload is None:
            req = urllib.request.Request(url)
        else:
            req = urllib.request.Request(
                url, data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())

    def _seed(self):
        result = self._request("/api/demo", {})
        self.assertGreater(result["seeded"], 0)
        return self._request("/api/findings")["findings"]

    def test_health_ok(self):
        body = self._request("/api/health")
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["product"], "KeySentry")
        self.assertIn("version", body)

    def test_scan_text_does_not_persist(self):
        before = self._request("/api/stats")["total"]
        body = self._request("/api/scan", {"text": AWS_TEXT})
        self.assertTrue(body["findings"])
        self.assertTrue(
            any(f["detector_id"] == "aws-access-key-id" for f in body["findings"]))
        after = self._request("/api/stats")["total"]
        self.assertEqual(before, after)

    def test_demo_seeds_and_findings_listed(self):
        findings = self._seed()
        self.assertTrue(findings)
        listed = self._request("/api/findings")["findings"]
        self.assertEqual(len(listed), len(findings))
        self.assertTrue(all("id" in f for f in listed))

    def test_status_change(self):
        finding = self._seed()[0]
        body = self._request(
            f"/api/findings/{finding['id']}/status", {"status": "triaged"})
        self.assertTrue(body["ok"])
        self.assertEqual(body["finding"]["status"], "triaged")
        fetched = self._request(f"/api/findings/{finding['id']}")
        self.assertEqual(fetched["finding"]["status"], "triaged")

    def test_triage_returns_verdict(self):
        finding = self._seed()[0]
        body = self._request("/api/triage", {"id": finding["id"]})
        self.assertTrue(body["ok"])
        self.assertIn(body["triage"]["verdict"], VERDICTS)
        self.assertIn("confidence", body["triage"])

    def test_allowlist_marks_false_positive(self):
        finding = self._seed()[0]
        body = self._request(
            "/api/allowlist",
            {"fingerprint": finding["fingerprint"], "reason": "test"})
        self.assertTrue(body["ok"])
        fetched = self._request(f"/api/findings/{finding['id']}")
        self.assertEqual(fetched["finding"]["status"], "false_positive")
        entries = self._request("/api/allowlist")["entries"]
        self.assertTrue(
            any(e["fingerprint"] == finding["fingerprint"] for e in entries))

    def test_stats_shape(self):
        self._seed()
        stats = self._request("/api/stats")
        for key in ("total", "open", "by_severity", "by_surface", "by_status",
                    "alerts_sent", "events_processed", "remediations"):
            self.assertIn(key, stats)
        self.assertIsInstance(stats["by_severity"], dict)
        self.assertGreater(stats["total"], 0)

    def test_events_and_alerts_endpoints(self):
        self._seed()
        events = self._request("/api/events")["events"]
        alerts = self._request("/api/alerts")["alerts"]
        self.assertIsInstance(events, list)
        self.assertIsInstance(alerts, list)
        self.assertTrue(events)
        self.assertTrue(alerts)


if __name__ == "__main__":
    unittest.main()