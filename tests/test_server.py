"""HTTP API: auth gate, RBAC, tokens, findings management, jobs, schedules, ops."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.cookies import SimpleCookie
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentrix.config import load_config
from sentrix.server import make_server

AWS_TEXT = 'AWS_KEY = "' + "AKIA" + "QRSTUVWXYZ123456" + '"'
ADMIN_PASSWORD = "test-admin-pass-123"
VERDICTS = {"likely_true_positive", "likely_false_positive", "needs_review"}
# Sentinel: _request uses the admin session cookie unless told otherwise.
_DEFAULT_COOKIE = object()


class ServerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        cfg = load_config()
        cfg["storage"]["path"] = str(Path(self._tmp.name) / "server.db")
        cfg["server"]["port"] = 0
        cfg["alerting"]["channels"] = ["outbox"]
        # make_server creates the admin account from this env var; restore it
        # right after so the rest of the suite sees the original environment.
        previous = os.environ.get("SENTRIX_ADMIN_PASSWORD")
        os.environ["SENTRIX_ADMIN_PASSWORD"] = ADMIN_PASSWORD
        try:
            self.server = make_server(cfg)
        finally:
            if previous is None:
                os.environ.pop("SENTRIX_ADMIN_PASSWORD", None)
            else:
                os.environ["SENTRIX_ADMIN_PASSWORD"] = previous
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.cookie = self._login()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.server.state.storage.close()

    # -- helpers

    def _http(self, path, payload=None, method=None, headers=None):
        """Low-level request; returns (status, headers, body bytes) for any code."""
        data = json.dumps(payload).encode() if payload is not None else None
        if method is None:
            method = "POST" if data is not None else "GET"
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            resp = urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers, exc.read()
        with resp:
            return resp.getcode(), resp.headers, resp.read()

    def _login(self, username="admin", password=ADMIN_PASSWORD):
        code, headers, body = self._http(
            "/api/auth/login", {"username": username, "password": password})
        self.assertEqual(code, 200, body.decode(errors="replace"))
        cookie = SimpleCookie(headers.get("Set-Cookie", ""))
        self.assertIn("sx_session", cookie)
        return cookie["sx_session"].value

    def _request(self, path, payload=None, cookie=_DEFAULT_COOKIE,
                 method=None, headers=None, expect=200):
        """Authenticated JSON request; pass cookie=None to send no session."""
        if cookie is _DEFAULT_COOKIE:
            cookie = self.cookie
        merged = dict(headers or {})
        if cookie:
            merged["Cookie"] = f"sx_session={cookie}"
        code, _, body = self._http(path, payload, method=method, headers=merged)
        self.assertEqual(code, expect, body.decode(errors="replace"))
        return json.loads(body.decode())

    def _seed(self):
        # First run auto-seeds demo data; a second demo call may seed 0.
        self._request("/api/demo", {})
        findings = self._request("/api/findings")["findings"]
        self.assertTrue(findings)
        return findings

    def _scan_target(self):
        target = Path(self._tmp.name) / "target"
        target.mkdir(exist_ok=True)
        (target / "leak.py").write_text(AWS_TEXT + "\n", encoding="utf-8")
        return target

    def _wait_job(self, jid, timeout=10.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            job = self._request(f"/api/jobs/{jid}")["job"]
            if job["status"] in ("done", "failed", "cancelled"):
                return job
            time.sleep(0.1)
        self.fail(f"job {jid} did not finish within {timeout}s")

    # -- public endpoints and the auth gate

    def test_health_ok_without_auth(self):
        code, _, body = self._http("/api/health")
        self.assertEqual(code, 200)
        payload = json.loads(body.decode())
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["product"], "SENTRIX")
        self.assertIn("version", payload)

    def test_unauthenticated_requests_rejected(self):
        self._request("/api/stats", cookie=None, expect=401)
        self._request("/api/scan", {"text": AWS_TEXT}, cookie=None, expect=401)
        self._request("/api/findings", cookie="not-a-real-session", expect=401)

    def test_login_wrong_password_rejected(self):
        body = self._request(
            "/api/auth/login", {"username": "admin", "password": "wrong-password"},
            cookie=None, expect=400)
        self.assertIn("error", body)

    def test_login_session_identifies_admin(self):
        me = self._request("/api/auth/me")
        self.assertEqual(me["user"]["username"], "admin")
        self.assertEqual(me["user"]["role"], "super_admin")

    # -- role based access control

    def test_viewer_role_cannot_post(self):
        self._request("/api/users", {
            "username": "viewer1", "password": "viewer-pass-123", "role": "viewer"})
        viewer_cookie = self._login("viewer1", "viewer-pass-123")
        self._request("/api/scan", {"text": AWS_TEXT},
                      cookie=viewer_cookie, expect=403)
        # Viewers keep read access.
        stats = self._request("/api/stats", cookie=viewer_cookie)
        self.assertIn("total", stats)

    def test_users_endpoint_admin_only(self):
        self._request("/api/users", {
            "username": "analyst1", "password": "analyst-pass-123", "role": "security_analyst"})
        analyst_cookie = self._login("analyst1", "analyst-pass-123")
        self._request("/api/users", cookie=analyst_cookie, expect=403)
        users = self._request("/api/users")["users"]
        self.assertTrue(any(u["username"] == "analyst1" for u in users))

    # -- scanning, demo, triage, allowlist, stats (authenticated)

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
        # First run already auto-seeded; a repeat demo call only dedupes.
        again = self._request("/api/demo", {})
        self.assertEqual(again["seeded"], 0)
        self.assertEqual(len(self._request("/api/findings")["findings"]),
                         len(findings))

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

    # -- finding management

    def test_notes_add_and_list(self):
        finding = self._seed()[0]
        fid = finding["id"]
        self._request(f"/api/findings/{fid}/notes", {"body": "rotated via vault"})
        notes = self._request(f"/api/findings/{fid}/notes")["notes"]
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["body"], "rotated via vault")
        self.assertEqual(notes[0]["username"], "admin")

    def test_bulk_status_update(self):
        findings = self._seed()
        ids = [f["id"] for f in findings[:2]]
        body = self._request(
            "/api/bulk", {"ids": ids, "action": "status", "value": "triaged"})
        self.assertTrue(body["ok"])
        self.assertEqual(body["affected"], len(ids))
        for fid in ids:
            fetched = self._request(f"/api/findings/{fid}")
            self.assertEqual(fetched["finding"]["status"], "triaged")

    # -- Hubs collaboration security

    def test_hubs_team_channel_requires_membership(self):
        self._request("/api/users", {
            "username": "analyst2", "password": "analyst-pass-456", "role": "security_analyst"})
        analyst_cookie = self._login("analyst2", "analyst-pass-456")
        created = self._request("/api/hubs/channels", {
            "name": "Private response", "description": "Restricted incident room"})
        cid = created["id"]
        self._request(f"/api/hubs/channels/{cid}/messages", cookie=analyst_cookie, expect=403)
        self._request(f"/api/hubs/channels/{cid}/join", {}, cookie=analyst_cookie)
        messages = self._request(f"/api/hubs/channels/{cid}/messages", cookie=analyst_cookie)["messages"]
        self.assertEqual(messages, [])

    def test_hubs_direct_messages_are_private_and_notify_recipient(self):
        for username in ("analyst3", "analyst4"):
            self._request("/api/users", {
                "username": username, "password": f"{username}-pass-123", "role": "security_analyst"})
        sender = self._login("analyst3", "analyst3-pass-123")
        recipient = self._login("analyst4", "analyst4-pass-123")
        posted = self._request("/api/hubs/dm/analyst4/messages", {"body": "Need a second look."}, cookie=sender)
        self.assertTrue(posted["ok"])
        received = self._request("/api/hubs/dm/analyst3/messages", cookie=recipient)
        self.assertEqual(received["messages"][0]["body"], "Need a second look.")
        notifications = self._request("/api/hubs/notifications", cookie=recipient)["notifications"]
        self.assertEqual(notifications[0]["type"], "direct_message")

    def test_hubs_ping_is_rate_limited_and_never_targets_sender(self):
        self._request("/api/users", {
            "username": "analyst5", "password": "analyst-pass-567", "role": "security_analyst"})
        analyst_cookie = self._login("analyst5", "analyst-pass-567")
        self._request("/api/hubs/ping", {"to_user": "analyst5"}, cookie=analyst_cookie, expect=400)
        for _ in range(3):
            self.assertTrue(self._request("/api/hubs/ping", {"to_user": "admin"}, cookie=analyst_cookie)["ok"])
        self._request("/api/hubs/ping", {"to_user": "admin"}, cookie=analyst_cookie, expect=429)

    def test_hubs_open_chat_notifies_eligible_participants(self):
        self._request("/api/users", {
            "username": "analyst6", "password": "analyst-pass-678", "role": "security_analyst"})
        analyst_cookie = self._login("analyst6", "analyst-pass-678")
        self._request("/api/hubs/channels/open-chat/messages", cookie=analyst_cookie)
        self._request("/api/hubs/channels/open-chat/messages", {"body": "Operational update."})
        notifications = self._request("/api/hubs/notifications", cookie=analyst_cookie)["notifications"]
        self.assertEqual(notifications[0]["type"], "channel_message")
        self.assertEqual(notifications[0]["channel_id"], "open-chat")

    def test_hubs_user_directory_excludes_self_and_password_data(self):
        self._request("/api/users", {
            "username": "analyst8", "password": "analyst-pass-890", "role": "security_analyst"})
        analyst_cookie = self._login("analyst8", "analyst-pass-890")
        users = self._request("/api/hubs/users", cookie=analyst_cookie)["users"]
        self.assertNotIn("analyst8", {u["username"] for u in users})
        self.assertIn("admin", {u["username"] for u in users})
        self.assertTrue(all("password_hash" not in u for u in users))

    def test_hubs_ping_everyone_is_admin_only(self):
        self._request("/api/users", {
            "username": "analyst7", "password": "analyst-pass-789", "role": "security_analyst"})
        analyst_cookie = self._login("analyst7", "analyst-pass-789")
        self._request("/api/hubs/ping-all", {"message": "Please check in."},
                      cookie=analyst_cookie, expect=403)
        result = self._request("/api/hubs/ping-all", {"message": "Please check in."})
        self.assertGreaterEqual(result["delivered"], 1)
        notifications = self._request("/api/hubs/notifications", cookie=analyst_cookie)["notifications"]
        self.assertEqual(notifications[0]["type"], "ping")

    def test_saved_filters_add_list_delete(self):
        params = {"severity": "high", "status": "open"}
        body = self._request("/api/filters", {"name": "high open", "params": params})
        fid = body["id"]
        filters = self._request("/api/filters")["filters"]
        match = next(f for f in filters if f["id"] == fid)
        self.assertEqual(match["name"], "high open")
        self.assertEqual(match["params"], params)
        self._request(f"/api/filters/{fid}/delete", {})
        remaining = self._request("/api/filters")["filters"]
        self.assertFalse(any(f["id"] == fid for f in remaining))

    # -- background jobs, schedules, rules

    def test_jobs_submit_and_poll_until_done(self):
        target = self._scan_target()
        body = self._request("/api/jobs", {"path": str(target)})
        self.assertTrue(body["ok"])
        job = self._wait_job(body["id"])
        self.assertEqual(job["status"], "done", job.get("error", ""))
        self.assertEqual(job["files"], 1)
        self.assertGreaterEqual(job["findings"], 1)

    def test_schedules_add_list_toggle_delete(self):
        body = self._request("/api/schedules", {"path": ".", "interval_seconds": 3600})
        sid = body["id"]
        listed = self._request("/api/schedules")["schedules"]
        sched = next(s for s in listed if s["id"] == sid)
        self.assertEqual(sched["enabled"], 1)
        self._request(f"/api/schedules/{sid}/toggle", {})
        toggled = next(s for s in self._request("/api/schedules")["schedules"]
                       if s["id"] == sid)
        self.assertEqual(toggled["enabled"], 0)
        self._request(f"/api/schedules/{sid}/delete", {})
        remaining = self._request("/api/schedules")["schedules"]
        self.assertFalse(any(s["id"] == sid for s in remaining))

    def test_rules_add_toggle_delete(self):
        body = self._request("/api/rules", {"channel": "outbox", "min_severity": "high"})
        rid = body["id"]
        rule = next(r for r in self._request("/api/rules")["rules"] if r["id"] == rid)
        self.assertEqual(rule["enabled"], 1)
        self._request(f"/api/rules/{rid}/toggle", {})
        toggled = next(r for r in self._request("/api/rules")["rules"] if r["id"] == rid)
        self.assertEqual(toggled["enabled"], 0)
        self._request(f"/api/rules/{rid}/delete", {})
        remaining = self._request("/api/rules")["rules"]
        self.assertFalse(any(r["id"] == rid for r in remaining))

    # -- observability and exports

    def test_logs_contain_auth_login_entry(self):
        logs = self._request("/api/logs")["logs"]
        self.assertTrue(any(
            entry["source"] == "auth" and "signed in" in entry["message"]
            for entry in logs))

    def test_logs_source_filter(self):
        logs = self._request("/api/logs?source=auth")["logs"]
        self.assertTrue(logs)
        self.assertTrue(all(entry["source"] == "auth" for entry in logs))
        self.assertEqual(self._request("/api/logs?source=no-such-source")["logs"], [])

    def test_pipeline_stage_telemetry_is_per_stage(self):
        self._seed()
        stages = {s["id"]: s for s in self._request("/api/pipeline")["stages"]}
        self.assertEqual(len(stages), 11)
        last = self.server.state.storage.log_last_run()
        for stage in stages.values():
            self.assertEqual(stage["last_run"], last.get(stage["logs_source"]))
        for sid in ("source", "ingestion", "validation", "dedup", "risk",
                    "finding", "alerting", "remediation", "verification"):
            self.assertIsNone(stages[sid]["avg_ms"])
        self.assertTrue(self._request("/api/logs?source=ingestion")["logs"])
        self.assertTrue(self._request("/api/logs?source=alert")["logs"])

    def test_overview_stages_keys(self):
        self._seed()
        body = self._request("/api/overview")
        self.assertEqual(set(body["stages"]),
                         {"events", "scans", "findings", "alerts", "remediations"})
        self.assertGreater(body["stages"]["findings"], 0)
        self.assertGreaterEqual(body["detectors"], 26)
        self.assertTrue(body["surfaces"])

    def test_detectors_list_at_least_26(self):
        detectors = self._request("/api/detectors")["detectors"]
        self.assertGreaterEqual(len(detectors), 26)
        self.assertIn("aws-access-key-id", {d["id"] for d in detectors})
        for detector in detectors:
            for key in ("id", "title", "severity", "family", "enabled"):
                self.assertIn(key, detector)

    def test_export_csv_header(self):
        self._seed()
        code, headers, body = self._http(
            "/api/export?format=csv",
            headers={"Cookie": f"sx_session={self.cookie}"})
        self.assertEqual(code, 200)
        self.assertIn("text/csv", headers.get("Content-Type", ""))
        self.assertTrue(body.decode().startswith("id,severity"))

    # -- ops and API tokens

    def test_ops_backup_returns_existing_path(self):
        body = self._request("/api/ops/backup", {})
        self.assertTrue(body["ok"])
        path = Path(body["path"])
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        self.assertTrue(path.is_file())
        self.assertGreater(path.stat().st_size, 0)

    def test_token_create_use_and_revoke(self):
        body = self._request("/api/tokens", {"name": "ci-test", "role": "security_analyst"})
        token = body["token"]
        self.assertTrue(token.startswith("sxt_"))
        bearer = {"Authorization": f"Bearer {token}"}
        stats = self._request("/api/stats", cookie=None, headers=bearer)
        self.assertIn("total", stats)
        tokens = self._request("/api/tokens")["tokens"]
        tid = next(t["id"] for t in tokens if t["name"] == "ci-test")
        self._request(f"/api/tokens/{tid}/revoke", {})
        self._request("/api/stats", cookie=None, headers=bearer, expect=401)


if __name__ == "__main__":
    unittest.main()
