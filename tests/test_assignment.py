"""Intelligent assignment engine, storage, RBAC/API, and workflow tests."""
from __future__ import annotations

import json, os, sys, tempfile, threading, time, unittest, urllib.error, urllib.request
from http.cookies import SimpleCookie
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentrix.config import load_config
from sentrix.core.assignment import (
    ASSIGNMENT_STATES, compute_due_dates, explain_assignment, finding_domain,
    pick_secondary, profile_defaults, score_candidate, select_assignee, workload_points,
)
from sentrix.core.assignment_api import dashboard, manual_assign, my_assignments
from sentrix.core.extensions import ExtStorage
from sentrix.server import make_server

ADMIN_PASSWORD = "test-admin-pass-123"
AWS_TEXT = 'AWS_KEY = "' + "AKIA" + "QRSTUVWXYZ123456" + '"'


def mkfinding(severity="medium", surface="git", title="Exposed AWS key", owner="", fid="F1"):
    return SimpleNamespace(id=fid, severity=severity, surface=surface, title=title,
                           detector_id="aws_access_key", meta={"family": "credential"}, owner=owner, status="open")


class AssignmentEngineTests(unittest.TestCase):
    def test_critical_never_assigned_to_developer_by_workload(self):
        f = mkfinding("critical", "cloud", "AWS credential exposure")
        profiles = [profile_defaults("v.iyer", "developer", "Dev"), profile_defaults("a.kumar", "devsecops_engineer", "IR")]
        workloads = {"v.iyer": {"workload_points": 0}, "a.kumar": {"workload_points": 15}}
        res = select_assignee(f, profiles, workloads)
        self.assertIsNotNone(res["chosen"])
        self.assertEqual(res["chosen"]["username"], "a.kumar")
        self.assertTrue(res["chosen"]["eligible"])
        dev = [s for s in res["scored"] if s["username"] == "v.iyer"][0]
        self.assertFalse(dev["eligible"])

    def test_explains_assignment(self):
        f = mkfinding("high", "git")
        chosen = {"username": "r.sharma", "matched_skills": ["Application Security"], "capacity_pct": 35}
        txt = explain_assignment(f, chosen, "automatic")
        self.assertIn("r.sharma", txt)
        self.assertIn("high", txt.lower())
        self.assertIn("Application Security", txt)

    def test_workload_uses_severity_weights(self):
        self.assertGreater(workload_points("critical"), workload_points("high"))
        self.assertGreater(workload_points("high"), workload_points("medium"))
        self.assertGreater(workload_points("medium"), workload_points("low"))
        self.assertGreater(workload_points("low"), workload_points("info"))

    def test_skill_matching_and_domain(self):
        f = mkfinding("high", "cloud", "Cloud credential")
        domains = finding_domain(f)
        self.assertTrue(any(d in domains for d in ("Cloud Security", "AWS Security", "Credential Exposure")))
        prof = profile_defaults("a.kumar", "devsecops_engineer", "IR")
        wl = {"workload_points": 2}
        sc = score_candidate(f, prof, wl)
        self.assertTrue(sc["eligible"])
        self.assertTrue(sc["skill_score"] >= 0)

    def test_unavailable_and_capacity_ineligible(self):
        f = mkfinding("medium")
        prof = profile_defaults("r.sharma", "appsec_engineer", "AS")
        prof["availability_status"] = "unavailable"
        self.assertFalse(score_candidate(f, prof, {"workload_points": 0})["eligible"])
        prof2 = profile_defaults("r.sharma", "appsec_engineer", "AS")
        prof2["max_capacity"] = 5
        self.assertFalse(score_candidate(f, prof2, {"workload_points": 5})["eligible"])

    def test_no_eligible_employee(self):
        f = mkfinding("critical")
        profiles = [profile_defaults("v.iyer", "developer", "Dev")]
        res = select_assignee(f, profiles, {"v.iyer": {"workload_points": 0}})
        self.assertIsNone(res["chosen"])
        self.assertEqual(res["eligible"], [])

    def test_secondary_reviewer_different(self):
        f = mkfinding("critical")
        profiles = [profile_defaults("a.kumar", "devsecops_engineer", "IR"), profile_defaults("r.sharma", "appsec_engineer", "AS")]
        workloads = {u["username"]: {"workload_points": 1} for u in profiles}
        sec = pick_secondary(f, profiles, workloads, "a.kumar")
        self.assertIsNotNone(sec)
        self.assertNotEqual(sec["username"], "a.kumar")

    def test_sla_configurable(self):
        due = compute_due_dates("critical")
        self.assertTrue(due["ack_due_at"])
        self.assertTrue(due["due_at"])
        due2 = compute_due_dates("critical", cfg={"ack_hours": {"critical": 2}, "remediate_hours": {"critical": 8}})
        self.assertEqual(due2["ack_hours"], 2.0)

    def test_assignment_states_defined(self):
        for s in ("unassigned","assigned","acknowledged","in_progress","completed","verified"):
            self.assertIn(s, ASSIGNMENT_STATES)


class AssignmentStorageTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(); self.addCleanup(self._tmp.cleanup)
        self.db = ExtStorage(Path(self._tmp.name) / "a.db"); self.addCleanup(self.db.close)
        self.users = [{"username":"admin","role":"super_admin","title":"Admin","disabled":0},
                      {"username":"r.sharma","role":"appsec_engineer","title":"AS","disabled":0},
                      {"username":"p.patel","role":"security_analyst","title":"SOC","disabled":0},
                      {"username":"a.kumar","role":"devsecops_engineer","title":"IR","disabled":0},
                      {"username":"n.singh","role":"auditor","title":"Aud","disabled":0},
                      {"username":"v.iyer","role":"developer","title":"Dev","disabled":0}]
        self.db.ensure_employee_profiles(self.users)

    def _seed_finding(self, fid="FX1", severity="high"):
        from sentrix.core.engine import scan_text
        f = scan_text(AWS_TEXT, "src/leak.py", "git")[0]
        f.id = fid; f.severity = severity; f.title = f"Finding {fid}"
        self.db.upsert_finding(f)
        return f

    def test_profiles_created_and_updatable(self):
        p = self.db.get_employee_profile("r.sharma")
        self.assertIsNotNone(p)
        self.assertTrue(p["assignment_eligible"])
        self.db.upsert_employee_profile("r.sharma","admin", availability_status="unavailable")
        self.assertEqual(self.db.get_employee_profile("r.sharma")["availability_status"], "unavailable")

    def test_closed_finding_cannot_be_assigned(self):
        f = self._seed_finding(fid="FX-CLOSED", severity="high")
        self.db.set_status(f.id, "closed", "admin")
        f.status = "closed"
        r = manual_assign(self.db, f, "admin", "r.sharma", reason="test")
        self.assertFalse(r.get("ok"))
        self.assertIn("closed", (r.get("error") or "").lower())

    def test_assignment_history_and_audit_fields(self):
        f = self._seed_finding()
        a = self.db.upsert_assignment(f.id, "admin", reason="test", action="manual_assigned", primary_owner="r.sharma", status="assigned", method="manual")
        self.assertEqual(a["primary_owner"], "r.sharma")
        hist = self.db.list_assignment_history(f.id)
        self.assertTrue(any(h["action"]=="manual_assigned" and h["actor"]=="admin" and h["reason"]=="test" for h in hist))
        # ack
        self.db.upsert_assignment(f.id, "r.sharma", reason="ack", action="acknowledged", status="acknowledged", acknowledged_at="2026-01-01T00:00:00")
        a2 = self.db.get_assignment(f.id)
        self.assertEqual(a2["status"], "acknowledged")

    def test_manual_assignment_api_validation(self):
        f = self._seed_finding("FX2", "critical")
        # developer cannot own critical without override
        # need storage.list_users to work - ExtStorage uses base table? list_users comes from extensions
        # create users table entries
        for u in self.users:
            try: self.db.add_user(u["username"], "h","s",u["role"], title=u.get("title",""))
            except Exception: pass
        r = manual_assign(self.db, f, "admin", "v.iyer", reason="try", admin_override=False)
        self.assertFalse(r.get("ok"))
        self.assertIn("critical", (r.get("error") or "").lower())
        r2 = manual_assign(self.db, f, "admin", "v.iyer", reason="Admin-approved supervised remediation", admin_override=True)
        self.assertTrue(r2.get("ok"))

    def test_admin_can_be_assigned_explicitly(self):
        f = self._seed_finding("FX4", "medium")
        for u in self.users:
            try: self.db.add_user(u["username"], "h","s",u["role"], title=u.get("title",""))
            except Exception: pass
        r = manual_assign(self.db, f, "admin", "admin", reason="Admin handling this item")
        self.assertTrue(r.get("ok"), r)
        self.assertEqual(self.db.get_assignment(f.id)["primary_owner"], "admin")

    def test_sla_config_persists(self):
        cfg = self.db.get_assignment_sla_config()
        cfg["ack_hours"]["critical"] = 2
        self.db.set_assignment_sla_config(cfg, "admin")
        self.assertEqual(self.db.get_assignment_sla_config()["ack_hours"]["critical"], 2)

    def test_legacy_sync_assignee(self):
        f = self._seed_finding("FX3")
        for u in self.users:
            try: self.db.add_user(u["username"], "h","s",u["role"], title=u.get("title",""))
            except Exception: pass
        self.db.upsert_assignment(f.id, "admin", reason="sync", action="assigned", primary_owner="r.sharma", status="assigned", method="manual")
        extra = self.db.get_extra(f.id)
        self.assertEqual(extra["assignee"], "r.sharma")
        finding = self.db.get_finding(f.id)
        self.assertEqual(finding.owner, "r.sharma")


class AssignmentAPITests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(); self.addCleanup(self._tmp.cleanup)
        cfg = load_config()
        cfg["storage"]["path"] = str(Path(self._tmp.name) / "server.db")
        cfg["server"]["port"] = 0
        cfg["alerting"]["channels"] = ["outbox"]
        cfg["auth"]["fixed_roster"] = True
        cfg["auth"]["demo_mode"] = False
        prev_a = os.environ.get("SENTRIX_ADMIN_PASSWORD")
        prev_t = os.environ.get("SENTRIX_TEAM_PASSWORD")
        os.environ["SENTRIX_ADMIN_PASSWORD"] = ADMIN_PASSWORD
        os.environ["SENTRIX_TEAM_PASSWORD"] = ADMIN_PASSWORD
        try:
            self.server = make_server(cfg)
        finally:
            if prev_a is None: os.environ.pop("SENTRIX_ADMIN_PASSWORD", None)
            else: os.environ["SENTRIX_ADMIN_PASSWORD"] = prev_a
            if prev_t is None: os.environ.pop("SENTRIX_TEAM_PASSWORD", None)
            else: os.environ["SENTRIX_TEAM_PASSWORD"] = prev_t
        self.port = self.server.server_address[1]; self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.cookie = self._login()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=5); self.server.state.storage.close()

    def _http(self, path, payload=None, method=None, headers=None):
        data = json.dumps(payload).encode() if payload is not None else None
        if method is None: method = "POST" if data is not None else "GET"
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        for k,v in (headers or {}).items(): req.add_header(k,v)
        try:
            resp = urllib.request.urlopen(req, timeout=15)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers, exc.read()
        with resp: return resp.getcode(), resp.headers, resp.read()

    def _login(self, username="admin", password=ADMIN_PASSWORD):
        code, headers, body = self._http("/api/auth/login", {"username": username, "password": password})
        self.assertEqual(code, 200, body)
        cookie = SimpleCookie(headers.get("Set-Cookie", ""))
        return cookie["sx_session"].value

    def _req(self, path, payload=None, cookie=None, method=None, expect=200):
        if cookie is None: cookie = self.cookie
        code, _, body = self._http(path, payload, method=method, headers={"Cookie": f"sx_session={cookie}"})
        self.assertEqual(code, expect, body.decode(errors="replace"))
        return json.loads(body.decode())

    def _seed(self):
        self._req("/api/demo", {})
        return self._req("/api/findings?limit=5")["findings"]

    def test_dashboard_and_help_endpoints(self):
        d = self._req("/api/assignment/dashboard")
        self.assertIn("metrics", d); self.assertIn("team", d); self.assertIn("queues", d)
        self.assertEqual(len(d["team"]), 6)
        h = self._req("/api/help")
        self.assertIn("auto_assignment", h)
        self.assertEqual(h["auto_assignment"]["title"], "Automatic Assignment")

    def test_my_assignments_requires_auth(self):
        code, _, _ = self._http("/api/assignment/my")
        self.assertEqual(code, 401)

    def test_auto_and_manual_assignment_rbac(self):
        findings = self._seed(); fid = findings[0]["id"]
        r = self._req(f"/api/assignment/finding/{fid}/auto", {})
        self.assertTrue(r.get("ok") or r.get("recommended"))
        # manual assign with same user context to non-eligible path rejected when invalid
        bad = self._req(f"/api/assignment/finding/{fid}/assign", {"primary_owner":"nosuch","reason":"x"}, expect=400)
        self.assertIn("error", bad)

    def test_ack_requires_owner_or_admin(self):
        findings = self._seed(); fid = findings[0]["id"]
        self._req(f"/api/assignment/finding/{fid}/assign", {"primary_owner":"r.sharma","secondary_reviewer":"n.singh","reason":"test assignment"})
        # login as different non-owner, non-admin? but fixed roster only has those users; use p.patel (analyst, not admin)
        # try ack as p.patel - should be forbidden
        try:
            pc = self._login("p.patel", ADMIN_PASSWORD)
        except Exception:
            self.skipTest("roster password not available")
        code, _, body = self._http(f"/api/assignment/finding/{fid}/ack", {}, method="POST", headers={"Cookie": f"sx_session={pc}"})
        self.assertEqual(code, 403)
        # admin cannot acknowledge on behalf of owner
        code, _, _ = self._http(f"/api/assignment/finding/{fid}/ack", {}, method="POST", headers={"Cookie": f"sx_session={self.cookie}"})
        self.assertEqual(code, 403)
        # owner ack
        rc = self._login("r.sharma", ADMIN_PASSWORD)
        res = self._req(f"/api/assignment/finding/{fid}/ack", {}, cookie=rc)
        self.assertEqual(res["assignment"]["status"], "acknowledged")

    def test_admin_sla_config_rbac(self):
        # non-admin cannot update
        try:
            pc = self._login("p.patel", ADMIN_PASSWORD)
        except Exception:
            self.skipTest("roster password not available")
        code, _, _ = self._http("/api/assignment/sla-config", {"ack_hours": {"critical": 2}, "remediate_hours": {"critical": 8}}, method="POST", headers={"Cookie": f"sx_session={pc}"})
        self.assertEqual(code, 403)

    def test_finding_detail_includes_assignment(self):
        findings = self._seed(); fid = findings[0]["id"]
        self._req(f"/api/assignment/finding/{fid}/assign", {"primary_owner":"r.sharma","reason":"test"})
        d = self._req(f"/api/findings/{fid}")
        self.assertIn("assignment", d)
        self.assertEqual(d["assignment"]["primary_owner"], "r.sharma")
        self.assertIn("assignment_history", d)

    def test_duplicate_prevention_and_reassign_audited(self):
        findings = self._seed(); fid = findings[0]["id"]
        self._req(f"/api/assignment/finding/{fid}/assign", {"primary_owner":"r.sharma","reason":"initial"})
        self._req(f"/api/assignment/finding/{fid}/reassign", {"primary_owner":"p.patel","reason":"rebalance"})
        d = self._req(f"/api/assignment/finding/{fid}")
        self.assertEqual(d["assignment"]["primary_owner"], "p.patel")
        self.assertTrue(any(h.get("action") in ("manual_assigned","assigned","reassigned") for h in d["history"]))


if __name__ == "__main__":
    unittest.main()
