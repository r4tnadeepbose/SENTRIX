"""Stdlib HTTP server: authenticated JSON API, static dashboard, login page."""
from __future__ import annotations

import csv
import hmac
import io
import json
import re
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from sentrix import __version__
from sentrix.ai.triage import triage_finding
from sentrix.auth import AuthError, AuthManager, hash_password, WRITE_ROLES, ADMIN_ROLES
from sentrix.config import ROOT, cfg_get, resolve_path
from sentrix.core import engine
from sentrix.core.extensions import ExtStorage
from sentrix.core.jobs import JobRunner, start_scheduler
from sentrix.core.lifecycle import describe as describe_lifecycle
from sentrix.core.models import STATUSES, SEVERITIES, SURFACES, now_iso
from sentrix.core.pipeline import Pipeline
from sentrix.core.util import at_least
from sentrix.alerting.router import AlertRouter
from sentrix.demo import seed_demo
from sentrix.hubs.api import HubsAPI
from sentrix.remediation import playbooks

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
}
STATIC_FILES = {"index.html", "app.js", "styles.css", "login.html"}
AVATAR_FILE = re.compile(r"^[A-Za-z0-9._-]+\.(?:jpg|jpeg|png|webp)$")
FINDING_ID = re.compile(r"^/api/findings/([A-Za-z0-9\-]+)$")
FINDING_SUB = re.compile(r"^/api/findings/([A-Za-z0-9\-]+)/(status|notes|tags|assign|severity|pin|mute|related|checklist|history)$")
ID_SUB = re.compile(r"^/api/(jobs|schedules|rules|tokens|users|filters)/([A-Za-z0-9_\-]+)/([A-Za-z0-9_\-]+)$")
PUBLIC_GET = {"/", "/login", "/favicon.svg", "/home-favicon.svg", "/home-favicon.png", "/logo.svg", "/api/health", "/api/auth/demo-info"}
ADMIN_PREFIXES = ("/api/users/", "/api/tokens", "/api/ops/restore", "/api/ops/import", "/api/ops/purge")
# Sentinel returned by response helpers so dispatchers can tell "handled"
# from "route not found" without inspecting the socket.
_HANDLED = object()


class AppState:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        engine.configure(cfg)
        self.storage = ExtStorage(resolve_path(cfg, cfg_get(cfg, "storage.path", "data/sentrix.db")))
        self.auth = AuthManager(self.storage, cfg)
        self.auth.ensure_admin()
        self.router = AlertRouter(cfg, self.storage)
        self.pipeline = Pipeline(cfg, self.storage, self.router)
        if self.storage.stats()["total"] == 0:
            seeded = seed_demo(self.pipeline)
            self.auth.log("info", "demo", f"First run: seeded {seeded} demo findings")
        self.runner = JobRunner(self.storage, self.pipeline, cfg, log=self.auth.log)
        self.scheduler_stop = start_scheduler(
            self.runner, self.storage, cfg, self.router, log=self.auth.log)
        self.started = time.time()


class Handler(BaseHTTPRequestHandler):
    state: AppState = None

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; "
                         "base-uri 'self'; form-action 'self'; img-src 'self' data:; "
                         "style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self'; media-src 'self'")
        self.send_header("Permissions-Policy", "geolocation=(), camera=(), microphone=(), usb=(), payment=(), autoplay=(), interest-cohort=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.end_headers()
        self.wfile.write(body)
        # Return a non-None marker so helpers such as _extra_get/_extra_post
        # signal "handled" and do_GET/do_POST do not append a second 404.
        return _HANDLED

    def _json(self, payload, code=200):
        return self._send(code, json.dumps(payload).encode(), "application/json")

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode())
        except json.JSONDecodeError:
            return {}

    def _session_token(self):
        """Per-tab token wins; the cookie remains for API clients/tests."""
        header = (self.headers.get("X-Session-Token") or "").strip()
        if header:
            return header
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        if "sx_session" in cookie:
            return cookie["sx_session"].value
        return ""

    def _user(self):
        token = self._session_token()
        if token:
            user = self.state.auth.session_user(token)
            if user:
                return user
        return self.state.auth.bearer_user(self.headers.get("Authorization", ""))

    def _authorized(self, method, path):
        if path in PUBLIC_GET or path.startswith("/static/"):
            return True
        if method == "POST" and path == "/api/auth/login":
            return True
        user = self._user()
        if not user:
            self._json({"error": "authentication required"}, 401)
            return False
        # Read-only roles may still manage their own reading state (read markers,
        # notifications and preferences) inside Hubs. Sending messages, pings
        # and deleting content remain blocked.
        hubs_personal = (
            "/api/hubs/mark-read", "/api/hubs/notifications/read",
            "/api/hubs/prefs", "/api/hubs/heartbeat",
        )
        if method in ("POST", "DELETE") and user["role"] not in WRITE_ROLES \
                and path not in ("/api/auth/logout", "/api/auth/password") \
                and path not in hubs_personal:
            if path.startswith("/api/hubs/"):
                self._json({"error": "this is a read-only account, so you can't "
                                     "send messages or pings"}, 403)
            else:
                self._json({"error": "role is read-only"}, 403)
            return False
        if any(path.startswith(p) for p in ADMIN_PREFIXES) and user["role"] not in ADMIN_ROLES:
            self._json({"error": "security administrator role required"}, 403)
            return False
        if method == "POST" and "Cookie" in self.headers and \
                not self.headers.get("Authorization", "").startswith("Bearer "):
            origin = self.headers.get("Origin", "")
            if origin and origin.split("//")[-1] != self.headers.get("Host", ""):
                self._json({"error": "cross-origin request rejected"}, 403)
                return False
        return True

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        if not self._authorized("GET", path):
            return
        state = self.state
        if path == "/":
            # The shell is public; the per-tab session is enforced by the API
            # and by app.js. This keeps tab sessions independent of the shared
            # browser cookie.
            return self._file(ROOT / "sentrix" / "dashboard" / "index.html")
        if path == "/login":
            return self._file(ROOT / "sentrix" / "dashboard" / "login.html")
        if path.startswith("/static/avatars/"):
            name = path[len("/static/avatars/"):]
            if not AVATAR_FILE.match(name):
                return self._json({"error": "not found"}, 404)
            return self._file(ROOT / "sentrix" / "dashboard" / "avatars" / name)
        if path.startswith("/static/"):
            name = path[len("/static/"):]
            if name not in STATIC_FILES:
                return self._json({"error": "not found"}, 404)
            return self._file(ROOT / "sentrix" / "dashboard" / name)
        if path == "/favicon.svg":
            return self._file(ROOT / "assets" / "favicon.svg")
        if path == "/home-favicon.svg":
            return self._file(ROOT / "assets" / "home-favicon.svg")
        if path == "/home-favicon.png":
            return self._file(ROOT / "assets" / "home-favicon.png")
        if path == "/logo.svg":
            return self._file(ROOT / "assets" / "logo.svg")
        if path == "/api/health":
            return self._json({
                "status": "ok", "product": "SENTRIX", "version": __version__,
                "uptime_seconds": int(time.time() - state.started),
                "python": __import__("platform").python_version(),
            })
        if path == "/api/auth/me":
            user = self._user()
            return self._json({"user": user}) if user else self._json({"error": "unauthenticated"}, 401)
        if path == "/api/lifecycle":
            return self._json(describe_lifecycle())
        if path == "/api/coordination":
            since = int(query.get("since", 0))
            return self._json({
                "revision": state.storage.coordination_revision(),
                "pings": state.storage.list_pings_since(since),
            })
        if path == "/api/auth/demo-info":
            enabled = False
            accounts = []
            if cfg_get(state.cfg, "auth.demo_mode", False) and \
                    cfg_get(state.cfg, "server.host", "127.0.0.1") in ("127.0.0.1", "localhost"):
                accounts = state.auth.demo_accounts()
                enabled = bool(accounts)
            info = {"enabled": enabled, "accounts": accounts}
            if accounts:
                info["username"] = accounts[0]["username"]
                info["password"] = accounts[0]["password"]
            return self._json(info)
        if path == "/api/stats":
            return self._json(state.storage.stats())
        if path == "/api/dashboard":
            return self._json(self._dashboard_data())
        if path == "/api/findings":
            base_status = query.get("status")
            tab = (query.get("tab") or "").strip()
            # tab-driven status pre-filter where simple
            status_q = base_status
            if tab in ("new","unassigned"): status_q = status_q or None
            elif tab in ("in_progress",): status_q = status_q or "in_progress"
            elif tab in ("verified",): status_q = status_q or "verified"
            elif tab in ("closed",): status_q = base_status or "closed" if base_status else None
            elif tab in ("reopened",): status_q = status_q or "reopened"
            elif tab in ("false_positive", "accepted_risk", "suppressed"): status_q = status_q or tab
            findings = state.storage.list_findings(
                status=status_q, severity=query.get("severity"),
                surface=query.get("surface"), q=query.get("q"),
                limit=int(query.get("limit", 5000)))
            # global summary (respect severity/surface/q; ignore tab/status for operational overview)
            summary_findings = state.storage.list_findings(
                severity=query.get("severity"), surface=query.get("surface"), q=query.get("q"), limit=5000)
            sort = query.get("sort", "created")
            if sort == "severity":
                findings.sort(key=lambda f: SEVERITIES.index(f.severity))
            elif sort == "occurrences":
                findings.sort(key=lambda f: state.storage.get_extra(f.id)["occurrences"], reverse=True)
            elif sort == "pinned":
                findings.sort(key=lambda f: state.storage.get_extra(f.id)["pinned"], reverse=True)
            from sentrix.core import assignment_api as _aapi
            from sentrix.core.assignment import compute_workflow
            summary = {"total": len(summary_findings), "new": 0, "awaiting_assignment": 0, "primary_assessment": 0,
                       "secondary_review": 0, "awaiting_admin_review": 0, "remediation_pending": 0, "verification_pending": 0,
                       "closed": 0, "critical": 0, "high": 0,
                       # compat keys
                       "assigned": 0, "ack_pending": 0, "in_progress": 0, "verified": 0}
            wf_cache = {}
            def _wf(f):
                if f.id not in wf_cache:
                    a = state.storage.get_assignment(f.id)
                    wf_cache[f.id] = (a, compute_workflow(f, a))
                return wf_cache[f.id]
            for f in summary_findings:
                if f.severity == "critical": summary["critical"] += 1
                if f.severity == "high": summary["high"] += 1
                a, wf = _wf(f); stage = wf.get("stage")
                if stage == "New": summary["new"] += 1; summary["awaiting_assignment"] += 1
                elif stage == "Assigned": summary["assigned"] += 1; summary["ack_pending"] += 1
                elif stage == "Primary Review": summary["primary_assessment"] += 1; summary["assigned"] += 1
                elif stage == "Secondary Review": summary["secondary_review"] += 1; summary["assigned"] += 1
                elif stage == "Admin Review": summary["awaiting_admin_review"] += 1; summary["assigned"] += 1
                elif stage == "Remediation": summary["remediation_pending"] += 1; summary["assigned"] += 1
                elif stage == "Verification": summary["verification_pending"] += 1; summary["assigned"] += 1
                elif stage == "Closed": summary["closed"] += 1
                if stage in ("Primary Review","Secondary Review","Admin Review","Remediation","Verification","Assigned"): summary["in_progress"] += (1 if stage != "Assigned" else 0)
                if a.get("verified_at") or wf.get("admin_decision") == "confirm_true_positive" and stage == "Closed": summary["verified"] += 1
            # apply composite tab filters (workflow-stage aware)
            if tab:
                filtered = []
                for f in findings:
                    a, wf = _wf(f); stage = wf.get("stage"); st = f.status
                    ok = True
                    if tab in ("new","unassigned","awaiting_assignment"): ok = stage == "New"
                    elif tab == "assigned": ok = stage == "Assigned"
                    elif tab in ("ack_pending","awaiting_ack"): ok = stage == "Assigned" and "Awaiting Acknowledgement" in (wf.get("status_labels") or [])
                    elif tab in ("primary_assessment","primary_review"): ok = stage == "Primary Review"
                    elif tab in ("secondary_review",): ok = stage == "Secondary Review"
                    elif tab in ("admin_review","awaiting_admin_review"): ok = stage == "Admin Review"
                    elif tab in ("remediation","remediation_pending"): ok = stage == "Remediation"
                    elif tab in ("verification_pending","verification"): ok = stage == "Verification"
                    elif tab in ("closed",): ok = stage == "Closed"
                    elif tab in ("reopened",): ok = st == "reopened"
                    elif tab in ("false_positive",): ok = st == "false_positive" or wf.get("admin_decision") == "confirm_false_positive"
                    elif tab in ("accepted_risk", "suppressed"): ok = st == tab
                    if ok: filtered.append(f)
                findings = filtered
            page = max(1, int(query.get("page", 1)))
            page_size = max(1, min(200, int(query.get("page_size", 50))))
            total = len(findings)
            chunk = findings[(page - 1) * page_size:page * page_size]
            out = []
            for f in chunk:
                data = f.to_dict()
                extra = state.storage.get_extra(f.id)
                a, wf = _wf(f)
                data.update({k: extra[k] for k in
                             ("assignee", "tags", "pinned", "muted", "occurrences", "severity_override")})
                data.update({k: f.meta.get(k) for k in
                             ("confidence", "validation", "environment", "risk")})
                data["last_seen"] = extra.get("last_seen") or f.updated_at
                data["category"] = f.meta.get("family") or f.detector_id
                data["detection_source"] = f.surface
                data["primary_assignee"] = a.get("primary_owner") or extra.get("assignee") or f.owner or ""
                data["secondary_assignee"] = a.get("secondary_reviewer") or ""
                data["assignment_status"] = a.get("status") or "unassigned"
                data["acknowledged"] = bool(a.get("acknowledged_at"))
                data["secondary_acknowledged"] = bool(a.get("secondary_acknowledged_at"))
                data["sla_status"] = "breached" if _aapi._sla_breached(a) else ("ok" if a.get("due_at") or a.get("ack_due_at") else "")
                data["priority"] = a.get("priority") or ""
                data["due_at"] = a.get("due_at") or ""
                data["verification_pending"] = bool(a.get("verification_requested_at") and not a.get("verification_decision"))
                data["workflow"] = wf
                data["workflow_stage"] = wf.get("stage")
                data["status_labels"] = wf.get("status_labels") or []
                out.append(data)
            return self._json({"findings": out, "total": total, "page": page, "page_size": page_size, "summary": summary})
        match = FINDING_ID.match(path)
        if match:
            finding = state.storage.get_finding(match.group(1))
            if not finding:
                return self._json({"error": "not found"}, 404)
            from sentrix.core import assignment_api as _aapi
            from sentrix.core.assignment import compute_workflow
            a = state.storage.get_assignment(finding.id)
            a["sla_breached"] = _aapi._sla_breached(a)
            wf = compute_workflow(finding, a)
            a["workflow"] = wf
            return self._json({
                "finding": finding.to_dict(),
                "extra": state.storage.get_extra(finding.id),
                "notes": state.storage.list_notes(finding.id),
                "history": state.storage.list_history(finding.id),
                "checklist": state.storage.get_checklist(finding.id),
                "remediations": state.storage.list_remediations(finding.id),
                "triage": finding.meta.get("triage"),
                "assignment": a,
                "workflow": wf,
                "assignment_history": state.storage.list_assignment_history(finding.id, 50),
            })
        match = FINDING_SUB.match(path)
        if match:
            fid, sub = match.groups()
            if sub == "related":
                return self._json({"findings": state.storage.related_findings(fid)})
            if sub == "notes":
                return self._json({"notes": state.storage.list_notes(fid)})
            if sub == "history":
                return self._json({"history": state.storage.list_history(fid)})
            if sub == "checklist":
                return self._json({"checklist": state.storage.get_checklist(fid)})
        if path == "/api/events":
            return self._json({"events": state.storage.list_events(int(query.get("limit", 50)))})
        if path == "/api/alerts":
            acks = state.storage.list_acks()
            alerts = state.storage.list_alerts(int(query.get("limit", 50)))
            for alert in alerts:
                alert["ack"] = acks.get(alert["id"])
            return self._json({"alerts": alerts})
        if path == "/api/logs":
            return self._json({"logs": state.storage.list_logs(
                int(query.get("limit", 200)), query.get("level"), query.get("source"))})
        if path == "/api/audit":
            return self._json({"audit": state.storage.list_audit(int(query.get("limit", 200)))})
        if path == "/api/allowlist":
            return self._json({"entries": state.storage.allowlist_entries()})
        if path == "/api/config":
            return self._json(state.cfg)
        if path == "/api/detectors":
            tuning = state.cfg.get("detectors", {})
            return self._json({"detectors": [
                {"id": d.id, "title": d.title,
                 "severity": tuning.get("severity_overrides", {}).get(d.id, d.severity),
                 "family": d.family, "enabled": d.id not in tuning.get("disabled", [])}
                for d in engine.all_detectors()]})
        if path == "/api/users":
            if not (self._user() or {}).get("role") in ADMIN_ROLES:
                return self._json({"error": "security administrator role required"}, 403)
            return self._json({"users": state.storage.list_users()})
        m = re.match(r"^/api/users/([A-Za-z0-9_\.\-]+)$", path)
        if m:
            username = m.group(1)
            user_row = state.storage.get_user(username)
            if not user_row:
                return self._json({"error": "not found"}, 404)
            # Strip sensitive fields before returning
            safe = {k: user_row[k] for k in ("username", "role", "title", "disabled", "created_at")}
            # Count assigned / owned findings
            all_findings = state.storage.list_findings(limit=5000)
            owned = sum(1 for f in all_findings if f.owner == username)
            assigned = sum(1 for f in all_findings
                          if state.storage.get_extra(f.id)["assignee"] == username)
            online_users = state.storage.hubs_online_users()
            online = any(u["username"] == username for u in online_users)
            prefs = state.storage.hubs_get_prefs(username)
            return self._json({
                "user": safe,
                "stats": {"owned": owned, "assigned": assigned},
                "online": online,
                "prefs": {"sound_enabled": prefs["sound_enabled"],
                          "notif_desktop": prefs["notif_desktop"]},
            })
        if path == "/api/tokens":
            return self._json({"tokens": state.storage.list_tokens()})
        if path == "/api/filters":
            return self._json({"filters": state.storage.list_filters(self._user()["username"])})
        if path == "/api/jobs":
            return self._json({"jobs": state.storage.list_jobs()})
        match = re.match(r"^/api/jobs/([A-Za-z0-9\-]+)$", path)
        if match:
            job = state.storage.get_job(match.group(1))
            return self._json({"job": job}) if job else self._json({"error": "not found"}, 404)
        if path == "/api/schedules":
            return self._json({"schedules": state.storage.list_schedules()})
        if path == "/api/rules":
            return self._json({"rules": state.storage.list_rules()})
        if path == "/api/digest":
            stats = state.storage.stats()
            return self._json({
                "period_hours": 24, "total": stats["total"], "open": stats["open"],
                "by_severity": stats["by_severity"], "alerts_sent": stats["alerts_sent"],
                "open_critical": stats["by_severity"].get("critical", 0),
            })
        if path == "/api/metrics":
            stats = state.storage.stats()
            lines = [
                f"sentrix_findings_total {stats['total']}",
                f"sentrix_findings_open {stats['open']}",
                f"sentrix_alerts_sent_total {stats['alerts_sent']}",
                f"sentrix_events_processed_total {stats['events_processed']}",
                f"sentrix_remediations_total {stats['remediations']}",
                f"sentrix_uptime_seconds {int(time.time() - state.started)}",
            ]
            return self._send(200, "\n".join(lines) + "\n", "text/plain; version=0.0.4")
        if path == "/api/ops/stats":
            return self._json({
                "db_bytes": state.storage.db_size(),
                "jobs": len(state.storage.list_jobs()),
                "schedules": len(state.storage.list_schedules()),
                "users": len(state.storage.list_users()),
            })
        if path == "/api/ops/dump":
            return self._json(state.storage.dump_json())
        if path == "/api/export":
            findings = state.storage.list_findings(limit=5000)
            if query.get("format") == "csv":
                buf = io.StringIO()
                writer = csv.writer(buf)
                writer.writerow(["id", "severity", "title", "surface", "path", "line",
                                 "status", "assignee", "created_at"])
                for f in findings:
                    writer.writerow([f.id, f.severity, f.title, f.surface, f.path,
                                     f.line, f.status, state.storage.get_extra(f.id)["assignee"],
                                     f.created_at])
                return self._send(200, buf.getvalue().encode(), "text/csv; charset=utf-8")
            return self._json({"findings": [f.to_dict() for f in findings]})
        extra = self._extra_get(path, query)
        if extra is not None:
            return extra
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        if not self._authorized("POST", path):
            return
        body = self._body()
        state = self.state
        user = self._user() or {"username": "anonymous", "role": "viewer"}
        uname = user["username"]
        if path != "/api/auth/login":
            state.auth.log("info", "http", f"{uname} POST {path}")
        try:
            return self._dispatch_post(path, body, uname)
        except AuthError as exc:
            return self._json({"error": str(exc)}, 400)
        except ValueError as exc:
            return self._json({"error": str(exc)}, 400)

    def _dispatch_post(self, path, body, uname):
        state = self.state
        if path == "/api/auth/login":
            token, user = state.auth.login(
                body.get("username", ""), body.get("password", ""),
                self.client_address[0], remember=bool(body.get("remember")))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie",
                             f"sx_session={token}; HttpOnly; Path=/; SameSite=Strict; "
                             f"Max-Age={int(state.auth.session_hours * 3600)}")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; "
                             "base-uri 'self'; form-action 'self'; img-src 'self' data:; "
                             "style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self'; media-src 'self'")
            self.send_header("Permissions-Policy", "geolocation=(), camera=(), microphone=(), usb=(), payment=(), autoplay=(), interest-cohort=()")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            payload = json.dumps({"ok": True, "user": user, "token": token}).encode()
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if path == "/api/auth/logout":
            token = self._session_token()
            if token:
                state.auth.logout(token)
            return self._json({"ok": True})
        if path == "/api/auth/password":
            state.auth.change_password(uname, body.get("old", ""), body.get("new", ""))
            return self._json({"ok": True})
        if path == "/api/users":
            state.auth.add_user(uname, body.get("username", ""), body.get("password", ""),
                                body.get("role", "viewer"))
            return self._json({"ok": True})
        match = ID_SUB.match(path)
        if match:
            kind, ident, action = match.groups()
            if kind == "users" and action == "role":
                state.auth.set_role(uname, ident, body.get("role", ""))
            elif kind == "users" and action == "disable":
                state.auth.set_disabled(uname, ident, bool(body.get("disabled", True)))
            elif kind == "tokens" and action == "revoke":
                state.auth.revoke_token(uname, ident)
            elif kind == "jobs" and action == "cancel":
                state.runner.cancel(ident)
            elif kind == "schedules" and action == "toggle":
                sched = next((s for s in state.storage.list_schedules() if s["id"] == ident), None)
                if sched:
                    state.storage.update_schedule(ident, enabled=0 if sched["enabled"] else 1)
            elif kind == "schedules" and action == "delete":
                state.storage.delete_schedule(ident)
            elif kind == "rules" and action == "toggle":
                rule = next((r for r in state.storage.list_rules() if r["id"] == ident), None)
                if rule:
                    state.storage.update_rule(ident, enabled=0 if rule["enabled"] else 1)
            elif kind == "rules" and action == "delete":
                state.storage.delete_rule(ident)
            elif kind == "filters" and action == "delete":
                state.storage.delete_filter(ident)
            else:
                return self._json({"error": "not found"}, 404)
            return self._json({"ok": True})
        if path == "/api/tokens":
            raw = state.auth.create_token(uname, body.get("name", "ci"), body.get("role", "analyst"))
            return self._json({"ok": True, "token": raw})
        if path == "/api/scan":
            if "text" not in body and "path" not in body:
                return self._json({"error": "body must include text or path"}, 400)
            if "text" in body:
                findings = engine.scan_text(
                    body.get("text", ""), body.get("path", "playground.txt"),
                    body.get("surface", "filesystem"), state.pipeline.allowlist)
                state.auth.log("info", "scan", f"Playground scan by {uname}: {len(findings)} finding(s)")
                return self._json({"findings": [f.to_dict() for f in findings], "scanned_files": 1})
            target = Path(body.get("path", "."))
            if not target.is_absolute():
                target = ROOT / target
            if not target.exists():
                return self._json({"error": f"path does not exist: {target}"}, 400)
            findings, count = engine.scan_tree(target, "filesystem", state.cfg, state.pipeline.allowlist)
            state.pipeline.ingest(findings, kind="scan.path")
            state.auth.log("info", "scan", f"Path scan by {uname}: {target} ({count} files, {len(findings)} findings)")
            return self._json({"findings": [f.to_dict() for f in findings], "scanned_files": count})
        if path == "/api/jobs":
            jid = state.runner.submit(body.get("path", "."), body.get("surface", "filesystem"), uname)
            return self._json({"ok": True, "id": jid})
        if path == "/api/schedules":
            import secrets as _secrets
            sid = "sch-" + _secrets.token_hex(4)
            state.storage.add_schedule(sid, body.get("path", "."), body.get("surface", "filesystem"),
                                       int(body.get("interval_seconds", 3600)))
            return self._json({"ok": True, "id": sid})
        if path == "/api/rules":
            import secrets as _secrets
            rid = "rule-" + _secrets.token_hex(4)
            state.storage.add_rule(rid, body.get("channel", "slack"), body.get("min_severity", "high"))
            return self._json({"ok": True, "id": rid})
        if path == "/api/filters":
            import secrets as _secrets
            fid = "flt-" + _secrets.token_hex(4)
            state.storage.add_filter(fid, uname, body.get("name", "filter"), body.get("params", {}))
            return self._json({"ok": True, "id": fid})
        if path == "/api/bulk":
            ids = body.get("ids", [])
            action = body.get("action", "")
            value = body.get("value", "")
            for fid in ids:
                if action == "status" and value in STATUSES:
                    state.storage.set_status(fid, value, uname)
                elif action == "allowlist":
                    finding = state.storage.get_finding(fid)
                    if finding:
                        state.storage.allowlist_add(finding.fingerprint, value or "bulk allowlist")
                        state.storage.set_status(fid, "false_positive", uname)
                elif action == "assign":
                    state.storage.update_extra(fid, assignee=value)
                elif action == "tag":
                    extra = state.storage.get_extra(fid)
                    tags = extra["tags"]
                    if value and value not in tags:
                        tags.append(value)
                    state.storage.update_extra(fid, tags=tags)
            state.pipeline.refresh_allowlist()
            state.auth.audit("bulk." + action, uname, f"{len(ids)} findings")
            return self._json({"ok": True, "affected": len(ids)})
        if path == "/api/demo":
            seeded = seed_demo(state.pipeline)
            state.auth.log("info", "demo", f"Demo data seeded by {uname}: {seeded} findings")
            return self._json({"ok": True, "seeded": seeded})
        if path == "/api/allowlist":
            fp = body.get("fingerprint", "")
            if not fp:
                return self._json({"error": "fingerprint required"}, 400)
            state.storage.allowlist_add(fp, body.get("reason", ""))
            state.pipeline.refresh_allowlist()
            for finding in state.storage.list_findings(limit=1000):
                if finding.fingerprint == fp:
                    state.storage.set_status(finding.id, "false_positive", uname)
            return self._json({"ok": True})
        if path == "/api/triage":
            finding = state.storage.get_finding(body.get("id", ""))
            if not finding:
                return self._json({"error": "not found"}, 404)
            result = triage_finding(finding, state.cfg)
            finding.meta["triage"] = result
            state.storage.set_meta(finding.id, finding.meta)
            return self._json({"ok": True, "triage": result})
        if path == "/api/remediate":
            finding = state.storage.get_finding(body.get("id", ""))
            if not finding:
                return self._json({"error": "not found"}, 404)
            detail = playbooks.execute(body.get("action", ""), finding, state.cfg, state.storage)
            state.auth.log("info", "remediation",
                           f"{uname} ran {body.get('action')} on {finding.id}")
            return self._json({"ok": True, "detail": detail})
        match = FINDING_SUB.match(path)
        if match:
            fid, sub = match.groups()
            finding = state.storage.get_finding(fid)
            if not finding:
                return self._json({"error": "not found"}, 404)
            if sub == "status":
                status = body.get("status", "")
                if status not in STATUSES:
                    return self._json({"error": f"status must be one of {STATUSES}"}, 400)
                updated = state.storage.set_status(fid, status, uname)
                return self._json({"ok": True, "finding": updated.to_dict()})
            if sub == "notes":
                state.storage.add_note(fid, uname, body.get("body", ""))
                return self._json({"ok": True})
            if sub == "tags":
                state.storage.update_extra(fid, tags=body.get("tags", []))
                return self._json({"ok": True})
            if sub == "assign":
                from sentrix.core import assignment_api as _aapi
                user = self._user() or {}
                assignee = (body.get("assignee") or "").strip()
                if assignee:
                    r = _aapi.manual_assign(state.storage, finding, user.get("username","anonymous"), assignee, "",
                                            body.get("reason","Legacy assignment update"), body.get("due_at",""), "", "manual",
                                            getattr(state,'alert_router',None), admin_override=False)
                    if not r.get("ok"): return self._json({"error": r.get("error","assignment failed")}, 400)
                else:
                    state.storage.upsert_assignment(fid, user.get("username","anonymous"), reason="Unassigned", action="unassigned",
                                                    primary_owner="", secondary_reviewer="", status="unassigned", method="")
                    state.storage.update_extra(fid, assignee="")
                return self._json({"ok": True})
            if sub == "severity":
                value = body.get("severity", "")
                if value and value not in SEVERITIES:
                    return self._json({"error": "invalid severity"}, 400)
                state.storage.update_extra(fid, severity_override=value)
                return self._json({"ok": True})
            if sub == "pin":
                state.storage.update_extra(fid, pinned=1 if body.get("pinned") else 0)
                return self._json({"ok": True})
            if sub == "mute":
                state.storage.update_extra(fid, muted=1 if body.get("muted") else 0)
                return self._json({"ok": True})
            if sub == "checklist":
                state.storage.set_checklist_step(fid, int(body.get("idx", 0)),
                                                 bool(body.get("done")), uname)
                return self._json({"ok": True})
        match = re.match(r"^/api/alerts/([A-Za-z0-9\-]+)/ack$", path)
        if match:
            state.storage.ack_alert(match.group(1), uname)
            return self._json({"ok": True})
        if path == "/api/ops/backup":
            dest = resolve_path(state.cfg, f"data/backups/sentrix-{int(time.time())}.db")
            state.storage.backup(dest)
            state.auth.audit("ops.backup", uname, str(dest))
            return self._json({"ok": True, "path": str(dest)})
        if path == "/api/ops/restore":
            src = Path(body.get("path", ""))
            if not src.is_file():
                return self._json({"error": "backup file not found"}, 400)
            state.storage.close()
            import shutil
            shutil.copyfile(src, resolve_path(state.cfg, cfg_get(state.cfg, "storage.path")))
            state.storage = ExtStorage(resolve_path(state.cfg, cfg_get(state.cfg, "storage.path")))
            state.pipeline.storage = state.storage
            state.auth.storage = state.storage
            state.auth.audit("ops.restore", uname, str(src))
            return self._json({"ok": True})
        if path == "/api/ops/purge":
            removed = state.storage.purge_retention(int(body.get("days", 90)))
            state.auth.audit("ops.purge", uname, f"{removed} findings")
            return self._json({"ok": True, "removed": removed})
        if path == "/api/ops/vacuum":
            state.storage.vacuum()
            return self._json({"ok": True})
        if path == "/api/ops/import":
            count = state.storage.import_json(body)
            state.auth.audit("ops.import", uname, f"{count} rows")
            return self._json({"ok": True, "imported": count})
        if path == "/api/detectors/tuning":
            state.cfg.setdefault("detectors", {})
            state.cfg["detectors"]["disabled"] = body.get("disabled", [])
            state.cfg["detectors"]["severity_overrides"] = body.get("severity_overrides", {})
            engine.configure(state.cfg)
            state.auth.audit("detectors.tuning", uname, json.dumps(body)[:200])
            return self._json({"ok": True})
        extra = self._extra_post(path, body, uname)
        if extra is not None:
            return extra
        return self._json({"error": "not found"}, 404)

    def _extra_get(self, path, query):
        from sentrix.core import integrations, reports, risk
        from sentrix.remediation.playbooks import PLAYBOOKS
        state = self.state
        storage = state.storage
        findings = storage.list_findings(limit=5000)
        demo = bool(cfg_get(state.cfg, "auth.demo_mode", False))

        # -- Assignment / workload / help --------------------------------------
        if path.startswith("/api/assignment") or path.startswith("/api/help"):
            from sentrix.core import assignment_api
            user = self._user() or {}
            uname = (user.get("username") or "anonymous")
            role = user.get("role") or "viewer"
            if path == "/api/help":
                return self._json(_help_registry())
            if path.startswith("/api/help/"):
                key = path.rsplit("/", 1)[-1]
                return self._json({"key": key, "item": _help_registry().get(key)})
            if path == "/api/assignment/sla-config":
                return self._json(storage.get_assignment_sla_config())
            if path == "/api/assignment/profiles":
                if role not in ("super_admin","security_admin","security_analyst","appsec_engineer","devsecops_engineer"):
                    return self._json({"error": "insufficient role"}, 403)
                return self._json({"profiles": storage.list_employee_profiles(storage.list_users()), "workloads": assignment_api.build_workloads(storage, findings)})
            if path == "/api/assignment/dashboard":
                if role not in ("super_admin","security_admin","security_analyst","appsec_engineer","devsecops_engineer"):
                    return self._json({"error": "insufficient role"}, 403)
                return self._json(assignment_api.dashboard(storage, user))
            if path == "/api/assignment/my":
                return self._json(assignment_api.my_assignments(storage, uname, user))
            if path.startswith("/api/assignment/finding/"):
                fid = path.rsplit("/", 1)[-1]
                f = storage.get_finding(fid)
                if not f: return self._json({"error": "finding not found"}, 404)
                a = storage.get_assignment(fid)
                a["sla_breached"] = assignment_api._sla_breached(a)
                return self._json({"assignment": a, "history": storage.list_assignment_history(fid, 50)})
            if path.startswith("/api/assignment/history/"):
                fid = path.rsplit("/", 1)[-1]
                return self._json({"history": storage.list_assignment_history(fid, 100)})

        if path == "/api/overview":
            stats = storage.stats()
            jobs = storage.list_jobs(limit=500)
            unresolved = sum(1 for f in findings if f.status in
                             ("open", "new", "triaged", "assigned", "in_progress", "reopened"))
            demo = bool(cfg_get(state.cfg, "auth.demo_mode", False))
            inv = __import__("sentrix.core.integrations", fromlist=["inventory"]).inventory(state.cfg, storage, demo)
            return self._json({
                "total": stats["total"],
                "critical": stats["by_severity"].get("critical", 0),
                "high": stats["by_severity"].get("high", 0),
                "medium": stats["by_severity"].get("medium", 0),
                "low": stats["by_severity"].get("low", 0),
                "info": stats["by_severity"].get("info", 0),
                "confirmed": sum(1 for f in findings if f.meta.get("validation") == "format_validated"),
                "unresolved": unresolved,
                "remediated": sum(1 for f in findings if f.status in ("remediated", "verified", "closed")),
                "false_positives": stats["by_status"].get("false_positive", 0),
                "repositories": len({f.path.split("/")[0] for f in findings if f.surface in ("git", "pre_push", "ci")}),
                "integrations_connected": sum(1 for i in inv if i["status"] == "connected"),
                "integrations_demo": sum(1 for i in inv if i["status"] == "demo"),
                "active_sources": len({f.surface for f in findings}),
                "scans_total": len(jobs),
                "scans_failed": sum(1 for j in jobs if j["status"] == "failed"),
                # Backward-compatible compact telemetry retained for API consumers.
                "stages": {
                    "events": stats["events_processed"],
                    "scans": len(jobs),
                    "findings": stats["total"],
                    "alerts": stats["alerts_sent"],
                    "remediations": stats["remediations"],
                },
                "detectors": len(__import__("sentrix.detectors", fromlist=["all_detectors"]).all_detectors()),
                "surfaces": sorted({f.surface for f in findings}),
                "demo": demo,
            })
        if path == "/api/home":
            stats = storage.stats()
            jobs = storage.list_jobs(limit=500)
            demo = bool(cfg_get(state.cfg, "auth.demo_mode", False))
            inv = __import__("sentrix.core.integrations", fromlist=["inventory"]).inventory(state.cfg, storage, demo)
            now = time.time()
            def _ts(s):
                try: return time.mktime(time.strptime((s or "")[:19], "%Y-%m-%dT%H:%M:%S"))
                except Exception: return None
            # MTTR (hours) from remediation history
            hist = []
            try:
                conn = storage._connect(); conn.row_factory = __import__("sqlite3").Row
                for r in conn.execute("SELECT ts, details FROM events WHERE event='remediation.success' ORDER BY id DESC LIMIT 100").fetchall():
                    try:
                        d = json.loads(r["details"] or "{}"); t1 = _ts(d.get("created_at")); t2 = _ts(r["ts"])
                        if t1 and t2 and t2 >= t1: hist.append(t2 - t1)
                    except Exception: pass
                conn.close()
            except Exception: pass
            mttr_hours = round(sum(hist)/len(hist)/3600, 2) if hist else None
            # Top sources with honest 30d trend (count in last 30d vs previous 30d) from findings
            src = {}
            for f in findings:
                s = src.setdefault(f.surface, {"surface": f.surface, "findings": 0, "last_event": f.updated_at or f.created_at, "last30": 0, "prev30": 0})
                s["findings"] += 1
                ts = _ts(f.created_at)
                if ts:
                    if ts >= now - 30*86400: s["last30"] += 1
                    elif ts >= now - 60*86400: s["prev30"] += 1
                if (f.updated_at or f.created_at or "") > (s["last_event"] or ""): s["last_event"] = f.updated_at or f.created_at
            top_sources = []
            for v in sorted(src.values(), key=lambda x: -x["findings"]):
                base = max(1, v["prev30"])
                trend_pct = round(100 * (v["last30"] - v["prev30"]) / base) if (v["last30"] or v["prev30"]) else None
                top_sources.append({"surface": v["surface"], "findings": v["findings"], "last_event": v["last_event"], "trend_30d_pct": trend_pct, "last30": v["last30"]})
            # Outcomes groups (real statuses)
            active_states = {"open","new","triaged","assigned","in_progress","reopened"}
            mitigated_states = {"remediated","verified","closed","accepted_risk","false_positive","suppressed"}
            def sev_breakdown(items):
                b = {k:0 for k in ["critical","high","medium","low","info"]}
                for f in items: b[f.severity] = b.get(f.severity,0)+1
                return b
            active = [f for f in findings if f.status in active_states]
            needs_attention = [f for f in active if f.status in {"open","new","triaged","reopened"}]
            in_progress = [f for f in active if f.status in {"assigned","in_progress"}]
            mitigated = [f for f in findings if f.status in mitigated_states]
            mitigated_controls = [f for f in findings if f.status in {"accepted_risk","suppressed","false_positive"}]
            resolved = [f for f in findings if f.status in {"remediated","verified","closed"}]
            # Assets
            assets = {}
            for f in findings:
                key = (f.meta or {}).get("asset") or f.path.split("/")[0].split("\\")[0] or f.surface
                assets.setdefault(key, {"findings":0})["findings"] += 1
            vulnerable_assets = sum(1 for a in assets.values() if a["findings"] > 0)
            total_assets = len(assets) if assets else len({f.surface for f in findings})
            scans_30d = sum(1 for j in jobs if (_ts(j.get("started") or j.get("created_at")) or 0) >= now - 30*86400)
            actionable = len([f for f in findings if f.status in active_states and f.severity in ("critical","high","medium")])
            unresolved = len(active)
            crit_high = stats["by_severity"].get("critical",0)+stats["by_severity"].get("high",0)
            total = max(1, stats["total"])
            # Security dimensions (honest, derived)
            coverage = round(100 * len({f.surface for f in findings}) / max(1, len(SURFACES)), 1)
            auto_pct = round(100 * stats["alerts_sent"] / max(1, stats["events_processed"]), 1) if stats["events_processed"] else 0
            dimensions = [
                {"label":"Automation Health","value": auto_pct, "unit":"%", "note":"alerts per ingested events (proxy)", "available": True},
                {"label":"Open Severity Burden","value": round(100*crit_high/total,1), "unit":"%", "note":"critical+high share", "available": True},
                {"label":"Exploit Pressure","value": round(100*stats["by_severity"].get("critical",0)/total,1), "unit":"%", "note":"critical share (proxy)", "available": True},
                {"label":"Coverage Confidence","value": coverage, "unit":"%", "note":"surfaces with findings", "available": True},
                {"label":"Security Posture","value": round(100*len(resolved)/total,1), "unit":"%", "note":"resolved/mitigated share", "available": True},
            ]
            return self._json({
                "center": {"ingested": stats["events_processed"], "unique_findings": stats["total"], "actionable": actionable},
                "top_sources": top_sources[:8],
                "outcomes": {
                    "active": {"total": len(active), "needs_attention": len(needs_attention), "in_progress": len(in_progress), "severity": sev_breakdown(active)},
                    "mitigated": {"total": len(mitigated), "mitigated_with_controls": len(mitigated_controls), "resolved": len(resolved), "accepted_risk": stats["by_status"].get("accepted_risk",0), "severity": sev_breakdown(mitigated)},
                },
                "dimensions": dimensions,
                "cards": {
                    "vulnerable_assets": {"value": vulnerable_assets, "total_assets": total_assets, "trend_30d": None, "never_scanned": None},
                    "active_findings": {"total": len(active), "severity": sev_breakdown(active), "trend_30d": None},
                    "mttr": {"hours": mttr_hours, "previous": None, "trend": None, "available": mttr_hours is not None},
                    "automation": {"percent": auto_pct, "auto_handled": stats["alerts_sent"], "note": "alerts/ingested proxy", "available": True},
                    "scanned_30d": {"value": scans_30d, "total_assets": total_assets, "percent": round(100*scans_30d/max(1,total_assets),1) if total_assets else None, "trend_30d": None, "note": "scan jobs in last 30d (proxy)"},
                },
                "meta": {"demo": demo, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
            })
        if path == "/api/pipeline":
            jobs = storage.list_jobs(limit=500)
            stats = storage.stats()
            durations = []
            for j in jobs:
                if j["finished"] and j["started"]:
                    try:
                        durations.append(time.mktime(time.strptime(j["finished"], "%Y-%m-%dT%H:%M:%S"))
                                         - time.mktime(time.strptime(j["started"], "%Y-%m-%dT%H:%M:%S")))
                    except ValueError:
                        pass
            avg_ms = int((sum(durations) / len(durations)) * 1000) if durations else None
            failed = sum(1 for j in jobs if j["status"] == "failed")
            last_run = storage.log_last_run()
            validated = sum(1 for f in findings if f.meta.get("validation") == "format_validated")
            scored = sum(1 for f in findings if f.meta.get("risk"))
            verified = sum(1 for f in findings if f.status in ("verified", "closed"))
            stages = [
                ("source", "Source event", stats["events_processed"], "ingestion", False),
                ("ingestion", "Ingestion", stats["events_processed"], "ingestion", False),
                ("normalization", "Normalization", stats["events_processed"], "scan", True),
                ("detection", "Detection", stats["total"], "scan", True),
                ("validation", "Validation", validated, "triage", False),
                ("dedup", "Deduplication", stats["total"], "ingestion", False),
                ("risk", "Risk assessment", scored, "ingestion", False),
                ("finding", "Finding creation", stats["total"], "ingestion", False),
                ("alerting", "Alerting", stats["alerts_sent"], "alert", False),
                ("remediation", "Remediation", stats["remediations"], "remediation", False),
                ("verification", "Verification", verified, "remediation", False),
            ]
            return self._json({"stages": [
                {"id": sid, "name": name,
                 "status": "degraded" if failed and sid == "detection"
                 else "operational" if count else "idle",
                 "events": count,
                 "failed": failed if sid == "detection" else 0,
                 "avg_ms": avg_ms if timed else None,
                 "last_run": last_run.get(src), "logs_source": src}
                for sid, name, count, src, timed in stages]})
        if path == "/api/posture":
            d = self._dashboard_data()
            hist = []
            for f in findings:
                for h in storage.list_history(f.id):
                    if h["new"] in ("remediated", "verified", "closed"):
                        try:
                            hist.append(time.mktime(time.strptime(h["ts"], "%Y-%m-%dT%H:%M:%S"))
                                        - time.mktime(time.strptime(f.created_at, "%Y-%m-%dT%H:%M:%S")))
                        except ValueError:
                            pass
            mttr = round(sum(hist) / len(hist) / 3600, 2) if hist else 0.0
            ages = {"<1d": 0, "1-7d": 0, "7-30d": 0, ">30d": 0}
            for f in findings:
                try:
                    days = (time.time() - time.mktime(time.strptime(f.created_at, "%Y-%m-%dT%H:%M:%S"))) / 86400
                except ValueError:
                    days = 0
                key = "<1d" if days < 1 else "1-7d" if days < 7 else "7-30d" if days < 30 else ">30d"
                ages[key] += 1
            demo = bool(cfg_get(state.cfg, "auth.demo_mode", False))
            inv = __import__("sentrix.core.integrations", fromlist=["inventory"]).inventory(state.cfg, storage, demo)
            return self._json({
                "trend": d["timeline"], "severity": d["severity"], "sources": d["surfaces"],
                "categories": [{"label": fam, "value": sum(1 for f in findings if f.meta.get("family", "generic") == fam)}
                               for fam in sorted({f.meta.get("family", "generic") for f in findings})],
                "environments": [{"label": env, "value": sum(1 for f in findings if f.meta.get("environment", "unknown") == env)}
                                 for env in sorted({f.meta.get("environment", "unknown") for f in findings})],
                "remediation_performance": {"mttr_hours": mttr, "mttd_hours": 0.0,
                                            "remediated_rate": round(100 * sum(1 for f in findings if f.status in ("remediated", "verified", "closed")) / len(findings), 1) if findings else 0},
                "age_buckets": [{"label": k, "value": v} for k, v in ages.items()],
                "integration_health": [{"label": i["name"], "value": 1 if i["status"] == "connected" else 0, "status": i["status"]} for i in inv],
            })
        if path == "/api/intelligence":
            scored = [(f, f.meta.get("risk") or risk.score(f)) for f in findings]
            bands = {}
            for _, r in scored:
                bands[r["band"]] = bands.get(r["band"], 0) + 1
            assets = {}
            for f, r in scored:
                key = f.path.split(":")[0].split("/")[0]
                a = assets.setdefault(key, {"asset": key, "open": 0, "critical": 0, "risk": 0})
                if f.status in ("open", "new", "triaged", "assigned", "in_progress", "reopened"):
                    a["open"] += 1
                if f.severity == "critical":
                    a["critical"] += 1
                a["risk"] = max(a["risk"], r["score"])
            conc = sorted(assets.values(), key=lambda a: -a["open"])[:8]
            priorities = sorted([(f, r) for f, r in scored if f.status in ("open", "new", "triaged")],
                                key=lambda fr: -fr[1]["score"])[:10]
            seen_surfaces = {f.surface for f in findings}
            return self._json({
                "risk_distribution": [{"label": k, "value": v} for k, v in bands.items()],
                "concentration": conc,
                "high_risk_assets": sorted(assets.values(), key=lambda a: -a["risk"])[:6],
                "priorities": [{"id": f.id, "title": f.title, "score": r["score"], "band": r["band"],
                                "severity": f.severity} for f, r in priorities],
                "coverage_gaps": [s for s in ("ide", "pre_push", "ci", "git", "cloud", "slack",
                                             "confluence", "jira", "postman", "filesystem")
                                  if s not in seen_surfaces],
                "repeated": [{"title": f.title, "masked": f.secret_masked,
                              "count": storage.get_extra(f.id)["occurrences"]}
                             for f in findings if storage.get_extra(f.id)["occurrences"] > 1][:8],
            })
        if path == "/api/sources":
            events = storage.list_events(limit=500)
            out = []
            for s in ("ide", "pre_push", "ci", "git", "cloud", "slack", "confluence", "jira", "postman", "filesystem"):
                rel = [f for f in findings if f.surface == s]
                ev = [e for e in events if e.get("surface") == s]
                out.append({"surface": s, "findings": len(rel),
                            "last_event": ev[0]["ts"] if ev else None,
                            "status": "monitored" if rel or ev else "idle"})
            return self._json({"sources": out})
        if path == "/api/assets":
            assets = {}
            for f in findings:
                key = f.path.split(":")[0].split("/")[0]
                fam = (f.meta or {}).get("family") or "unknown"
                det = f.detector_id.split(".")[0] if f.detector_id else "unknown"
                a = assets.setdefault(key, {"id": "asset-" + key, "name": key,
                                            "type": f.surface, "owner": f.owner or "unowned",
                                            "environment": (f.meta or {}).get("environment", "unknown"),
                                            "integration": f.surface, "monitored": True,
                                            "last_scan": f.updated_at, "findings": 0,
                                            "critical": 0, "risk": 0, "technologies": set(), "groups": set()})
                a["findings"] += 1
                if f.severity == "critical":
                    a["critical"] += 1
                a["risk"] = max(a["risk"], ((f.meta or {}).get("risk") or {}).get("score", 0))
                a["technologies"].add(det)
                a["groups"].add(fam)
            rows = []
            for a in assets.values():
                a["technologies"] = sorted(a["technologies"])
                a["groups"] = sorted(a["groups"])
                rows.append(a)
            return self._json({"assets": sorted(rows, key=lambda a: -a["risk"])})
        if path == "/api/integrations":
            return self._json({"integrations": integrations.inventory(state.cfg, storage, demo)})

        if path == "/api/architecture":
            demo = bool(cfg_get(state.cfg, "auth.demo_mode", False))
            jobs = storage.list_jobs(limit=500)
            by = {}
            for j in jobs:
                by[j["status"]] = by.get(j["status"], 0) + 1
            return self._json({
                "product": "SENTRIX",
                "version": __version__,
                "mode": "local modular monolith (single process, stdlib-only runtime)",
                "note": "Tier mapping is SENTRIX-native: no external Postgres/Redis/RustFS/gRPC worker fleet is required or added.",
                "tiers": [
                    {"tier": 1, "name": "Web console", "components": [
                        {"id": "dashboard", "name": "SENTRIX Command Center", "type": "spa", "status": "active",
                         "details": "Hash-routed SPA served by the core API; per-tab sessions, RBAC-aware UI."}
                    ]},
                    {"tier": 2, "name": "Core API", "components": [
                        {"id": "api", "name": "Core HTTP API", "type": "service", "status": "active",
                         "details": "Stdlib ThreadingHTTPServer; JSON API, auth, lifecycle metadata, audit/logging."}
                    ]},
                    {"tier": 3, "name": "Infrastructure", "components": [
                        {"id": "sqlite", "name": "SQLite storage", "type": "database", "status": "active",
                         "details": f"Local DB at {cfg_get(state.cfg, 'storage.path', 'data/sentrix.db')}; migrations, WAL-friendly access."},
                        {"id": "queue", "name": "In-process job coordination", "type": "queue", "status": "active",
                         "details": "Thread-safe JobRunner with bounded concurrency (2 slots) and cancellation; no Redis/BullMQ dependency."},
                        {"id": "artifacts", "name": "Local artifacts", "type": "object-store", "status": "active",
                         "details": "Reports/exports/quarantine stored on local filesystem; no external object store required."},
                        {"id": "enrichment", "name": "Risk/intelligence enrichment", "type": "enrichment", "status": "active",
                         "details": "Deterministic risk scoring, fingerprinting, dedupe and metadata enrichment in-process."}
                    ]},
                    {"tier": 4, "name": "Workers / agents", "components": [
                        {"id": "jobrunner", "name": "JobRunner", "type": "worker", "status": "active",
                         "details": f"Background scan worker pool; job states: {by}."},
                        {"id": "scheduler", "name": "Scheduler", "type": "worker", "status": "active",
                         "details": "Background schedule/remediation loop thread."}
                    ]},
                    {"tier": 5, "name": "Connectors / surfaces", "components": [
                        {"id": "surfaces", "name": "Surface adapters", "type": "connector", "status": "active",
                         "details": f"Monitored surfaces: {', '.join(SURFACES)}."},
                        {"id": "integrations", "name": "SENTRIX Connect integrations", "type": "connector", "status": "active",
                         "details": f"{len(__import__('sentrix.core.integrations', fromlist=['inventory']).inventory(state.cfg, storage, demo))} providers with honest connection states."}
                    ]},
                ],
                "lifecycle": describe_lifecycle(),
            })

        if path == "/api/workers":
            findings = storage.list_findings(limit=5000)
            jobs = storage.list_jobs(limit=500)
            by = {}
            for j in jobs:
                by[j["status"]] = by.get(j["status"], 0) + 1
            running = [j for j in jobs if j.get("status") == "running"]
            queued = [j for j in jobs if j.get("status") == "queued"]
            demo = bool(cfg_get(state.cfg, "auth.demo_mode", False))
            inv = __import__("sentrix.core.integrations", fromlist=["inventory"]).inventory(state.cfg, storage, demo)
            agents = [
                {"id": "agent-api", "name": "Core API", "kind": "service", "status": "running",
                 "runtime": "python/stdlib", "capabilities": ["http", "auth", "rbac", "api"], "queue": None},
                {"id": "agent-jobrunner", "name": "JobRunner", "kind": "worker-pool", "status": "running",
                 "runtime": "python/threading", "capabilities": ["scan", "incremental-cache", "cancel"],
                 "capacity": 2, "running": len(running), "queued": len(queued), "jobs_by_status": by},
                {"id": "agent-scheduler", "name": "Scheduler", "kind": "worker", "status": "running",
                 "runtime": "python/thread", "capabilities": ["schedules", "remediation-checks", "alert-checks"], "queue": None},
            ]
            for s in SURFACES:
                rel = [f for f in findings if f.surface == s]
                agents.append({"id": f"connector-{s}", "name": s.replace('_', ' ').title(), "kind": "connector",
                               "status": "monitored" if rel else "idle", "runtime": "in-process adapter",
                               "capabilities": ["ingest", "scan"], "findings": len(rel)})
            for i in inv:
                agents.append({"id": f"integration-{i['id']}", "name": i['name'], "kind": "integration-agent",
                               "status": i['status'], "runtime": "connector",
                               "capabilities": i.get('permissions', []), "last_sync": i.get('last_sync')})
            return self._json({"workers": agents, "agents": agents, "jobs_by_status": by, "capacity": {"job_slots": 2}})


        if path == "/api/agents":
            # AI/assistant agents (honest capabilities)
            ai_enabled = bool(cfg_get(state.cfg, "ai.enabled", False))
            has_key = bool(__import__("sentrix.config", fromlist=["env_secret"]).env_secret(state.cfg, "ai.api_key_env")) if ai_enabled else False
            mode = "gpt-compatible" if ai_enabled and has_key else "heuristic"
            agents = [
                {"id": "triage-agent", "name": "Triage Agent", "kind": "analysis", "status": "available",
                 "mode": mode, "capabilities": ["finding-triage", "confidence", "verdict", "recommendation"],
                 "endpoint": "/api/triage", "details": "Heuristic triage runs locally; GPT-compatible mode requires ai.enabled and API key env."},
                {"id": "lifecycle-agent", "name": "Lifecycle Advisor", "kind": "workflow", "status": "available",
                 "mode": "deterministic", "capabilities": ["state-machine", "transitions", "labels"],
                 "endpoint": "/api/lifecycle", "details": "Machine-readable workflow metadata for findings, jobs, alerts and integrations."},
            ]
            return self._json({"agents": agents, "ai": {"enabled": ai_enabled, "mode": mode, "configured": ai_enabled and has_key}})

        if path == "/api/mcp":
            return self._json({
                "mcp": {
                    "server_implemented": False,
                    "status": "agent-ready-apis",
                    "note": "SENTRIX does not claim a bundled MCP stdio server by default. It exposes authenticated HTTP APIs and machine-readable registries that MCP/tooling adapters can consume in a deployment-specific setup.",
                    "agent_ready_endpoints": [
                        {"path": "/api/lifecycle", "purpose": "State machines and workflow metadata"},
                        {"path": "/api/tools", "purpose": "Detectors, adapters, integrations, playbooks"},
                        {"path": "/api/workers", "purpose": "Local workers/connectors and job capacity"},
                        {"path": "/api/architecture", "purpose": "Platform architecture and component status"},
                        {"path": "/api/findings", "purpose": "Findings/exposures inventory and evidence"},
                        {"path": "/api/triage", "purpose": "AI/heuristic finding triage (POST)"},
                    ],
                    "configuration": {"transport": "http-json", "auth": "session cookie or bearer token", "external_mcp_bridge": "deployment-specific"}
                }
            })

        if path == "/api/tools":
            detectors = []
            try:
                for d in all_detectors():
                    detectors.append({"id": d.id, "name": getattr(d, "name", d.id), "category": getattr(d, "category", "general"),
                                      "severity": getattr(d, "severity", "medium"), "kind": "detector", "status": "enabled"})
            except Exception:
                pass
            demo = bool(cfg_get(state.cfg, "auth.demo_mode", False))
            inv = __import__("sentrix.core.integrations", fromlist=["inventory"]).inventory(state.cfg, storage, demo)
            tools = [{"id": f"surface-{s}", "name": s, "kind": "surface-adapter", "status": "available", "capabilities": ["scan","ingest"]} for s in SURFACES]
            tools += [{"id": f"integration-{i['id']}", "name": i['name'], "kind": "integration", "status": i['status'], "capabilities": i.get('permissions', [])} for i in inv]
            tools += [{"id": f"playbook-{k}", "name": k.replace('-', ' '), "kind": "playbook", "status": "available", "capabilities": ["remediation","guidance"], "steps": len(v)} for k, v in PLAYBOOKS.items()]
            return self._json({"tools": tools, "detectors": detectors, "counts": {"tools": len(tools), "detectors": len(detectors)}})

        if path == "/api/technologies":
            findings = storage.list_findings(limit=5000)
            tech = {}
            for f in findings:
                fam = (f.meta or {}).get("family") or (f.meta or {}).get("technology") or "unknown"
                det = f.detector_id.split(".")[0] if f.detector_id else "unknown"
                key = f"{fam}:{det}"
                t = tech.setdefault(key, {"id": key, "name": det.replace('_',' ').title(), "family": fam, "category": det,
                                          "findings": 0, "critical": 0, "assets": set(), "surfaces": set()})
                t["findings"] += 1
                if f.severity == "critical":
                    t["critical"] += 1
                t["assets"].add(f.path.split(":")[0].split("/")[0])
                t["surfaces"].add(f.surface)
            rows = []
            for v in tech.values():
                v["assets"] = len(v["assets"])
                v["surfaces"] = sorted(v["surfaces"])
                rows.append(v)
            return self._json({"technologies": sorted(rows, key=lambda x: (-x["critical"], -x["findings"], x["name"]))})

        if path == "/api/groups":
            findings = storage.list_findings(limit=5000)
            by = {"surface": {}, "environment": {}, "owner": {}, "severity": {}}
            for f in findings:
                for dim, val in (("surface", f.surface), ("environment", (f.meta or {}).get("environment","unknown")), ("owner", f.owner or "unowned"), ("severity", f.severity)):
                    g = by[dim].setdefault(val, {"name": val, "dimension": dim, "findings": 0, "assets": set(), "critical": 0})
                    g["findings"] += 1
                    if f.severity == "critical": g["critical"] += 1
                    g["assets"].add(f.path.split(":")[0].split("/")[0])
            groups = []
            for dim, items in by.items():
                for g in items.values():
                    g["assets"] = len(g["assets"])
                    groups.append(g)
            return self._json({"groups": sorted(groups, key=lambda x: (x["dimension"], -x["findings"]))})
        if path == "/api/remediation":
            sla = {"critical": 24, "high": 72, "medium": 168, "low": 336, "info": 720}
            tasks = []
            for f in findings:
                if f.status not in ("open", "new", "triaged", "assigned", "in_progress", "reopened"):
                    continue
                extra = storage.get_extra(f.id)
                checklist = storage.get_checklist(f.id)
                try:
                    age = (time.time() - time.mktime(time.strptime(extra.get("first_seen") or f.created_at, "%Y-%m-%dT%H:%M:%S"))) / 3600
                except ValueError:
                    age = 0
                limit = sla.get(f.severity, 168)
                tasks.append({"finding_id": f.id, "title": f.title, "severity": f.severity,
                              "assignee": extra["assignee"] or f.owner, "status": f.status,
                              "sla_hours": limit, "age_hours": round(age, 1),
                              "breached": age > limit,
                              "checklist_done": sum(1 for c in checklist.values() if c["done"]),
                              "checklist_total": 5})
            return self._json({"tasks": sorted(tasks, key=lambda t: -t["breached"]),
                               "playbooks": [{"family": k, "steps": v} for k, v in PLAYBOOKS.items()],
                               "sla": {"breached": sum(1 for t in tasks if t["breached"]),
                                       "at_risk": sum(1 for t in tasks if not t["breached"] and t["age_hours"] > t["sla_hours"] * 0.7)}})
        if path == "/api/investigations":
            out = []
            for f in findings:
                notes = storage.list_notes(f.id)
                extra = storage.get_extra(f.id)
                if f.status in ("closed", "verified", "false_positive"):
                    continue
                if notes or extra["assignee"]:
                    out.append({"id": f.id, "title": f.title, "severity": f.severity,
                                "status": f.status, "assignee": extra["assignee"] or f.owner,
                                "notes": len(notes),
                                "related": len(storage.related_findings(f.id))})
            return self._json({"investigations": out})
        if path == "/api/exceptions":
            return self._json({
                "allowlist": storage.allowlist_entries(),
                "exceptions": [f.to_dict() for f in findings
                               if f.status in ("accepted_risk", "suppressed", "false_positive")],
            })
        if path == "/api/compliance":
            return self._json({"mappings": [
                {"framework": "SOC 2", "control": "CC6.1", "title": "Logical access security",
                 "evidence": ["RBAC with eight roles", "session expiration", "audit trail"], "status": "supported"},
                {"framework": "SOC 2", "control": "CC7.2", "title": "Monitoring for anomalies",
                 "evidence": ["multi-surface detection", "alert routing", "system logs"], "status": "supported"},
                {"framework": "ISO 27001", "control": "A.8.24", "title": "Cryptography key management",
                 "evidence": ["private-key detectors", "rotation playbooks"], "status": "partial"},
                {"framework": "ISO 27001", "control": "A.8.16", "title": "Monitoring activities",
                 "evidence": ["scheduled scans", "integration health"], "status": "supported"},
                {"framework": "PCI DSS", "control": "Req. 3", "title": "Protect stored account data",
                 "evidence": ["masked evidence", "fingerprint-only storage"], "status": "partial"},
                {"framework": "NIST CSF", "control": "DE.CM", "title": "Continuous monitoring",
                 "evidence": ["watch mode", "jobs", "SaaS ingestion"], "status": "supported"},
            ], "note": "Evidence mapping only. Generating a report does not certify compliance."})
        if path == "/api/system/health":
            jobs = storage.list_jobs(limit=500)
            by_status = {}
            for j in jobs:
                by_status[j["status"]] = by_status.get(j["status"], 0) + 1
            return self._json({
                "uptime_seconds": int(time.time() - state.started),
                "version": __version__, "db_bytes": storage.db_size(),
                "storage": cfg_get(state.cfg, "storage.path"),
                "jobs": by_status, "users": len(storage.list_users()),
                "threads": __import__("threading").active_count(),
                "python": __import__("platform").python_version(),
            })
        if path == "/api/reports":
            return self._json({"reports": storage.list_reports(),
                               "types": [{"id": k, "title": v} for k, v in reports.REPORT_TYPES.items()]})
        m = re.match(r"^/api/reports/([A-Za-z0-9\-]+)/download$", path)
        if m:
            row = storage.get_report(m.group(1))
            if not row:
                return self._json({"error": "not found"}, 404)
            mime = "text/csv; charset=utf-8" if row["format"] == "csv" else "application/json"
            return self._send(200, (row["body"] or "").encode(), mime)
        if path == "/api/logs/export":
            logs = storage.list_logs(int(query.get("limit", 1000)), query.get("level"))
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["ts", "level", "source", "component", "event_type", "exec_id",
                        "resource", "status", "correlation_id", "message"])
            for l in logs:
                w.writerow([l.get(k, "") for k in ("ts", "level", "source", "component",
                            "event_type", "exec_id", "resource", "status", "correlation_id", "message")])
            return self._send(200, buf.getvalue().encode(), "text/csv; charset=utf-8")
        if path == "/api/detection-rules":
            return self._json({"rules": storage.list_custom_rules()})
        # ── Risk Acceptances API ─────────────────────────────────
        if path == "/api/risk-acceptances":
            storage.expire_risk_acceptances()
            return self._json({"risk_acceptances": storage.list_risk_acceptances()})
        m = re.match(r"^/api/risk-acceptances/([A-Za-z0-9_\-]+)$", path)
        if m:
            ra = storage.get_risk_acceptance(m.group(1))
            return self._json({"risk_acceptance": ra}) if ra else self._json({"error": "not found"}, 404)
        # ── Hubs API ──────────────────────────────────────────────
        result = HubsAPI(state).handle_get(path, query, self._user())
        if result is not None:
            payload, code = result
            return self._json(payload, code)
        return None

    def _extra_post(self, path, body, uname):
        from sentrix.core import reports
        state = self.state
        storage = state.storage
        user = self._user() or {}
        uname = (user.get("username") or "anonymous")
        role = user.get("role") or "viewer"
        # -- Reopen closed finding (admin only) ---------------------------------
        m_reopen = re.match(r"^/api/findings/([A-Za-z0-9\-]+)/reopen$", path)
        if m_reopen:
            if role not in ("super_admin", "security_admin"):
                return self._json({"error":"security administrator role required"}, 403)
            fid = m_reopen.group(1)
            finding = storage.get_finding(fid)
            if not finding:
                return self._json({"error":"finding not found"}, 404)
            storage.set_status(fid, "reopened", uname)
            storage.upsert_assignment(fid, uname, reason="Reopened by admin", action="reopened",
                                      primary_owner="", secondary_reviewer="", status="unassigned",
                                      assigned_by="", assigned_at="", acknowledged_at="", secondary_acknowledged_at="",
                                      primary_investigation_started_at="", primary_classification="", primary_reasoning="",
                                      primary_evidence="", primary_submitted_at="",
                                      secondary_review_started_at="", secondary_outcome="", secondary_reasoning="",
                                      secondary_evidence="", secondary_submitted_at="",
                                      admin_decision="", admin_decision_reason="", admin_decision_by="", admin_decision_at="",
                                      reassessment_target="", remediation_owner="", remediation_status="",
                                      remediation_submitted_at="", remediation_note="",
                                      verification_requested_at="", verification_note="", verification_evidence="",
                                      verification_decision="", verification_decided_by="", verification_decided_at="",
                                      verification_rejection_reason="", blocked_reason="", reassignment_requested_by="",
                                      reassignment_reason="", completed_at="", verified_at="")
            storage.add_note(fid, uname, "Finding reopened by admin")
            state.auth.audit("finding.reopened", uname, fid)
            return self._json({"ok": True, "id": fid, "status": "reopened"})
        # -- Assignment / workload POST ----------------------------------------
        if path.startswith("/api/assignment"):
            from sentrix.core import assignment_api
            user = self._user() or {}
            uname = (user.get("username") or "anonymous")
            role = user.get("role") or "viewer"
            is_admin = role in ("super_admin","security_admin")
            can_manage = role in ("super_admin","security_admin","security_analyst","appsec_engineer","devsecops_engineer")
            if path == "/api/assignment/sla-config":
                if not is_admin: return self._json({"error":"security administrator role required"}, 403)
                storage.set_assignment_sla_config(body or {}, uname)
                state.auth.audit("assignment.sla_config", uname, json.dumps(body)[:500])
                return self._json({"ok":True, "config": storage.get_assignment_sla_config()})
            if path == "/api/assignment/escalate-check":
                if not can_manage: return self._json({"error":"insufficient role"}, 403)
                r = assignment_api.check_sla_escalations(storage, getattr(state,'alert_router',None))
                state.auth.audit("assignment.escalate_check", uname, json.dumps(r))
                return self._json(r)
            if path.startswith("/api/assignment/profiles/"):
                if not is_admin: return self._json({"error":"security administrator role required"}, 403)
                target = path.rsplit("/",1)[-1]
                if target not in {u["username"] for u in storage.list_users()}: return self._json({"error":"user not found"}, 404)
                storage.upsert_employee_profile(target, uname, **(body or {}))
                state.auth.audit("assignment.profile", uname, f"{target}:{json.dumps(body)[:300]}")
                return self._json({"ok":True, "profile": storage.get_employee_profile(target)})
            if path == "/api/assignment/bulk":
                if not can_manage: return self._json({"error":"insufficient role"}, 403)
                fids = body.get("finding_ids") or []
                action = body.get("action") or "assign"
                if not fids: return self._json({"error":"finding_ids required"}, 400)
                results = []
                for fid in fids[:200]:
                    finding = storage.get_finding(fid)
                    if not finding: results.append({"id":fid,"ok":False,"error":"not found"}); continue
                    if action == "auto":
                        r = assignment_api.do_auto_assign(storage, finding, uname, getattr(state,'alert_router',None))
                    elif action == "assign":
                        r = assignment_api.manual_assign(storage, finding, uname, body.get("primary_owner",""), body.get("secondary_reviewer",""),
                                                         body.get("reason",""), body.get("due_at",""), body.get("instructions",""), "manual",
                                                         getattr(state,'alert_router',None), admin_override=bool(body.get("admin_override")) and is_admin)
                    else:
                        r = {"ok":False,"error":"unsupported bulk action"}
                    results.append({"id":fid, **r})
                state.auth.audit("assignment.bulk", uname, f"{action}:{len(fids)}")
                return self._json({"ok": True, "results": results})
            if path.startswith("/api/assignment/finding/"):
                parts = path.strip("/").split("/")
                # /api/assignment/finding/<id>/<action>
                if len(parts) >= 5:
                    fid = parts[3]; action = parts[4]
                    finding = storage.get_finding(fid)
                    if not finding: return self._json({"error":"finding not found"}, 404)
                    a = storage.get_assignment(fid)
                    if action == "recommend":
                        if not can_manage: return self._json({"error":"insufficient role"}, 403)
                        r = assignment_api.do_auto_assign(storage, finding, uname, getattr(state,'alert_router',None), finalize=False)
                        return self._json(r, 200 if r.get("ok") or r.get("recommended") else 400)
                    if action == "auto":
                        if not can_manage: return self._json({"error":"insufficient role"}, 403)
                        r = assignment_api.do_auto_assign(storage, finding, uname, getattr(state,'alert_router',None), finalize=True)
                        state.auth.audit("assignment.auto", uname, f"{fid}:{'ok' if r.get('ok') else 'recommended'}")
                        return self._json(r, 200 if r.get("ok") or r.get("recommended") else 400)
                    if action == "approve":
                        if not can_manage: return self._json({"error":"insufficient role"}, 403)
                        r = assignment_api.approve_recommendation(storage, finding, uname, body.get("primary_owner"), body.get("secondary_reviewer"), body.get("reason",""), getattr(state,'alert_router',None))
                        if r.get("ok"): state.auth.audit("assignment.approve", uname, f"{fid}->{body.get('primary_owner') or 'recommended'}")
                        return self._json(r, 200 if r.get("ok") else 400)
                    if action == "reject":
                        if not can_manage: return self._json({"error":"insufficient role"}, 403)
                        storage.upsert_assignment(fid, uname, reason=body.get("reason","Recommendation rejected"), action="recommendation_rejected", status="unassigned", primary_owner="", secondary_reviewer="", method="")
                        state.auth.audit("assignment.reject", uname, f"{fid}:{body.get('reason','')[:200]}")
                        return self._json({"ok": True})
                    if action == "assign":
                        if not can_manage: return self._json({"error":"insufficient role"}, 403)
                        override = bool(body.get("admin_override")) and is_admin
                        r = assignment_api.manual_assign(storage, finding, uname, body.get("primary_owner",""), body.get("secondary_reviewer",""),
                                                         body.get("reason",""), body.get("due_at",""), body.get("instructions",""),
                                                         body.get("method","manual"), getattr(state,'alert_router',None), admin_override=override)
                        if not r.get("ok") and r.get("error"): return self._json(r, 400)
                        state.auth.audit("assignment.override" if override else "assignment.assign", uname, f"{fid}->{body.get('primary_owner','')} reason={str(body.get('reason',''))[:200]}")
                        return self._json(r)
                    # actions by owner/admin
                    owner = a.get("primary_owner"); reviewer = a.get("secondary_reviewer")
                    if action in ("ack","acknowledge"):
                        if uname == owner:
                            na = storage.upsert_assignment(fid, uname, reason=body.get("reason","Acknowledged by primary owner"), action="primary_acknowledged",
                                                           status="acknowledged", acknowledged_at=now_iso())
                            state.auth.audit("assignment.ack", uname, f"{fid}:primary")
                            return self._json({"ok":True,"assignment":na})
                        if uname == reviewer and reviewer:
                            na = storage.upsert_assignment(fid, uname, reason=body.get("reason","Acknowledged by secondary assignee"), action="secondary_acknowledged",
                                                           status="acknowledged" if a.get("acknowledged_at") else "assigned",
                                                           secondary_acknowledged_at=now_iso())
                            state.auth.audit("assignment.ack", uname, f"{fid}:secondary")
                            return self._json({"ok":True,"assignment":na})
                        return self._json({"error":"only the assigned primary or secondary employee can acknowledge this assignment"}, 403)
                    if action == "request-assistance":
                        if not (is_admin or uname == owner or uname == reviewer): return self._json({"error":"forbidden"}, 403)
                        na = storage.upsert_assignment(fid, uname, reason=body.get("reason","Assistance requested"), action="assistance_requested",
                                                       assistance_requested_at=now_iso(), assistance_reason=body.get("reason",""))
                        try: storage.add_log("warn","assignment", f"Admin assistance requested for {fid} by {uname}: {str(body.get('reason',''))[:300]}", component="assignment", event_type="assistance_requested", resource=fid)
                        except Exception: pass
                        state.auth.audit("assignment.assistance", uname, fid)
                        return self._json({"ok":True,"assignment":na})
                    # --- Three-stage review workflow ---
                    if action == "primary-start-investigation":
                        if not (is_admin or uname == owner): return self._json({"error":"only primary assignee can start investigation"}, 403)
                        if a.get("primary_submitted_at"): return self._json({"error":"primary assessment already submitted (read-only)"}, 409)
                        na = storage.upsert_assignment(fid, uname, reason="Investigation started", action="primary_investigation_started",
                                                       status="in_progress", primary_investigation_started_at=now_iso(), reassessment_target="",
                                                       acknowledged_at=a.get("acknowledged_at") or now_iso())
                        state.auth.audit("assignment.primary_start", uname, fid)
                        return self._json({"ok":True,"assignment":na})
                    if action == "primary-submit-assessment":
                        if not (is_admin or uname == owner): return self._json({"error":"only primary assignee can submit primary assessment"}, 403)
                        if a.get("primary_submitted_at") and a.get("reassessment_target") != "primary": return self._json({"error":"primary assessment already submitted (read-only)"}, 409)
                        classification = str(body.get("classification") or body.get("verdict") or "").strip().lower().replace(" ", "_")
                        if classification in ("truepositive","tp","genuine","confirmed"): classification = "true_positive"
                        if classification in ("falsepositive","fp"): classification = "false_positive"
                        if classification not in ("true_positive","false_positive"):
                            return self._json({"error":"classification must be True Positive or False Positive"}, 400)
                        reasoning = str(body.get("reasoning") or body.get("reason") or body.get("notes") or "").strip()
                        evidence = body.get("evidence") if isinstance(body.get("evidence"), str) else json.dumps(body.get("evidence") or [])[:4000]
                        na = storage.upsert_assignment(fid, uname, reason=reasoning[:500], action="primary_assessment_submitted",
                                                       status="in_progress", primary_classification=classification, primary_reasoning=reasoning[:4000],
                                                       primary_evidence=evidence[:4000], primary_submitted_at=now_iso(), reassessment_target="", primary_investigation_started_at=a.get("primary_investigation_started_at") or now_iso(), acknowledged_at=a.get("acknowledged_at") or now_iso())
                        try:
                            from sentrix.core import assignment_api as _aapi
                            fobj = storage.get_finding(fid)
                            if fobj and reviewer: _aapi._notify(storage, getattr(state,'alert_router',None), fobj, "assignment.secondary_review_requested", f"Primary assessment submitted for {fid} ({classification}); secondary review requested.", uname)
                        except Exception: pass
                        state.auth.audit("assignment.primary_submitted", uname, f"{fid}:{classification}")
                        return self._json({"ok":True,"assignment":na,"stage":"Awaiting Secondary Review" if reviewer else "Awaiting Admin Review"})
                    if action == "secondary-start-review":
                        if not (is_admin or uname == reviewer): return self._json({"error":"only secondary assignee can start review"}, 403)
                        if not a.get("primary_submitted_at"): return self._json({"error":"primary assessment has not been submitted yet"}, 409)
                        if a.get("secondary_submitted_at") and a.get("reassessment_target") != "secondary": return self._json({"error":"secondary assessment already submitted"}, 409)
                        na = storage.upsert_assignment(fid, uname, reason="Secondary review started", action="secondary_review_started",
                                                       secondary_review_started_at=now_iso(), reassessment_target="",
                                                       secondary_acknowledged_at=a.get("secondary_acknowledged_at") or now_iso())
                        state.auth.audit("assignment.secondary_start", uname, fid)
                        return self._json({"ok":True,"assignment":na})
                    if action == "secondary-submit-assessment":
                        if not (is_admin or uname == reviewer): return self._json({"error":"only secondary assignee can submit final assessment"}, 403)
                        if not a.get("primary_submitted_at"): return self._json({"error":"primary assessment has not been submitted yet"}, 409)
                        if a.get("secondary_submitted_at") and a.get("reassessment_target") != "secondary": return self._json({"error":"secondary assessment already submitted"}, 409)
                        classification = str(body.get("classification") or body.get("secondary_classification") or "").strip().lower().replace(" ", "_")
                        if classification in ("truepositive","tp","confirm_true_positive","true"): classification = "true_positive"
                        if classification in ("falsepositive","fp","confirm_false_positive","false"): classification = "false_positive"
                        outcome = str(body.get("outcome") or body.get("verdict") or "").strip().lower().replace(" ", "_").replace("-","_")
                        if classification in ("true_positive","false_positive"):
                            disagrees = bool(body.get("disagrees") or body.get("disagree")) or (outcome == "disagree") or (classification != (a.get("primary_classification") or ""))
                            outcome = ("disagree_" + classification) if disagrees else classification
                        else:
                            aliases = {"confirm":"confirm","confirm_primary":"confirm","agree":"confirm","confirmed":"confirm",
                                       "disagree":"disagree","challenge":"disagree","reject_primary":"disagree",
                                       "request_further_investigation":"request_further_investigation","further_investigation":"request_further_investigation","reassess":"request_further_investigation","needs_more_info":"request_further_investigation"}
                            outcome = aliases.get(outcome, outcome)
                            if outcome == "confirm": outcome = a.get("primary_classification") or "confirm"
                        if outcome not in ("true_positive","false_positive","disagree_true_positive","disagree_false_positive","confirm","disagree","request_further_investigation") and not outcome.startswith("disagree_"):
                            return self._json({"error":"secondary assessment required: choose True Positive or False Positive (and reason)"}, 400)
                        reasoning = str(body.get("reasoning") or body.get("reason") or body.get("notes") or "").strip()
                        evidence = body.get("evidence") if isinstance(body.get("evidence"), str) else json.dumps(body.get("evidence") or [])[:4000]
                        na = storage.upsert_assignment(fid, uname, reason=reasoning[:500], action="secondary_assessment_submitted",
                                                       secondary_outcome=outcome, secondary_reasoning=reasoning[:4000],
                                                       secondary_evidence=evidence[:4000], secondary_submitted_at=now_iso(), secondary_review_started_at=a.get("secondary_review_started_at") or now_iso(), secondary_acknowledged_at=a.get("secondary_acknowledged_at") or now_iso(),
                                                       reassessment_target="", admin_decision="")
                        try:
                            from sentrix.core import assignment_api as _aapi
                            fobj = storage.get_finding(fid)
                            if fobj: _aapi._notify(storage, getattr(state,'alert_router',None), fobj, "assignment.admin_review_requested", f"Secondary assessment submitted for {fid} ({outcome.replace('_',' ')}); admin final review requested.", uname)
                        except Exception: pass
                        state.auth.audit("assignment.secondary_submitted", uname, f"{fid}:{outcome}")
                        return self._json({"ok":True,"assignment":na,"stage":"Awaiting Admin Review"})
                    if action == "admin-final-decision":
                        if not is_admin: return self._json({"error":"admin only"}, 403)
                        if not a.get("secondary_submitted_at") and a.get("secondary_reviewer"): return self._json({"error":"secondary assessment must be submitted before admin final decision"}, 409)
                        decision = str(body.get("decision") or "").strip().lower().replace(" ", "_").replace("-","_")
                        aliases = {"confirm_true_positive":"confirm_true_positive","true_positive":"confirm_true_positive","genuine":"confirm_true_positive","accept":"confirm_true_positive",
                                   "confirm_false_positive":"confirm_false_positive","false_positive":"confirm_false_positive","fp":"confirm_false_positive",
                                   "request_reassessment":"request_reassessment","reassess":"request_reassessment","return":"request_reassessment"}
                        decision = aliases.get(decision, decision)
                        if decision not in ("confirm_true_positive","confirm_false_positive","request_reassessment"):
                            return self._json({"error":"decision must be confirm_true_positive, confirm_false_positive, or request_reassessment"}, 400)
                        reason = str(body.get("reason") or body.get("justification") or "").strip()
                        if not reason: return self._json({"error":"reason/justification is required"}, 400)
                        target = str(body.get("target") or body.get("reassessment_target") or "primary").strip().lower()
                        if decision == "request_reassessment" and target not in ("primary","secondary"): target = "primary"
                        updates = dict(admin_decision=decision, admin_decision_reason=reason[:2000], admin_decision_by=uname, admin_decision_at=now_iso(), reassessment_target=(target if decision=="request_reassessment" else ""))
                        if decision == "request_reassessment":
                            if target == "primary": updates.update(primary_submitted_at="", primary_classification="", primary_reasoning="", primary_evidence="")
                            else: updates.update(secondary_submitted_at="", secondary_outcome="", secondary_reasoning="", secondary_evidence="")
                            updates["status"] = "in_progress"
                        elif decision == "confirm_true_positive":
                            rem_owner = str(body.get("remediation_owner") or a.get("primary_owner") or "").strip()
                            updates.update(remediation_owner=rem_owner, remediation_status="pending", status="in_progress")
                            try: storage.set_status(fid, "in_progress", uname)
                            except Exception: pass
                        elif decision == "confirm_false_positive":
                            updates.update(status="completed", remediation_status="not_applicable")
                            try: storage.set_status(fid, "false_positive", uname)
                            except Exception: pass
                        na = storage.upsert_assignment(fid, uname, reason=reason[:500], action=f"admin_decision:{decision}", **updates)
                        state.auth.audit("assignment.admin_decision", uname, f"{fid}:{decision}")
                        return self._json({"ok":True,"assignment":na})
                    if action == "assign-remediation":
                        if not is_admin: return self._json({"error":"admin only"}, 403)
                        if a.get("admin_decision") != "confirm_true_positive": return self._json({"error":"finding must be confirmed as true positive by admin before assigning remediation"}, 409)
                        rem_owner = str(body.get("remediation_owner") or body.get("owner") or "").strip()
                        if not rem_owner: return self._json({"error":"remediation owner required"}, 400)
                        na = storage.upsert_assignment(fid, uname, reason=str(body.get("reason") or "Remediation assigned")[:500], action="remediation_assigned",
                                                       remediation_owner=rem_owner, remediation_status="in_progress", status="in_progress")
                        state.auth.audit("assignment.remediation_assigned", uname, f"{fid}->{rem_owner}")
                        return self._json({"ok":True,"assignment":na})
                    if action == "submit-remediation":
                        if not (is_admin or uname == owner or uname == a.get("remediation_owner")): return self._json({"error":"only remediation owner/primary/admin can submit remediation"}, 403)
                        if a.get("admin_decision") != "confirm_true_positive": return self._json({"error":"finding is not in confirmed true-positive remediation flow"}, 409)
                        note = str(body.get("note") or body.get("reason") or "").strip()
                        if not note: return self._json({"error":"remediation notes/evidence are required"}, 400)
                        na = storage.upsert_assignment(fid, uname, reason=note[:500], action="remediation_submitted",
                                                       remediation_status="submitted", remediation_submitted_at=now_iso(), remediation_note=note[:4000])
                        try: storage.set_status(fid, "remediated", uname)
                        except Exception: pass
                        state.auth.audit("assignment.remediation_submitted", uname, fid)
                        return self._json({"ok":True,"assignment":na})
                    if action == "request-verification":
                        if not (is_admin or uname == owner): return self._json({"error":"only primary owner or admin can request verification"}, 403)
                        note = str(body.get("note") or body.get("reason") or "")[:2000]
                        evidence = body.get("evidence") if isinstance(body.get("evidence"), str) else json.dumps(body.get("evidence") or "")[:2000]
                        na = storage.upsert_assignment(fid, uname, reason=note or "Verification requested", action="verification_requested",
                                                       status="completed", verification_requested_at=now_iso(), verification_note=note, verification_evidence=evidence,
                                                       verification_decision="", verification_decided_at="", verification_rejection_reason="")
                        try:
                            from sentrix.core import assignment_api as _aapi
                            fobj = storage.get_finding(fid)
                            if fobj: _aapi._notify(storage, getattr(state,'alert_router',None), fobj, "assignment.verification_requested", f"Verification requested for {fid} by {uname}", uname)
                        except Exception: pass
                        state.auth.audit("assignment.verification_requested", uname, fid)
                        return self._json({"ok":True,"assignment":na})
                    if action == "approve-verification":
                        if not is_admin: return self._json({"error":"security administrator role required"}, 403)
                        na = storage.upsert_assignment(fid, uname, reason=body.get("reason","Verification approved"), action="verification_approved",
                                                       status="verified", verified_at=now_iso(), verification_decision="approved", verification_decided_by=uname, verification_decided_at=now_iso())
                        try: storage.set_status(fid, "verified", uname)
                        except Exception: pass
                        state.auth.audit("assignment.verification_approved", uname, fid)
                        return self._json({"ok":True,"assignment":na})
                    if action == "reject-verification":
                        if not is_admin: return self._json({"error":"security administrator role required"}, 403)
                        reason = str(body.get("reason") or "Verification rejected")[:1000]
                        na = storage.upsert_assignment(fid, uname, reason=reason, action="verification_rejected",
                                                       status="in_progress", verification_decision="rejected", verification_decided_by=uname, verification_decided_at=now_iso(), verification_rejection_reason=reason)
                        try: storage.set_status(fid, "in_progress", uname)
                        except Exception: pass
                        state.auth.audit("assignment.verification_rejected", uname, f"{fid}:{reason[:200]}")
                        return self._json({"ok":True,"assignment":na})
                    if action == "start":
                        if is_admin or uname == owner:
                            if a.get("primary_submitted_at") and a.get("reassessment_target") != "primary" and not is_admin:
                                return self._json({"error":"primary assessment already submitted (read-only)"}, 409)
                            na = storage.upsert_assignment(fid, uname, reason=body.get("reason","Investigation started"), action="started",
                                                           status="in_progress", primary_investigation_started_at=a.get("primary_investigation_started_at") or now_iso())
                            return self._json({"ok":True,"assignment":na})
                        if uname == reviewer and reviewer:
                            if not a.get("primary_submitted_at"): return self._json({"error":"primary assessment not submitted yet"}, 409)
                            na = storage.upsert_assignment(fid, uname, reason=body.get("reason","Secondary review started"), action="secondary_review_started",
                                                           secondary_review_started_at=a.get("secondary_review_started_at") or now_iso())
                            return self._json({"ok":True,"assignment":na})
                        return self._json({"error":"forbidden"}, 403)
                    if action == "block":
                        if not (is_admin or uname == owner): return self._json({"error":"forbidden"}, 403)
                        na = storage.upsert_assignment(fid, uname, reason=body.get("reason","Blocked"), action="blocked", status="blocked", blocked_reason=body.get("reason",""))
                        return self._json({"ok":True,"assignment":na})
                    if action == "request-reassign":
                        if not (is_admin or uname == owner): return self._json({"error":"forbidden"}, 403)
                        na = storage.upsert_assignment(fid, uname, reason=body.get("reason","Reassignment requested"), action="reassignment_requested",
                                                       status="reassignment_requested", reassignment_requested_by=uname, reassignment_reason=body.get("reason",""))
                        state.auth.audit("assignment.request_reassign", uname, fid)
                        return self._json({"ok":True,"assignment":na})
                    if action == "complete":
                        if not (is_admin or uname == owner): return self._json({"error":"forbidden"}, 403)
                        na = storage.upsert_assignment(fid, uname, reason=body.get("reason","Completed"), action="completed", status="completed", completed_at=now_iso())
                        return self._json({"ok":True,"assignment":na})
                    if action == "verify":
                        if not (is_admin or uname == reviewer or can_manage): return self._json({"error":"forbidden"}, 403)
                        na = storage.upsert_assignment(fid, uname, reason=body.get("reason","Verified"), action="verified", status="verified", verified_at=now_iso())
                        return self._json({"ok":True,"assignment":na})
                    if action == "reassign":
                        if not can_manage: return self._json({"error":"insufficient role"}, 403)
                        override = bool(body.get("admin_override")) and is_admin
                        r = assignment_api.manual_assign(storage, finding, uname, body.get("primary_owner", owner), body.get("secondary_reviewer", reviewer),
                                                         body.get("reason",""), body.get("due_at",""), body.get("instructions",""), "manual",
                                                         getattr(state,'alert_router',None), admin_override=override)
                        if r.get("ok"):
                            storage.upsert_assignment(fid, uname, reason=body.get("reason","Reassigned"), action="reassigned", status="assigned")
                            state.auth.audit("assignment.reassign", uname, f"{fid}:{owner}->{body.get('primary_owner',owner)} reason={str(body.get('reason',''))[:200]}")
                        return self._json(r, 200 if r.get("ok") else 400)
                    return self._json({"error":"unsupported action"}, 400)


        if path == "/api/coordination/ping":
            message = str(body.get("message", "")).strip()[:240] or "Please refresh your command center."
            ping_id = storage.add_ping(uname, message)
            state.auth.audit("coordination.ping", uname, message)
            return self._json({"ok": True, "id": ping_id})
        # ── Hubs API ──────────────────────────────────────────────
        result = HubsAPI(state).handle_post(path, body, self._user())
        if result is not None:
            payload, code = result
            return self._json(payload, code)
        # ── Risk Acceptances POST ────────────────────────────────
        if path == "/api/risk-acceptances":
            import secrets as _sec
            ra_id = "ra-" + _sec.token_hex(5)
            storage.add_risk_acceptance(
                ra_id,
                str(body.get("name", "")).strip()[:200] or ra_id,
                str(body.get("owner", uname)).strip()[:80],
                str(body.get("decision", "accept")).strip()[:40],
                str(body.get("reason", "")).strip()[:1000],
                str(body.get("proof", "")).strip()[:500],
                body.get("expires_at"),
                bool(body.get("sla_restart", False)),
                uname,
            )
            for fid in (body.get("finding_ids") or []):
                f = storage.get_finding(str(fid))
                if f:
                    storage.add_finding_to_risk_acceptance(ra_id, f.id, uname)
            state.auth.audit("risk_acceptance.created", uname, ra_id)
            return self._json({"ok": True, "id": ra_id})
        m = re.match(r"^/api/risk-acceptances/([A-Za-z0-9_\-]+)/findings$", path)
        if m:
            ra_id = m.group(1)
            fid = str(body.get("finding_id", ""))
            action = str(body.get("action", "add"))
            f = storage.get_finding(fid)
            if not f:
                return self._json({"error": "finding not found"}, 404)
            if action == "remove":
                storage.remove_finding_from_risk_acceptance(ra_id, fid, uname)
            else:
                storage.add_finding_to_risk_acceptance(ra_id, fid, uname)
            return self._json({"ok": True})
        m = re.match(r"^/api/risk-acceptances/([A-Za-z0-9_\-]+)/expire$", path)
        if m:
            ra = storage.get_risk_acceptance(m.group(1))
            if not ra:
                return self._json({"error": "not found"}, 404)
            for fid in ra.get("finding_ids", []):
                storage.set_status(fid, "open", uname)
            state.storage._db.execute(
                "UPDATE risk_acceptances SET expired_handled=1 WHERE id=?", (m.group(1),)
            )
            state.storage._db.commit()
            return self._json({"ok": True})
        m = re.match(r"^/api/integrations/([a-z]+)/(sync|toggle|disconnect)$", path)
        if m:
            pid, action = m.groups()
            if action == "sync":
                from sentrix.core.models import Event
                storage.add_event(Event(
                    kind="integration.sync", surface=pid, payload={"by": uname}))
                storage.add_log("info", "integrations", f"Manual sync requested for {pid} by {uname}",
                                component="integrations", event_type="sync", resource=pid,
                                status="requested", exec_id="sync-" + pid)
                return self._json({"ok": True, "status": "sync-recorded"})
            state.integrations_disabled = getattr(state, "integrations_disabled", set())
            if action == "disconnect":
                state.integrations_disabled.add(pid)
            else:
                state.integrations_disabled.discard(pid)
            storage.add_audit(f"integration.{action}", uname, pid)
            return self._json({"ok": True})
        if path == "/api/reports":
            try:
                result = reports.generate(body.get("type", "executive"),
                                          body.get("format", "csv"), storage, uname)
            except ValueError as exc:
                return self._json({"error": str(exc)}, 400)
            return self._json({"ok": True, "id": result["id"], "rows": result["rows"],
                               "download": f"/api/reports/{result['id']}/download"})
        if path == "/api/exceptions":
            fid = body.get("finding_id", "")
            kind = body.get("kind", "")
            if kind not in ("accepted_risk", "suppressed"):
                return self._json({"error": "kind must be accepted_risk or suppressed"}, 400)
            finding = storage.get_finding(fid)
            if not finding:
                return self._json({"error": "not found"}, 404)
            storage.set_status(fid, kind, uname)
            storage.add_note(fid, uname, f"Exception {kind}: {body.get('reason', '')}")
            storage.add_audit("exception." + kind, uname, fid)
            return self._json({"ok": True})
        if path == "/api/detection-rules":
            import re as _re
            pattern = body.get("pattern", "")
            try:
                compiled = _re.compile(pattern)
            except _re.error as exc:
                return self._json({"error": f"invalid pattern: {exc}"}, 400)
            rid = body.get("id") or "custom-" + __import__("secrets").token_hex(4)
            storage.add_custom_rule(rid, body.get("title", rid),
                                    body.get("severity", "medium"), pattern, uname)
            from sentrix.detectors.base import Detector, register
            register(Detector(id=rid, title=body.get("title", rid),
                              severity=body.get("severity", "medium"),
                              pattern=compiled, family="custom"))
            storage.add_audit("rule.created", uname, rid)
            return self._json({"ok": True, "id": rid})
        m = re.match(r"^/api/detection-rules/([A-Za-z0-9\-]+)/delete$", path)
        if m:
            storage.delete_custom_rule(m.group(1))
            return self._json({"ok": True})
        if path == "/api/demo/reset" or (path == "/api/demo" and body.get("reset")):
            # Full reset: findings demo state + ALL assignment/workload/employee operations state back to current demo defaults
            removed = 0
            for f in storage.list_findings(limit=5000):
                if f.meta.get("demo"):
                    try: storage.set_status(f.id, "closed", "demo-reset")
                    except Exception: pass
                    removed += 1
            try:
                storage.reset_assignment_demo_state(uname)
            except Exception as e:
                storage.add_log("warn", "demo", f"Assignment state reset warning: {e}")
            # remove demo findings so reseed produces the current demo state
            try:
                with storage._lock:
                    storage._db.execute("DELETE FROM findings WHERE json_extract(meta,'$.demo')=1")
                    storage._db.execute("DELETE FROM finding_extra WHERE finding_id NOT IN (SELECT id FROM findings)")
                    storage._db.execute("DELETE FROM finding_assignments WHERE finding_id NOT IN (SELECT id FROM findings)")
                    storage._db.execute("DELETE FROM assignment_history WHERE finding_id NOT IN (SELECT id FROM findings)")
                    storage._db.commit()
            except Exception:
                try:
                    demo_ids = [f.id for f in storage.list_findings(limit=5000) if (f.meta or {}).get("demo")]
                    with storage._lock:
                        for fid in demo_ids:
                            storage._db.execute("DELETE FROM status_history WHERE finding_id=?", (fid,))
                            storage._db.execute("DELETE FROM notes WHERE finding_id=?", (fid,))
                            storage._db.execute("DELETE FROM finding_extra WHERE finding_id=?", (fid,))
                            storage._db.execute("DELETE FROM finding_assignments WHERE finding_id=?", (fid,))
                            storage._db.execute("DELETE FROM assignment_history WHERE finding_id=?", (fid,))
                            storage._db.execute("DELETE FROM findings WHERE id=?", (fid,))
                        storage._db.execute("DELETE FROM finding_extra WHERE finding_id NOT IN (SELECT id FROM findings)")
                        storage._db.execute("DELETE FROM finding_assignments WHERE finding_id NOT IN (SELECT id FROM findings)")
                        storage._db.execute("DELETE FROM assignment_history WHERE finding_id NOT IN (SELECT id FROM findings)")
                        storage._db.commit()
                except Exception:
                    pass
            from sentrix.demo import seed_demo
            seeded = seed_demo(state.pipeline)
            state.auth.audit("demo.reset_all", uname, f"closed={removed} seeded={seeded}")
            storage.add_log("info", "demo", f"Demo FULL reset by {uname}: assignments/employees/workloads reset, demo findings reseeded ({seeded})")
            return self._json({"ok": True, "closed": removed, "seeded": seeded, "reset": "full"})
        return None

    def _dashboard_data(self) -> dict:
        storage = self.state.storage
        findings = storage.list_findings(limit=5000)
        stats = storage.stats()
        severity = {s: 0 for s in SEVERITIES}
        status: dict = {}
        surfaces: dict = {}
        scatter = []
        assignees: dict = {}
        owners: dict = {}
        for idx, f in enumerate(findings):
            severity[f.severity] = severity.get(f.severity, 0) + 1
            status[f.status] = status.get(f.status, 0) + 1
            surfaces[f.surface] = surfaces.get(f.surface, 0) + 1
            owners[f.owner] = owners.get(f.owner, 0) + 1
            if idx < 300:
                extra = storage.get_extra(f.id)
                assignees[extra["assignee"]] = assignees.get(extra["assignee"], 0) + 1
                scatter.append({"entropy": f.entropy, "occurrences": extra["occurrences"],
                                "severity": f.severity, "title": f.title})
        days = []
        for i in range(13, -1, -1):
            day = time.strftime("%Y-%m-%d", time.gmtime(time.time() - i * 86400))
            days.append({"date": day,
                         "count": sum(1 for f in findings if f.created_at.startswith(day))})
        channels: dict = {}
        for alert in storage.list_alerts(limit=1000):
            channels[alert["channel"]] = channels.get(alert["channel"], 0) + 1
        team = []
        for user in storage.list_users():
            name = user["username"]
            team.append({"username": name, "title": user.get("title", ""),
                         "role": user["role"],
                         "owned": owners.get(name, 0),
                         "assigned": assignees.get(name, 0)})
        return {
            "kpis": {
                "total": stats["total"], "open": stats["open"],
                "critical_high": severity.get("critical", 0) + severity.get("high", 0),
                "alerts": stats["alerts_sent"], "remediations": stats["remediations"],
                "false_positives": status.get("false_positive", 0),
            },
            "severity": [{"label": k, "value": v} for k, v in severity.items()],
            "status": [{"label": k, "value": v} for k, v in status.items()],
            "surfaces": [{"label": k, "value": v} for k, v in
                         sorted(surfaces.items(), key=lambda kv: -kv[1])],
            "timeline": days,
            "channels": [{"label": k, "value": v} for k, v in channels.items()],
            "scatter": scatter,
            "team": team,
        }

    def _file(self, path: Path):
        if not path.is_file():
            return self._json({"error": "not found"}, 404)
        self._send(200, path.read_bytes(), CONTENT_TYPES.get(path.suffix, "application/octet-stream"))


def _help_registry():
    """Centralized, reusable contextual help registry (no generic placeholders)."""
    R = {
      "auto_assignment": {"title":"Automatic Assignment","what":"SENTRIX evaluates severity, technical domain, role/eligibility, skills, workload, availability and ownership context to select an appropriate owner.","solves":"Reduces manual triage delay and routes findings to accountable, capable owners.","how":"The assignment engine scores eligible employees, generates an explanation, and assigns primary (and reviewer for critical/high when appropriate).","who":"Runs by authorized workflow/admin action; results visible per RBAC.","action":"Review the explanation; admins can override with a reason if needed.","example":"An exposed AWS credential is routed to an eligible cloud/incident-response owner, not to a developer by default."},
      "primary_owner": {"title":"Primary Owner","what":"The person accountable for investigation and remediation coordination.","solves":"Ensures every finding has clear ownership.","how":"Receives notifications, must acknowledge, and progresses the assignment.","who":"Assigned by admin/authorized manager or auto-assignment.","action":"Acknowledge, investigate, update status, and submit for verification."},
      "secondary_reviewer": {"title":"Secondary Reviewer","what":"Provides oversight or independent verification for sensitive findings.","solves":"Adds quality control for critical/high remediation.","how":"Reviews evidence and can request additional investigation; does not inherit primary owner permissions automatically.","who":"Assigned for critical/high or by admin.","action":"Review remediation evidence and verify/feedback."},
      "workload": {"title":"Workload","what":"Severity-weighted active assignment load vs. employee capacity.","solves":"Prevents overloading individuals and highlights risk.","how":"Calculated from active assigned findings (critical findings weigh more than informational).","who":"Visible in Team Workload & Assignment per RBAC.","action":"Rebalance or adjust capacity if someone is over threshold."},
      "sla": {"title":"SLA","what":"Configurable acknowledgement and remediation deadlines by severity.","solves":"Makes response expectations explicit and measurable.","how":"Due dates are set at assignment; breaches trigger overdue/escalation indicators and notifications.","who":"Configured by administrators; visible to assignees/managers.","action":"Acknowledge and remediate before due dates; escalate blockers."},
      "acknowledgement": {"title":"Acknowledgement","what":"Confirmation that the primary owner has seen and accepted responsibility for the assignment.","solves":"Prevents silent drops.","how":"Owner acknowledges; timestamp is recorded; SLA timers tracked.","who":"Primary owner (or authorized admin action).","action":"Acknowledge promptly, especially for critical/high findings."},
      "reassignment": {"title":"Reassignment","what":"Moving ownership/review responsibility with a recorded reason.","solves":"Handles availability, expertise mismatch, or workload issues.","how":"Authorized reassignment notifies parties and preserves history.","who":"Admins and authorized managers; employees may request reassignment.","action":"Provide a clear reason; ensure new owner is eligible."},
      "severity": {"title":"Finding Severity","what":"Impact/urgency classification (critical/high/medium/low/info).","solves":"Prioritizes response.","how":"Set by detectors/risk context; can be managed per workflow/RBAC.","who":"Visible to users with finding access.","action":"Handle critical/high first; follow SLA and ownership rules."},
      "risk_score": {"title":"Risk Score","what":"Explainable 0–100 prioritization based on context and evidence.","solves":"Ranks findings beyond raw severity alone.","how":"Combines factors such as severity, exposure, validation and context (see finding details).","who":"Visible in finding views.","action":"Use with severity/ownership to prioritize remediation."},
      "integration_state": {"title":"Integration State","what":"Honest connection/sync status for a provider (connected/demo/disconnected/error).","solves":"Prevents assuming live data where not configured.","how":"Derived from configuration and sync/health checks.","who":"Admins/managers; visible in Integrations.","action":"Configure credentials and verify sync for production use."},
      "escalation": {"title":"Escalation","what":"Notifying administrators/owners when acknowledgement or remediation SLAs are missed or risk is high.","solves":"Ensures stalled critical work gets attention.","how":"SLA checks and assignment events generate escalations/notifications and audit records.","who":"Admins receive escalations; assignees get due reminders.","action":"Acknowledge, remediate, or request reassignment with a blocker reason."},
      "override": {"title":"Admin Override","what":"Administrator manually changes an automatic/recommended assignment decision.","solves":"Allows expert judgment when context requires it.","how":"Override requires a mandatory reason and is audited.","who":"Administrators (per RBAC).","action":"Document why the override is necessary."},
      "read_only": {"title":"Read-Only Access","what":"Your role can view data but cannot perform write/remediation/assignment mutations.","solves":"Protects integrity and enforces least privilege.","how":"RBAC is enforced on the backend; restricted actions return 403.","who":"Viewer/auditor/read-limited contexts as configured.","action":"Contact an administrator if you need write access."},
      "finding_lifecycle": {"title":"Finding Lifecycle","what":"The status progression of a detected finding (separate from assignment workflow).","solves":"Tracks detection-to-closure state consistently.","how":"Findings move through states like open/triaged/in progress/remediated/closed per existing SENTRIX workflows.","who":"Authorized users per RBAC.","action":"Update finding status as work progresses; use assignment status for ownership accountability."},
      "assignment_lifecycle": {"title":"Assignment Lifecycle","what":"Ownership workflow states tracked separately from finding lifecycle.","solves":"Makes accountability explicit without breaking finding states.","how":"States include unassigned, recommended, assigned, acknowledged, in progress, blocked, reassignment requested, reassigned, completed, verified.","who":"Assignees, reviewers, admins per RBAC.","action":"Acknowledge, progress, request reassignment with reason, and complete/verify."},
      "bulk_operations": {"title":"Bulk Operations","what":"Assign, reassign, or set due dates for multiple findings at once.","solves":"Speeds up triage for queues.","how":"Authorized users select findings and apply an action with confirmation; each finding gets an individual audit/history record.","who":"Admins and authorized managers.","action":"Review selection carefully and provide reasons where required."},
    }
    return R


def make_server(cfg: dict) -> ThreadingHTTPServer:
    state = AppState(cfg)
    handler = type("BoundHandler", (Handler,), {"state": state})
    server = ThreadingHTTPServer(
        (cfg_get(cfg, "server.host", "127.0.0.1"), cfg_get(cfg, "server.port", 8710)), handler)
    server.state = state
    return server


def serve_forever(cfg: dict):
    try:
        server = make_server(cfg)
    except OSError:
        host = cfg_get(cfg, "server.host", "127.0.0.1")
        port = cfg_get(cfg, "server.port", 8710)
        print(f"Cannot start: {host}:{port} is already held by another process.")
        print("An older console window (e.g. the previous KeySentry folder) is usually")
        print("the cause. Close that window and run this launcher again, or change")
        print("[server] port in config.toml.")
        raise SystemExit(1)
    host, port = server.server_address
    print(f"SENTRIX dashboard: http://{host}:{port}")
    print("First run: initial admin password is in data/INITIAL_ADMIN_PASSWORD.txt")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.state.scheduler_stop.set()
        server.server_close()
        server.state.storage.close()
