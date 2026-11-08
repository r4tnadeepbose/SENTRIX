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

from wintermute import __version__
from wintermute.ai.triage import triage_finding
from wintermute.auth import AuthError, AuthManager, hash_password
from wintermute.config import ROOT, cfg_get, resolve_path
from wintermute.core import engine
from wintermute.core.extensions import ExtStorage
from wintermute.core.jobs import JobRunner, start_scheduler
from wintermute.core.models import STATUSES, SEVERITIES
from wintermute.core.pipeline import Pipeline
from wintermute.core.util import at_least
from wintermute.alerting.router import AlertRouter
from wintermute.demo import seed_demo
from wintermute.remediation import playbooks

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json",
}
STATIC_FILES = {"index.html", "app.js", "styles.css", "login.html"}
FINDING_ID = re.compile(r"^/api/findings/([A-Za-z0-9\-]+)$")
FINDING_SUB = re.compile(r"^/api/findings/([A-Za-z0-9\-]+)/(status|notes|tags|assign|severity|pin|mute|related|checklist|history)$")
ID_SUB = re.compile(r"^/api/(jobs|schedules|rules|tokens|users|filters)/([A-Za-z0-9_\-]+)/([A-Za-z0-9_\-]+)$")
PUBLIC_GET = {"/", "/login", "/favicon.svg", "/logo.svg", "/api/health", "/api/auth/demo-info"}
ADMIN_PREFIXES = ("/api/users", "/api/tokens", "/api/ops/restore", "/api/ops/import", "/api/ops/purge")


class AppState:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        engine.configure(cfg)
        self.storage = ExtStorage(resolve_path(cfg, cfg_get(cfg, "storage.path", "data/wintermute.db")))
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
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload, code=200):
        self._send(code, json.dumps(payload).encode(), "application/json")

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode())
        except json.JSONDecodeError:
            return {}

    def _user(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        if "wm_session" in cookie:
            user = self.state.auth.session_user(cookie["wm_session"].value)
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
        if method in ("POST", "DELETE") and user["role"] == "viewer" \
                and path not in ("/api/auth/logout", "/api/auth/password"):
            self._json({"error": "viewer role is read-only"}, 403)
            return False
        if any(path.startswith(p) for p in ADMIN_PREFIXES) and user["role"] != "admin":
            self._json({"error": "admin role required"}, 403)
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
            if not self._user():
                self.send_response(302)
                self.send_header("Location", "/login")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            return self._file(ROOT / "wintermute" / "dashboard" / "index.html")
        if path == "/login":
            return self._file(ROOT / "wintermute" / "dashboard" / "login.html")
        if path.startswith("/static/"):
            name = path[len("/static/"):]
            if name not in STATIC_FILES:
                return self._json({"error": "not found"}, 404)
            return self._file(ROOT / "wintermute" / "dashboard" / name)
        if path == "/favicon.svg":
            return self._file(ROOT / "assets" / "favicon.svg")
        if path == "/logo.svg":
            return self._file(ROOT / "assets" / "logo.svg")
        if path == "/api/health":
            return self._json({
                "status": "ok", "product": "Wintermute", "version": __version__,
                "uptime_seconds": int(time.time() - state.started),
                "python": __import__("platform").python_version(),
            })
        if path == "/api/auth/me":
            user = self._user()
            return self._json({"user": user}) if user else self._json({"error": "unauthenticated"}, 401)
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
            return self._json(self._dashboard())
        if path == "/api/overview":
            stats = state.storage.stats()
            return self._json({
                "stages": {
                    "events": stats["events_processed"],
                    "scans": len(state.storage.list_jobs()),
                    "findings": stats["total"],
                    "alerts": stats["alerts_sent"],
                    "remediations": stats["remediations"],
                },
                "detectors": len(engine.all_detectors()),
                "surfaces": ["ide", "pre_push", "ci", "git", "cloud",
                             "slack", "confluence", "jira", "postman", "filesystem"],
                "how": [
                    "1. Events arrive from a surface: editor save, git hook, CI diff, schedule, SaaS export or API poll.",
                    "2. The shared engine applies the detector registry, entropy scoring and the allowlist to the changed content.",
                    "3. New findings are masked, fingerprinted and stored; duplicates only bump occurrence counters.",
                    "4. The alert router evaluates channel rules, quiet hours and dedupe windows, then delivers or defers.",
                    "5. Remediation playbooks rotate, redact, quarantine or ticket; verification rescans close the loop.",
                    "Every stage writes a system log entry, visible live in the Logs view.",
                ],
            })
        if path == "/api/findings":
            findings = state.storage.list_findings(
                status=query.get("status"), severity=query.get("severity"),
                surface=query.get("surface"), q=query.get("q"),
                limit=int(query.get("limit", 500)))
            sort = query.get("sort", "created")
            if sort == "severity":
                findings.sort(key=lambda f: SEVERITIES.index(f.severity))
            elif sort == "occurrences":
                findings.sort(key=lambda f: state.storage.get_extra(f.id)["occurrences"], reverse=True)
            elif sort == "pinned":
                findings.sort(key=lambda f: state.storage.get_extra(f.id)["pinned"], reverse=True)
            page = int(query.get("page", 1))
            page_size = int(query.get("page_size", 50))
            total = len(findings)
            chunk = findings[(page - 1) * page_size:page * page_size]
            out = []
            for f in chunk:
                data = f.to_dict()
                extra = state.storage.get_extra(f.id)
                data.update({k: extra[k] for k in
                             ("assignee", "tags", "pinned", "muted", "occurrences", "severity_override")})
                out.append(data)
            return self._json({"findings": out, "total": total, "page": page, "page_size": page_size})
        match = FINDING_ID.match(path)
        if match:
            finding = state.storage.get_finding(match.group(1))
            if not finding:
                return self._json({"error": "not found"}, 404)
            return self._json({
                "finding": finding.to_dict(),
                "extra": state.storage.get_extra(finding.id),
                "notes": state.storage.list_notes(finding.id),
                "history": state.storage.list_history(finding.id),
                "checklist": state.storage.get_checklist(finding.id),
                "remediations": state.storage.list_remediations(finding.id),
                "triage": finding.meta.get("triage"),
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
                int(query.get("limit", 200)), query.get("level"))})
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
            return self._json({"users": state.storage.list_users()})
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
                f"wintermute_findings_total {stats['total']}",
                f"wintermute_findings_open {stats['open']}",
                f"wintermute_alerts_sent_total {stats['alerts_sent']}",
                f"wintermute_events_processed_total {stats['events_processed']}",
                f"wintermute_remediations_total {stats['remediations']}",
                f"wintermute_uptime_seconds {int(time.time() - state.started)}",
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
                self.client_address[0])
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie",
                             f"wm_session={token}; HttpOnly; Path=/; SameSite=Strict; "
                             f"Max-Age={int(state.auth.session_hours * 3600)}")
            payload = json.dumps({"ok": True, "user": user}).encode()
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if path == "/api/auth/logout":
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            if "wm_session" in cookie:
                state.auth.logout(cookie["wm_session"].value)
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
                state.storage.update_extra(fid, assignee=body.get("assignee", ""))
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
            dest = resolve_path(state.cfg, f"data/backups/wintermute-{int(time.time())}.db")
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
        return self._json({"error": "not found"}, 404)

    def _dashboard(self) -> dict:
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


def make_server(cfg: dict) -> ThreadingHTTPServer:
    state = AppState(cfg)
    handler = type("BoundHandler", (Handler,), {"state": state})
    server = ThreadingHTTPServer(
        (cfg_get(cfg, "server.host", "127.0.0.1"), cfg_get(cfg, "server.port", 8710)), handler)
    server.state = state
    return server


def serve_forever(cfg: dict):
    server = make_server(cfg)
    host, port = server.server_address
    print(f"Wintermute dashboard: http://{host}:{port}")
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