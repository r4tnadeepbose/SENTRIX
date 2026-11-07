"""Stdlib-only HTTP server: JSON API plus the static dashboard."""
from __future__ import annotations

import json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from keysentry import __version__
from keysentry.ai.triage import triage_finding
from keysentry.config import ROOT, cfg_get, resolve_path
from keysentry.core.engine import scan_text, scan_tree
from keysentry.core.models import STATUSES
from keysentry.core.pipeline import Pipeline
from keysentry.core.storage import Storage
from keysentry.alerting.router import AlertRouter
from keysentry.demo import seed_demo
from keysentry.remediation import playbooks

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json",
}
STATIC_FILES = {"index.html", "app.js", "styles.css"}
FINDING_ID = re.compile(r"^/api/findings/([A-Za-z0-9\-]+)$")
FINDING_STATUS = re.compile(r"^/api/findings/([A-Za-z0-9\-]+)/status$")


class AppState:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.storage = Storage(resolve_path(cfg, cfg_get(cfg, "storage.path", "data/keysentry.db")))
        self.router = AlertRouter(cfg, self.storage)
        self.pipeline = Pipeline(cfg, self.storage, self.router)
        self.started = time.time()


class Handler(BaseHTTPRequestHandler):
    state: AppState = None  # set by make_server

    def log_message(self, fmt, *args):
        pass

    def _send(self, code: int, body: bytes, content_type: str):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: dict, code: int = 200):
        self._send(code, json.dumps(payload).encode(), "application/json")

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode())
        except json.JSONDecodeError:
            return {}

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        state = self.state
        if path == "/":
            return self._file(ROOT / "keysentry" / "dashboard" / "index.html")
        if path.startswith("/static/"):
            name = path[len("/static/"):]
            if name not in STATIC_FILES:
                return self._json({"error": "not found"}, 404)
            return self._file(ROOT / "keysentry" / "dashboard" / name)
        if path == "/logo.svg":
            return self._file(ROOT / "assets" / "logo.svg")
        if path == "/api/health":
            return self._json({
                "status": "ok", "product": "KeySentry", "version": __version__,
                "uptime_seconds": int(time.time() - state.started),
                "python": __import__("platform").python_version(),
            })
        if path == "/api/stats":
            return self._json(state.storage.stats())
        if path == "/api/findings":
            findings = state.storage.list_findings(
                status=query.get("status"), severity=query.get("severity"),
                surface=query.get("surface"), q=query.get("q"),
                limit=int(query.get("limit", 500)))
            return self._json({"findings": [f.to_dict() for f in findings]})
        match = FINDING_ID.match(path)
        if match:
            finding = state.storage.get_finding(match.group(1))
            if not finding:
                return self._json({"error": "not found"}, 404)
            return self._json({
                "finding": finding.to_dict(),
                "remediations": state.storage.list_remediations(finding.id),
                "triage": finding.meta.get("triage"),
            })
        if path == "/api/events":
            return self._json({"events": state.storage.list_events(int(query.get("limit", 50)))})
        if path == "/api/alerts":
            return self._json({"alerts": state.storage.list_alerts(int(query.get("limit", 50)))})
        if path == "/api/allowlist":
            return self._json({"entries": state.storage.allowlist_entries()})
        if path == "/api/config":
            return self._json(state.cfg)
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._body()
        state = self.state
        if path == "/api/scan":
            if "text" not in body and "path" not in body:
                return self._json({"error": "body must include text or path"}, 400)
            if "text" in body:
                findings = scan_text(
                    body.get("text", ""), body.get("path", "playground.txt"),
                    body.get("surface", "filesystem"), state.pipeline.allowlist)
                return self._json({"findings": [f.to_dict() for f in findings], "scanned_files": 1})
            target = Path(body.get("path", "."))
            if not target.is_absolute():
                target = ROOT / target
            if not target.exists():
                return self._json({"error": f"path does not exist: {target}"}, 400)
            findings, count = scan_tree(target, "filesystem", state.cfg, state.pipeline.allowlist)
            state.pipeline.ingest(findings, kind="scan.path")
            return self._json({"findings": [f.to_dict() for f in findings], "scanned_files": count})
        if path == "/api/demo":
            return self._json({"ok": True, "seeded": seed_demo(state.pipeline)})
        if path == "/api/allowlist":
            fp = body.get("fingerprint", "")
            if not fp:
                return self._json({"error": "fingerprint required"}, 400)
            state.storage.allowlist_add(fp, body.get("reason", ""))
            state.pipeline.refresh_allowlist()
            for finding in state.storage.list_findings(limit=1000):
                if finding.fingerprint == fp:
                    state.storage.set_status(finding.id, "false_positive")
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
            try:
                detail = playbooks.execute(body.get("action", ""), finding, state.cfg, state.storage)
            except ValueError as exc:
                return self._json({"error": str(exc)}, 400)
            return self._json({"ok": True, "detail": detail})
        match = FINDING_STATUS.match(path)
        if match:
            status = body.get("status", "")
            if status not in STATUSES:
                return self._json({"error": f"status must be one of {STATUSES}"}, 400)
            finding = state.storage.set_status(match.group(1), status)
            if not finding:
                return self._json({"error": "not found"}, 404)
            return self._json({"ok": True, "finding": finding.to_dict()})
        return self._json({"error": "not found"}, 404)

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
    print(f"KeySentry dashboard: http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.server_close()
        server.state.storage.close()