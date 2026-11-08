"""ASM persistence: schema plus storage mixin used by ExtStorage."""
from __future__ import annotations

import json
import sqlite3

from sentrix.core.models import now_iso

ASM_SCHEMA = """
CREATE TABLE IF NOT EXISTS asm_targets (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT DEFAULT 'domain',
  status TEXT DEFAULT 'pending', score REAL DEFAULT 0, last_run TEXT,
  created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS asm_groups (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, interval_seconds INTEGER DEFAULT 86400,
  enabled INTEGER DEFAULT 1, status TEXT DEFAULT 'idle', last_run TEXT, next_run TEXT,
  created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS asm_group_hosts (
  group_id TEXT, host TEXT, PRIMARY KEY (group_id, host));
CREATE TABLE IF NOT EXISTS asm_group_tools (
  group_id TEXT, tool_id TEXT, PRIMARY KEY (group_id, tool_id));
CREATE TABLE IF NOT EXISTS asm_services (
  id TEXT PRIMARY KEY, target_id TEXT, host TEXT, port INTEGER, protocol TEXT DEFAULT 'https',
  status_code INTEGER, redirect_to INTEGER, title TEXT, ips TEXT DEFAULT '[]',
  technologies TEXT DEFAULT '[]', cert_id TEXT, screenshot INTEGER DEFAULT 0,
  country TEXT DEFAULT '', last_seen TEXT);
CREATE TABLE IF NOT EXISTS asm_technologies (
  id TEXT PRIMARY KEY, name TEXT, category TEXT, description TEXT);
CREATE TABLE IF NOT EXISTS asm_certs (
  id TEXT PRIMARY KEY, host TEXT, issuer TEXT, common_name TEXT, alt_names TEXT DEFAULT '[]',
  not_before TEXT, not_after TEXT, status TEXT DEFAULT 'valid');
CREATE TABLE IF NOT EXISTS asm_vulns (
  id TEXT PRIMARY KEY, target_id TEXT, service_id TEXT, name TEXT, severity TEXT,
  cvss REAL DEFAULT 0, vector TEXT DEFAULT '', cves TEXT DEFAULT '[]', tags TEXT DEFAULT '[]',
  description TEXT, refs TEXT DEFAULT '[]', affected_url TEXT, ip TEXT, ports TEXT DEFAULT '[]',
  status TEXT DEFAULT 'open', first_seen TEXT, last_seen TEXT, scanned_by TEXT,
  analysis TEXT DEFAULT '', weaknesses TEXT DEFAULT '[]');
CREATE TABLE IF NOT EXISTS asm_workflows (
  id TEXT PRIMARY KEY, group_id TEXT, name TEXT, status TEXT DEFAULT 'running',
  trigger TEXT DEFAULT 'manual', steps TEXT DEFAULT '[]', started TEXT, finished TEXT);
CREATE TABLE IF NOT EXISTS asm_jobs (
  id TEXT PRIMARY KEY, workflow_id TEXT, target TEXT, tool_id TEXT, status TEXT DEFAULT 'done',
  started TEXT, finished TEXT, duration_s INTEGER DEFAULT 0, results INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS asm_workers (
  id TEXT PRIMARY KEY, name TEXT, mode TEXT DEFAULT 'agent', status TEXT DEFAULT 'online',
  cpu REAL DEFAULT 0, mem_used REAL DEFAULT 0, mem_total REAL DEFAULT 0,
  jobs_active INTEGER DEFAULT 0, jobs_max INTEGER DEFAULT 12, uptime_s INTEGER DEFAULT 0,
  containers TEXT DEFAULT '[]');
CREATE TABLE IF NOT EXISTS asm_chats (
  id TEXT PRIMARY KEY, title TEXT, model TEXT DEFAULT 'sentrix-triage', created_at TEXT,
  messages TEXT DEFAULT '[]');
CREATE TABLE IF NOT EXISTS asm_installed (
  tool_id TEXT PRIMARY KEY, installed_at TEXT);
"""


def _j(value):
    return json.dumps(value if value is not None else [])


def _un(row, keys):
    out = dict(row)
    for k in keys:
        out[k] = json.loads(out.get(k) or "[]")
    return out


class AsmMixin:
    """Mixed into ExtStorage; assumes self._db and self._lock exist."""

    def init_asm(self):
        self._db.executescript(ASM_SCHEMA)
        self._db.commit()

    # -- targets
    def asm_targets(self):
        return [dict(r) for r in self._db.execute(
            "SELECT * FROM asm_targets ORDER BY created_at DESC")]

    def asm_target(self, tid):
        row = self._db.execute("SELECT * FROM asm_targets WHERE id=?", (tid,)).fetchone()
        return dict(row) if row else None

    def asm_add_target(self, tid, name, kind="domain"):
        with self._lock:
            self._db.execute("INSERT INTO asm_targets VALUES (?,?,?,?,?,?,?,?)",
                             (tid, name, kind, "pending", 0, None, now_iso(), now_iso()))
            self._db.commit()

    def asm_set_target(self, tid, **fields):
        allowed = {"status", "score", "last_run", "name", "kind"}
        sets, params = [], []
        for k, v in fields.items():
            if k in allowed:
                sets.append(f"{k}=?")
                params.append(v)
        if not sets:
            return
        sets.append("updated_at=?")
        params.append(now_iso())
        with self._lock:
            self._db.execute(f"UPDATE asm_targets SET {', '.join(sets)} WHERE id=?",
                             (*params, tid))
            self._db.commit()

    def asm_delete_target(self, tid):
        with self._lock:
            for table in ("asm_services", "asm_vulns"):
                self._db.execute(f"DELETE FROM {table} WHERE target_id=?", (tid,))
            self._db.execute("DELETE FROM asm_targets WHERE id=?", (tid,))
            self._db.commit()

    # -- groups
    def asm_groups(self):
        out = []
        for r in self._db.execute("SELECT * FROM asm_groups ORDER BY created_at DESC"):
            g = dict(r)
            g["hosts"] = [x["host"] for x in self._db.execute(
                "SELECT host FROM asm_group_hosts WHERE group_id=? ORDER BY host", (g["id"],))]
            g["tools"] = [x["tool_id"] for x in self._db.execute(
                "SELECT tool_id FROM asm_group_tools WHERE group_id=?", (g["id"],))]
            out.append(g)
        return out

    def asm_group(self, gid):
        return next((g for g in self.asm_groups() if g["id"] == gid), None)

    def asm_add_group(self, gid, name, interval=86400):
        with self._lock:
            self._db.execute("INSERT INTO asm_groups VALUES (?,?,?,?,?,?,?,?,?)",
                             (gid, name, interval, 1, "idle", None, None,
                              now_iso(), now_iso()))
            self._db.commit()

    def asm_update_group(self, gid, **fields):
        allowed = {"name", "interval_seconds", "enabled", "status", "last_run", "next_run"}
        sets, params = [], []
        for k, v in fields.items():
            if k in allowed:
                sets.append(f"{k}=?")
                params.append(v)
        if not sets:
            return
        sets.append("updated_at=?")
        params.append(now_iso())
        with self._lock:
            self._db.execute(f"UPDATE asm_groups SET {', '.join(sets)} WHERE id=?",
                             (*params, gid))
            self._db.commit()

    def asm_delete_group(self, gid):
        with self._lock:
            self._db.execute("DELETE FROM asm_group_hosts WHERE group_id=?", (gid,))
            self._db.execute("DELETE FROM asm_group_tools WHERE group_id=?", (gid,))
            self._db.execute("DELETE FROM asm_groups WHERE id=?", (gid,))
            self._db.commit()

    def asm_group_hosts_set(self, gid, hosts):
        with self._lock:
            self._db.execute("DELETE FROM asm_group_hosts WHERE group_id=?", (gid,))
            self._db.executemany("INSERT OR IGNORE INTO asm_group_hosts VALUES (?,?)",
                                 [(gid, h) for h in hosts])
            self._db.commit()

    def asm_group_tools_set(self, gid, tools):
        with self._lock:
            self._db.execute("DELETE FROM asm_group_tools WHERE group_id=?", (gid,))
            self._db.executemany("INSERT OR IGNORE INTO asm_group_tools VALUES (?,?)",
                                 [(gid, t) for t in tools])
            self._db.commit()

    # -- services / technologies / certs
    def asm_services(self, target_id=None):
        if target_id:
            rows = self._db.execute(
                "SELECT * FROM asm_services WHERE target_id=? ORDER BY host, port", (target_id,))
        else:
            rows = self._db.execute("SELECT * FROM asm_services ORDER BY host, port")
        return [_un(r, ("ips", "technologies")) for r in rows]

    def asm_service(self, sid):
        row = self._db.execute("SELECT * FROM asm_services WHERE id=?", (sid,)).fetchone()
        return _un(row, ("ips", "technologies")) if row else None

    def asm_add_service(self, svc: dict):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO asm_services VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (svc["id"], svc.get("target_id"), svc["host"], svc["port"],
                 svc.get("protocol", "https"), svc.get("status_code"), svc.get("redirect_to"),
                 svc.get("title", ""), _j(svc.get("ips")), _j(svc.get("technologies")),
                 svc.get("cert_id"), 1 if svc.get("screenshot") else 0,
                 svc.get("country", ""), svc.get("last_seen") or now_iso()))
            self._db.commit()

    def asm_technologies(self):
        counts = {}
        for s in self.asm_services():
            for t in s["technologies"]:
                counts[t] = counts.get(t, 0) + 1
        out = []
        for r in self._db.execute("SELECT * FROM asm_technologies ORDER BY name"):
            t = dict(r)
            t["services"] = counts.get(t["id"], 0)
            out.append(t)
        return out

    def asm_add_technology(self, tid, name, category, description):
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO asm_technologies VALUES (?,?,?,?)",
                             (tid, name, category, description))
            self._db.commit()

    def asm_certs(self):
        return [_un(r, ("alt_names",)) for r in self._db.execute(
            "SELECT * FROM asm_certs ORDER BY not_after")]

    def asm_add_cert(self, cert: dict):
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO asm_certs VALUES (?,?,?,?,?,?,?,?)",
                             (cert["id"], cert["host"], cert["issuer"], cert["common_name"],
                              _j(cert.get("alt_names")), cert["not_before"], cert["not_after"],
                              cert.get("status", "valid")))
            self._db.commit()

    # -- vulnerabilities
    def asm_vulns(self, severity=None, status=None, q=None, target_id=None):
        clauses, params = [], []
        for col, val in (("severity", severity), ("status", status), ("target_id", target_id)):
            if val:
                clauses.append(f"{col}=?")
                params.append(val)
        if q:
            clauses.append("(name LIKE ? OR affected_url LIKE ?)")
            params += [f"%{q}%", f"%{q}%"]
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._db.execute(
            f"SELECT * FROM asm_vulns{where} ORDER BY cvss DESC, last_seen DESC", params)
        return [_un(r, ("cves", "tags", "refs", "ports", "weaknesses")) for r in rows]

    def asm_vuln(self, vid):
        row = self._db.execute("SELECT * FROM asm_vulns WHERE id=?", (vid,)).fetchone()
        return _un(row, ("cves", "tags", "refs", "ports", "weaknesses")) if row else None

    def asm_add_vuln(self, v: dict):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO asm_vulns VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (v["id"], v.get("target_id"), v.get("service_id"), v["name"], v["severity"],
                 v.get("cvss", 0), v.get("vector", ""), _j(v.get("cves")), _j(v.get("tags")),
                 v.get("description", ""), _j(v.get("refs")), v.get("affected_url", ""),
                 v.get("ip", ""), _j(v.get("ports")), v.get("status", "open"),
                 v.get("first_seen") or now_iso(), v.get("last_seen") or now_iso(),
                 v.get("scanned_by", "nuclei"), v.get("analysis", ""),
                 _j(v.get("weaknesses"))))
            self._db.commit()

    def asm_set_vuln(self, vid, **fields):
        allowed = {"status", "analysis"}
        sets, params = [], []
        for k, val in fields.items():
            if k in allowed:
                sets.append(f"{k}=?")
                params.append(val)
        if not sets:
            return
        with self._lock:
            self._db.execute(f"UPDATE asm_vulns SET {', '.join(sets)} WHERE id=?",
                             (*params, vid))
            self._db.commit()

    # -- workflows / jobs
    def asm_add_workflow(self, wf: dict):
        with self._lock:
            self._db.execute("INSERT INTO asm_workflows VALUES (?,?,?,?,?,?,?,?)",
                             (wf["id"], wf.get("group_id"), wf["name"], wf.get("status", "running"),
                              wf.get("trigger", "manual"), _j(wf.get("steps")),
                              wf.get("started") or now_iso(), wf.get("finished")))
            self._db.commit()

    def asm_set_workflow(self, wid, **fields):
        allowed = {"status", "finished", "steps"}
        sets, params = [], []
        for k, v in fields.items():
            if k in allowed:
                sets.append(f"{k}=?")
                params.append(_j(v) if k == "steps" else v)
        if not sets:
            return
        with self._lock:
            self._db.execute(f"UPDATE asm_workflows SET {', '.join(sets)} WHERE id=?",
                             (*params, wid))
            self._db.commit()

    def asm_workflows(self, limit=50):
        return [_un(r, ("steps",)) for r in self._db.execute(
            "SELECT * FROM asm_workflows ORDER BY started DESC LIMIT ?", (limit,))]

    def asm_workflow(self, wid):
        row = self._db.execute("SELECT * FROM asm_workflows WHERE id=?", (wid,)).fetchone()
        if not row:
            return None
        wf = _un(row, ("steps",))
        wf["jobs"] = [dict(r) for r in self._db.execute(
            "SELECT * FROM asm_jobs WHERE workflow_id=? ORDER BY started", (wid,))]
        return wf

    def asm_add_job(self, job: dict):
        with self._lock:
            self._db.execute("INSERT INTO asm_jobs VALUES (?,?,?,?,?,?,?,?,?)",
                             (job["id"], job["workflow_id"], job["target"], job["tool_id"],
                              job.get("status", "done"), job.get("started") or now_iso(),
                              job.get("finished") or now_iso(), job.get("duration_s", 0),
                              job.get("results", 0)))
            self._db.commit()

    # -- workers
    def asm_workers(self):
        return [_un(r, ("containers",)) for r in self._db.execute(
            "SELECT * FROM asm_workers ORDER BY name")]

    def asm_upsert_worker(self, w: dict):
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO asm_workers VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                             (w["id"], w["name"], w.get("mode", "agent"), w.get("status", "online"),
                              w.get("cpu", 0), w.get("mem_used", 0), w.get("mem_total", 0),
                              w.get("jobs_active", 0), w.get("jobs_max", 12),
                              w.get("uptime_s", 0), _j(w.get("containers"))))
            self._db.commit()

    # -- chats
    def asm_chats(self):
        return [_un(r, ("messages",)) for r in self._db.execute(
            "SELECT * FROM asm_chats ORDER BY created_at DESC")]

    def asm_chat(self, cid):
        row = self._db.execute("SELECT * FROM asm_chats WHERE id=?", (cid,)).fetchone()
        return _un(row, ("messages",)) if row else None

    def asm_add_chat(self, cid, title, model="sentrix-triage"):
        with self._lock:
            self._db.execute("INSERT INTO asm_chats VALUES (?,?,?,?,?)",
                             (cid, title, model, now_iso(), _j([])))
            self._db.commit()

    def asm_chat_append(self, cid, message: dict):
        with self._lock:
            chat = self.asm_chat(cid)
            if not chat:
                return
            msgs = chat["messages"] + [message]
            self._db.execute("UPDATE asm_chats SET messages=? WHERE id=?", (_j(msgs), cid))
            self._db.commit()

    # -- installed tools
    def asm_installed(self):
        return [r["tool_id"] for r in self._db.execute("SELECT tool_id FROM asm_installed")]

    def asm_set_installed(self, tool_id, installed: bool):
        with self._lock:
            if installed:
                self._db.execute("INSERT OR IGNORE INTO asm_installed VALUES (?,?)",
                                 (tool_id, now_iso()))
            else:
                self._db.execute("DELETE FROM asm_installed WHERE tool_id=?", (tool_id,))
            self._db.commit()