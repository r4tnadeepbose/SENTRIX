"""Extended storage: users, sessions, management, jobs, rules, ops."""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from sentrix.core.models import Finding, now_iso
from sentrix.core.storage import Storage

EXT_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY, pw_hash TEXT, salt TEXT, role TEXT,
    disabled INTEGER DEFAULT 0, created_at TEXT, title TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY, username TEXT, role TEXT, expires_at REAL
);
CREATE TABLE IF NOT EXISTS tokens (
    id TEXT PRIMARY KEY, name TEXT, token_hash TEXT, role TEXT,
    created_by TEXT, created_at TEXT, revoked INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, username TEXT, action TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS coordination_pings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, message TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS system_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, level TEXT, source TEXT, message TEXT
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT, username TEXT, body TEXT, ts TEXT
);
CREATE TABLE IF NOT EXISTS finding_extra (
    finding_id TEXT PRIMARY KEY, assignee TEXT DEFAULT '', tags TEXT DEFAULT '[]',
    severity_override TEXT DEFAULT '', pinned INTEGER DEFAULT 0, muted INTEGER DEFAULT 0,
    occurrences INTEGER DEFAULT 1, first_seen TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS status_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT, old TEXT, new TEXT, username TEXT, ts TEXT
);
CREATE TABLE IF NOT EXISTS saved_filters (
    id TEXT PRIMARY KEY, username TEXT, name TEXT, params TEXT, ts TEXT
);
CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY, path TEXT, surface TEXT, interval_seconds INTEGER,
    enabled INTEGER DEFAULT 1, last_run REAL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY, path TEXT, surface TEXT, status TEXT, triggered_by TEXT,
    started TEXT, finished TEXT, files INTEGER DEFAULT 0, findings INTEGER DEFAULT 0, error TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS scan_cache (
    path TEXT PRIMARY KEY, mtime REAL, size INTEGER, findings TEXT, scanned_at TEXT
);
CREATE TABLE IF NOT EXISTS alert_rules (
    id TEXT PRIMARY KEY, channel TEXT, min_severity TEXT, enabled INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS alert_acks (
    alert_id TEXT PRIMARY KEY, username TEXT, ts TEXT
);
CREATE TABLE IF NOT EXISTS checklists (
    id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT, step_idx INTEGER,
    done INTEGER DEFAULT 0, username TEXT, ts TEXT,
    UNIQUE(finding_id, step_idx)
);
CREATE TABLE IF NOT EXISTS migrations (
    version INTEGER PRIMARY KEY, applied_at TEXT
);
CREATE TABLE IF NOT EXISTS report_history (
    id TEXT PRIMARY KEY, type TEXT, format TEXT, created_by TEXT,
    rows INTEGER, created_at TEXT, body TEXT
);
CREATE TABLE IF NOT EXISTS custom_rules (
    id TEXT PRIMARY KEY, title TEXT, severity TEXT, pattern TEXT,
    created_by TEXT, created_at TEXT, enabled INTEGER DEFAULT 1
);
"""


class ExtStorage(Storage):
    def __init__(self, path: Path):
        if not path.exists():
            for legacy in ("wintermute.db", "keysentry.db"):
                old = path.parent / legacy
                if old.exists():
                    old.replace(path)
                    break
        super().__init__(path)
        self._db.executescript(EXT_SCHEMA)
        for ddl in (
            "ALTER TABLE users ADD COLUMN title TEXT DEFAULT ''",
            "ALTER TABLE system_log ADD COLUMN component TEXT DEFAULT ''",
            "ALTER TABLE system_log ADD COLUMN event_type TEXT DEFAULT ''",
            "ALTER TABLE system_log ADD COLUMN exec_id TEXT DEFAULT ''",
            "ALTER TABLE system_log ADD COLUMN resource TEXT DEFAULT ''",
            "ALTER TABLE system_log ADD COLUMN status TEXT DEFAULT ''",
            "ALTER TABLE system_log ADD COLUMN correlation_id TEXT DEFAULT ''",
        ):
            try:
                self._db.execute(ddl)
            except sqlite3.OperationalError:
                pass
        self._db.execute("UPDATE users SET role='super_admin' WHERE role='admin'")
        self._db.execute("UPDATE users SET role='security_analyst' WHERE role='analyst'")
        self._db.execute("INSERT OR IGNORE INTO migrations VALUES (2, ?)", (now_iso(),))
        self._db.execute("INSERT OR IGNORE INTO migrations VALUES (3, ?)", (now_iso(),))
        self._db.commit()

    # -- users / sessions / tokens
    def add_report(self, rid, rtype, fmt, user, rows, body=""):
        with self._lock:
            self._db.execute("INSERT INTO report_history VALUES (?,?,?,?,?,?,?)",
                             (rid, rtype, fmt, user, rows, now_iso(), body))
            self._db.commit()

    def list_reports(self):
        return [dict(r) for r in self._db.execute(
            "SELECT id, type, format, created_by, rows, created_at FROM report_history "
            "ORDER BY created_at DESC LIMIT 100")]

    def get_report(self, rid):
        row = self._db.execute("SELECT * FROM report_history WHERE id=?", (rid,)).fetchone()
        return dict(row) if row else None

    def add_custom_rule(self, rid, title, severity, pattern, user):
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO custom_rules VALUES (?,?,?,?,?,?,1)",
                             (rid, title, severity, pattern, user, now_iso()))
            self._db.commit()

    def list_custom_rules(self):
        return [dict(r) for r in self._db.execute("SELECT * FROM custom_rules ORDER BY created_at")]

    def delete_custom_rule(self, rid):
        with self._lock:
            self._db.execute("DELETE FROM custom_rules WHERE id=?", (rid,))
            self._db.commit()

    def add_user(self, username, pw_hash, salt, role, title=""):
        with self._lock:
            self._db.execute("INSERT INTO users VALUES (?,?,?,?,0,?,?)",
                             (username, pw_hash, salt, role, now_iso(), title))
            self._db.commit()

    def get_user(self, username):
        row = self._db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None

    def list_users(self):
        return [dict(r) for r in self._db.execute(
            "SELECT username, role, title, disabled, created_at FROM users ORDER BY username")]

    def update_user(self, username, **fields):
        with self._lock:
            for key, value in fields.items():
                self._db.execute(f"UPDATE users SET {key}=? WHERE username=?", (value, username))
            self._db.commit()

    def add_session(self, token, username, role, expires):
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO sessions VALUES (?,?,?,?)",
                             (token, username, role, expires))
            self._db.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
            self._db.commit()

    def get_session(self, token):
        row = self._db.execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone()
        return dict(row) if row else None

    def delete_session(self, token):
        with self._lock:
            self._db.execute("DELETE FROM sessions WHERE token=?", (token,))
            self._db.commit()

    def add_token(self, tid, name, token_hash, role, by):
        with self._lock:
            self._db.execute("INSERT INTO tokens VALUES (?,?,?,?,?,?,0)",
                             (tid, name, token_hash, role, by, now_iso()))
            self._db.commit()

    def get_token_by_hash(self, token_hash):
        row = self._db.execute("SELECT * FROM tokens WHERE token_hash=?", (token_hash,)).fetchone()
        return dict(row) if row else None

    def list_tokens(self):
        return [dict(r) for r in self._db.execute(
            "SELECT id, name, role, created_by, created_at, revoked FROM tokens ORDER BY created_at DESC")]

    def revoke_token(self, tid):
        with self._lock:
            self._db.execute("UPDATE tokens SET revoked=1 WHERE id=?", (tid,))
            self._db.commit()

    # -- audit / system log
    def add_audit(self, action, username, detail):
        with self._lock:
            self._db.execute("INSERT INTO audit (ts, username, action, detail) VALUES (?,?,?,?)",
                             (now_iso(), username, action, detail))
            self._db.commit()

    def list_audit(self, limit=200):
        return [dict(r) for r in self._db.execute(
            "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]

    def add_ping(self, username, message):
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO coordination_pings (username, message, created_at) VALUES (?,?,?)",
                (username, message, now_iso()))
            self._db.commit()
            return cur.lastrowid

    def list_pings_since(self, ping_id=0, limit=20):
        return [dict(r) for r in self._db.execute(
            "SELECT * FROM coordination_pings WHERE id>? ORDER BY id ASC LIMIT ?",
            (ping_id, limit))]

    def coordination_revision(self):
        row = self._db.execute(
            "SELECT (SELECT COALESCE(MAX(id), 0) FROM audit) AS audit_revision,"
            " (SELECT COALESCE(MAX(id), 0) FROM coordination_pings) AS ping_revision"
        ).fetchone()
        return {"audit": int(row["audit_revision"]), "ping": int(row["ping_revision"])}

    def add_log(self, level, source, message, component="", event_type="",
                exec_id="", resource="", status="", correlation_id=""):
        with self._lock:
            self._db.execute(
                "INSERT INTO system_log (ts, level, source, message, component, event_type,"
                " exec_id, resource, status, correlation_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (now_iso(), level, source, message, component or source, event_type,
                 exec_id, resource, status, correlation_id))
            self._db.commit()

    def list_logs(self, limit=200, level=None, source=None):
        clauses, params = [], []
        if level:
            clauses.append("level=?")
            params.append(level)
        if source:
            clauses.append("source=?")
            params.append(source)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._db.execute(
            f"SELECT * FROM system_log{where} ORDER BY id DESC LIMIT ?", (*params, limit))
        return [dict(r) for r in rows]

    def log_last_run(self) -> dict:
        rows = self._db.execute(
            "SELECT source, MAX(ts) AS ts FROM system_log GROUP BY source")
        return {r["source"]: r["ts"] for r in rows}

    # -- finding management
    def get_extra(self, fid):
        row = self._db.execute("SELECT * FROM finding_extra WHERE finding_id=?", (fid,)).fetchone()
        if not row:
            return {"assignee": "", "tags": [], "severity_override": "", "pinned": 0,
                    "muted": 0, "occurrences": 1, "first_seen": "", "last_seen": ""}
        data = dict(row)
        data["tags"] = json.loads(data["tags"] or "[]")
        return data

    def update_extra(self, fid, **fields):
        if "tags" in fields:
            fields["tags"] = json.dumps(fields["tags"])
        with self._lock:
            self._db.execute("INSERT OR IGNORE INTO finding_extra (finding_id, first_seen, last_seen) "
                             "VALUES (?,?,?)", (fid, now_iso(), now_iso()))
            for key, value in fields.items():
                self._db.execute(f"UPDATE finding_extra SET {key}=? WHERE finding_id=?", (value, fid))
            self._db.commit()

    def upsert_finding(self, finding: Finding) -> bool:
        is_new = super().upsert_finding(finding)
        if is_new:
            self.update_extra(finding.id, occurrences=1)
        else:
            extra = self.get_extra(finding.id)
            self.update_extra(finding.id, occurrences=extra["occurrences"] + 1, last_seen=now_iso())
        return is_new

    def set_status(self, finding_id, status, user="system"):
        old = self.get_finding(finding_id)
        result = super().set_status(finding_id, status)
        if old and old.status != status:
            with self._lock:
                self._db.execute(
                    "INSERT INTO status_history (finding_id, old, new, username, ts) VALUES (?,?,?,?,?)",
                    (finding_id, old.status, status, user, now_iso()))
                self._db.commit()
        return result

    def add_note(self, fid, username, body):
        with self._lock:
            self._db.execute("INSERT INTO notes (finding_id, username, body, ts) VALUES (?,?,?,?)",
                             (fid, username, body, now_iso()))
            self._db.commit()

    def list_notes(self, fid):
        return [dict(r) for r in self._db.execute(
            "SELECT * FROM notes WHERE finding_id=? ORDER BY id", (fid,))]

    def list_history(self, fid):
        return [dict(r) for r in self._db.execute(
            "SELECT * FROM status_history WHERE finding_id=? ORDER BY id", (fid,))]

    def related_findings(self, fid):
        finding = self.get_finding(fid)
        if not finding:
            return []
        return [f.to_dict() for f in self.list_findings(limit=1000)
                if f.fingerprint == finding.fingerprint and f.id != fid]

    def add_filter(self, fid, username, name, params):
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO saved_filters VALUES (?,?,?,?,?)",
                             (fid, username, name, json.dumps(params), now_iso()))
            self._db.commit()

    def list_filters(self, username):
        return [{"id": r["id"], "name": r["name"], "params": json.loads(r["params"])}
                for r in self._db.execute(
                    "SELECT * FROM saved_filters WHERE username=? ORDER BY ts DESC", (username,))]

    def delete_filter(self, fid):
        with self._lock:
            self._db.execute("DELETE FROM saved_filters WHERE id=?", (fid,))
            self._db.commit()

    # -- schedules / jobs / cache
    def add_schedule(self, sid, path, surface, interval):
        with self._lock:
            self._db.execute("INSERT INTO schedules VALUES (?,?,?,?,1,0)",
                             (sid, path, surface, interval))
            self._db.commit()

    def list_schedules(self):
        return [dict(r) for r in self._db.execute("SELECT * FROM schedules ORDER BY rowid")]

    def update_schedule(self, sid, **fields):
        with self._lock:
            for key, value in fields.items():
                self._db.execute(f"UPDATE schedules SET {key}=? WHERE id=?", (value, sid))
            self._db.commit()

    def delete_schedule(self, sid):
        with self._lock:
            self._db.execute("DELETE FROM schedules WHERE id=?", (sid,))
            self._db.commit()

    def due_schedules(self):
        now = time.time()
        return [dict(r) for r in self._db.execute(
            "SELECT * FROM schedules WHERE enabled=1 AND last_run + interval_seconds <= ?", (now,))]

    def add_job(self, jid, path, surface, triggered_by):
        with self._lock:
            self._db.execute("INSERT INTO scan_jobs VALUES (?,?,?,?,?,?,?,0,0,'')",
                             (jid, path, surface, "queued", triggered_by, now_iso(), ""))
            self._db.commit()

    def update_job(self, jid, **fields):
        with self._lock:
            for key, value in fields.items():
                self._db.execute(f"UPDATE scan_jobs SET {key}=? WHERE id=?", (value, jid))
            self._db.commit()

    def get_job(self, jid):
        row = self._db.execute("SELECT * FROM scan_jobs WHERE id=?", (jid,)).fetchone()
        return dict(row) if row else None

    def list_jobs(self, limit=50):
        return [dict(r) for r in self._db.execute(
            "SELECT * FROM scan_jobs ORDER BY started DESC LIMIT ?", (limit,))]

    def cache_get(self, path):
        row = self._db.execute("SELECT * FROM scan_cache WHERE path=?", (path,)).fetchone()
        return dict(row) if row else None

    def cache_put(self, path, mtime, size, findings):
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO scan_cache VALUES (?,?,?,?,?)",
                             (path, mtime, size, json.dumps(findings), now_iso()))
            self._db.commit()

    # -- alert rules / acks / checklists
    def add_rule(self, rid, channel, min_severity):
        with self._lock:
            self._db.execute("INSERT INTO alert_rules VALUES (?,?,?,1)", (rid, channel, min_severity))
            self._db.commit()

    def list_rules(self):
        return [dict(r) for r in self._db.execute("SELECT * FROM alert_rules ORDER BY rowid")]

    def update_rule(self, rid, **fields):
        with self._lock:
            for key, value in fields.items():
                self._db.execute(f"UPDATE alert_rules SET {key}=? WHERE id=?", (value, rid))
            self._db.commit()

    def delete_rule(self, rid):
        with self._lock:
            self._db.execute("DELETE FROM alert_rules WHERE id=?", (rid,))
            self._db.commit()

    def ack_alert(self, alert_id, username):
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO alert_acks VALUES (?,?,?)",
                             (alert_id, username, now_iso()))
            self._db.commit()

    def list_acks(self):
        return {r["alert_id"]: dict(r) for r in self._db.execute("SELECT * FROM alert_acks")}

    def get_checklist(self, fid):
        return {r["step_idx"]: dict(r) for r in self._db.execute(
            "SELECT * FROM checklists WHERE finding_id=? ORDER BY step_idx", (fid,))}

    def set_checklist_step(self, fid, idx, done, username):
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO checklists "
                             "(finding_id, step_idx, done, username, ts) VALUES (?,?,?,?,?)",
                             (fid, idx, 1 if done else 0, username, now_iso()))
            self._db.commit()

    # -- ops
    def backup(self, dest: Path):
        dest.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            target = sqlite3.connect(str(dest))
            try:
                self._db.backup(target)
            finally:
                target.close()

    def purge_retention(self, days: int) -> int:
        cutoff = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - days * 86400))
        with self._lock:
            rows = self._db.execute(
                "SELECT id FROM findings WHERE status IN ('remediated','false_positive') "
                "AND updated_at < ?", (cutoff,)).fetchall()
            ids = [r["id"] for r in rows]
            for fid in ids:
                for table in ("notes", "status_history", "finding_extra", "checklists"):
                    self._db.execute(f"DELETE FROM {table} WHERE finding_id=?", (fid,))
                self._db.execute("DELETE FROM findings WHERE id=?", (fid,))
            self._db.execute("DELETE FROM system_log WHERE ts < ?", (cutoff,))
            self._db.commit()
        return len(ids)

    def vacuum(self):
        with self._lock:
            self._db.execute("VACUUM")

    def db_size(self) -> int:
        return Path(self._db.execute("PRAGMA database_list").fetchone()[2]).stat().st_size

    def dump_json(self) -> dict:
        tables = ("findings", "events", "alerts", "allowlist", "remediations",
                  "notes", "finding_extra", "saved_filters", "schedules", "alert_rules")
        out = {}
        for table in tables:
            out[table] = [dict(r) for r in self._db.execute(f"SELECT * FROM {table}")]
        return out

    def import_json(self, data: dict) -> int:
        count = 0
        with self._lock:
            for table, rows in data.items():
                if table not in ("findings", "allowlist", "notes", "finding_extra",
                                 "schedules", "alert_rules", "saved_filters",
                                 "events", "alerts", "remediations"):
                    continue
                for row in rows:
                    keys = list(row.keys())
                    self._db.execute(
                        f"INSERT OR REPLACE INTO {table} ({','.join(keys)}) "
                        f"VALUES ({','.join('?' for _ in keys)})",
                        [row[k] for k in keys])
                    count += 1
            self._db.commit()
        return count