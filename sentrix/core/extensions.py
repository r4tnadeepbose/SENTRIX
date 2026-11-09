"""Extended storage: users, sessions, management, jobs, rules, ops."""
from __future__ import annotations

import json
import re
import sqlite3
import time
from pathlib import Path

from sentrix.core.models import Finding, now_iso
from sentrix.core.storage import Storage
from sentrix.hubs.storage import HubsStorage

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
CREATE TABLE IF NOT EXISTS employee_profiles (
    username TEXT PRIMARY KEY, skills TEXT DEFAULT '[]', expertise TEXT DEFAULT '{}',
    max_capacity REAL DEFAULT 20, availability_status TEXT DEFAULT 'available',
    assignment_eligible INTEGER DEFAULT 1, updated_by TEXT DEFAULT '', updated_at TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS finding_assignments (
    finding_id TEXT PRIMARY KEY, primary_owner TEXT DEFAULT '', secondary_reviewer TEXT DEFAULT '',
    status TEXT DEFAULT 'unassigned', method TEXT DEFAULT '', explanation TEXT DEFAULT '',
    scoring TEXT DEFAULT '{}', assigned_by TEXT DEFAULT '', assigned_at TEXT DEFAULT '',
    acknowledged_at TEXT DEFAULT '', secondary_acknowledged_at TEXT DEFAULT '', ack_due_at TEXT DEFAULT '', due_at TEXT DEFAULT '',
    priority TEXT DEFAULT '', assignment_instructions TEXT DEFAULT '', assistance_requested_at TEXT DEFAULT '', assistance_reason TEXT DEFAULT '',
    primary_investigation_started_at TEXT DEFAULT '', primary_classification TEXT DEFAULT '', primary_reasoning TEXT DEFAULT '', primary_evidence TEXT DEFAULT '', primary_submitted_at TEXT DEFAULT '',
    secondary_review_started_at TEXT DEFAULT '', secondary_outcome TEXT DEFAULT '', secondary_reasoning TEXT DEFAULT '', secondary_evidence TEXT DEFAULT '', secondary_submitted_at TEXT DEFAULT '',
    admin_decision TEXT DEFAULT '', admin_decision_reason TEXT DEFAULT '', admin_decision_by TEXT DEFAULT '', admin_decision_at TEXT DEFAULT '', reassessment_target TEXT DEFAULT '',
    remediation_owner TEXT DEFAULT '', remediation_status TEXT DEFAULT '', remediation_submitted_at TEXT DEFAULT '', remediation_note TEXT DEFAULT '',
    verification_requested_at TEXT DEFAULT '', verification_note TEXT DEFAULT '', verification_evidence TEXT DEFAULT '', verification_decision TEXT DEFAULT '', verification_decided_by TEXT DEFAULT '', verification_decided_at TEXT DEFAULT '', verification_rejection_reason TEXT DEFAULT '',
    blocked_reason TEXT DEFAULT '', reassignment_requested_by TEXT DEFAULT '',
    reassignment_reason TEXT DEFAULT '', completed_at TEXT DEFAULT '', verified_at TEXT DEFAULT '',
    sla_config TEXT DEFAULT '{}', updated_at TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS assignment_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT NOT NULL, action TEXT NOT NULL,
    from_owner TEXT DEFAULT '', to_owner TEXT DEFAULT '', from_reviewer TEXT DEFAULT '',
    to_reviewer TEXT DEFAULT '', status TEXT DEFAULT '', reason TEXT DEFAULT '',
    actor TEXT DEFAULT '', details TEXT DEFAULT '{}', ts TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS assignment_sla_config (
    id INTEGER PRIMARY KEY CHECK (id=1), config TEXT NOT NULL, updated_by TEXT DEFAULT '', updated_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_assign_primary ON finding_assignments(primary_owner);
CREATE INDEX IF NOT EXISTS idx_assign_secondary ON finding_assignments(secondary_reviewer);
CREATE INDEX IF NOT EXISTS idx_assign_status ON finding_assignments(status);
CREATE INDEX IF NOT EXISTS idx_assign_history_fid ON assignment_history(finding_id);
"""


class ExtStorage(Storage, HubsStorage):
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
        self._db.execute("INSERT OR IGNORE INTO migrations VALUES (4, ?)", (now_iso(),))
        for ddl in (
            "ALTER TABLE finding_assignments ADD COLUMN secondary_acknowledged_at TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN priority TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN assignment_instructions TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN assistance_requested_at TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN assistance_reason TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN verification_requested_at TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN verification_note TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN verification_evidence TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN verification_decision TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN verification_decided_by TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN verification_decided_at TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN verification_rejection_reason TEXT DEFAULT ''",
        ):
            try: self._db.execute(ddl)
            except sqlite3.OperationalError: pass
        for ddl in (
            "ALTER TABLE finding_assignments ADD COLUMN primary_investigation_started_at TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN primary_classification TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN primary_reasoning TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN primary_evidence TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN primary_submitted_at TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN secondary_review_started_at TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN secondary_outcome TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN secondary_reasoning TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN secondary_evidence TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN secondary_submitted_at TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN admin_decision TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN admin_decision_reason TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN admin_decision_by TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN admin_decision_at TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN reassessment_target TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN remediation_owner TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN remediation_status TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN remediation_submitted_at TEXT DEFAULT ''",
            "ALTER TABLE finding_assignments ADD COLUMN remediation_note TEXT DEFAULT ''",
        ):
            try: self._db.execute(ddl)
            except sqlite3.OperationalError: pass
        self._db.execute("INSERT OR IGNORE INTO migrations VALUES (5, ?)", (now_iso(),))
        self._db.execute("INSERT OR IGNORE INTO migrations VALUES (6, ?)", (now_iso(),))
        self._db.commit()
        self._ensure_assignment_sla_config()
        self.hubs_init()

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

    def delete_user(self, username):
        """Remove an account and every trace of it (sessions, tokens, Hubs)."""
        with self._lock:
            self._db.execute("DELETE FROM users WHERE username=?", (username,))
            self._db.execute("DELETE FROM sessions WHERE username=?", (username,))
            self._db.execute("DELETE FROM tokens WHERE created_by=?", (username,))
            # Remove the person from operational records so no stale name
            # survives in findings, history, reports or logs.
            self._db.execute("UPDATE findings SET owner='' WHERE owner=?", (username,))
            self._db.execute("UPDATE finding_extra SET assignee='' WHERE assignee=?", (username,))
            self._db.execute("DELETE FROM status_history WHERE username=?", (username,))
            self._db.execute("DELETE FROM audit WHERE username=?", (username,))
            self._db.execute("DELETE FROM system_log WHERE instr(message, ?) > 0", (username,))
            self._db.execute("DELETE FROM coordination_pings WHERE username=?", (username,))
            self._db.execute(
                "UPDATE report_history SET body=replace(body, ?, 'removed account')",
                (username,))
            self._db.commit()
        self.hubs_purge_user(username)

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
                    keys = [k for k in row.keys() if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(k))]
                    if not keys:
                        continue
                    self._db.execute(
                        f"INSERT OR REPLACE INTO {table} ({','.join(keys)}) "
                        f"VALUES ({','.join('?' for _ in keys)})",
                        [row[k] for k in keys])
                    count += 1
            self._db.commit()
        return count

    # ── risk acceptance ───────────────────────────────────────────────────

    def ensure_risk_acceptance_table(self):
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS risk_acceptances (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                owner TEXT NOT NULL,
                decision TEXT DEFAULT 'accept',
                reason TEXT DEFAULT '',
                proof TEXT DEFAULT '',
                expires_at TEXT,
                sla_restart INTEGER DEFAULT 0,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expired_handled INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS risk_acceptance_findings (
                ra_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                added_at TEXT NOT NULL,
                PRIMARY KEY (ra_id, finding_id)
            );
            CREATE INDEX IF NOT EXISTS idx_ra_owner ON risk_acceptances(owner);
            CREATE INDEX IF NOT EXISTS idx_raf_finding ON risk_acceptance_findings(finding_id);
        """)
        self._db.commit()

    def add_risk_acceptance(self, ra_id, name, owner, decision, reason, proof,
                            expires_at, sla_restart, created_by):
        self.ensure_risk_acceptance_table()
        with self._lock:
            self._db.execute(
                "INSERT INTO risk_acceptances "
                "(id,name,owner,decision,reason,proof,expires_at,sla_restart,created_by,created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (ra_id, name, owner, decision, reason, proof,
                 expires_at, 1 if sla_restart else 0, created_by, now_iso()),
            )
            self._db.commit()

    def list_risk_acceptances(self, limit=100):
        self.ensure_risk_acceptance_table()
        rows = self._db.execute(
            "SELECT ra.*, GROUP_CONCAT(raf.finding_id) AS finding_ids "
            "FROM risk_acceptances ra "
            "LEFT JOIN risk_acceptance_findings raf ON raf.ra_id=ra.id "
            "GROUP BY ra.id ORDER BY ra.created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["finding_ids"] = [x for x in (d.get("finding_ids") or "").split(",") if x]
            result.append(d)
        return result

    def get_risk_acceptance(self, ra_id):
        self.ensure_risk_acceptance_table()
        row = self._db.execute(
            "SELECT * FROM risk_acceptances WHERE id=?", (ra_id,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["finding_ids"] = [dict(r)["finding_id"] for r in self._db.execute(
            "SELECT finding_id FROM risk_acceptance_findings WHERE ra_id=?", (ra_id,)
        )]
        return d

    def add_finding_to_risk_acceptance(self, ra_id, finding_id, username):
        self.ensure_risk_acceptance_table()
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO risk_acceptance_findings (ra_id, finding_id, added_at) "
                "VALUES (?,?,?)", (ra_id, finding_id, now_iso()),
            )
            self._db.commit()
        self.set_status(finding_id, "accepted_risk", username)

    def remove_finding_from_risk_acceptance(self, ra_id, finding_id, username):
        self.ensure_risk_acceptance_table()
        with self._lock:
            self._db.execute(
                "DELETE FROM risk_acceptance_findings WHERE ra_id=? AND finding_id=?",
                (ra_id, finding_id),
            )
            self._db.commit()
        self.set_status(finding_id, "open", username)

    def expire_risk_acceptances(self, username="system"):
        """Reactivate findings from expired, unhandled risk acceptances."""
        self.ensure_risk_acceptance_table()
        now = now_iso()
        expired = self._db.execute(
            "SELECT id FROM risk_acceptances WHERE expires_at IS NOT NULL "
            "AND expires_at < ? AND expired_handled=0", (now,)
        ).fetchall()
        reactivated = 0
        for row in expired:
            ra = self.get_risk_acceptance(row["id"])
            for fid in ra.get("finding_ids", []):
                self.set_status(fid, "open", username)
                reactivated += 1
            with self._lock:
                self._db.execute(
                    "UPDATE risk_acceptances SET expired_handled=1 WHERE id=?", (row["id"],)
                )
                self._db.commit()
        return reactivated

    # ── SLA helpers ───────────────────────────────────────────────────────

    SLA_HOURS = {"critical": 24, "high": 72, "medium": 168, "low": 336, "info": 720}



    # -- assignment / workload / SLA (enterprise assignment engine) -------------
    def _ensure_assignment_sla_config(self):
        from sentrix.core.assignment import default_sla_config
        with self._lock:
            row = self._db.execute("SELECT 1 FROM assignment_sla_config WHERE id=1").fetchone()
            if not row:
                self._db.execute("INSERT INTO assignment_sla_config (id, config, updated_by, updated_at) VALUES (1,?,?,?)",
                                 (json.dumps(default_sla_config()), "system", now_iso()))
                self._db.commit()

    def get_assignment_sla_config(self):
        row = self._db.execute("SELECT * FROM assignment_sla_config WHERE id=1").fetchone()
        if not row:
            from sentrix.core.assignment import default_sla_config
            return default_sla_config()
        try: return json.loads(row["config"])
        except Exception:
            from sentrix.core.assignment import default_sla_config
            return default_sla_config()

    def set_assignment_sla_config(self, config, actor="admin"):
        with self._lock:
            self._db.execute("INSERT INTO assignment_sla_config (id, config, updated_by, updated_at) VALUES (1,?,?,?) "
                             "ON CONFLICT(id) DO UPDATE SET config=excluded.config, updated_by=excluded.updated_by, updated_at=excluded.updated_at",
                             (json.dumps(config), actor, now_iso()))
            self._db.commit()

    def reset_assignment_demo_state(self, actor="system"):
        """Reset assignment/workload/employee state to current demo defaults (admin action)."""
        from sentrix.core.assignment import default_sla_config, profile_defaults
        users = self.list_users()
        with self._lock:
            self._db.execute("DELETE FROM finding_assignments")
            self._db.execute("DELETE FROM assignment_history")
            self._db.execute("DELETE FROM employee_profiles")
            self._db.execute("UPDATE finding_extra SET assignee=''")
            self._db.execute("UPDATE findings SET owner=''")
            self._db.execute("INSERT OR REPLACE INTO assignment_sla_config (id, config, updated_by, updated_at) VALUES (1,?,?,?)",
                             (json.dumps(default_sla_config()), actor, now_iso()))
            self._db.commit()
        for u in users:
            uname = u.get("username")
            if not uname: continue
            d = profile_defaults(uname, u.get("role",""), u.get("title",""))
            with self._lock:
                self._db.execute("INSERT INTO employee_profiles (username,skills,expertise,max_capacity,availability_status,assignment_eligible,updated_by,updated_at) VALUES (?,?,?,?,?,?,?,?)",
                                 (uname, json.dumps(d["skills"]), json.dumps(d["expertise"]), d["max_capacity"],
                                  d["availability_status"], 1 if d["assignment_eligible"] else 0, actor, now_iso()))
                self._db.commit()

    def ensure_employee_profiles(self, users):
        from sentrix.core.assignment import profile_defaults
        for u in users:
            uname = u.get("username") if isinstance(u, dict) else getattr(u, "username", "")
            if not uname: continue
            row = self._db.execute("SELECT 1 FROM employee_profiles WHERE username=?", (uname,)).fetchone()
            if row: continue
            d = profile_defaults(uname, u.get("role","") if isinstance(u,dict) else getattr(u,"role",""),
                                 u.get("title","") if isinstance(u,dict) else getattr(u,"title",""))
            with self._lock:
                self._db.execute("INSERT INTO employee_profiles (username,skills,expertise,max_capacity,availability_status,assignment_eligible,updated_by,updated_at) VALUES (?,?,?,?,?,?,?,?)",
                                 (uname, json.dumps(d["skills"]), json.dumps(d["expertise"]), d["max_capacity"],
                                  d["availability_status"], 1 if d["assignment_eligible"] else 0, "system", now_iso()))
                self._db.commit()

    def get_employee_profile(self, username):
        row = self._db.execute("SELECT * FROM employee_profiles WHERE username=?", (username,)).fetchone()
        if not row: return None
        d = dict(row)
        d["skills"] = json.loads(d.get("skills") or "[]")
        d["expertise"] = json.loads(d.get("expertise") or "{}")
        d["assignment_eligible"] = bool(d.get("assignment_eligible"))
        return d

    def upsert_employee_profile(self, username, actor, **fields):
        # ensure row
        if not self._db.execute("SELECT 1 FROM employee_profiles WHERE username=?", (username,)).fetchone():
            self.ensure_employee_profiles([{"username": username}])
        if "skills" in fields and not isinstance(fields["skills"], str): fields["skills"] = json.dumps(fields["skills"])
        if "expertise" in fields and not isinstance(fields["expertise"], str): fields["expertise"] = json.dumps(fields["expertise"])
        if "assignment_eligible" in fields: fields["assignment_eligible"] = 1 if fields["assignment_eligible"] else 0
        fields["updated_by"] = actor; fields["updated_at"] = now_iso()
        allowed = {"skills","expertise","max_capacity","availability_status","assignment_eligible","updated_by","updated_at"}
        sets = []; vals = []
        for k,v in fields.items():
            if k in allowed: sets.append(f"{k}=?"); vals.append(v)
        if not sets: return self.get_employee_profile(username)
        vals.append(username)
        with self._lock:
            self._db.execute(f"UPDATE employee_profiles SET {', '.join(sets)} WHERE username=?", vals)
            self._db.commit()
        return self.get_employee_profile(username)

    def list_employee_profiles(self, users=None):
        if users is not None:
            self.ensure_employee_profiles(users)
        rows = self._db.execute("SELECT * FROM employee_profiles").fetchall()
        out = []
        for r in rows:
            d = dict(r); d["skills"] = json.loads(d.get("skills") or "[]"); d["expertise"] = json.loads(d.get("expertise") or "{}")
            d["assignment_eligible"] = bool(d.get("assignment_eligible")); out.append(d)
        return out

    def get_assignment(self, finding_id):
        row = self._db.execute("SELECT * FROM finding_assignments WHERE finding_id=?", (finding_id,)).fetchone()
        base = {"finding_id": finding_id, "primary_owner": "", "secondary_reviewer": "", "status": "unassigned",
                "method": "", "explanation": "", "scoring": {}, "assigned_by": "", "assigned_at": "",
                "acknowledged_at": "", "secondary_acknowledged_at": "", "ack_due_at": "", "due_at": "",
                "priority": "", "assignment_instructions": "", "assistance_requested_at": "", "assistance_reason": "",
                "primary_investigation_started_at": "", "primary_classification": "", "primary_reasoning": "", "primary_evidence": "", "primary_submitted_at": "",
                "secondary_review_started_at": "", "secondary_outcome": "", "secondary_reasoning": "", "secondary_evidence": "", "secondary_submitted_at": "",
                "admin_decision": "", "admin_decision_reason": "", "admin_decision_by": "", "admin_decision_at": "", "reassessment_target": "",
                "remediation_owner": "", "remediation_status": "", "remediation_submitted_at": "", "remediation_note": "",
                "verification_requested_at": "", "verification_note": "", "verification_evidence": "", "verification_decision": "", "verification_decided_by": "", "verification_decided_at": "", "verification_rejection_reason": "",
                "blocked_reason": "", "reassignment_requested_by": "", "reassignment_reason": "", "completed_at": "", "verified_at": "", "sla_config": {}}
        if not row:
            return base
        d = dict(row)
        for k in ("scoring","sla_config"):
            try: d[k] = json.loads(d.get(k) or "{}")
            except Exception: d[k] = {}
        return d

    def upsert_assignment(self, finding_id, actor, reason="", action="update", sync_finding=True, **fields):
        now = now_iso()
        cur = self.get_assignment(finding_id)
        with self._lock:
            self._db.execute("INSERT OR IGNORE INTO finding_assignments (finding_id, updated_at) VALUES (?,?)", (finding_id, now))
            if "scoring" in fields and not isinstance(fields["scoring"], str): fields["scoring"] = json.dumps(fields["scoring"])
            if "sla_config" in fields and not isinstance(fields["sla_config"], str): fields["sla_config"] = json.dumps(fields["sla_config"])
            fields["updated_at"] = now
            sets=[]; vals=[]
            for k,v in fields.items():
                sets.append(f"{k}=?"); vals.append(v)
            if sets:
                vals.append(finding_id)
                self._db.execute(f"UPDATE finding_assignments SET {', '.join(sets)} WHERE finding_id=?", vals)
            self._db.commit()
        new = self.get_assignment(finding_id)
        # sync legacy fields for compatibility
        if sync_finding and new.get("primary_owner") is not None:
            try:
                self.update_extra(finding_id, assignee=new.get("primary_owner") or "")
                with self._lock:
                    self._db.execute("UPDATE findings SET owner=?, updated_at=? WHERE id=?",
                                     (new.get("primary_owner") or "", now, finding_id))
                    self._db.commit()
            except Exception:
                pass
        # history
        self.add_assignment_history(finding_id, action,
                                    from_owner=cur.get("primary_owner",""), to_owner=new.get("primary_owner",""),
                                    from_reviewer=cur.get("secondary_reviewer",""), to_reviewer=new.get("secondary_reviewer",""),
                                    status=new.get("status",""), reason=reason, actor=actor,
                                    details={"method": new.get("method",""), "prev_status": cur.get("status","")})
        return new

    def add_assignment_history(self, finding_id, action, from_owner="", to_owner="", from_reviewer="", to_reviewer="",
                               status="", reason="", actor="", details=None):
        with self._lock:
            self._db.execute("INSERT INTO assignment_history (finding_id,action,from_owner,to_owner,from_reviewer,to_reviewer,status,reason,actor,details,ts) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                             (finding_id, action, from_owner, to_owner, from_reviewer, to_reviewer, status, reason, actor,
                              json.dumps(details or {}), now_iso()))
            self._db.commit()

    def list_assignment_history(self, finding_id, limit=100):
        rows = self._db.execute("SELECT * FROM assignment_history WHERE finding_id=? ORDER BY id DESC LIMIT ?", (finding_id, limit)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try: d["details"] = json.loads(d.get("details") or "{}")
            except Exception: d["details"] = {}
            out.append(d)
        return out

    def list_assignments(self, status=None, primary_owner=None, secondary_reviewer=None, limit=2000):
        sql = "SELECT * FROM finding_assignments WHERE 1=1"; args=[]
        if status: sql += " AND status=?"; args.append(status)
        if primary_owner: sql += " AND primary_owner=?"; args.append(primary_owner)
        if secondary_reviewer: sql += " AND secondary_reviewer=?"; args.append(secondary_reviewer)
        sql += " ORDER BY updated_at DESC LIMIT ?"; args.append(limit)
        rows = self._db.execute(sql, args).fetchall()
        out=[]
        for r in rows:
            d=dict(r)
            for k in ("scoring","sla_config"):
                try: d[k]=json.loads(d.get(k) or "{}")
                except Exception: d[k]={}
            out.append(d)
        return out

    def finding_sla(self, finding, extra=None):
        """Return SLA info dict for a finding."""
        extra = extra or self.get_extra(finding.id)
        sla_h = self.SLA_HOURS.get(finding.severity, 168)
        first_seen = extra.get("first_seen") or finding.created_at
        try:
            age_h = (time.time() - time.mktime(
                time.strptime(first_seen, "%Y-%m-%dT%H:%M:%S"))) / 3600
        except ValueError:
            age_h = 0.0
        remaining_h = max(0.0, sla_h - age_h)
        breached = age_h > sla_h
        at_risk = not breached and age_h > sla_h * 0.7
        return {
            "sla_hours": sla_h,
            "age_hours": round(age_h, 1),
            "remaining_hours": round(remaining_h, 1),
            "breached": breached,
            "at_risk": at_risk,
        }
