"""SQLite persistence: findings, events, alerts, allowlist, remediations."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from keysentry.core.models import Alert, Event, Finding, Remediation, now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    detector_id TEXT, title TEXT, severity TEXT, surface TEXT,
    path TEXT, line INTEGER, secret_masked TEXT, entropy REAL,
    fingerprint TEXT, status TEXT, owner TEXT,
    created_at TEXT, updated_at TEXT, meta TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY, kind TEXT, surface TEXT, payload TEXT, ts TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY, finding_id TEXT, channel TEXT, message TEXT, status TEXT, ts TEXT
);
CREATE TABLE IF NOT EXISTS allowlist (
    fingerprint TEXT PRIMARY KEY, reason TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS remediations (
    id TEXT PRIMARY KEY, finding_id TEXT, action TEXT, detail TEXT, ts TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
"""


class Storage:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(SCHEMA)
        self._db.commit()

    def close(self):
        self._db.close()

    def upsert_finding(self, finding: Finding) -> bool:
        """Insert if new; returns True when the finding was newly stored."""
        with self._lock:
            existing = self._db.execute(
                "SELECT id, status FROM findings WHERE fingerprint=? AND path=? AND line=?",
                (finding.fingerprint, finding.path, finding.line),
            ).fetchone()
            if existing:
                self._db.execute(
                    "UPDATE findings SET updated_at=? WHERE id=?",
                    (now_iso(), existing["id"]),
                )
                self._db.commit()
                finding.id = existing["id"]
                finding.status = existing["status"]
                return False
            self._db.execute(
                "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    finding.id, finding.detector_id, finding.title, finding.severity,
                    finding.surface, finding.path, finding.line, finding.secret_masked,
                    finding.entropy, finding.fingerprint, finding.status, finding.owner,
                    finding.created_at, finding.updated_at, json.dumps(finding.meta),
                ),
            )
            self._db.commit()
            return True

    def get_finding(self, finding_id: str) -> Finding | None:
        row = self._db.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        return self._row_finding(row) if row else None

    def list_findings(self, status=None, severity=None, surface=None, q=None, limit=500) -> list[Finding]:
        sql = "SELECT * FROM findings WHERE 1=1"
        args: list = []
        for column, value in (("status", status), ("severity", severity), ("surface", surface)):
            if value:
                sql += f" AND {column}=?"
                args.append(value)
        if q:
            sql += " AND (title LIKE ? OR path LIKE ? OR detector_id LIKE ?)"
            args += [f"%{q}%"] * 3
        sql += " ORDER BY created_at DESC, id LIMIT ?"
        args.append(limit)
        return [self._row_finding(r) for r in self._db.execute(sql, args)]

    def set_meta(self, finding_id: str, meta: dict):
        with self._lock:
            self._db.execute(
                "UPDATE findings SET meta=?, updated_at=? WHERE id=?",
                (json.dumps(meta), now_iso(), finding_id),
            )
            self._db.commit()

    def set_status(self, finding_id: str, status: str) -> Finding | None:
        with self._lock:
            self._db.execute(
                "UPDATE findings SET status=?, updated_at=? WHERE id=?",
                (status, now_iso(), finding_id),
            )
            self._db.commit()
        return self.get_finding(finding_id)

    def stats(self) -> dict:
        rows = self._db.execute("SELECT severity, surface, status FROM findings").fetchall()
        by_severity: dict = {}
        by_surface: dict = {}
        by_status: dict = {}
        for row in rows:
            by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + 1
            by_surface[row["surface"]] = by_surface.get(row["surface"], 0) + 1
            by_status[row["status"]] = by_status.get(row["status"], 0) + 1
        return {
            "total": len(rows),
            "open": by_status.get("open", 0),
            "by_severity": by_severity,
            "by_surface": by_surface,
            "by_status": by_status,
            "alerts_sent": self._db.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"],
            "events_processed": self._db.execute("SELECT COUNT(*) c FROM events").fetchone()["c"],
            "remediations": self._db.execute("SELECT COUNT(*) c FROM remediations").fetchone()["c"],
        }

    def add_event(self, event: Event):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO events VALUES (?,?,?,?,?)",
                (event.id, event.kind, event.surface, json.dumps(event.payload), event.ts),
            )
            self._db.commit()

    def list_events(self, limit=50) -> list[dict]:
        rows = self._db.execute("SELECT * FROM events ORDER BY ts DESC, id DESC LIMIT ?", (limit,))
        return [
            {"id": r["id"], "kind": r["kind"], "surface": r["surface"],
             "payload": json.loads(r["payload"]), "ts": r["ts"]}
            for r in rows
        ]

    def add_alert(self, alert: Alert):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?)",
                (alert.id, alert.finding_id, alert.channel, alert.message, alert.status, alert.ts),
            )
            self._db.commit()

    def recent_alert_for(self, finding_id: str, window_seconds: int) -> bool:
        row = self._db.execute(
            "SELECT ts FROM alerts WHERE finding_id=? ORDER BY ts DESC LIMIT 1",
            (finding_id,),
        ).fetchone()
        if not row:
            return False
        import time
        try:
            last = time.mktime(time.strptime(row["ts"], "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            return False
        return (time.time() - last) < window_seconds

    def list_alerts(self, limit=50) -> list[dict]:
        return [dict(r) for r in self._db.execute(
            "SELECT * FROM alerts ORDER BY ts DESC, id DESC LIMIT ?", (limit,))]

    def allowlist_entries(self) -> list[dict]:
        return [dict(r) for r in self._db.execute(
            "SELECT * FROM allowlist ORDER BY created_at DESC")]

    def allowlist_add(self, fingerprint: str, reason: str):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO allowlist VALUES (?,?,?)",
                (fingerprint, reason, now_iso()),
            )
            self._db.commit()

    def allowlist_fingerprints(self) -> set[str]:
        return {r["fingerprint"] for r in self._db.execute("SELECT fingerprint FROM allowlist")}

    def add_remediation(self, remediation: Remediation):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO remediations VALUES (?,?,?,?,?)",
                (remediation.id, remediation.finding_id, remediation.action,
                 remediation.detail, remediation.ts),
            )
            self._db.commit()

    def list_remediations(self, finding_id: str) -> list[dict]:
        return [dict(r) for r in self._db.execute(
            "SELECT * FROM remediations WHERE finding_id=? ORDER BY ts DESC", (finding_id,))]

    @staticmethod
    def _row_finding(row) -> Finding:
        data = dict(row)
        data["meta"] = json.loads(data.get("meta") or "{}")
        return Finding.from_dict(data)