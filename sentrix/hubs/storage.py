"""Hubs persistence layer — channels, messages, DMs, pings, notifications."""
from __future__ import annotations

import json
import time
from typing import Optional

from sentrix.core.models import now_iso

HUBS_SCHEMA = """
CREATE TABLE IF NOT EXISTS hubs_channels (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    is_default INTEGER DEFAULT 0,
    archived INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS hubs_channel_members (
    channel_id TEXT NOT NULL,
    username TEXT NOT NULL,
    joined_at TEXT NOT NULL,
    role TEXT DEFAULT 'member',
    PRIMARY KEY (channel_id, username)
);
CREATE TABLE IF NOT EXISTS hubs_messages (
    id TEXT PRIMARY KEY,
    channel_id TEXT,
    dm_key TEXT,
    sender TEXT NOT NULL,
    body TEXT NOT NULL,
    msg_type TEXT DEFAULT 'message',
    reply_to TEXT,
    edited INTEGER DEFAULT 0,
    edited_at TEXT,
    deleted INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hubs_message_reads (
    username TEXT NOT NULL,
    channel_id TEXT,
    dm_key TEXT,
    last_read_id TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (username, channel_id, dm_key)
);
CREATE TABLE IF NOT EXISTS hubs_notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    type TEXT NOT NULL,
    sender TEXT NOT NULL,
    channel_id TEXT,
    dm_key TEXT,
    message_id TEXT,
    body TEXT,
    read INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hubs_pings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user TEXT NOT NULL,
    to_user TEXT NOT NULL,
    message TEXT DEFAULT '',
    delivered INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hubs_presence (
    username TEXT PRIMARY KEY,
    last_seen TEXT NOT NULL,
    status TEXT DEFAULT 'online'
);
CREATE TABLE IF NOT EXISTS hubs_user_prefs (
    username TEXT PRIMARY KEY,
    muted_channels TEXT DEFAULT '[]',
    muted_dms TEXT DEFAULT '[]',
    sound_enabled INTEGER DEFAULT 1,
    notif_desktop INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_hubs_msg_channel ON hubs_messages(channel_id, created_at);
CREATE INDEX IF NOT EXISTS idx_hubs_msg_dm ON hubs_messages(dm_key, created_at);
CREATE INDEX IF NOT EXISTS idx_hubs_notif_user ON hubs_notifications(username, read);
CREATE INDEX IF NOT EXISTS idx_hubs_pings_to ON hubs_pings(to_user, delivered);
"""

# Per-user ping rate limit: max 3 pings to same target per 5 minutes
_PING_WINDOW = 300
_PING_MAX = 3


class HubsStorage:
    """Mixin — attached to ExtStorage; expects self._db and self._lock."""

    def hubs_init(self):
        self._db.executescript(HUBS_SCHEMA)
        self._db.commit()
        self._ensure_default_channels()

    def _ensure_default_channels(self):
        defaults = [
            ("open-chat", "Open Chat", "Organization-wide conversation for all SENTRIX users.", 1),
            ("soc-team", "SOC Team", "Security Operations Center team channel.", 0),
            ("red-team", "Red Team", "Offensive security operations.", 0),
            ("blue-team", "Blue Team", "Defensive security operations.", 0),
            ("vapt-team", "VAPT Team", "Vulnerability assessment and penetration testing.", 0),
            ("incident-response", "Incident Response", "Active incident coordination.", 0),
            ("devsecops", "DevSecOps", "Development security operations.", 0),
            ("security-engineering", "Security Engineering", "Platform and tooling security.", 0),
        ]
        for cid, name, desc, is_default in defaults:
            self._db.execute(
                "INSERT OR IGNORE INTO hubs_channels (id, name, description, created_by, created_at, is_default) "
                "VALUES (?,?,?,'system',?,?)",
                (cid, name, desc, now_iso(), is_default),
            )
        self._db.commit()

    # ── channels ──────────────────────────────────────────────────────────

    def hubs_list_channels(self, username: str) -> list[dict]:
        rows = self._db.execute(
            "SELECT c.*, "
            "(SELECT COUNT(*) FROM hubs_channel_members m WHERE m.channel_id=c.id AND m.username=?) AS joined "
            "FROM hubs_channels c WHERE c.archived=0 ORDER BY c.is_default DESC, c.name",
            (username,),
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["joined"] = bool(d["joined"])
            d["unread"] = self._channel_unread(r["id"], username)
            result.append(d)
        return result

    def hubs_create_channel(self, cid: str, name: str, description: str, creator: str) -> dict:
        with self._lock:
            self._db.execute(
                "INSERT INTO hubs_channels (id, name, description, created_by, created_at) VALUES (?,?,?,?,?)",
                (cid, name, description, creator, now_iso()),
            )
            self._db.execute(
                "INSERT OR IGNORE INTO hubs_channel_members (channel_id, username, joined_at, role) VALUES (?,?,?,?)",
                (cid, creator, now_iso(), "owner"),
            )
            self._db.commit()
        return self._db.execute("SELECT * FROM hubs_channels WHERE id=?", (cid,)).fetchone()

    def hubs_join_channel(self, channel_id: str, username: str):
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO hubs_channel_members (channel_id, username, joined_at) VALUES (?,?,?)",
                (channel_id, username, now_iso()),
            )
            self._db.commit()

    def hubs_leave_channel(self, channel_id: str, username: str):
        with self._lock:
            row = self._db.execute(
                "SELECT role FROM hubs_channel_members WHERE channel_id=? AND username=?",
                (channel_id, username),
            ).fetchone()
            if row and row["role"] == "owner":
                return False  # owners can't leave
            self._db.execute(
                "DELETE FROM hubs_channel_members WHERE channel_id=? AND username=?",
                (channel_id, username),
            )
            self._db.commit()
            return True

    def hubs_channel_members(self, channel_id: str) -> list[dict]:
        return [dict(r) for r in self._db.execute(
            "SELECT hcm.username, hcm.role, hcm.joined_at, u.title, u.role AS user_role "
            "FROM hubs_channel_members hcm "
            "LEFT JOIN users u ON u.username=hcm.username "
            "WHERE hcm.channel_id=? ORDER BY hcm.joined_at",
            (channel_id,),
        )]

    def hubs_is_channel_member(self, channel_id: str, username: str) -> bool:
        row = self._db.execute(
            "SELECT 1 FROM hubs_channel_members WHERE channel_id=? AND username=?",
            (channel_id, username),
        ).fetchone()
        return row is not None

    # ── messages ──────────────────────────────────────────────────────────

    def hubs_post_message(self, msg_id: str, channel_id: Optional[str],
                          dm_key: Optional[str], sender: str, body: str,
                          msg_type: str = "message", reply_to: Optional[str] = None) -> dict:
        ts = now_iso()
        with self._lock:
            self._db.execute(
                "INSERT INTO hubs_messages (id, channel_id, dm_key, sender, body, msg_type, reply_to, created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (msg_id, channel_id, dm_key, sender, body, msg_type, reply_to, ts),
            )
            self._db.commit()
        return {
            "id": msg_id, "channel_id": channel_id, "dm_key": dm_key,
            "sender": sender, "body": body, "msg_type": msg_type,
            "reply_to": reply_to, "edited": 0, "created_at": ts,
        }

    def hubs_edit_message(self, msg_id: str, username: str, body: str) -> bool:
        row = self._db.execute(
            "SELECT sender FROM hubs_messages WHERE id=? AND deleted=0", (msg_id,)
        ).fetchone()
        if not row or row["sender"] != username:
            return False
        with self._lock:
            self._db.execute(
                "UPDATE hubs_messages SET body=?, edited=1, edited_at=? WHERE id=?",
                (body, now_iso(), msg_id),
            )
            self._db.commit()
        return True

    def hubs_delete_message(self, msg_id: str, username: str, is_admin: bool = False) -> bool:
        row = self._db.execute(
            "SELECT sender FROM hubs_messages WHERE id=? AND deleted=0", (msg_id,)
        ).fetchone()
        if not row:
            return False
        if not is_admin and row["sender"] != username:
            return False
        with self._lock:
            self._db.execute(
                "UPDATE hubs_messages SET deleted=1, body='' WHERE id=?", (msg_id,)
            )
            self._db.commit()
        return True

    def hubs_get_messages(self, channel_id: Optional[str], dm_key: Optional[str],
                          before_id: Optional[str] = None, limit: int = 50) -> list[dict]:
        if channel_id:
            clause = "channel_id=?"
            param = channel_id
        elif dm_key:
            clause = "dm_key=?"
            param = dm_key
        else:
            return []

        if before_id:
            rows = self._db.execute(
                f"SELECT * FROM hubs_messages WHERE {clause} AND deleted=0 AND id<? "
                f"ORDER BY id DESC LIMIT ?",
                (param, before_id, limit),
            ).fetchall()
        else:
            rows = self._db.execute(
                f"SELECT * FROM hubs_messages WHERE {clause} AND deleted=0 "
                f"ORDER BY id DESC LIMIT ?",
                (param, limit),
            ).fetchall()
        return list(reversed([dict(r) for r in rows]))

    def hubs_get_message(self, msg_id: str) -> Optional[dict]:
        row = self._db.execute("SELECT * FROM hubs_messages WHERE id=?", (msg_id,)).fetchone()
        return dict(row) if row else None

    def hubs_latest_message_id(self, channel_id: Optional[str], dm_key: Optional[str]) -> Optional[str]:
        if channel_id:
            row = self._db.execute(
                "SELECT id FROM hubs_messages WHERE channel_id=? AND deleted=0 ORDER BY id DESC LIMIT 1",
                (channel_id,),
            ).fetchone()
        elif dm_key:
            row = self._db.execute(
                "SELECT id FROM hubs_messages WHERE dm_key=? AND deleted=0 ORDER BY id DESC LIMIT 1",
                (dm_key,),
            ).fetchone()
        else:
            return None
        return row["id"] if row else None

    # ── unread tracking ───────────────────────────────────────────────────

    def hubs_mark_read(self, username: str, channel_id: Optional[str],
                       dm_key: Optional[str], last_read_id: str):
        with self._lock:
            # Use COALESCE key for unique constraint
            ck = channel_id or ""
            dk = dm_key or ""
            self._db.execute(
                "INSERT OR REPLACE INTO hubs_message_reads "
                "(username, channel_id, dm_key, last_read_id, updated_at) VALUES (?,?,?,?,?)",
                (username, ck, dk, last_read_id, now_iso()),
            )
            self._db.commit()

    def _channel_unread(self, channel_id: str, username: str) -> int:
        row = self._db.execute(
            "SELECT last_read_id FROM hubs_message_reads WHERE username=? AND channel_id=? AND dm_key=''",
            (username, channel_id),
        ).fetchone()
        last = row["last_read_id"] if row else "0"
        count = self._db.execute(
            "SELECT COUNT(*) FROM hubs_messages WHERE channel_id=? AND deleted=0 AND sender!=? AND id>?",
            (channel_id, username, last),
        ).fetchone()[0]
        return count

    def hubs_dm_unread(self, dm_key: str, username: str) -> int:
        row = self._db.execute(
            "SELECT last_read_id FROM hubs_message_reads WHERE username=? AND dm_key=? AND channel_id=''",
            (username, dm_key),
        ).fetchone()
        last = row["last_read_id"] if row else "0"
        count = self._db.execute(
            "SELECT COUNT(*) FROM hubs_messages WHERE dm_key=? AND deleted=0 AND sender!=? AND id>?",
            (dm_key, username, last),
        ).fetchone()[0]
        return count

    def hubs_dm_list(self, username: str) -> list[dict]:
        """All DM conversations involving username."""
        rows = self._db.execute(
            "SELECT DISTINCT dm_key FROM hubs_messages WHERE (dm_key LIKE ? OR dm_key LIKE ?) AND deleted=0",
            (f"{username}:%", f"%:{username}"),
        ).fetchall()
        result = []
        for r in rows:
            dk = r["dm_key"]
            parts = dk.split(":", 1)
            peer = parts[1] if parts[0] == username else parts[0]
            last_row = self._db.execute(
                "SELECT body, sender, created_at FROM hubs_messages "
                "WHERE dm_key=? AND deleted=0 ORDER BY id DESC LIMIT 1", (dk,)
            ).fetchone()
            unread = self.hubs_dm_unread(dk, username)
            result.append({
                "dm_key": dk, "peer": peer,
                "last_message": dict(last_row) if last_row else None,
                "unread": unread,
            })
        return sorted(result, key=lambda x: x["last_message"]["created_at"] if x["last_message"] else "", reverse=True)

    # ── notifications ─────────────────────────────────────────────────────

    def hubs_add_notification(self, username: str, ntype: str, sender: str,
                              channel_id: Optional[str] = None, dm_key: Optional[str] = None,
                              message_id: Optional[str] = None, body: str = "") -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO hubs_notifications (username, type, sender, channel_id, dm_key, message_id, body, created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (username, ntype, sender, channel_id, dm_key, message_id, body[:200], now_iso()),
            )
            self._db.commit()
            return cur.lastrowid

    def hubs_list_notifications(self, username: str, limit: int = 50) -> list[dict]:
        return [dict(r) for r in self._db.execute(
            "SELECT * FROM hubs_notifications WHERE username=? ORDER BY id DESC LIMIT ?",
            (username, limit),
        )]

    def hubs_mark_notifications_read(self, username: str, notif_ids: Optional[list] = None):
        with self._lock:
            if notif_ids:
                placeholders = ",".join("?" for _ in notif_ids)
                self._db.execute(
                    f"UPDATE hubs_notifications SET read=1 WHERE username=? AND id IN ({placeholders})",
                    [username] + list(notif_ids),
                )
            else:
                self._db.execute(
                    "UPDATE hubs_notifications SET read=1 WHERE username=?", (username,)
                )
            self._db.commit()

    def hubs_unread_notification_count(self, username: str) -> int:
        row = self._db.execute(
            "SELECT COUNT(*) FROM hubs_notifications WHERE username=? AND read=0", (username,)
        ).fetchone()
        return row[0]

    # ── pings ─────────────────────────────────────────────────────────────

    def hubs_send_ping(self, from_user: str, to_user: str, message: str = "") -> tuple[bool, str]:
        """Rate-limited ping. Returns (ok, error_reason)."""
        now = time.time()
        cutoff = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now - _PING_WINDOW))
        count = self._db.execute(
            "SELECT COUNT(*) FROM hubs_pings WHERE from_user=? AND to_user=? AND created_at>?",
            (from_user, to_user, cutoff),
        ).fetchone()[0]
        if count >= _PING_MAX:
            return False, f"Ping rate limit: max {_PING_MAX} per {_PING_WINDOW // 60} minutes."
        with self._lock:
            self._db.execute(
                "INSERT INTO hubs_pings (from_user, to_user, message, created_at) VALUES (?,?,?,?)",
                (from_user, to_user, message[:200], now_iso()),
            )
            self._db.commit()
        return True, ""

    def hubs_pending_pings(self, username: str) -> list[dict]:
        rows = [dict(r) for r in self._db.execute(
            "SELECT * FROM hubs_pings WHERE to_user=? AND delivered=0 ORDER BY id", (username,)
        )]
        if rows:
            ids = [r["id"] for r in rows]
            with self._lock:
                self._db.execute(
                    f"UPDATE hubs_pings SET delivered=1 WHERE id IN ({','.join('?'*len(ids))})",
                    ids,
                )
                self._db.commit()
        return rows

    # ── presence ─────────────────────────────────────────────────────────

    def hubs_heartbeat(self, username: str):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO hubs_presence (username, last_seen, status) VALUES (?,?,?)",
                (username, now_iso(), "online"),
            )
            self._db.commit()

    def hubs_online_users(self, window_seconds: int = 90) -> list[dict]:
        cutoff = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - window_seconds))
        return [dict(r) for r in self._db.execute(
            "SELECT hp.username, hp.last_seen, hp.status, u.title, u.role "
            "FROM hubs_presence hp LEFT JOIN users u ON u.username=hp.username "
            "WHERE hp.last_seen>? ORDER BY hp.username",
            (cutoff,),
        )]

    # ── user prefs ────────────────────────────────────────────────────────

    def hubs_get_prefs(self, username: str) -> dict:
        row = self._db.execute(
            "SELECT * FROM hubs_user_prefs WHERE username=?", (username,)
        ).fetchone()
        if not row:
            return {"username": username, "muted_channels": [], "muted_dms": [],
                    "sound_enabled": True, "notif_desktop": True}
        d = dict(row)
        d["muted_channels"] = json.loads(d["muted_channels"] or "[]")
        d["muted_dms"] = json.loads(d["muted_dms"] or "[]")
        d["sound_enabled"] = bool(d["sound_enabled"])
        d["notif_desktop"] = bool(d["notif_desktop"])
        return d

    def hubs_set_prefs(self, username: str, **fields):
        prefs = self.hubs_get_prefs(username)
        prefs.update(fields)
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO hubs_user_prefs "
                "(username, muted_channels, muted_dms, sound_enabled, notif_desktop) VALUES (?,?,?,?,?)",
                (username,
                 json.dumps(prefs["muted_channels"]),
                 json.dumps(prefs["muted_dms"]),
                 1 if prefs["sound_enabled"] else 0,
                 1 if prefs["notif_desktop"] else 0),
            )
            self._db.commit()

    # ── SSE event stream ─────────────────────────────────────────────────

    def hubs_events_since(self, username: str, last_msg_id: int,
                          last_ping_id: int, last_notif_id: int) -> dict:
        """Poll for new events since client's last known IDs."""
        # New messages in channels the user is a member of
        channel_ids = [r["channel_id"] for r in self._db.execute(
            "SELECT channel_id FROM hubs_channel_members WHERE username=?", (username,)
        )]
        new_messages = []
        if channel_ids:
            placeholders = ",".join("?" for _ in channel_ids)
            rows = self._db.execute(
                f"SELECT * FROM hubs_messages WHERE channel_id IN ({placeholders}) "
                f"AND deleted=0 AND id>? ORDER BY id LIMIT 30",
                [*channel_ids, str(last_msg_id)],
            ).fetchall()
            new_messages.extend(dict(r) for r in rows)
        # New DMs
        dm_rows = self._db.execute(
            "SELECT * FROM hubs_messages WHERE (dm_key LIKE ? OR dm_key LIKE ?) "
            "AND deleted=0 AND id>? ORDER BY id LIMIT 20",
            (f"{username}:%", f"%:{username}", str(last_msg_id)),
        ).fetchall()
        new_messages.extend(dict(r) for r in dm_rows)

        # Pending pings
        new_pings = self.hubs_pending_pings(username)

        # New notifications
        new_notifs = [dict(r) for r in self._db.execute(
            "SELECT * FROM hubs_notifications WHERE username=? AND id>? ORDER BY id LIMIT 20",
            (username, last_notif_id),
        )]

        return {
            "messages": new_messages,
            "pings": new_pings,
            "notifications": new_notifs,
        }
