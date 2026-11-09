"""SQLite persistence for Hubs: Open Chat, private DMs, pings and notifications.

Only one shared channel exists — ``open-chat``. Everything else is a private
conversation keyed by two usernames in a canonical, order-independent form.
The schema is unchanged from earlier releases so existing Open Chat history is
preserved when the workspace is upgraded.
"""
from __future__ import annotations

import json
import time
from typing import Optional

from sentrix.core.models import now_iso

OPEN_CHAT = "open-chat"
ONLINE_WINDOW_SECONDS = 120

SCHEMA = """
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


def dm_key(a: str, b: str) -> str:
    """Canonical private-conversation key: the smaller username comes first."""
    return f"{min(a, b)}:{max(a, b)}"


def _dm_patterns(username: str) -> tuple[str, str]:
    """LIKE patterns that match only this user's DM keys.

    Usernames may contain ``_``, ``%`` or ``\\``; escaping keeps a conversation
    from leaking into another account whose name merely looks similar.
    """
    escaped = username.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"{escaped}:%", f"%:{escaped}"


def _cutoff(seconds: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - seconds))


class HubsStorage:
    """Mixin attached to ``ExtStorage``; expects ``self._db`` and ``self._lock``."""

    # ── lifecycle ─────────────────────────────────────────────────────────

    def hubs_init(self) -> None:
        self._db.executescript(SCHEMA)
        self._db.commit()
        self._reset_workspace()

    def _reset_workspace(self) -> None:
        """Keep exactly one shared channel and discard legacy team rooms."""
        with self._lock:
            self._db.execute(
                "DELETE FROM hubs_channel_members WHERE channel_id NOT IN ('', ?)",
                (OPEN_CHAT,),
            )
            self._db.execute(
                "DELETE FROM hubs_messages WHERE channel_id NOT IN ('', ?) "
                "AND channel_id IS NOT NULL",
                (OPEN_CHAT,),
            )
            self._db.execute(
                "DELETE FROM hubs_message_reads WHERE channel_id NOT IN ('', ?) "
                "AND channel_id IS NOT NULL",
                (OPEN_CHAT,),
            )
            self._db.execute(
                "DELETE FROM hubs_notifications WHERE channel_id NOT IN ('', ?) "
                "AND channel_id IS NOT NULL",
                (OPEN_CHAT,),
            )
            self._db.execute("DELETE FROM hubs_channels WHERE id!=?", (OPEN_CHAT,))
            self._db.execute(
                "INSERT OR IGNORE INTO hubs_channels "
                "(id, name, description, created_by, created_at, is_default) "
                "VALUES (?,?,?,'system',?,1)",
                (OPEN_CHAT, "Open Chat",
                 "Organization-wide conversation for the whole company.", now_iso()),
            )
            self._db.execute(
                "UPDATE hubs_channels SET name='Open Chat', "
                "description='Organization-wide conversation for the whole company.', "
                "is_default=1, archived=0 WHERE id=?",
                (OPEN_CHAT,),
            )
            self._db.commit()

    def hubs_ensure_open_chat(self, usernames) -> None:
        """Guarantee that every roster member can read Open Chat."""
        with self._lock:
            for username in usernames:
                self._db.execute(
                    "INSERT OR IGNORE INTO hubs_channel_members "
                    "(channel_id, username, joined_at, role) VALUES (?,?,?,'member')",
                    (OPEN_CHAT, username, now_iso()),
                )
            self._db.commit()

    def hubs_purge_user(self, username: str) -> None:
        """Remove every Hubs record owned by, sent by or addressed to a user."""
        threads = self._db.execute(
            "SELECT DISTINCT dm_key FROM hubs_messages "
            "WHERE dm_key LIKE ? ESCAPE '\\' OR dm_key LIKE ? ESCAPE '\\'",
            _dm_patterns(username),
        ).fetchall()
        with self._lock:
            for row in threads:
                key = row["dm_key"]
                self._db.execute("DELETE FROM hubs_messages WHERE dm_key=?", (key,))
                self._db.execute("DELETE FROM hubs_message_reads WHERE dm_key=?", (key,))
                self._db.execute("DELETE FROM hubs_notifications WHERE dm_key=?", (key,))
            self._db.execute("DELETE FROM hubs_messages WHERE sender=?", (username,))
            self._db.execute("DELETE FROM hubs_channel_members WHERE username=?", (username,))
            self._db.execute("DELETE FROM hubs_message_reads WHERE username=?", (username,))
            self._db.execute(
                "DELETE FROM hubs_notifications WHERE username=? OR sender=?",
                (username, username),
            )
            self._db.execute(
                "DELETE FROM hubs_pings WHERE from_user=? OR to_user=?",
                (username, username),
            )
            self._db.execute("DELETE FROM hubs_presence WHERE username=?", (username,))
            self._db.execute("DELETE FROM hubs_user_prefs WHERE username=?", (username,))
            self._db.commit()

    # ── channels ──────────────────────────────────────────────────────────

    def hubs_list_channels(self, username: str) -> list[dict]:
        rows = self._db.execute(
            "SELECT c.*, "
            "(SELECT COUNT(*) FROM hubs_channel_members m "
            " WHERE m.channel_id=c.id AND m.username=?) AS joined "
            "FROM hubs_channels c WHERE c.archived=0 "
            "ORDER BY c.is_default DESC, c.name",
            (username,),
        ).fetchall()
        channels = []
        for row in rows:
            item = dict(row)
            item["joined"] = bool(item["joined"])
            item["unread"] = self._channel_unread(row["id"], username)
            channels.append(item)
        return channels

    def hubs_join_channel(self, channel_id: str, username: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO hubs_channel_members "
                "(channel_id, username, joined_at) VALUES (?,?,?)",
                (channel_id, username, now_iso()),
            )
            self._db.commit()

    def hubs_is_channel_member(self, channel_id: str, username: str) -> bool:
        row = self._db.execute(
            "SELECT 1 FROM hubs_channel_members WHERE channel_id=? AND username=?",
            (channel_id, username),
        ).fetchone()
        return row is not None

    def hubs_channel(self, channel_id: str) -> Optional[dict]:
        row = self._db.execute(
            "SELECT * FROM hubs_channels WHERE id=?", (channel_id,)
        ).fetchone()
        return dict(row) if row else None

    def hubs_channel_members(self, channel_id: str) -> list[dict]:
        return [dict(row) for row in self._db.execute(
            "SELECT m.username, m.role, m.joined_at, u.title, u.role AS user_role "
            "FROM hubs_channel_members m "
            "LEFT JOIN users u ON u.username=m.username "
            "WHERE m.channel_id=? ORDER BY m.joined_at, m.username",
            (channel_id,),
        )]

    # ── messages ──────────────────────────────────────────────────────────

    def hubs_post_message(self, msg_id: str, channel_id: Optional[str],
                          dm_key_value: Optional[str], sender: str, body: str,
                          reply_to: Optional[str] = None) -> dict:
        created = now_iso()
        with self._lock:
            self._db.execute(
                "INSERT INTO hubs_messages "
                "(id, channel_id, dm_key, sender, body, reply_to, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (msg_id, channel_id, dm_key_value, sender, body, reply_to, created),
            )
            self._db.commit()
            seq = self._db.execute(
                "SELECT rowid FROM hubs_messages WHERE id=?", (msg_id,)
            ).fetchone()[0]
        return {
            "id": msg_id, "seq": seq, "channel_id": channel_id,
            "dm_key": dm_key_value, "sender": sender, "body": body,
            "reply_to": reply_to, "edited": 0, "created_at": created,
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

    def hubs_delete_message(self, msg_id: str, username: str) -> bool:
        """Only the author can remove a message, in Open Chat or a DM."""
        row = self._db.execute(
            "SELECT sender FROM hubs_messages WHERE id=? AND deleted=0", (msg_id,)
        ).fetchone()
        if not row or row["sender"] != username:
            return False
        with self._lock:
            self._db.execute(
                "UPDATE hubs_messages SET deleted=1, body='' WHERE id=?", (msg_id,)
            )
            self._db.commit()
        return True

    def hubs_get_messages(self, channel_id: Optional[str], dm_key_value: Optional[str],
                          before_id: Optional[str] = None, limit: int = 50) -> list[dict]:
        if channel_id:
            column, value = "channel_id", channel_id
        elif dm_key_value:
            column, value = "dm_key", dm_key_value
        else:
            return []

        before_seq = None
        if before_id:
            row = self._db.execute(
                "SELECT rowid FROM hubs_messages WHERE id=?", (before_id,)
            ).fetchone()
            if not row:
                return []
            before_seq = row[0]

        sql = (f"SELECT rowid AS seq, * FROM hubs_messages "
               f"WHERE {column}=? AND deleted=0")
        params: list = [value]
        if before_seq is not None:
            sql += " AND rowid<?"
            params.append(before_seq)
        sql += " ORDER BY rowid DESC LIMIT ?"
        params.append(limit)
        rows = self._db.execute(sql, params).fetchall()
        return [dict(row) for row in reversed(rows)]

    # ── read markers ──────────────────────────────────────────────────────

    def hubs_mark_read(self, username: str, channel_id: Optional[str],
                       dm_key_value: Optional[str], last_read_id: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO hubs_message_reads "
                "(username, channel_id, dm_key, last_read_id, updated_at) "
                "VALUES (?,?,?,?,?)",
                (username, channel_id or "", dm_key_value or "", last_read_id, now_iso()),
            )
            self._db.commit()

    def _last_read_seq(self, username: str, channel_id: Optional[str],
                       dm_key_value: Optional[str]) -> int:
        if channel_id:
            row = self._db.execute(
                "SELECT last_read_id FROM hubs_message_reads "
                "WHERE username=? AND channel_id=? AND dm_key=''",
                (username, channel_id),
            ).fetchone()
        else:
            row = self._db.execute(
                "SELECT last_read_id FROM hubs_message_reads "
                "WHERE username=? AND dm_key=? AND channel_id=''",
                (username, dm_key_value or ""),
            ).fetchone()
        if not row:
            return 0
        seq = self._db.execute(
            "SELECT rowid FROM hubs_messages WHERE id=?", (row["last_read_id"],)
        ).fetchone()
        return seq[0] if seq else 0

    def _channel_unread(self, channel_id: str, username: str) -> int:
        return self._db.execute(
            "SELECT COUNT(*) FROM hubs_messages WHERE channel_id=? AND deleted=0 "
            "AND sender!=? AND rowid>?",
            (channel_id, username,
             self._last_read_seq(username, channel_id, None)),
        ).fetchone()[0]

    def hubs_dm_unread(self, key: str, username: str) -> int:
        return self._db.execute(
            "SELECT COUNT(*) FROM hubs_messages WHERE dm_key=? AND deleted=0 "
            "AND sender!=? AND rowid>?",
            (key, username, self._last_read_seq(username, None, key)),
        ).fetchone()[0]

    # ── direct messages ───────────────────────────────────────────────────

    def hubs_dm_list(self, username: str) -> list[dict]:
        """This user's private conversations, most recently active first."""
        rows = self._db.execute(
            "SELECT DISTINCT dm_key FROM hubs_messages "
            "WHERE (dm_key LIKE ? ESCAPE '\\' OR dm_key LIKE ? ESCAPE '\\') "
            "AND deleted=0",
            _dm_patterns(username),
        ).fetchall()
        conversations = []
        for row in rows:
            key = row["dm_key"]
            parts = key.split(":", 1)
            peer = parts[1] if parts[0] == username else parts[0]
            last = self._db.execute(
                "SELECT rowid AS seq, body, sender, created_at FROM hubs_messages "
                "WHERE dm_key=? AND deleted=0 ORDER BY rowid DESC LIMIT 1", (key,)
            ).fetchone()
            conversations.append((
                last["seq"] if last else 0,
                {
                    "dm_key": key,
                    "peer": peer,
                    "last_message": dict(last) if last else None,
                    "unread": self.hubs_dm_unread(key, username),
                },
            ))
        conversations.sort(key=lambda item: item[0], reverse=True)
        return [item for _, item in conversations]

    # ── notifications ─────────────────────────────────────────────────────

    def hubs_add_notification(self, username: str, ntype: str, sender: str,
                              channel_id: Optional[str] = None,
                              dm_key_value: Optional[str] = None,
                              message_id: Optional[str] = None,
                              body: str = "") -> int:
        with self._lock:
            cursor = self._db.execute(
                "INSERT INTO hubs_notifications "
                "(username, type, sender, channel_id, dm_key, message_id, body, created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (username, ntype, sender, channel_id, dm_key_value,
                 message_id, body[:200], now_iso()),
            )
            self._db.commit()
            return cursor.lastrowid

    def hubs_list_notifications(self, username: str, limit: int = 50) -> list[dict]:
        return [dict(row) for row in self._db.execute(
            "SELECT * FROM hubs_notifications WHERE username=? ORDER BY id DESC LIMIT ?",
            (username, limit),
        )]

    def hubs_mark_notifications_read(self, username: str,
                                     notif_ids: Optional[list] = None) -> None:
        with self._lock:
            if notif_ids:
                placeholders = ",".join("?" for _ in notif_ids)
                self._db.execute(
                    f"UPDATE hubs_notifications SET read=1 "
                    f"WHERE username=? AND id IN ({placeholders})",
                    [username, *notif_ids],
                )
            else:
                self._db.execute(
                    "UPDATE hubs_notifications SET read=1 WHERE username=?", (username,)
                )
            self._db.commit()

    def hubs_unread_notification_count(self, username: str) -> int:
        return self._db.execute(
            "SELECT COUNT(*) FROM hubs_notifications WHERE username=? AND read=0",
            (username,),
        ).fetchone()[0]

    # ── pings ─────────────────────────────────────────────────────────────

    def hubs_send_ping(self, from_user: str, to_user: str, message: str = "") -> None:
        """Record a ping. Pings are unlimited person-to-person signals."""
        with self._lock:
            self._db.execute(
                "INSERT INTO hubs_pings (from_user, to_user, message, created_at) "
                "VALUES (?,?,?,?)",
                (from_user, to_user, message[:200], now_iso()),
            )
            self._db.commit()

    def hubs_pending_pings(self, username: str) -> list[dict]:
        rows = [dict(row) for row in self._db.execute(
            "SELECT * FROM hubs_pings WHERE to_user=? AND delivered=0 ORDER BY id",
            (username,),
        )]
        if rows:
            ids = [row["id"] for row in rows]
            with self._lock:
                self._db.execute(
                    f"UPDATE hubs_pings SET delivered=1 "
                    f"WHERE id IN ({','.join('?' * len(ids))})",
                    ids,
                )
                self._db.commit()
        return rows

    # ── presence ──────────────────────────────────────────────────────────

    def hubs_heartbeat(self, username: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO hubs_presence (username, last_seen, status) "
                "VALUES (?,?,'online')",
                (username, now_iso()),
            )
            self._db.commit()

    def hubs_online_users(self, window_seconds: int = ONLINE_WINDOW_SECONDS) -> list[dict]:
        return [dict(row) for row in self._db.execute(
            "SELECT p.username, p.last_seen, p.status, u.title, u.role "
            "FROM hubs_presence p LEFT JOIN users u ON u.username=p.username "
            "WHERE p.last_seen>? ORDER BY p.username",
            (_cutoff(window_seconds),),
        )]

    # ── preferences ───────────────────────────────────────────────────────

    def hubs_get_prefs(self, username: str) -> dict:
        row = self._db.execute(
            "SELECT * FROM hubs_user_prefs WHERE username=?", (username,)
        ).fetchone()
        if not row:
            return {
                "username": username, "muted_channels": [], "muted_dms": [],
                "sound_enabled": True, "notif_desktop": True,
            }
        prefs = dict(row)
        prefs["muted_channels"] = json.loads(prefs["muted_channels"] or "[]")
        prefs["muted_dms"] = json.loads(prefs["muted_dms"] or "[]")
        prefs["sound_enabled"] = bool(prefs["sound_enabled"])
        prefs["notif_desktop"] = bool(prefs["notif_desktop"])
        return prefs

    def hubs_set_prefs(self, username: str, **fields) -> None:
        prefs = self.hubs_get_prefs(username)
        prefs.update(fields)
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO hubs_user_prefs "
                "(username, muted_channels, muted_dms, sound_enabled, notif_desktop) "
                "VALUES (?,?,?,?,?)",
                (username,
                 json.dumps(prefs["muted_channels"]),
                 json.dumps(prefs["muted_dms"]),
                 1 if prefs["sound_enabled"] else 0,
                 1 if prefs["notif_desktop"] else 0),
            )
            self._db.commit()

    # ── event polling ─────────────────────────────────────────────────────

    def hubs_events_since(self, username: str, last_msg_seq: int,
                          last_ping_id: int = 0, last_notif_id: int = 0) -> dict:
        """Return activity after the client's cursors.

        ``seq`` is SQLite's insertion sequence, which is monotonic even though
        message ids are random.
        """
        channel_ids = [row["channel_id"] for row in self._db.execute(
            "SELECT channel_id FROM hubs_channel_members WHERE username=?",
            (username,),
        )]
        conditions = ["(dm_key LIKE ? ESCAPE '\\' OR dm_key LIKE ? ESCAPE '\\')"]
        params: list = [last_msg_seq]
        if channel_ids:
            conditions.insert(
                0, f"channel_id IN ({','.join('?' for _ in channel_ids)})")
            params.extend(channel_ids)
        params.extend(_dm_patterns(username))
        rows = self._db.execute(
            f"SELECT rowid AS seq, * FROM hubs_messages "
            f"WHERE deleted=0 AND rowid>? AND ({' OR '.join(conditions)}) "
            f"ORDER BY rowid LIMIT 50",
            params,
        ).fetchall()
        messages = [dict(row) for row in rows]
        pings = self.hubs_pending_pings(username)
        notifications = [dict(row) for row in self._db.execute(
            "SELECT * FROM hubs_notifications WHERE username=? AND id>? ORDER BY id LIMIT 20",
            (username, last_notif_id),
        )]
        return {
            "messages": messages,
            "pings": pings,
            "notifications": notifications,
            "cursor": {
                "last_msg": max((m["seq"] for m in messages), default=last_msg_seq),
                "last_notif": max((n["id"] for n in notifications),
                                  default=last_notif_id),
            },
        }
