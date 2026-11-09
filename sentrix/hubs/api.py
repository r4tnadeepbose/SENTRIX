"""HTTP-facing Hubs API.

Every handler returns ``(payload, status_code)`` — or ``None`` when the path is
not a Hubs route, which lets the server fall through to its other APIs.

Security model
--------------
* ``open-chat`` is readable and writable by every signed-in member.
* A direct message is readable only by its two participants. There is no
  administrative directory of conversations and no route that reads a DM on
  someone else's behalf.
* Pings are unlimited person-to-person signals; only self-pings are rejected.
"""
from __future__ import annotations

import re
import secrets

from sentrix.auth import WRITE_ROLES
from sentrix.hubs.storage import OPEN_CHAT, dm_key

_CHANNEL_MESSAGES = re.compile(r"^/api/hubs/channels/([A-Za-z0-9_\-]+)/messages$")
_CHANNEL_ACTION = re.compile(r"^/api/hubs/channels/([A-Za-z0-9_\-]+)/(join|leave)$")
_DM_MESSAGES = re.compile(r"^/api/hubs/dm/([A-Za-z0-9_.@+\-]+)/messages$")
_MESSAGE_ACTION = re.compile(r"^/api/hubs/messages/([A-Za-z0-9_\-]+)/(edit|delete)$")

MAX_BODY = 4000


class HubsAPI:
    def __init__(self, state):
        self.state = state
        self.storage = state.storage

    # ── helpers ───────────────────────────────────────────────────────────

    def _roster(self) -> set[str]:
        return set(self.state.auth.roster_usernames())

    def _known(self, username: str) -> bool:
        return username in self._roster() and bool(self.storage.get_user(username))

    def _online(self) -> set[str]:
        return {row["username"] for row in self.storage.hubs_online_users()}

    # ── GET ───────────────────────────────────────────────────────────────

    def handle_get(self, path: str, query: dict, user: dict):
        uname = user["username"]
        storage = self.storage

        if path == "/api/hubs/channels":
            storage.hubs_heartbeat(uname)
            return {
                "channels": storage.hubs_list_channels(uname),
                "dms": storage.hubs_dm_list(uname),
                "online_users": storage.hubs_online_users(),
                "unread_notifications": storage.hubs_unread_notification_count(uname),
                "role": user.get("role", ""),
                "read_only": user.get("role") not in WRITE_ROLES,
            }, 200

        if path == "/api/hubs/users":
            storage.hubs_heartbeat(uname)
            online = self._online()
            roster = self._roster()
            people = [
                {
                    "username": row["username"],
                    "title": row.get("title", ""),
                    "role": row["role"],
                    "online": row["username"] in online,
                }
                for row in storage.list_users()
                if row["username"] != uname
                and not row.get("disabled")
                and row["username"] in roster
            ]
            return {"users": people}, 200

        match = _CHANNEL_MESSAGES.match(path)
        if match:
            channel_id = match.group(1)
            storage.hubs_heartbeat(uname)
            channel = storage.hubs_channel(channel_id)
            if not channel:
                return {"error": "channel not found"}, 404
            if channel.get("is_default") == 1:
                storage.hubs_join_channel(channel_id, uname)
            elif not storage.hubs_is_channel_member(channel_id, uname):
                return {"error": "channel membership required"}, 403
            messages = storage.hubs_get_messages(
                channel_id, None, before_id=query.get("before"), limit=50)
            return {
                "messages": messages,
                "members": storage.hubs_channel_members(channel_id),
            }, 200

        match = _DM_MESSAGES.match(path)
        if match:
            peer = match.group(1)
            if peer == uname:
                return {"error": "cannot open a direct message with yourself"}, 400
            if not self._known(peer):
                return {"error": "user not found"}, 404
            storage.hubs_heartbeat(uname)
            key = dm_key(uname, peer)
            messages = storage.hubs_get_messages(
                None, key, before_id=query.get("before"), limit=50)
            profile = storage.get_user(peer) or {}
            peer_info = {
                "username": profile.get("username", peer),
                "title": profile.get("title", ""),
                "role": profile.get("role", ""),
            }
            return {
                "messages": messages,
                "peer": peer_info,
                "dm_key": key,
            }, 200

        if path == "/api/hubs/notifications":
            notifications = storage.hubs_list_notifications(uname)
            return {
                "notifications": notifications,
                "unread": sum(1 for n in notifications if not n["read"]),
            }, 200

        if path == "/api/hubs/events":
            storage.hubs_heartbeat(uname)

            def number(name: str) -> int:
                try:
                    return max(0, int(query.get(name, 0)))
                except (TypeError, ValueError):
                    return 0

            return storage.hubs_events_since(
                uname, number("last_msg"), number("last_ping"),
                number("last_notif"),
            ), 200

        if path == "/api/hubs/online":
            storage.hubs_heartbeat(uname)
            return {"online": storage.hubs_online_users()}, 200

        if path == "/api/hubs/prefs":
            return {"prefs": storage.hubs_get_prefs(uname)}, 200

        return None

    # ── POST ──────────────────────────────────────────────────────────────

    def handle_post(self, path: str, body: dict, user: dict):
        uname = user["username"]
        storage = self.storage

        if path == "/api/hubs/channels":
            return {
                "error": "Hubs uses one shared Open Chat channel; "
                         "channels cannot be created."
            }, 403

        match = _CHANNEL_ACTION.match(path)
        if match:
            channel_id, action = match.groups()
            if not storage.hubs_channel(channel_id):
                return {"error": "channel not found"}, 404
            if action == "leave":
                if channel_id == OPEN_CHAT:
                    return {"error": "Open Chat cannot be left"}, 400
                return {"error": "only Open Chat exists"}, 400
            storage.hubs_join_channel(channel_id, uname)
            return {"ok": True}, 200

        match = _CHANNEL_MESSAGES.match(path)
        if match:
            return self._post_channel(match.group(1), body, uname)

        match = _DM_MESSAGES.match(path)
        if match:
            peer = match.group(1)
            if peer == uname:
                return {"error": "cannot DM yourself"}, 400
            if not self._known(peer):
                return {"error": "user not found"}, 404
            text = str(body.get("body", "")).strip()[:MAX_BODY]
            if not text:
                return {"error": "body required"}, 400
            key = dm_key(uname, peer)
            message_id = "msg-" + secrets.token_hex(8)
            message = storage.hubs_post_message(
                message_id, None, key, uname, text, reply_to=body.get("reply_to"))
            if key not in storage.hubs_get_prefs(peer).get("muted_dms", []):
                storage.hubs_add_notification(
                    peer, "direct_message", uname, dm_key_value=key,
                    message_id=message_id, body=text[:120])
            return {"ok": True, "message": message}, 200

        match = _MESSAGE_ACTION.match(path)
        if match:
            message_id, action = match.groups()
            if action == "delete":
                return {"ok": storage.hubs_delete_message(message_id, uname)}, 200
            text = str(body.get("body", "")).strip()[:MAX_BODY]
            if not text:
                return {"error": "body required"}, 400
            return {"ok": storage.hubs_edit_message(message_id, uname, text)}, 200

        if path == "/api/hubs/ping":
            target = str(body.get("to_user", "")).strip()
            note = str(body.get("message", "")).strip()[:200]
            if not target:
                return {"error": "to_user required"}, 400
            if target == uname:
                return {"error": "cannot ping yourself"}, 400
            if not self._known(target):
                return {"error": "user not found"}, 404
            storage.hubs_send_ping(uname, target, note)
            storage.hubs_add_notification(
                target, "ping", uname, body=note or f"{uname} pinged you")
            self.state.auth.audit("hubs.ping", uname, f"→ {target}")
            return {"ok": True}, 200

        if path == "/api/hubs/mark-read":
            last_id = str(body.get("last_id", ""))
            if not last_id:
                return {"error": "last_id required"}, 400
            storage.hubs_mark_read(
                uname, body.get("channel_id"), body.get("dm_key"), last_id)
            return {"ok": True}, 200

        if path == "/api/hubs/notifications/read":
            ids = body.get("ids")
            storage.hubs_mark_notifications_read(
                uname, ids if isinstance(ids, list) else None)
            return {"ok": True}, 200

        if path == "/api/hubs/prefs":
            updates = {}
            if "sound_enabled" in body:
                updates["sound_enabled"] = bool(body["sound_enabled"])
            if "notif_desktop" in body:
                updates["notif_desktop"] = bool(body["notif_desktop"])
            if isinstance(body.get("muted_channels"), list):
                updates["muted_channels"] = [
                    str(c)[:80] for c in body["muted_channels"][:50]]
            if isinstance(body.get("muted_dms"), list):
                updates["muted_dms"] = [
                    str(d)[:80] for d in body["muted_dms"][:50]]
            if updates:
                storage.hubs_set_prefs(uname, **updates)
            return {"ok": True}, 200

        if path == "/api/hubs/heartbeat":
            storage.hubs_heartbeat(uname)
            return {"ok": True}, 200

        return None

    # ── channel message posting ───────────────────────────────────────────

    def _post_channel(self, channel_id: str, body: dict, uname: str):
        storage = self.storage
        text = str(body.get("body", "")).strip()[:MAX_BODY]
        if not text:
            return {"error": "body required"}, 400
        channel = storage.hubs_channel(channel_id)
        if not channel:
            return {"error": "channel not found"}, 404
        if channel.get("is_default") == 1:
            storage.hubs_join_channel(channel_id, uname)
        elif not storage.hubs_is_channel_member(channel_id, uname):
            return {"error": "not a member"}, 403

        message_id = "msg-" + secrets.token_hex(8)
        message = storage.hubs_post_message(
            message_id, channel_id, None, uname, text,
            reply_to=body.get("reply_to"))

        for member in storage.hubs_channel_members(channel_id):
            recipient = member["username"]
            if recipient == uname:
                continue
            if channel_id not in storage.hubs_get_prefs(recipient).get("muted_channels", []):
                storage.hubs_add_notification(
                    recipient, "channel_message", uname,
                    channel_id=channel_id, message_id=message_id, body=text[:120])
        return {"ok": True, "message": message}, 200
