"""Slack surface: export scanning plus optional live, rate-limited polling."""
from __future__ import annotations

from keysentry.config import cfg_get, env_secret
from keysentry.core.engine import scan_text
from keysentry.core.models import Finding
from keysentry.surfaces.common import load_export, rate_limit, rest_json


def scan_export(path: str, allowlist=None) -> list[Finding]:
    data = load_export(path)
    messages = data if isinstance(data, list) else data.get("messages", [])
    findings: list[Finding] = []
    for msg in messages:
        channel = msg.get("channel", "unknown")
        ts = msg.get("ts", "")
        text = msg.get("text", "")
        for finding in scan_text(text, f"slack:#{channel}/{ts}", "slack", allowlist):
            finding.owner = msg.get("user", "")
            findings.append(finding)
    return findings


def live_scan(cfg: dict, allowlist=None) -> list[Finding]:
    token = env_secret(cfg, "surfaces.slack.token_env")
    if not token:
        return []
    headers = {"Authorization": f"Bearer {token}"}
    channels = cfg_get(cfg, "surfaces.slack.channels", [])
    findings: list[Finding] = []
    for channel in channels:
        cursor = None
        while True:
            url = (f"https://slack.com/api/conversations.history?channel={channel}&limit=200")
            if cursor:
                url += f"&cursor={cursor}"
            body = rest_json(url, headers)
            if not body.get("ok"):
                break
            for msg in body.get("messages", []):
                for finding in scan_text(
                        msg.get("text", ""), f"slack:#{channel}/{msg.get('ts', '')}",
                        "slack", allowlist):
                    finding.owner = msg.get("user", "")
                    findings.append(finding)
            cursor = body.get("response_metadata", {}).get("next_cursor")
            rate_limit()
            if not cursor:
                break
    return findings