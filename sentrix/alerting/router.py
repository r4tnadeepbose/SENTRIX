"""Route findings to configured channels with rules, quiet hours, retries, dedupe."""
from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path

from sentrix.config import resolve_path
from sentrix.core.models import Alert, Finding
from sentrix.core.storage import Storage
from sentrix.core.util import at_least


class AlertRouter:
    def __init__(self, cfg: dict, storage: Storage):
        self.cfg = cfg
        self.storage = storage
        self.outbox = resolve_path(cfg, "data/outbox")
        self.outbox.mkdir(parents=True, exist_ok=True)

    def _quiet_now(self) -> bool:
        quiet = self.cfg.get("alerting", {}).get("quiet_hours", {})
        start, end = quiet.get("start"), quiet.get("end")
        if not start or not end:
            return False
        now = time.strftime("%H:%M", time.gmtime())
        if start <= end:
            return start <= now < end
        return now >= start or now < end

    def _channel_allowed(self, channel: str, finding: Finding) -> bool:
        if hasattr(self.storage, "list_rules"):
            for rule in self.storage.list_rules():
                if rule["channel"] == channel and rule["enabled"]:
                    return at_least(finding.severity, rule["min_severity"])
        return True

    def send(self, finding: Finding) -> list[Alert]:
        alert_cfg = self.cfg.get("alerting", {})
        window = alert_cfg.get("dedupe_window_seconds", 3600)
        if self.storage.recent_alert_for(finding.id, window):
            return []
        if hasattr(self.storage, "get_extra") and self.storage.get_extra(finding.id)["muted"]:
            return []
        message = (
            f"[{finding.severity.upper()}] {finding.title} on {finding.surface} "
            f"at {finding.path}:{finding.line} (masked: {finding.secret_masked})"
        )
        sent: list[Alert] = []
        for channel in alert_cfg.get("channels", ["console", "outbox"]):
            if not self._channel_allowed(channel, finding):
                continue
            alert = Alert(finding_id=finding.id, channel=channel, message=message)
            if channel == "console":
                print(f"  ALERT {message}")
            elif channel == "outbox":
                (self.outbox / f"{alert.id}.json").write_text(
                    json.dumps(alert.to_dict(), indent=2), encoding="utf-8")
            elif channel in ("slack", "webhook"):
                if self._quiet_now():
                    alert.status = "deferred-quiet-hours"
                else:
                    url = alert_cfg.get(
                        "slack_webhook" if channel == "slack" else "webhook_url", "")
                    payload = self.slack_payload(finding, message) if channel == "slack" else {
                        "finding": finding.to_dict(), "message": message}
                    alert.status = self._post_json(url, payload)
            self.storage.add_alert(alert)
            sent.append(alert)
        return sent

    @staticmethod
    def slack_payload(finding: Finding, message: str) -> dict:
        """Every secret posts to the channel and mentions the responsible user."""
        text = message
        if finding.owner:
            import re
            text += f" <@{finding.owner}>" if re.match(
                r"^U[A-Z0-9]{8,}$", finding.owner) else f" cc @{finding.owner}"
        return {"text": text}

    @staticmethod
    def _post_json(url: str, payload: dict) -> str:
        if not url:
            return "dry-run"
        last = "failed: no attempt"
        for delay in (0, 1, 2):
            if delay:
                time.sleep(delay)
            try:
                req = urllib.request.Request(
                    url, data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    if resp.status < 300:
                        return "sent"
                    last = f"http-{resp.status}"
            except Exception as exc:
                last = f"failed: {exc}"
        return last