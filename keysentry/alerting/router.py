"""Route findings to configured channels with dedupe and dry-run safety."""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from keysentry.config import ROOT, resolve_path
from keysentry.core.models import Alert, Finding
from keysentry.core.storage import Storage


class AlertRouter:
    def __init__(self, cfg: dict, storage: Storage):
        self.cfg = cfg
        self.storage = storage
        self.outbox = resolve_path(cfg, "data/outbox")
        self.outbox.mkdir(parents=True, exist_ok=True)

    def send(self, finding: Finding) -> list[Alert]:
        alert_cfg = self.cfg.get("alerting", {})
        window = alert_cfg.get("dedupe_window_seconds", 3600)
        if self.storage.recent_alert_for(finding.id, window):
            return []
        message = (
            f"[{finding.severity.upper()}] {finding.title} on {finding.surface} "
            f"at {finding.path}:{finding.line} (masked: {finding.secret_masked})"
        )
        sent: list[Alert] = []
        for channel in alert_cfg.get("channels", ["console", "outbox"]):
            alert = Alert(finding_id=finding.id, channel=channel, message=message)
            if channel == "console":
                print(f"  ALERT {message}")
            elif channel == "outbox":
                (self.outbox / f"{alert.id}.json").write_text(
                    json.dumps(alert.to_dict(), indent=2), encoding="utf-8")
            elif channel == "slack":
                alert.status = self._post_json(
                    alert_cfg.get("slack_webhook", ""), {"text": message})
            elif channel == "webhook":
                alert.status = self._post_json(
                    alert_cfg.get("webhook_url", ""),
                    {"finding": finding.to_dict(), "message": message})
            self.storage.add_alert(alert)
            sent.append(alert)
        return sent

    @staticmethod
    def _post_json(url: str, payload: dict) -> str:
        if not url:
            return "dry-run"
        try:
            req = urllib.request.Request(
                url, data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                return "sent" if resp.status < 300 else f"http-{resp.status}"
        except Exception as exc:
            return f"failed: {exc}"