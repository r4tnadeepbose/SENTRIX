"""Unified flow: event -> scan -> alert -> remediation."""
from __future__ import annotations

from sentrix.ai.triage import heuristic_triage
from sentrix.core.allowlist import Allowlist
from sentrix.core.models import Event, Finding, now_iso
from sentrix.core.storage import Storage
from sentrix.core.util import at_least

SAAS_SURFACES = ("slack", "confluence", "jira", "postman")


class Pipeline:
    def __init__(self, cfg: dict, storage: Storage, router=None):
        self.cfg = cfg
        self.storage = storage
        self.router = router
        self.allowlist = Allowlist(
            fingerprints=storage.allowlist_fingerprints(),
            extra_patterns=cfg.get("scan", {}).get("allowlist_patterns", []),
        )

    def refresh_allowlist(self):
        self.allowlist.fingerprints = self.storage.allowlist_fingerprints()

    def ingest(self, findings: list[Finding], kind: str = "scan.completed", owner: str = "",
               provenance: dict | None = None) -> dict:
        new: list[Finding] = []
        known: list[Finding] = []
        for finding in findings:
            if self.allowlist.is_allowed(finding.fingerprint, finding.secret_masked, finding.path):
                continue
            if owner and not finding.owner:
                finding.owner = owner
            origin = finding.meta.setdefault("origin", {})
            origin.update({"surface": finding.surface, "event": kind,
                           "recorded_at": now_iso(), **(provenance or {})})
            from sentrix.core import risk
            finding.meta["risk"] = risk.score(finding)
            if self.storage.upsert_finding(finding):
                new.append(finding)
            else:
                known.append(finding)
        self.storage.add_event(Event(
            kind=kind,
            surface=findings[0].surface if findings else "system",
            payload={"new": len(new), "known": len(known),
                     "paths": sorted({f.path for f in findings})[:20]},
        ))
        for finding in new:
            self._confirm_and_notify(finding)
        return {"new": new, "known": known}

    def _confirm_and_notify(self, finding: Finding):
        """SaaS branch: confirmed findings alert; unconfirmed are logged for audit."""
        if finding.surface in SAAS_SURFACES:
            verdict = heuristic_triage(finding)
            finding.meta["triage"] = verdict
            self.storage.set_meta(finding.id, finding.meta)
            if verdict["verdict"] == "likely_false_positive":
                self.storage.set_status(finding.id, "false_positive", "auto-triage")
                self.storage.add_log(
                    "info", "audit",
                    f"Finding {finding.id} not confirmed ({verdict['confidence']}); "
                    "ignored and logged for audit")
                return
            self.storage.add_log(
                "info", "triage", f"Finding {finding.id} confirmed on {finding.surface}; notifying")
        if self.router:
            self.router.send(finding)
        alert_cfg = self.cfg.get("alerting", {})
        if alert_cfg.get("auto_ticket", False) and at_least(
                finding.severity, alert_cfg.get("auto_ticket_min_severity", "critical")):
            from sentrix.remediation import playbooks
            playbooks.auto_ticket(finding, self.cfg, self.storage)