"""Unified flow: event -> scan -> alert -> remediation."""
from __future__ import annotations

from wintermute.core.allowlist import Allowlist
from wintermute.core.models import Event, Finding
from wintermute.core.storage import Storage


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

    def ingest(self, findings: list[Finding], kind: str = "scan.completed", owner: str = "") -> dict:
        new: list[Finding] = []
        known: list[Finding] = []
        for finding in findings:
            if self.allowlist.is_allowed(finding.fingerprint, finding.secret_masked, finding.path):
                continue
            if owner and not finding.owner:
                finding.owner = owner
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
        if self.router:
            for finding in new:
                self.router.send(finding)
        return {"new": new, "known": known}