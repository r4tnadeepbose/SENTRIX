"""Playbooks: rotation guides plus redact / quarantine / ticket actions."""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from wintermute.config import resolve_path
from wintermute.core.models import Finding, Remediation
from wintermute.core.storage import Storage
from wintermute.detectors import REGISTRY

PLAYBOOKS = {
    "rotate-aws": [
        "Deactivate the exposed access key in IAM immediately.",
        "Create a replacement key and store it in a secrets manager.",
        "Update every consumer (CI, Lambda env, local configs).",
        "Review CloudTrail for misuse since the exposure window.",
        "Purge the secret from git history and force-push with team consent.",
    ],
    "rotate-gcp": [
        "Restrict or delete the exposed API key / service account key.",
        "Issue a replacement with least-privilege IAM bindings.",
        "Redeploy workloads referencing the old key.",
        "Audit Cloud Audit Logs for the exposure window.",
    ],
    "rotate-azure": [
        "Regenerate the storage account key or rotate the AD client secret.",
        "Update connection strings via Key Vault references.",
        "Review sign-in and storage access logs.",
    ],
    "rotate-github": [
        "Revoke the token in GitHub settings (or via the security API).",
        "Issue a fine-grained replacement with minimal scopes.",
        "Audit the audit log for token use during exposure.",
    ],
    "rotate-gitlab": [
        "Revoke the personal access token and issue a scoped replacement.",
        "Check audit events for anomalous API activity.",
    ],
    "rotate-slack": [
        "Revoke the token / regenerate the webhook in the Slack app config.",
        "Delete the exposing message and notify the channel owner.",
        "Review app access logs.",
    ],
    "rotate-stripe": [
        "Roll the secret key in the Stripe dashboard.",
        "Update server-side consumers; never ship secret keys to clients.",
        "Review Stripe logs for unauthorized calls.",
    ],
    "rotate-openai": [
        "Revoke the API key and create a replacement with spend limits.",
        "Review usage dashboards for unexpected consumption.",
    ],
    "rotate-db": [
        "Rotate the database password and update the secrets manager.",
        "Restart dependent services; audit DB access logs.",
    ],
    "rotate-keypair": [
        "Generate a new keypair and revoke trust in the exposed public key.",
        "Update authorized_keys / KMS / deployment targets.",
        "Audit authentication logs for the exposure window.",
    ],
    "rotate": [
        "Revoke or rotate the exposed credential at its provider.",
        "Store the replacement in a secrets manager, not in code.",
        "Remove the exposure from history, docs and chat.",
        "Verify with a fresh Wintermute scan.",
    ],
}


def rotation_guide(finding: Finding) -> str:
    detector = REGISTRY.get(finding.detector_id)
    steps = PLAYBOOKS.get(detector.remediation if detector else "rotate", PLAYBOOKS["rotate"])
    lines = [
        f"# Remediation guide - {finding.title}",
        f"Finding: {finding.id} | severity: {finding.severity} | surface: {finding.surface}",
        f"Location: {finding.path}:{finding.line}",
        "",
    ]
    lines += [f"{idx}. {step}" for idx, step in enumerate(steps, 1)]
    return "\n".join(lines) + "\n"


def execute(action: str, finding: Finding, cfg: dict, storage: Storage) -> str:
    if action == "rotate-guide":
        guide = rotation_guide(finding)
        target = resolve_path(cfg, f"data/remediation/{finding.id}.md")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(guide, encoding="utf-8")
        detail = f"Rotation guide written to {target}"
        storage.set_status(finding.id, "triaged")
    elif action == "redact":
        detail = _redact(finding)
        storage.set_status(finding.id, "remediated")
    elif action == "quarantine":
        detail = _quarantine(finding, cfg)
        storage.set_status(finding.id, "remediated")
    elif action == "ticket":
        detail = _ticket(finding, cfg)
        storage.set_status(finding.id, "triaged")
    elif action == "preview-redact":
        return _preview_redact(finding)
    elif action == "restore":
        detail = _restore(finding, cfg)
    elif action == "verify":
        detail = _verify(finding, cfg, storage)
    else:
        raise ValueError(f"unknown remediation action: {action}")
    storage.add_remediation(Remediation(finding_id=finding.id, action=action, detail=detail))
    return detail


def _redact(finding: Finding) -> str:
    path = Path(finding.path)
    detector = REGISTRY.get(finding.detector_id)
    if not path.is_file() or not detector:
        return "Source file unavailable; redact manually and rotate the credential."
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.split("\n")
    if finding.line - 1 >= len(lines):
        return "Line no longer present; redact manually and rotate the credential."
    original = lines[finding.line - 1]
    replaced = detector.pattern.sub(
        lambda m: m.group(0).replace(detector.extract(m), f"<REDACTED:{detector.id}>"),
        original,
    )
    if replaced == original:
        return "Pattern no longer matches; redact manually and rotate the credential."
    lines[finding.line - 1] = replaced
    path.write_text("\n".join(lines), encoding="utf-8")
    return f"Redacted {finding.path}:{finding.line}; rotate the credential now."


def _quarantine(finding: Finding, cfg: dict) -> str:
    path = Path(finding.path)
    if not path.is_file():
        return "Source file unavailable; nothing to quarantine."
    target = resolve_path(cfg, f"data/quarantine/{finding.id}-{path.name}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(path), str(target))
    return f"Moved {path} to {target}; rotate the credential now."


def _preview_redact(finding: Finding) -> str:
    path = Path(finding.path)
    detector = REGISTRY.get(finding.detector_id)
    if not path.is_file() or not detector:
        return "Source file unavailable; nothing to preview."
    lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
    if finding.line - 1 >= len(lines):
        return "Line no longer present."
    original = lines[finding.line - 1]
    replaced = detector.pattern.sub(
        lambda m: m.group(0).replace(detector.extract(m), f"<REDACTED:{detector.id}>"),
        original,
    )
    return f"Before: {original.strip()}\nAfter:  {replaced.strip()}"


def _restore(finding: Finding, cfg: dict) -> str:
    target = resolve_path(cfg, f"data/quarantine/{finding.id}-{Path(finding.path).name}")
    original = Path(finding.path)
    if not target.is_file():
        return "No quarantined copy found for this finding."
    if original.exists():
        return f"Original path {original} already exists; restore manually."
    original.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(target), str(original))
    return f"Restored {original} from quarantine."


def _verify(finding: Finding, cfg: dict, storage: Storage) -> str:
    from wintermute.core.engine import scan_file
    path = Path(finding.path)
    if not path.is_file():
        return "Source file unavailable; cannot verify."
    remaining = [f for f in scan_file(path, finding.surface, cfg)
                 if f.detector_id == finding.detector_id and f.line == finding.line]
    if remaining:
        return "Verification failed: the secret is still present at the recorded location."
    storage.set_status(finding.id, "remediated")
    return "Verified clean: no matching secret remains at the recorded location."


def auto_ticket(finding: Finding, cfg: dict, storage: Storage) -> str:
    """Findings store -> Jira ticket (or outbox draft), without changing status."""
    detail = _ticket(finding, cfg)
    storage.add_remediation(Remediation(finding_id=finding.id, action="auto-ticket", detail=detail))
    storage.add_log("info", "ticket", f"Auto ticket for {finding.id}: {detail}")
    return detail


def _ticket(finding: Finding, cfg: dict) -> str:
    from wintermute.surfaces import jira
    created = jira.create_security_ticket(finding, cfg)
    if created:
        return created
    target = resolve_path(cfg, f"data/outbox/ticket-{finding.id}.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({
        "project": "SEC",
        "summary": f"[Wintermute] {finding.title} in {finding.path}",
        "description": rotation_guide(finding),
        "priority": finding.severity,
    }, indent=2), encoding="utf-8")
    return f"Jira not configured; ticket draft written to {target}"