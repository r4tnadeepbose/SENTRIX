"""SENTRIX reporting: generated from live storage, with export history."""
from __future__ import annotations

import csv
import io
import json
import secrets

from sentrix.core.models import now_iso

REPORT_TYPES = {
    "executive": "Executive security posture",
    "exposure": "Exposure management",
    "critical": "Critical findings",
    "repository": "Repository security",
    "cloud": "Cloud security",
    "saas": "SaaS security",
    "remediation": "Remediation performance",
    "effectiveness": "Detection effectiveness",
    "false_positive": "False-positive analysis",
    "integration_health": "Integration health",
    "audit": "Audit report",
}


def generate(rtype: str, fmt: str, storage, user: str) -> dict:
    if rtype not in REPORT_TYPES:
        raise ValueError(f"unknown report type: {rtype}")
    findings = storage.list_findings(limit=5000)
    if rtype == "critical":
        findings = [f for f in findings if f.severity in ("critical", "high")]
    elif rtype == "repository":
        findings = [f for f in findings if f.surface in ("git", "pre_push", "ci")]
    elif rtype == "cloud":
        findings = [f for f in findings if f.surface == "cloud"]
    elif rtype == "saas":
        findings = [f for f in findings if f.surface in ("slack", "jira", "confluence", "postman")]
    elif rtype == "remediation":
        findings = [f for f in findings if f.status in ("remediated", "verified", "closed")]
    elif rtype == "false_positive":
        findings = [f for f in findings if f.status == "false_positive"]
    stats = storage.stats()
    rid = "rpt-" + secrets.token_hex(5)
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["id", "severity", "title", "surface", "path", "line",
                         "status", "owner", "created_at"])
        for f in findings:
            writer.writerow([f.id, f.severity, f.title, f.surface, f.path,
                             f.line, f.status, f.owner, f.created_at])
        body, mime = buf.getvalue(), "text/csv; charset=utf-8"
    else:
        body = json.dumps({
            "report": REPORT_TYPES[rtype], "generated_at": now_iso(),
            "summary": stats, "findings": [f.to_dict() for f in findings],
        }, indent=2)
        mime = "application/json"
    storage.add_report(rid, rtype, fmt, user, len(findings), body)
    return {"id": rid, "type": rtype, "title": REPORT_TYPES[rtype], "format": fmt,
            "rows": len(findings), "body": body, "mime": mime, "created_at": now_iso()}