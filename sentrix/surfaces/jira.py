"""Jira surface: issue export scanning, live JQL polling, security ticket creation."""
from __future__ import annotations

import json
import urllib.request

from sentrix.config import cfg_get, env_secret
from sentrix.core.engine import scan_text
from sentrix.core.models import Finding
from sentrix.surfaces.common import load_export, rate_limit, rest_json


def scan_export(path: str, allowlist=None) -> list[Finding]:
    issues = load_export(path)
    if isinstance(issues, dict):
        issues = issues.get("issues", [])
    findings: list[Finding] = []
    for issue in issues:
        fields = issue.get("fields", issue)
        text = "\n".join(filter(None, [
            fields.get("summary", ""), fields.get("description", "") or "",
        ]))
        location = f"jira:{issue.get('key', issue.get('id', ''))}"
        for finding in scan_text(text, location, "jira", allowlist):
            finding.owner = fields.get("reporter", {}).get("displayName", "") if isinstance(
                fields.get("reporter"), dict) else ""
            finding.meta.setdefault("origin", {}).update(
                {"issue": issue.get("key", issue.get("id", "")), "reporter": finding.owner})
            findings.append(finding)
    return findings


def live_scan(cfg: dict, allowlist=None) -> list[Finding]:
    base_url = cfg_get(cfg, "surfaces.jira.base_url", "")
    token = env_secret(cfg, "surfaces.jira.token_env")
    if not base_url or not token:
        return []
    headers = {"Authorization": f"Bearer {token}"}
    findings: list[Finding] = []
    start = 0
    while True:
        body = rest_json(
            f"{base_url.rstrip('/')}/rest/api/2/search?jql=updated>=-1d&maxResults=50"
            f"&startAt={start}", headers)
        issues = body.get("issues", [])
        for issue in issues:
            fields = issue.get("fields", {})
            text = "\n".join(filter(None, [
                fields.get("summary", ""), fields.get("description", "") or "",
            ]))
            for finding in scan_text(text, f"jira:{issue.get('key', '')}", "jira", allowlist):
                findings.append(finding)
        rate_limit()
        if start + len(issues) >= body.get("total", 0) or not issues:
            break
        start += 50
    return findings


def create_security_ticket(finding: Finding, cfg: dict) -> str:
    base_url = cfg_get(cfg, "surfaces.jira.base_url", "")
    token = env_secret(cfg, "surfaces.jira.token_env")
    if not base_url or not token:
        return ""
    payload = {
        "fields": {
            "project": {"key": cfg_get(cfg, "surfaces.jira.project", "SEC")},
            "summary": f"[SENTRIX] {finding.title} in {finding.path}",
            "description": f"Severity {finding.severity} on {finding.surface}. "
                           f"Masked value: {finding.secret_masked}. Rotate and remove.",
            "issuetype": {"name": "Task"},
        }
    }
    try:
        from sentrix.core.net import assert_safe_outbound_url
        assert_safe_outbound_url(base_url)
        req = urllib.request.Request(
            f"{base_url.rstrip('/')}/rest/api/2/issue",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
            method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return f"Jira ticket created: {json.loads(resp.read().decode()).get('key', '')}"
    except Exception as exc:
        return f"Jira ticket failed: {exc}"