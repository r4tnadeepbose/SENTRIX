"""SENTRIX Connect: integration registry with honest connection states."""
from __future__ import annotations

from sentrix.config import cfg_get, env_secret
from sentrix.core.lifecycle import INTEGRATION_STATES

PROVIDERS = [
    ("github", "GitHub", "git", ["repo:read", "pull_request:read"], "60 req/min"),
    ("gitlab", "GitLab", "git", ["read_api", "read_repository"], "60 req/min"),
    ("bitbucket", "Bitbucket", "git", ["repository:read"], "60 req/min"),
    ("jenkins", "Jenkins", "ci", ["job:read", "build:read"], "30 req/min"),
    ("aws", "AWS", "cloud", ["lambda:ListFunctions", "lambda:GetFunctionConfiguration"], "SDK default"),
    ("slack", "Slack", "slack", ["channels:history", "channels:read"], "50 req/min"),
    ("jira", "Jira", "jira", ["read:jira-work", "write:jira-work"], "60 req/min"),
    ("confluence", "Confluence", "confluence", ["read:confluence-content"], "60 req/min"),
    ("postman", "Postman", "postman", ["collections:read", "environments:read"], "30 req/min"),
]


def _configured(cfg: dict, pid: str) -> bool:
    if pid == "aws":
        return cfg_get(cfg, "surfaces.cloud.provider", "local") == "aws"
    if pid in ("slack", "jira", "confluence", "postman"):
        return bool(env_secret(cfg, f"surfaces.{pid}.token_env" if pid != "postman"
                                else "surfaces.postman.api_key_env")) or bool(
            cfg_get(cfg, f"surfaces.{pid}.base_url", ""))
    return False


def inventory(cfg: dict, storage, demo: bool) -> list[dict]:
    findings = storage.list_findings(limit=5000)
    events = storage.list_events(limit=500)
    logs = storage.list_logs(limit=300)
    out = []
    for pid, name, surface, permissions, rate in PROVIDERS:
        configured = _configured(cfg, pid)
        if configured:
            status, auth = INTEGRATION_STATES[0], "credentials present"  # connected
        elif demo:
            status, auth = INTEGRATION_STATES[1], "synthetic connector - no live credentials"  # demo
        else:
            status, auth = INTEGRATION_STATES[2], "authentication required"  # disconnected
        related = [f for f in findings if f.surface == surface]
        syncs = [e for e in events if e.get("surface") == surface]
        errors = [l for l in logs if l["source"] == "integrations" and l["level"] == "error"]
        out.append({
            "id": pid, "name": name, "surface": surface, "status": status,
            "auth": auth, "permissions": permissions, "rate_limit": rate,
            "last_sync": syncs[0]["ts"] if syncs else None,
            "last_scan": syncs[0]["ts"] if syncs else None,
            "resources": sorted({f.path.split(":")[0] for f in related})[:12],
            "findings": len(related),
            "errors": [e["message"] for e in errors][:5],
            "enabled": True,
        })
    return out