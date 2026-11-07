"""Confluence surface: page export scanning plus optional live REST polling."""
from __future__ import annotations

import re

from keysentry.config import cfg_get, env_secret
from keysentry.core.engine import scan_text
from keysentry.core.models import Finding
from keysentry.surfaces.common import load_export, rate_limit, rest_json

TAG_STRIP = re.compile(r"<[^>]+>")


def scan_export(path: str, allowlist=None) -> list[Finding]:
    pages = load_export(path)
    if isinstance(pages, dict):
        pages = pages.get("pages", pages.get("results", []))
    findings: list[Finding] = []
    for page in pages:
        body = TAG_STRIP.sub(" ", page.get("body", ""))
        location = page.get("url") or f"confluence:{page.get('title', page.get('id', ''))}"
        for finding in scan_text(body, location, "confluence", allowlist):
            finding.owner = page.get("owner", "")
            findings.append(finding)
    return findings


def live_scan(cfg: dict, allowlist=None) -> list[Finding]:
    base_url = cfg_get(cfg, "surfaces.confluence.base_url", "")
    token = env_secret(cfg, "surfaces.confluence.token_env")
    if not base_url or not token:
        return []
    headers = {"Authorization": f"Bearer {token}"}
    findings: list[Finding] = []
    start = 0
    while True:
        body = rest_json(
            f"{base_url.rstrip('/')}/rest/api/content?limit=50&start={start}"
            "&expand=body.storage,version", headers)
        results = body.get("results", [])
        for page in results:
            text = TAG_STRIP.sub(" ", page.get("body", {}).get("storage", {}).get("value", ""))
            location = f"confluence:{page.get('title', page.get('id', ''))}"
            for finding in scan_text(text, location, "confluence", allowlist):
                finding.owner = page.get("version", {}).get("by", {}).get("displayName", "")
                findings.append(finding)
        rate_limit()
        if len(results) < 50:
            break
        start += 50
    return findings