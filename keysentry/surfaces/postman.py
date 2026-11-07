"""Postman surface: collection and environment JSON scanning."""
from __future__ import annotations

from keysentry.core.engine import scan_text
from keysentry.core.models import Finding
from keysentry.surfaces.common import load_export, walk_strings


def scan_collection(path: str, allowlist=None) -> list[Finding]:
    data = load_export(path)
    findings: list[Finding] = []
    name = data.get("info", {}).get("name", path)
    for key_path, value in walk_strings(data):
        if len(value) < 8:
            continue
        for finding in scan_text(f"{key_path} = \"{value}\"", f"postman:{name}", "postman", allowlist):
            finding.meta["json_path"] = key_path
            findings.append(finding)
    return findings


def scan_environment(path: str, allowlist=None) -> list[Finding]:
    data = load_export(path)
    findings: list[Finding] = []
    name = data.get("name", path)
    for entry in data.get("values", []):
        key = entry.get("key", "")
        value = entry.get("value", "")
        if not isinstance(value, str) or len(value) < 8:
            continue
        for finding in scan_text(f"{key} = \"{value}\"", f"postman-env:{name}", "postman", allowlist):
            finding.meta["env_key"] = key
            findings.append(finding)
    return findings