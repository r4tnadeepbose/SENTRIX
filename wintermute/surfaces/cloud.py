"""Cloud surface: Lambda code + environment variable scanning.

Local mode scans exported function artifacts; live AWS mode activates only
when boto3 is installed and credentials are present, and never blocks deploys.
"""
from __future__ import annotations

import json
from pathlib import Path

from wintermute.config import cfg_get, resolve_path
from wintermute.core.engine import scan_file, scan_text
from wintermute.core.models import Finding


def scan_lambda_dir(directory: str | Path, cfg: dict, allowlist=None) -> list[Finding]:
    root = Path(directory)
    findings: list[Finding] = []
    if not root.exists():
        return findings
    for config_path in sorted(root.glob("*/config.json")) + sorted(root.glob("config.json")):
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        fn_name = config.get("FunctionName", config_path.parent.name)
        env_vars = config.get("Environment", {}).get("Variables", {})
        for key, value in env_vars.items():
            for finding in scan_text(
                    f"{key} = \"{value}\"", f"lambda:{fn_name}/env", "cloud", allowlist):
                finding.meta["env_key"] = key
                finding.meta.setdefault("origin", {}).update(
                    {"function": fn_name, "env_key": key})
                findings.append(finding)
    for code_path in sorted(root.rglob("*.py")) + sorted(root.rglob("*.js")):
        findings.extend(scan_file(code_path, "cloud", cfg, allowlist))
    return findings


def live_scan(cfg: dict, allowlist=None) -> list[Finding]:
    if cfg_get(cfg, "surfaces.cloud.provider", "local") != "aws":
        return []
    try:
        import boto3
    except ImportError:
        return []
    findings: list[Finding] = []
    client = boto3.client("lambda")
    paginator = client.get_paginator("list_functions")
    for page in paginator.paginate():
        for fn in page["Functions"]:
            config = client.get_function_configuration(FunctionName=fn["FunctionName"])
            for key, value in config.get("Environment", {}).get("Variables", {}).items():
                for finding in scan_text(
                        f"{key} = \"{value}\"", f"lambda:{fn['FunctionName']}/env",
                        "cloud", allowlist):
                    finding.meta["env_key"] = key
                    findings.append(finding)
    return findings


def default_scan(cfg: dict, allowlist=None) -> list[Finding]:
    directory = resolve_path(cfg, cfg_get(cfg, "surfaces.cloud.lambda_dir", "examples/lambda"))
    return scan_lambda_dir(directory, cfg, allowlist)