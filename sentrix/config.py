"""Configuration loading: defaults < config.toml < config.local.toml < env."""
from __future__ import annotations

import os
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DEFAULTS = {
    "server": {"host": "127.0.0.1", "port": 8710},
    "auth": {"session_hours": 12, "login_rate_limit": 5,
             "demo_mode": True, "demo_password": "sentrix-demo"},
    "detectors": {"disabled": [], "severity_overrides": {}},
    "scan": {
        "max_file_bytes": 1_000_000,
        "entropy_threshold": 4.5,
        "fail_on": "high",
        "ignore_dirs": [
            ".git", "node_modules", "__pycache__", ".venv", "venv",
            "dist", "build", "data", "logs", ".mypy_cache", ".pytest_cache",
            "examples", "tests", "docs", "assets", "sentrix",
        ],
        "ignore_files": ["*.png", "*.jpg", "*.jpeg", "*.gif", "*.pdf", "*.ico", "*.lock"],
    },
    "storage": {"path": "data/sentrix.db"},
    "alerting": {
        "channels": ["console", "outbox"],
        "slack_webhook": "",
        "webhook_url": "",
        "dedupe_window_seconds": 3600,
        "auto_ticket": True,
        "auto_ticket_min_severity": "critical",
    },
    "ai": {
        "enabled": False,
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "api_key_env": "SENTRIX_AI_KEY",
    },
    "surfaces": {
        "slack": {"token_env": "SENTRIX_SLACK_TOKEN", "channels": [], "poll_seconds": 300},
        "confluence": {"base_url": "", "token_env": "SENTRIX_CONFLUENCE_TOKEN"},
        "jira": {"base_url": "", "token_env": "SENTRIX_JIRA_TOKEN"},
        "postman": {"api_key_env": "SENTRIX_POSTMAN_KEY", "workspaces": []},
        "cloud": {"provider": "local", "lambda_dir": "examples/lambda"},
    },
    "features": {
        "github_webhooks": {"enabled": True},
        "github_pr_scanner": {"enabled": True},
        "github_push_scanner": {"enabled": True},
        "github_actions_gate": {"enabled": True},
        "github": {"token_env": "SENTRIX_GITHUB_TOKEN", "webhook_secret_env": "SENTRIX_GITHUB_WEBHOOK_SECRET", "api_base": "https://api.github.com"},
        "full_repo_rescan": {"enabled": True, "paths": [], "interval_seconds": 86400},
        "aws_lambda_monitoring": {"enabled": True},
        "aws_multi_account": {"enabled": True, "accounts": []},
        "lambda_env_scan": {"enabled": True},
        "lambda_zip_scan": {"enabled": True},
        "realtime_slack_monitoring": {"enabled": True},
        "slack_private_consent": {"enabled": False, "allowed_channels": []},
        "realtime_jira_monitoring": {"enabled": True},
        "realtime_confluence_monitoring": {"enabled": True},
        "postman_monitoring": {"enabled": True, "export_paths": []},
        "secret_validation": {"enabled": False, "github_api": False},
        "s3_audit_archival": {"enabled": False, "bucket": "", "prefix": "sentrix/audit/", "interval_seconds": 3600},
        "missed_webhook_detection": {"enabled": True},
        "integration_health_monitoring": {"enabled": True},
        "realtime_monitoring": {"interval_seconds": 300},
    },
}


def _merge(base: dict, overlay: dict) -> dict:
    out = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(root: Path | None = None) -> dict:
    root = root or ROOT
    cfg = _merge({}, DEFAULTS)
    for name in ("config.toml", "config.local.toml"):
        path = root / name
        if path.exists():
            with open(path, "rb") as fh:
                cfg = _merge(cfg, tomllib.load(fh))
    return cfg


def cfg_get(cfg: dict, dotted: str, default=None):
    node = cfg
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def resolve_path(cfg: dict, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def env_secret(cfg: dict, dotted: str) -> str:
    env_name = cfg_get(cfg, dotted, "")
    return os.environ.get(env_name, "") if env_name else ""