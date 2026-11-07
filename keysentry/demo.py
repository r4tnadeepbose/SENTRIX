"""Synthetic demo findings so the dashboard is explorable out of the box."""
from __future__ import annotations

from keysentry.core.engine import scan_text
from keysentry.core.pipeline import Pipeline

DEMO_SAMPLES = [
    ("ide", "src/settings.py", 'AWS_KEY = "AWS_KEY_REDACTED"'),
    ("pre_push", "deploy/keys.env", 'GITHUB_TOKEN=GITHUB_TOKEN_REDACTED'),
    ("ci", ".gitlab-ci.yml", 'DATABASE_URL: "postgres://admin:Sup3rSecretPass@db.internal:5432/prod"'),
    ("cloud", "lambda:payments/env", 'STRIPE_KEY = "STRIPE_KEY_REDACTED"'),
    ("slack", "slack:#eng-debug/1712345678.001", 'bot token SLACK_TOKEN_REDACTED'),
    ("confluence", "confluence:Runbook - Payments", 'password = "PASSWORD_REDACTED"'),
    ("jira", "jira:OPS-4212", 'SendGrid key SENDGRID_KEY_REDACTED'),
    ("postman", "postman:Payments API", 'api_key = "API_KEY_REDACTED"'),
    ("filesystem", "infra/tls/server.pem", '-----BEGIN RSA PRIVATE KEY-----'),
    ("git", "scripts/bootstrap.sh", 'export API_TOKEN="tok_9f8e7d6c5b4a39281706f5e4d3c2b1a0"'),
]


def seed_demo(pipeline: Pipeline) -> int:
    seeded = 0
    for surface, path, text in DEMO_SAMPLES:
        findings = scan_text(text, path, surface, pipeline.allowlist)
        for finding in findings:
            finding.owner = "demo-user"
            finding.meta["demo"] = True
        result = pipeline.ingest(findings, kind="demo.seeded")
        seeded += len(result["new"])
    return seeded