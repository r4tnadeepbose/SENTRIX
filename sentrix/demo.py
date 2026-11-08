"""Synthetic demo findings so the dashboard is explorable out of the box."""
from __future__ import annotations

import time

from sentrix.core.engine import scan_text
from sentrix.core.pipeline import Pipeline

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

TEAM_OWNERS = ["s.chen", "m.ross", "i.kumar", "j.lee", "a.diaz", "admin"]


def seed_demo(pipeline: Pipeline) -> int:
    seeded = 0
    stored = []
    for idx, (surface, path, text) in enumerate(DEMO_SAMPLES):
        findings = scan_text(text, path, surface, pipeline.allowlist)
        age = (idx * 3) % 14
        created = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - age * 86400))
        for finding in findings:
            finding.owner = TEAM_OWNERS[idx % len(TEAM_OWNERS)]
            finding.created_at = created
            finding.updated_at = created
            finding.meta["demo"] = True
        result = pipeline.ingest(findings, kind="demo.seeded")
        seeded += len(result["new"])
        stored += result["new"]
    for idx, finding in enumerate(stored):
        pipeline.storage.update_extra(finding.id, assignee=finding.owner)
        if idx % 5 == 3:
            pipeline.storage.set_status(finding.id, "triaged", finding.owner)
        elif idx % 5 == 4:
            pipeline.storage.set_status(finding.id, "remediated", finding.owner)
    return seeded