"""Prompt construction for triage; only masked values ever leave the machine."""
from __future__ import annotations

import json

from keysentry.core.models import Finding

SYSTEM = (
    "You are a security analyst triaging secret-detection findings. "
    "You receive masked secret values only. Respond with strict JSON: "
    '{"verdict": "likely_true_positive" | "likely_false_positive" | "needs_review", '
    '"confidence": 0.0-1.0, "reasons": ["..."], "recommendation": "..."}'
)


def build_messages(finding: Finding) -> list[dict]:
    return [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": json.dumps({
            "detector": finding.detector_id,
            "title": finding.title,
            "severity": finding.severity,
            "surface": finding.surface,
            "path": finding.path,
            "line": finding.line,
            "masked_secret": finding.secret_masked,
            "entropy": finding.entropy,
        })},
    ]