"""Triage orchestration: GPT when configured, deterministic heuristic otherwise."""
from __future__ import annotations

import json

from keysentry.ai.gpt import GPTClient
from keysentry.ai.prompts import build_messages
from keysentry.config import cfg_get, env_secret
from keysentry.core.models import Finding

FP_PATH_HINTS = ("test", "example", "fixture", "sample", "mock", "docs/")


def heuristic_triage(finding: Finding) -> dict:
    reasons: list[str] = []
    score = 0.5
    lowered = finding.path.lower()
    if any(hint in lowered for hint in FP_PATH_HINTS):
        score -= 0.25
        reasons.append("Path looks like test/example material.")
    if "EXAMPLE" in finding.secret_masked or finding.secret_masked.startswith("your"):
        score -= 0.3
        reasons.append("Masked value resembles a documented placeholder.")
    if finding.entropy >= 4.5:
        score += 0.2
        reasons.append("High Shannon entropy consistent with a generated credential.")
    if finding.severity in ("critical", "high"):
        score += 0.15
        reasons.append("Detector matches a known credential format with high confidence.")
    if finding.surface in ("slack", "confluence", "jira"):
        score += 0.1
        reasons.append("Collaboration surfaces rarely contain intentional fixtures.")
    score = max(0.05, min(0.95, score))
    verdict = (
        "likely_true_positive" if score >= 0.65
        else "likely_false_positive" if score <= 0.35
        else "needs_review"
    )
    recommendation = (
        "Rotate the credential and remove the exposure; follow the rotation guide."
        if verdict == "likely_true_positive"
        else "Confirm it is a placeholder, then add the fingerprint to the allowlist."
        if verdict == "likely_false_positive"
        else "Inspect the source context and verify against the provider before acting."
    )
    return {
        "source": "heuristic",
        "confidence": round(score, 2),
        "verdict": verdict,
        "reasons": reasons or ["No strong signals either way."],
        "recommendation": recommendation,
    }


def triage_finding(finding: Finding, cfg: dict) -> dict:
    if cfg_get(cfg, "ai.enabled", False):
        api_key = env_secret(cfg, "ai.api_key_env")
        if api_key:
            try:
                client = GPTClient(
                    cfg_get(cfg, "ai.base_url"), cfg_get(cfg, "ai.model"), api_key)
                raw = client.chat(build_messages(finding))
                result = json.loads(raw[raw.index("{"):raw.rindex("}") + 1])
                result["source"] = "gpt"
                return result
            except Exception:
                pass
    return heuristic_triage(finding)