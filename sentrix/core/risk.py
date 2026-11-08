"""SENTRIX Risk Intelligence: explainable scoring for every finding."""
from __future__ import annotations

import time

CATEGORY_WEIGHT = {
    "cloud": 30, "crypto": 28, "ai": 24, "saas": 22, "generic": 14, "custom": 18,
}
SURFACE_EXPOSURE = {
    "ci": 18, "pre_push": 10, "git": 16, "cloud": 20, "slack": 16,
    "confluence": 14, "jira": 12, "postman": 14, "filesystem": 8, "ide": 6,
}
SEVERITY_BASE = {"critical": 40, "high": 30, "medium": 18, "low": 8, "info": 2}


def _age_days(iso: str) -> float:
    try:
        return max(0.0, (time.time() - time.mktime(time.strptime(iso, "%Y-%m-%dT%H:%M:%S"))) / 86400)
    except (ValueError, TypeError):
        return 0.0


def score(finding, extra: dict | None = None) -> dict:
    """Return a 0-100 risk score with the factors that produced it."""
    extra = extra or {}
    factors = []
    total = SEVERITY_BASE.get(finding.severity, 10)
    factors.append(f"Severity baseline ({finding.severity}): +{total}")
    family = finding.meta.get("family", "generic")
    weight = CATEGORY_WEIGHT.get(family, 14)
    total += weight
    factors.append(f"Secret category ({family}): +{weight}")
    exposure = SURFACE_EXPOSURE.get(finding.surface, 10)
    total += exposure
    factors.append(f"Exposure surface ({finding.surface}): +{exposure}")
    confidence = finding.meta.get("confidence", 0.6)
    conf_pts = round(confidence * 10)
    total += conf_pts
    factors.append(f"Detection confidence ({confidence:.2f}): +{conf_pts}")
    if finding.meta.get("validation") == "format_validated":
        total += 6
        factors.append("Provider format validated: +6")
    environment = finding.meta.get("environment", "unknown")
    if environment == "production":
        total += 10
        factors.append("Production environment: +10")
    age = _age_days(extra.get("first_seen") or finding.created_at)
    age_pts = min(10, round(age))
    total += age_pts
    factors.append(f"Exposure duration ({age:.1f} days): +{age_pts}")
    occurrences = extra.get("occurrences", 1)
    if occurrences > 1:
        pts = min(6, occurrences)
        total += pts
        factors.append(f"Repeated exposure ({occurrences} sightings): +{pts}")
    total = max(0, min(100, total))
    band = ("critical" if total >= 80 else "high" if total >= 60
            else "medium" if total >= 40 else "low" if total >= 20 else "info")
    return {"score": total, "band": band, "factors": factors,
            "explainable": True, "confirmed_validity": False}