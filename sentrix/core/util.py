"""Small shared helpers: masking, fingerprinting, severity math."""
from __future__ import annotations

import hashlib

from sentrix.core.models import SEVERITY_ORDER


def mask_secret(secret: str) -> str:
    """Never store or display a raw secret; keep only enough to recognize it."""
    secret = secret.strip()
    if len(secret) <= 8:
        return secret[:2] + "*" * (len(secret) - 2)
    return secret[:4] + "*" * 8 + secret[-4:]


def fingerprint(detector_id: str, secret: str) -> str:
    """Stable dedupe key derived from the raw value; the raw value is never kept."""
    return hashlib.sha256(f"{detector_id}|{secret.strip()}".encode()).hexdigest()


def severity_max(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 99) <= SEVERITY_ORDER.get(b, 99) else b


def at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity, 99) <= SEVERITY_ORDER.get(threshold, 99)