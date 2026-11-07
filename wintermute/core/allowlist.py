"""Allowlist / false-positive registry shared by all layers."""
from __future__ import annotations

import re

BUILTIN_SAFE_VALUES = {
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "changeme",
    "placeholder",
    "your_api_key",
    "your-api-key",
    "xxxxxxxx",
}

BUILTIN_SAFE_PATTERNS = [
    re.compile(r"EXAMPLE", re.IGNORECASE),
    re.compile(r"^x{6,}$", re.IGNORECASE),
    re.compile(r"^(your[-_]|my[-_]|sample[-_]|dummy[-_]|fake[-_])", re.IGNORECASE),
    re.compile(r"^\$\{?[A-Z0-9_]+\}?$"),
    re.compile(r"^<[^>]+>$"),
]


class Allowlist:
    def __init__(self, fingerprints: set[str] | None = None, extra_patterns: list[str] | None = None):
        self.fingerprints = fingerprints or set()
        self.patterns = list(BUILTIN_SAFE_PATTERNS)
        for raw in extra_patterns or []:
            self.patterns.append(re.compile(raw))

    def is_allowed(self, fingerprint: str, secret: str, path: str = "") -> bool:
        if fingerprint in self.fingerprints:
            return True
        if secret in BUILTIN_SAFE_VALUES:
            return True
        return any(p.search(secret) for p in self.patterns)