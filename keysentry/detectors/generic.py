"""Generic assignment and high-entropy catch-all detectors."""
from __future__ import annotations

import re

from keysentry.core.entropy import looks_random
from keysentry.detectors.base import Detector, register

register(Detector(
    id="generic-secret-assignment",
    title="Hardcoded Secret Assignment",
    severity="high",
    pattern=re.compile(
        r"(?:password|passwd|secret|token|api_key|apikey|access_key|auth_token|client_secret)"
        r"[\"']?\s*[:=]\s*[\"']([A-Za-z0-9\-_./+=]{8,})[\"']",
        re.IGNORECASE,
    ),
    secret_group=1,
    keywords=("password", "secret", "token", "api_key", "apikey"),
    family="generic",
))

register(Detector(
    id="high-entropy-string",
    title="High-Entropy String (possible secret)",
    severity="medium",
    pattern=re.compile(r"[\"']([A-Za-z0-9+/=\-_]{24,120})[\"']"),
    secret_group=1,
    validator=lambda value: looks_random(value, 4.5),
    family="generic",
))

register(Detector(
    id="env-secret",
    title="Secret in Environment File",
    severity="high",
    pattern=re.compile(
        r"^(?:export\s+)?[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|APIKEY|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*=\s*[\"']?([^\s\"'#]{8,})[\"']?",
        re.MULTILINE,
    ),
    secret_group=1,
    keywords=("SECRET=", "TOKEN=", "PASSWORD=", "API_KEY="),
    family="generic",
))