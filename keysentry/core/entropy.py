"""Shannon entropy scoring used to rank candidate secrets."""
from __future__ import annotations

import math
from collections import Counter


def shannon(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def looks_random(value: str, threshold: float = 4.5) -> bool:
    return len(value) >= 16 and shannon(value) >= threshold