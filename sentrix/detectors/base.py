"""Detector framework shared by every surface and layer."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class Detector:
    id: str
    title: str
    severity: str
    pattern: re.Pattern
    secret_group: int = 0
    validator: Optional[Callable[[str], bool]] = None
    keywords: tuple = ()
    family: str = "generic"
    remediation: str = "rotate"

    def extract(self, match: re.Match) -> str:
        try:
            return match.group(self.secret_group)
        except IndexError:
            return match.group(0)


REGISTRY: dict[str, Detector] = {}


def register(detector: Detector) -> Detector:
    REGISTRY[detector.id] = detector
    return detector


def all_detectors() -> list[Detector]:
    return list(REGISTRY.values())