"""Shared data models for every layer of the system."""
from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_ORDER = {name: idx for idx, name in enumerate(SEVERITIES)}
STATUSES = ("open", "triaged", "false_positive", "remediated")
SURFACES = (
    "ide", "pre_push", "ci", "git", "cloud",
    "slack", "confluence", "jira", "postman", "filesystem",
)


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


@dataclass
class Finding:
    detector_id: str
    title: str
    severity: str
    surface: str
    path: str
    line: int
    secret_masked: str
    entropy: float
    fingerprint: str
    id: str = ""
    status: str = "open"
    owner: str = ""
    created_at: str = ""
    updated_at: str = ""
    meta: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = hashlib.sha256(
                f"{self.fingerprint}|{self.path}|{self.line}".encode()
            ).hexdigest()[:12]
        if not self.created_at:
            self.created_at = now_iso()
        if not self.updated_at:
            self.updated_at = self.created_at

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class Event:
    kind: str
    surface: str
    payload: dict = field(default_factory=dict)
    id: str = ""
    ts: str = ""

    def __post_init__(self):
        if not self.ts:
            self.ts = now_iso()
        if not self.id:
            self.id = f"ev-{int(time.time() * 1000):x}"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Alert:
    finding_id: str
    channel: str
    message: str
    id: str = ""
    status: str = "sent"
    ts: str = ""

    def __post_init__(self):
        if not self.ts:
            self.ts = now_iso()
        if not self.id:
            self.id = f"al-{int(time.time() * 1000):x}"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Remediation:
    finding_id: str
    action: str
    detail: str
    id: str = ""
    ts: str = ""

    def __post_init__(self):
        if not self.ts:
            self.ts = now_iso()
        if not self.id:
            self.id = f"rm-{int(time.time() * 1000):x}"

    def to_dict(self) -> dict:
        return asdict(self)