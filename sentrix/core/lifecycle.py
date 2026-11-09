"""Central, declarative state machines for SENTRIX workflows.

This module is the single source of truth for workflow states, transitions,
labels, and terminal conditions. It improves:
- UX: consistent labels, allowed actions, and lifecycle visualization.
- DX: no scattered status strings; one place to evolve workflows.
- AX: machine-readable state graphs for agents and integrations.

All helpers are pure and permissive by default: they describe canonical
behavior without rejecting previously valid data unless explicitly requested.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Finding lifecycle
# ---------------------------------------------------------------------------

FINDING_STATES: Tuple[str, ...] = (
    "open",
    "new",
    "triaged",
    "assigned",
    "in_progress",
    "remediated",
    "verified",
    "closed",
    "false_positive",
    "accepted_risk",
    "suppressed",
    "reopened",
)

# Happy-path progression shown in the drawer/timeline.
FINDING_LIFECYCLE_PATH: Tuple[str, ...] = (
    "new",
    "triaged",
    "assigned",
    "in_progress",
    "remediated",
    "verified",
    "closed",
)

# Exception/disposition states reachable from investigation/remediation flows.
FINDING_EXCEPTION_STATES: Tuple[str, ...] = (
    "false_positive",
    "accepted_risk",
    "suppressed",
    "reopened",
)

FINDING_TERMINAL_STATES: Set[str] = {"closed"}

# Canonical transitions (advisory). "open" and "new" are intake aliases in
# current behavior; transitions are permissive for compatibility, but this
# graph captures the intended workflow for UX/DX/AX.
FINDING_TRANSITIONS: Dict[str, Set[str]] = {
    "open": {
        "new", "triaged", "assigned", "in_progress", "remediated", "verified",
        "closed", "false_positive", "accepted_risk", "suppressed", "reopened",
    },
    "new": {
        "triaged", "assigned", "in_progress", "remediated", "verified",
        "closed", "false_positive", "accepted_risk", "suppressed", "reopened",
    },
    "triaged": {
        "assigned", "in_progress", "remediated", "verified", "closed",
        "false_positive", "accepted_risk", "suppressed", "reopened",
    },
    "assigned": {
        "triaged", "in_progress", "remediated", "verified", "closed",
        "false_positive", "accepted_risk", "suppressed", "reopened",
    },
    "in_progress": {
        "assigned", "remediated", "verified", "closed",
        "false_positive", "accepted_risk", "suppressed", "reopened",
    },
    "remediated": {
        "in_progress", "verified", "closed", "reopened",
        "false_positive", "accepted_risk", "suppressed",
    },
    "verified": {
        "closed", "reopened", "in_progress", "remediated",
        "false_positive", "accepted_risk", "suppressed",
    },
    "closed": {"reopened", "open", "new", "triaged", "in_progress"},
    "false_positive": {"open", "new", "triaged", "reopened"},
    "accepted_risk": {"open", "new", "triaged", "in_progress", "reopened", "closed"},
    "suppressed": {"open", "new", "triaged", "in_progress", "reopened"},
    "reopened": {
        "new", "triaged", "assigned", "in_progress", "remediated", "verified",
        "closed", "false_positive", "accepted_risk", "suppressed",
    },
}

FINDING_LABELS: Dict[str, str] = {
    "open": "Open",
    "new": "New",
    "triaged": "Triaged",
    "assigned": "Assigned",
    "in_progress": "In Progress",
    "remediated": "Remediated",
    "verified": "Verified",
    "closed": "Closed",
    "false_positive": "False Positive",
    "accepted_risk": "Accepted Risk",
    "suppressed": "Suppressed",
    "reopened": "Reopened",
}

# Semantic groups for filtering, badges, and UX copy.
FINDING_GROUPS: Dict[str, Tuple[str, ...]] = {
    "intake": ("open", "new"),
    "active": ("triaged", "assigned", "in_progress", "reopened"),
    "resolved": ("remediated", "verified", "closed"),
    "exceptions": FINDING_EXCEPTION_STATES,
}


def finding_label(status: str) -> str:
    return FINDING_LABELS.get(status, (status or "").replace("_", " ").title())


def finding_is_terminal(status: str) -> bool:
    return status in FINDING_TERMINAL_STATES


def finding_allowed_next(status: str, permissive: bool = True) -> List[str]:
    """Return canonical next states. Permissive mode includes all states."""
    if permissive or status not in FINDING_TRANSITIONS:
        return [s for s in FINDING_STATES if s != status]
    return sorted(FINDING_TRANSITIONS.get(status, set()))


def finding_can_transition(from_status: str, to_status: str, strict: bool = False) -> Tuple[bool, str]:
    """Validate a finding transition.

    strict=False (default): allow any known status; warn only via reason when
    non-canonical. strict=True: require the canonical transition graph.
    """
    if to_status not in FINDING_STATES:
        return False, f"unknown status: {to_status}"
    if from_status == to_status:
        return True, "no-op"
    if from_status not in FINDING_STATES:
        return (not strict), "unknown source status"
    allowed = FINDING_TRANSITIONS.get(from_status, set())
    if to_status in allowed:
        return True, "canonical"
    if strict:
        return False, f"non-canonical transition: {from_status} -> {to_status}"
    return True, f"non-canonical transition allowed for compatibility: {from_status} -> {to_status}"


# ---------------------------------------------------------------------------
# Scan jobs
# ---------------------------------------------------------------------------

JOB_STATES: Tuple[str, ...] = ("queued", "running", "done", "failed", "cancelled")
JOB_TERMINAL_STATES: Set[str] = {"done", "failed", "cancelled"}
JOB_TRANSITIONS: Dict[str, Set[str]] = {
    "queued": {"running", "cancelled", "failed"},
    "running": {"done", "failed", "cancelled"},
    "done": set(),
    "failed": set(),
    "cancelled": set(),
}
JOB_LABELS: Dict[str, str] = {
    "queued": "Queued",
    "running": "Running",
    "done": "Done",
    "failed": "Failed",
    "cancelled": "Cancelled",
}


def job_is_terminal(status: str) -> bool:
    return status in JOB_TERMINAL_STATES


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

ALERT_STATE_CATEGORIES: Tuple[str, ...] = (
    "queued", "dry_run", "deferred", "sent", "partial", "failed",
)


def alert_status_category(status: str) -> str:
    """Normalize a stored alert status string into a stable category."""
    s = (status or "").lower()
    if s == "dry-run":
        return "dry_run"
    if s.startswith("deferred"):
        return "deferred"
    if s == "sent" or s.startswith("http-2") or s.startswith("http-3"):
        return "sent"
    if s.startswith("failed"):
        return "failed"
    if s.startswith("partial"):
        return "partial"
    return "queued"


# ---------------------------------------------------------------------------
# Integrations
# ---------------------------------------------------------------------------

INTEGRATION_STATES: Tuple[str, ...] = ("connected", "demo", "disconnected")
INTEGRATION_LABELS: Dict[str, str] = {
    "connected": "Connected",
    "demo": "Demo",
    "disconnected": "Disconnected",
}


# ---------------------------------------------------------------------------
# Agent / UI introspection
# ---------------------------------------------------------------------------


def describe() -> dict:
    """Machine-readable description of all known state machines."""
    return {
        "finding": {
            "states": list(FINDING_STATES),
            "lifecycle_path": list(FINDING_LIFECYCLE_PATH),
            "exception_states": list(FINDING_EXCEPTION_STATES),
            "terminal_states": sorted(FINDING_TERMINAL_STATES),
            "groups": {k: list(v) for k, v in FINDING_GROUPS.items()},
            "labels": FINDING_LABELS,
            "transitions": {k: sorted(v) for k, v in FINDING_TRANSITIONS.items()},
            "transition_policy": "advisory/permissive for compatibility",
        },
        "job": {
            "states": list(JOB_STATES),
            "terminal_states": sorted(JOB_TERMINAL_STATES),
            "labels": JOB_LABELS,
            "transitions": {k: sorted(v) for k, v in JOB_TRANSITIONS.items()},
        },
        "alert": {
            "categories": list(ALERT_STATE_CATEGORIES),
            "normalizer": "lifecycle.alert_status_category",
        },
        "integration": {
            "states": list(INTEGRATION_STATES),
            "labels": INTEGRATION_LABELS,
        },
    }
