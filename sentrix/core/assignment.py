"""Intelligent assignment engine, employee profiles, workload, SLA and audit helpers.

Assignment status is tracked separately from the finding lifecycle.
Decisions are explainable and RBAC/eligibility aware. This module contains
pure logic; persistence and notifications are handled by storage/server layers.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sentrix.core.models import SEVERITY_ORDER, SURFACES, now_iso

# Assignment workflow states (separate from finding.status)
ASSIGNMENT_STATES = (
    "unassigned", "recommended", "assigned", "acknowledged", "in_progress",
    "blocked", "reassignment_requested", "reassigned", "completed", "verified",
)
ASSIGNMENT_TERMINAL = {"completed", "verified"}
ASSIGNMENT_METHODS = ("automatic", "manual", "recommended")

# Severity workload weights (not raw counts)
SEVERITY_WEIGHT = {"critical": 8, "high": 5, "medium": 3, "low": 1, "info": 0.5}
DEFAULT_MAX_CAPACITY = 20.0  # workload points
SLA_HOURS_DEFAULT = {"critical": 4, "high": 24, "medium": 72, "low": 168, "info": 336}
ACK_HOURS_DEFAULT = {"critical": 1, "high": 4, "medium": 8, "low": 24, "info": 48}

SKILLS = [
    "Web Application Security", "API Security", "Cloud Security", "AWS Security",
    "Credential Exposure", "Secret Scanning", "Network Security", "Application Security",
    "DevSecOps", "CI/CD Security", "Incident Response", "Vulnerability Management",
    "Compliance", "Security Monitoring", "Infrastructure Security",
]

# Default profiles for the fixed 6-person roster (admin + 5 team members).
# Skills influence suitability; RBAC remains authoritative for permissions.
DEFAULT_PROFILES = {
    "admin": {
        "skills": ["Vulnerability Management", "Security Monitoring", "Incident Response", "Compliance"],
        "expertise": {"Vulnerability Management": "expert", "Security Monitoring": "advanced"},
        "max_capacity": 24.0, "availability_status": "available", "assignment_eligible": False,
        "title_role_hint": "Platform administration and assignment oversight",
    },
    "r.sharma": {
        "skills": ["Web Application Security", "API Security", "Application Security", "Vulnerability Management", "Secret Scanning"],
        "expertise": {"Application Security": "expert", "Web Application Security": "expert", "API Security": "advanced"},
        "max_capacity": 20.0, "availability_status": "available", "assignment_eligible": True,
        "title_role_hint": "Application security and vulnerability analysis",
    },
    "p.patel": {
        "skills": ["Security Monitoring", "Incident Response", "Vulnerability Management", "Secret Scanning", "Network Security"],
        "expertise": {"Security Monitoring": "expert", "Incident Response": "advanced"},
        "max_capacity": 20.0, "availability_status": "available", "assignment_eligible": True,
        "title_role_hint": "SOC operations, monitoring and alert triage",
    },
    "a.kumar": {
        "skills": ["Incident Response", "DevSecOps", "CI/CD Security", "Cloud Security", "AWS Security", "Infrastructure Security", "Secret Scanning"],
        "expertise": {"Incident Response": "expert", "DevSecOps": "expert", "Cloud Security": "advanced"},
        "max_capacity": 20.0, "availability_status": "available", "assignment_eligible": True,
        "title_role_hint": "Incident response, infrastructure and DevSecOps",
    },
    "n.singh": {
        "skills": ["Compliance", "Vulnerability Management", "Security Monitoring", "Secret Scanning"],
        "expertise": {"Compliance": "expert", "Vulnerability Management": "advanced"},
        "max_capacity": 18.0, "availability_status": "available", "assignment_eligible": True,
        "title_role_hint": "Compliance, audit and verification",
    },
    "v.iyer": {
        "skills": ["Application Security", "Web Application Security", "API Security", "DevSecOps", "Secret Scanning"],
        "expertise": {"Application Security": "advanced", "Web Application Security": "intermediate"},
        "max_capacity": 18.0, "availability_status": "available", "assignment_eligible": True,
        "title_role_hint": "Application code and development remediation",
    },
}

EXPERTISE_SCORE = {"expert": 1.0, "advanced": 0.75, "intermediate": 0.5, "basic": 0.25, "none": 0.0}


def _json_load(val: Any, default: Any) -> Any:
    if val is None or val == "":
        return default
    if isinstance(val, (dict, list)):
        return val
    try:
        return json.loads(val)
    except Exception:
        return default


def profile_defaults(username: str, role: str = "", title: str = "") -> Dict[str, Any]:
    base = dict(DEFAULT_PROFILES.get(username) or {})
    p = {
        "username": username,
        "role": role,
        "title": title,
        "skills": list(base.get("skills") or []),
        "expertise": dict(base.get("expertise") or {}),
        "max_capacity": float(base.get("max_capacity") or DEFAULT_MAX_CAPACITY),
        "availability_status": base.get("availability_status") or "available",
        "assignment_eligible": bool(base.get("assignment_eligible", username != "admin")),
    }
    return p


def finding_domain(finding: Any) -> List[str]:
    """Infer technical domains/skills relevant to a finding."""
    surface = getattr(finding, "surface", "") or (finding.get("surface") if isinstance(finding, dict) else "")
    title = (getattr(finding, "title", "") or (finding.get("title") if isinstance(finding, dict) else "") or "").lower()
    detector = (getattr(finding, "detector_id", "") or (finding.get("detector_id") if isinstance(finding, dict) else "") or "").lower()
    meta = getattr(finding, "meta", None) or (finding.get("meta") if isinstance(finding, dict) else {}) or {}
    family = (meta.get("family") or "").lower()
    domains = set(["Secret Scanning", "Credential Exposure"])
    if surface in ("git", "ide", "filesystem"):
        domains |= {"Application Security", "Web Application Security"}
    if surface in ("ci", "pre_push"):
        domains |= {"DevSecOps", "CI/CD Security", "Application Security"}
    if surface == "cloud":
        domains |= {"Cloud Security", "AWS Security", "Infrastructure Security"}
    if surface in ("slack", "jira", "confluence", "postman"):
        domains |= {"API Security", "Security Monitoring"}
    if "api" in title or "token" in detector or "api" in detector:
        domains.add("API Security")
    if "aws" in title or "aws" in detector or "cloud" in family:
        domains |= {"Cloud Security", "AWS Security"}
    if "key" in detector or "private" in title or "credential" in title:
        domains.add("Credential Exposure")
    if "network" in family:
        domains.add("Network Security")
    return sorted(domains)


def workload_points(severity: str) -> float:
    return float(SEVERITY_WEIGHT.get((severity or "info").lower(), 1.0))


def calculate_workload(findings: Iterable[Dict[str, Any]], username: str) -> Dict[str, Any]:
    active_states = {"open", "new", "triaged", "assigned", "in_progress", "reopened", "acknowledged", "blocked"}
    # findings may be dicts with status/severity and assignment owner info
    points = 0.0
    active = 0
    critical_high = 0
    overdue = 0
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        points += workload_points(f.get("severity"))
        active += 1
        sev = (f.get("severity") or "info").lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        if sev in ("critical", "high"):
            critical_high += 1
        if f.get("sla_breached"):
            overdue += 1
    return {"username": username, "active_findings": active, "workload_points": round(points, 2),
            "critical_high": critical_high, "overdue": overdue, "by_severity": by_sev}


def _role_allows_owner(role: str, severity: str, domains: List[str]) -> Tuple[bool, str]:
    sev = (severity or "info").lower()
    role = role or ""
    # Developer can remediate code-level issues (low/medium, and implementation tasks) but is not incident owner for critical/high by default.
    if role == "developer":
        if sev in ("critical", "high"):
            return False, "developer role is not default incident owner for critical/high findings (can assist under oversight)"
        return True, "developer eligible for code-level remediation"
    if role == "auditor":
        if sev in ("low", "info") and ("Compliance" in domains or "Vulnerability Management" in domains):
            return True, "auditor eligible for low/info review/compliance context"
        return False, "auditor role is verification/compliance focused; not default technical remediation owner"
    # security/appsec/devsecops/super/security_admin/analyst - generally eligible, with severity nuance
    if role in ("super_admin", "security_admin", "appsec_engineer", "security_analyst", "devsecops_engineer"):
        if sev == "critical" and role in ("appsec_engineer", "security_analyst", "devsecops_engineer", "security_admin", "super_admin"):
            return True, "eligible senior/security owner for critical incident"
        return True, "eligible security/engineering owner"
    return False, "role not eligible for assignment ownership"


def score_candidate(finding: Any, profile: Dict[str, Any], workload: Dict[str, Any]) -> Dict[str, Any]:
    domains = finding_domain(finding)
    sev = (getattr(finding, "severity", None) or (finding.get("severity") if isinstance(finding, dict) else "info") or "info").lower()
    role = profile.get("role") or ""
    username = profile.get("username")
    eligible, role_reason = _role_allows_owner(role, sev, domains)
    if not profile.get("assignment_eligible", True):
        eligible = False
        role_reason = "profile not assignment-eligible"
    if (profile.get("availability_status") or "available") != "available":
        eligible = False
        role_reason = f"employee unavailable ({profile.get('availability_status')})"
    max_cap = float(profile.get("max_capacity") or DEFAULT_MAX_CAPACITY)
    points = float(workload.get("workload_points") or 0)
    over_capacity = points >= max_cap
    if over_capacity:
        eligible = False
        role_reason = "employee at or over max workload capacity"

    # Skill match
    skills = set(profile.get("skills") or [])
    expertise = profile.get("expertise") or {}
    matched = [d for d in domains if d in skills]
    skill_score = 0.0
    for d in matched:
        skill_score += EXPERTISE_SCORE.get(expertise.get(d, "intermediate"), 0.5)
    skill_score = (skill_score / max(1, len(domains))) * 40.0

    # Severity/role fit
    severity_fit = 0.0
    ir_fit = role == "devsecops_engineer" or "Incident Response" in skills
    app_fit = role == "appsec_engineer" or "Application Security" in skills
    if sev == "critical":
        if ir_fit:
            severity_fit += 18
        if app_fit:
            severity_fit += 14
        if role == "security_analyst":
            severity_fit += 10
        if role == "security_admin":
            severity_fit += 12
        if role == "developer":
            severity_fit -= 30  # never assign critical solely by low workload; also not eligible
    elif sev == "high":
        if role in ("appsec_engineer", "devsecops_engineer", "security_analyst", "security_admin", "super_admin"):
            severity_fit += 14
        if role == "developer":
            severity_fit -= 15
    elif sev in ("medium", "low"):
        if role == "developer" and (app_fit or "Web Application Security" in skills):
            severity_fit += 10
        if role in ("appsec_engineer", "security_analyst", "devsecops_engineer"):
            severity_fit += 8
        if role == "auditor" and sev in ("low", "info"):
            severity_fit += 4
    else:
        severity_fit += 4

    # Workload balance (lower is better) - but NOT sole factor for critical
    capacity_ratio = points / max_cap if max_cap else 1.0
    workload_score = max(0.0, (1.0 - min(capacity_ratio, 1.5)) * 25.0)
    if sev == "critical":
        workload_score *= 0.35  # de-emphasize for critical

    # Ownership/context bonus
    owner = (getattr(finding, "owner", None) or (finding.get("owner") if isinstance(finding, dict) else "") or "")
    ownership_bonus = 8.0 if owner and owner == username else 0.0

    total = (skill_score + severity_fit + workload_score + ownership_bonus) if eligible else -999.0
    reasons = [role_reason]
    if matched:
        reasons.append(f"matches domains/skills: {', '.join(matched[:4])}")
    reasons.append(f"workload {points:.1f}/{max_cap:.1f} pts ({round(100*capacity_ratio)}%)")
    if ownership_bonus:
        reasons.append("current asset/finding owner context")
    return {
        "username": username, "role": role, "eligible": eligible, "total": round(total, 2),
        "skill_score": round(skill_score, 2), "severity_fit": round(severity_fit, 2),
        "workload_score": round(workload_score, 2), "ownership_bonus": ownership_bonus,
        "workload_points": round(points, 2), "max_capacity": max_cap, "capacity_pct": round(100 * capacity_ratio, 1),
        "over_capacity": over_capacity, "domains": domains, "matched_skills": matched,
        "reasons": reasons,
    }


def explain_assignment(finding: Any, chosen: Dict[str, Any], method: str) -> str:
    title = getattr(finding, "title", None) or (finding.get("title") if isinstance(finding, dict) else "Finding")
    sev = (getattr(finding, "severity", None) or (finding.get("severity") if isinstance(finding, dict) else "") or "").lower()
    who = chosen.get("username")
    matched = chosen.get("matched_skills") or []
    cap = chosen.get("capacity_pct")
    if method == "automatic":
        parts = [f"Assigned to {who} automatically"]
        if sev:
            parts.append(f"for a {sev} finding")
        if matched:
            parts.append(f"matching {', '.join(matched[:3])}")
        parts.append(f"with workload at {cap}% of capacity")
        return (". ".join(parts) + ".").replace("..", ".")
    if method == "recommended":
        return f"Recommended {who}: eligible for {sev or 'this'} finding; skills {', '.join(matched[:3]) or 'general'}; workload {cap}%."
    return f"Manually assigned to {who} by an authorized user."


def select_assignee(finding: Any, profiles: List[Dict[str, Any]], workloads: Dict[str, Dict[str, Any]],
                    exclude: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    exclude = set(exclude or [])
    scored = []
    for p in profiles:
        u = p.get("username")
        if not u or u in exclude or p.get("disabled"):
            continue
        wl = workloads.get(u) or {"workload_points": 0}
        scored.append(score_candidate(finding, p, wl))
    scored.sort(key=lambda x: -x["total"])
    eligible = [s for s in scored if s["eligible"]]
    sev = (getattr(finding, "severity", None) or (finding.get("severity") if isinstance(finding, dict) else "") or "").lower()
    confident = False
    if eligible:
        top = eligible[0]
        # confidence heuristic
        confident = top["total"] >= 20 or (sev in ("medium", "low", "info") and top["total"] >= 10)
        if sev == "critical":
            confident = top["total"] >= 25 and ("Incident Response" in (top.get("matched_skills") or []) or top.get("severity_fit", 0) >= 14 or top["role"] in ("devsecops_engineer","appsec_engineer","security_admin","super_admin"))
    return {"scored": scored, "eligible": eligible, "chosen": eligible[0] if eligible else None,
            "recommendations": eligible[:3], "confident": confident}


def pick_secondary(finding: Any, profiles: List[Dict[str, Any]], workloads: Dict[str, Dict[str, Any]],
                   primary: str) -> Optional[Dict[str, Any]]:
    res = select_assignee(finding, profiles, workloads, exclude=[primary])
    for c in res["eligible"]:
        if c["username"] != primary and c["role"] in ("security_admin","super_admin","appsec_engineer","devsecops_engineer","security_analyst","auditor"):
            return c
    return res["eligible"][0] if res["eligible"] else None


def default_sla_config() -> Dict[str, Any]:
    return {"ack_hours": dict(ACK_HOURS_DEFAULT), "remediate_hours": dict(SLA_HOURS_DEFAULT),
            "escalate_after_ack_breach": True, "escalate_after_remediation_breach": True,
            "assignment_mode": "admin_approval", "assignment_enabled": True}


def compute_due_dates(severity: str, assigned_at: Optional[str] = None, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Optional[str]]:
    import time as _time
    from datetime import datetime, timedelta, timezone
    cfg = cfg or default_sla_config()
    sev = (severity or "info").lower()
    try:
        base = datetime.strptime((assigned_at or now_iso())[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except Exception:
        base = datetime.now(timezone.utc)
    ack_h = float((cfg.get("ack_hours") or ACK_HOURS_DEFAULT).get(sev, ACK_HOURS_DEFAULT.get(sev, 24)))
    rem_h = float((cfg.get("remediate_hours") or SLA_HOURS_DEFAULT).get(sev, SLA_HOURS_DEFAULT.get(sev, 72)))
    return {
        "ack_due_at": (base + timedelta(hours=ack_h)).strftime("%Y-%m-%dT%H:%M:%S"),
        "due_at": (base + timedelta(hours=rem_h)).strftime("%Y-%m-%dT%H:%M:%S"),
        "ack_hours": ack_h, "remediate_hours": rem_h,
    }


def compute_workflow(finding: Any, assignment: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Compute the simplified 3-stage review workflow stage (single source of truth).

    Stages: New, Assigned, Primary Review, Secondary Review, Admin Review,
    Remediation, Verification, Closed.
    """
    a = assignment or {}
    fstatus = getattr(finding, "status", "") if finding else (a.get("finding_status") or "")
    if isinstance(finding, dict):
        fstatus = finding.get("status", "") or fstatus
    primary = a.get("primary_owner") or ""
    secondary = a.get("secondary_reviewer") or ""
    p_ack = bool(a.get("acknowledged_at"))
    s_ack = bool(a.get("secondary_acknowledged_at"))
    p_started = bool(a.get("primary_investigation_started_at"))
    p_sub = bool(a.get("primary_submitted_at"))
    p_class = (a.get("primary_classification") or "").strip()
    s_started = bool(a.get("secondary_review_started_at"))
    s_sub = bool(a.get("secondary_submitted_at"))
    s_out = (a.get("secondary_outcome") or "").strip()
    admin = (a.get("admin_decision") or "").strip()
    reassess = (a.get("reassessment_target") or "").strip()
    rem_owner = (a.get("remediation_owner") or "").strip()
    rem_status = (a.get("remediation_status") or "").strip()
    rem_sub = bool(a.get("remediation_submitted_at"))
    ver_req = bool(a.get("verification_requested_at"))
    ver_dec = (a.get("verification_decision") or "").strip()

    if admin == "confirm_false_positive" or (fstatus == "closed" and (admin or not primary)):
        status_labels = ["False Positive"] if admin == "confirm_false_positive" else []
        return _wf(stage="Closed", label="Closed", status_labels=status_labels, p_class=p_class, s_out=s_out, admin=admin)
    if fstatus == "closed":
        return _wf("Closed", "Closed", [], p_class, s_out, admin)
    if fstatus == "false_positive" and not admin:
        # A finding already classified as false positive (by disposition or stale demo state) is closed.
        return _wf("Closed", "Closed", ["False Positive"], p_class, s_out, admin)

    if not primary:
        return _wf("New", "New", ["Awaiting Assignment"] if not reassess else ["Reassessment Requested"], p_class, s_out, admin)
    # Admin assignment automatically puts the finding into Primary Triage mode.
    # No separate acknowledgement click is required to proceed.
    if reassess == "primary" or (reassess and not p_sub):
        return _wf("Primary Review", "Primary Review", ["Reassessment Requested"] + (["In Progress"] if p_started else ["Awaiting Primary Triage"]), p_class, s_out, admin)
    if not p_sub:
        return _wf("Primary Review", "Primary Review", ["Awaiting Primary Triage" if not p_started else "Primary Triage In Progress"], p_class, s_out, admin)

    if not secondary:
        return _wf("Admin Review", "Admin Review", ["Primary Triage Complete; secondary assignment needed"], p_class, s_out, admin)
    if reassess == "secondary":
        return _wf("Secondary Review", "Secondary Review", ["Reassessment Requested"] + (["In Progress"] if s_started else ["Awaiting Secondary Review"]), p_class, s_out, admin)
    if not s_sub:
        return _wf("Secondary Review", "Secondary Review", ["Awaiting Secondary Review" if not s_started else "Secondary Review In Progress"], p_class, s_out, admin)

    s_norm = (s_out or "").replace("disagree_", "").replace("confirm_", "")
    disagreement = bool(s_out.startswith("disagree") if s_out else False) or bool(p_class and s_norm in ("true_positive","false_positive") and s_norm != p_class)
    if not admin or admin == "request_reassessment":
        labels = []
        if disagreement and admin != "request_reassessment": labels.append("Disagreement")
        if admin == "request_reassessment": labels.append("Reassessment Requested")
        return _wf("Admin Review", "Admin Review", labels, p_class, s_out, admin)

    if admin == "confirm_true_positive":
        if ver_dec == "approved" or a.get("verified_at"):
            return _wf("Closed", "Closed", ["Verified"], p_class, s_out, admin)
        if ver_req and ver_dec != "rejected":
            return _wf("Verification", "Verification", ["Verification Pending"], p_class, s_out, admin)
        if rem_sub or rem_status in ("submitted", "completed") or fstatus == "remediated":
            return _wf("Verification", "Verification", ["Verification Pending"], p_class, s_out, admin)
        return _wf("Remediation", "Remediation", ["Remediation Pending"] if not rem_owner else ["In Progress"], p_class, s_out, admin)

    return _wf("Admin Review", "Admin Review", [], p_class, s_out, admin)


def _wf(stage, label, status_labels, p_class, s_out, admin):
    return {
        "stage": stage, "label": label, "status_labels": status_labels or [],
        "primary_classification": p_class, "secondary_outcome": s_out, "admin_decision": admin,
        "stages": ["New","Assigned","Primary Review","Secondary Review","Admin Review","Remediation","Verification","Closed"],
    }
