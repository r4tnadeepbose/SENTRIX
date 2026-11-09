"""Server-facing helpers for the assignment/workload/help system (RBAC-aware)."""
from __future__ import annotations

import json, time
from typing import Any, Dict, List, Optional, Tuple

from sentrix.auth import ADMIN_ROLES, ROLES, WRITE_ROLES
from sentrix.core.assignment import (
    ASSIGNMENT_METHODS, ASSIGNMENT_STATES, compute_due_dates, default_sla_config,
    explain_assignment, pick_secondary, select_assignee, workload_points, compute_workflow,
)
from sentrix.core.models import SEVERITIES, now_iso


def _is_admin(user): return (user or {}).get("role") in ADMIN_ROLES
def _can_write(user): return (user or {}).get("role") in WRITE_ROLES
def _can_manage_assignments(user):
    # admins + security/appsec/devsecops can manage; read-only cannot
    return (user or {}).get("role") in ("super_admin","security_admin","security_analyst","appsec_engineer","devsecops_engineer")

def ensure_profiles(storage):
    users = storage.list_users()
    storage.ensure_employee_profiles(users)
    return users

def _active_assignment_map(storage, findings):
    # get assignments for findings (limit to relevant)
    amap = {}
    for f in findings:
        a = storage.get_assignment(f.id)
        if a.get("status") and a["status"] != "unassigned":
            amap[f.id] = a
        elif a.get("primary_owner"):
            amap[f.id] = a
    return amap

def _finding_workload_items(storage, username, findings):
    items = []
    for f in findings:
        a = storage.get_assignment(f.id)
        if a.get("primary_owner") == username and a.get("status") not in ("completed","verified","unassigned",""):
            items.append({"id": f.id, "severity": f.severity, "status": f.status, "assignment_status": a.get("status"),
                          "sla_breached": _sla_breached(a), "ack_due_at": a.get("ack_due_at"), "due_at": a.get("due_at")})
    return items

def _sla_breached(a):
    try:
        now = time.time()
        for key in ("ack_due_at","due_at"):
            v = a.get(key)
            if not v: continue
            ts = time.mktime(time.strptime(v[:19], "%Y-%m-%dT%H:%M:%S"))
            # ack breach only if not acknowledged
            if key == "ack_due_at" and a.get("acknowledged_at"): continue
            if key == "due_at" and a.get("status") in ("completed","verified"): continue
            if now > ts: return True
    except Exception: pass
    return False

def build_workloads(storage, findings=None):
    from sentrix.core.assignment import calculate_workload
    findings = findings if findings is not None else storage.list_findings(limit=5000)
    users = ensure_profiles(storage)
    # collect active assigned findings per user
    per = {u["username"]: [] for u in users}
    for f in findings:
        a = storage.get_assignment(f.id)
        owner = a.get("primary_owner") or ""
        if not owner: continue
        if a.get("status") in ("completed","verified","unassigned"): continue
        if f.status in ("remediated","verified","closed","false_positive","accepted_risk","suppressed"): continue
        item = {"severity": f.severity, "status": f.status, "sla_breached": _sla_breached(a)}
        per.setdefault(owner, []).append(item)
    res = {}
    for u in users:
        wl = calculate_workload(per.get(u["username"], []), u["username"])
        prof = storage.get_employee_profile(u["username"]) or {}
        cap = float(prof.get("max_capacity") or 20)
        pct = round(100 * wl["workload_points"] / cap, 1) if cap else 0
        res[u["username"]] = {**wl, "max_capacity": cap, "workload_pct": pct, "available_capacity": max(0, round(cap - wl["workload_points"],2)),
                              "availability_status": prof.get("availability_status","available"),
                              "assignment_eligible": prof.get("assignment_eligible", True),
                              "skills": prof.get("skills",[]), "expertise": prof.get("expertise",{}),
                              "role": u.get("role"), "title": u.get("title","")}
    return res

def check_sla_escalations(storage, router=None):
    """Emit deduplicated SLA breach notifications/escalation markers."""
    findings = storage.list_findings(limit=5000)
    escalated = 0
    for f in findings:
        a = storage.get_assignment(f.id)
        st = a.get("status") or "unassigned"
        if st in ("completed","verified","unassigned",""):
            continue
        scoring = a.get("scoring") or {}
        breached = _sla_breached(a)
        if not breached:
            continue
        key = "escalated_breach"
        if scoring.get(key):
            continue
        msg = f"SLA breach/escalation: finding {f.id} ({f.severity}) owner={a.get('primary_owner') or '-'} status={st}"
        _notify(storage, router, f, "assignment.escalation", msg, "system")
        scoring[key] = now_iso()
        try:
            storage.upsert_assignment(f.id, "system", reason="SLA breach escalation emitted", action="sla_escalated",
                                      sync_finding=False, scoring=scoring)
            escalated += 1
        except Exception:
            pass
        if (f.severity or "").lower() == "critical":
            _notify(storage, router, f, "assignment.critical_escalation", f"Critical SLA/escalation attention required for {f.id} ({a.get('primary_owner') or 'unassigned'})", "system")
    return {"ok": True, "escalated": escalated}


def dashboard(storage, user):
    findings = storage.list_findings(limit=5000)
    try:
        check_sla_escalations(storage, None)
    except Exception:
        pass
    users = ensure_profiles(storage)
    workloads = build_workloads(storage, findings)
    assignments = {}
    unassigned = []; awaiting_ack=[]; inprog=[]; blocked=[]; overdue=[]; reassignment_requests=[]; recommended=[]; completed=[]
    critical_unassigned = 0
    high_assigned = 0
    for f in findings:
        if f.status in ("closed",): continue
        a = storage.get_assignment(f.id)
        st = a.get("status") or "unassigned"
        breached = _sla_breached(a)
        row = {"finding_id": f.id, "title": f.title, "severity": f.severity, "finding_status": f.status,
               "surface": f.surface, "primary_owner": a.get("primary_owner",""), "secondary_reviewer": a.get("secondary_reviewer",""),
               "assignment_status": st, "method": a.get("method",""), "ack_due_at": a.get("ack_due_at"),
               "due_at": a.get("due_at"), "sla_breached": breached, "explanation": a.get("explanation","")}
        assignments[f.id] = row
        if st in ("unassigned",""):
            unassigned.append(row)
            if f.severity == "critical": critical_unassigned += 1
        elif st == "recommended": recommended.append(row)
        elif st == "assigned": awaiting_ack.append(row)
        elif st in ("acknowledged","in_progress"): inprog.append(row)
        elif st == "blocked": blocked.append(row)
        elif st == "reassignment_requested": reassignment_requests.append(row)
        elif st in ("completed","verified"): completed.append(row)
        if breached and st not in ("completed","verified","unassigned",""): overdue.append(row)
        if st not in ("unassigned","completed","verified","") and f.severity == "high": high_assigned += 1
    team = []
    for u in users:
        w = workloads.get(u["username"],{})
        team.append({"username": u["username"], "role": u.get("role"), "title": u.get("title",""),
                     "skills": w.get("skills",[]), "expertise": w.get("expertise",{}),
                     "active_findings": w.get("active_findings",0), "critical_high": w.get("critical_high",0),
                     "workload_points": w.get("workload_points",0), "max_capacity": w.get("max_capacity",20),
                     "workload_pct": w.get("workload_pct",0), "available_capacity": w.get("available_capacity",0),
                     "availability_status": w.get("availability_status","available"),
                     "assignment_eligible": w.get("assignment_eligible",True), "overdue": w.get("overdue",0),
                     "by_severity": w.get("by_severity",{})})
    return {
        "metrics": {"total_findings": len(findings), "unassigned": len(unassigned),
                    "critical_unassigned": critical_unassigned, "high_assigned": high_assigned,
                    "pending_ack": len(awaiting_ack), "overdue": len(overdue),
                    "reassignment_requests": len(reassignment_requests), "sla_breaches": len([r for r in assignments.values() if r["sla_breached"]])},
        "team": team,
        "queues": {"unassigned": unassigned[:200], "recommended": recommended[:200], "awaiting_ack": awaiting_ack[:200],
                   "in_progress": inprog[:200], "blocked": blocked[:200], "overdue": overdue[:200],
                   "reassignment_requests": reassignment_requests[:200], "completed": completed[:100]},
        "sla_config": storage.get_assignment_sla_config(),
    }

def my_assignments(storage, username, user=None):
    findings = storage.list_findings(limit=5000)
    role = (user or {}).get("role") or ""
    is_admin = role in ("super_admin","security_admin")
    mine=[]; critical=[]; high=[]; pending_ack=[]; overdue=[]; reviews=[]; completed=[]
    primary_reviews=[]; secondary_reviews=[]; remediation_tasks=[]; verification_requests=[]
    awaiting_admin=[]; remediation_progress=[]; admin_decided=[]
    for f in findings:
        a = storage.get_assignment(f.id)
        wf = compute_workflow(f, a)
        stage = wf.get("stage")
        row = {"finding_id": f.id, "title": f.title, "severity": f.severity, "finding_status": f.status,
               "surface": f.surface, "assignment_status": a.get("status","unassigned"), "primary_owner": a.get("primary_owner",""),
               "secondary_reviewer": a.get("secondary_reviewer",""), "due_at": a.get("due_at"), "ack_due_at": a.get("ack_due_at"),
               "sla_breached": _sla_breached(a), "explanation": a.get("explanation",""), "method": a.get("method",""),
               "workflow_stage": stage, "status_labels": wf.get("status_labels",[]),
               "assigned_by": a.get("assigned_by",""), "assignment_instructions": a.get("assignment_instructions",""),
               "assigned_at": a.get("assigned_at",""), "primary_classification": a.get("primary_classification",""),
               "my_role": "primary" if a.get("primary_owner")==username else ("secondary" if a.get("secondary_reviewer")==username else ("remediation" if a.get("remediation_owner")==username else ""))}
        is_primary = a.get("primary_owner")==username
        is_secondary = a.get("secondary_reviewer")==username
        is_rem = a.get("remediation_owner")==username
        involved = is_primary or is_secondary or is_rem
        if is_admin:
            if stage == "Admin Review": awaiting_admin.append(row)
            if stage in ("Remediation","Verification"):
                remediation_progress.append(row)
            if a.get("admin_decision"): admin_decided.append(row)
        if stage == "Closed" and involved:
            completed.append(row); continue
        if involved:
            mine.append(row)
            if f.severity=="critical": critical.append(row)
            if f.severity=="high": high.append(row)
            if row["sla_breached"]: overdue.append(row)
        if stage == "Assigned":
            if is_primary and not a.get("acknowledged_at"): pending_ack.append(row)
            if is_secondary and not a.get("secondary_acknowledged_at"): pending_ack.append(row)
        if is_primary and stage == "Primary Review" and not is_admin: primary_reviews.append(row)
        if is_secondary and stage == "Secondary Review" and not is_admin: secondary_reviews.append(row); reviews.append(row)
        if (is_primary or is_rem) and stage == "Remediation" and not is_admin: remediation_tasks.append(row)
        if (is_primary or is_rem or is_secondary) and stage == "Verification" and not is_admin: verification_requests.append(row)
    seen=set(); pa=[]
    for r in pending_ack:
        if r["finding_id"] in seen: continue
        seen.add(r["finding_id"]); pa.append(r)
    return {"username": username, "my_assignments": mine, "critical": critical, "high": high,
            "pending_ack": pa, "overdue": overdue, "reviews": reviews, "completed": completed[:50],
            "primary_reviews": primary_reviews, "secondary_reviews": secondary_reviews,
            "remediation_tasks": remediation_tasks, "verification_requests": verification_requests,
            "awaiting_final_review": awaiting_admin, "remediation_progress": remediation_progress, "admin_decided": admin_decided[:50]}

def _notify(storage, router, finding, kind, message, actor="system"):
    try:
        storage.add_log("info","assignment", message, component="assignment", event_type=kind, resource=finding.id if finding else "", status="sent")
    except Exception: pass
    # outbox notification via alert-like record where possible
    try:
        from sentrix.core.models import Alert
        alert = Alert(finding_id=finding.id if finding else "", channel="outbox", message=f"[ASSIGNMENT] {message}", status="sent")
        storage.add_alert(alert)
        if router and hasattr(router,'outbox'):
            (router.outbox / f"{alert.id}.json").write_text(json.dumps({"alert":alert.to_dict(),"kind":kind,"actor":actor}, indent=2), encoding="utf-8")
    except Exception: pass

def do_auto_assign(storage, finding, actor, router=None, force_reason=None, finalize=None):
    """Run engine. finalize=True assigns; finalize=False creates recommendation/awaiting approval.
    If finalize is None, uses assignment policy mode (automatic=>assign, admin_approval/manual/recommended=>recommend when system-driven).
    """
    sla_cfg = storage.get_assignment_sla_config() or {}
    mode = (sla_cfg.get("assignment_mode") or "admin_approval").lower()
    if finalize is None:
        # explicit admin-initiated calls should pass finalize; system intake follows mode
        finalize = (mode == "automatic")
    users = ensure_profiles(storage)
    findings = storage.list_findings(limit=5000)
    workloads = build_workloads(storage, findings)
    profiles = []
    for u in users:
        p = storage.get_employee_profile(u["username"]) or {}
        p.update({"username": u["username"], "role": u.get("role"), "title": u.get("title",""), "disabled": u.get("disabled")})
        profiles.append(p)
    res = select_assignee(finding, profiles, workloads)
    if not res["chosen"]:
        storage.upsert_assignment(finding.id, actor, reason="No eligible employee found; escalated to administrator",
                                  action="auto_assign_failed", status="unassigned", method="automatic",
                                  explanation="No eligible employee found. Finding remains unassigned and requires administrator attention.", scoring={"recommendations": res.get("recommendations",[])})
        _notify(storage, router, finding, "assignment.escalated", f"No eligible assignee for {finding.id} ({finding.severity}): escalated to administrator", actor)
        return {"ok": False, "error": "No eligible employee found; finding remains unassigned and escalated to administrator", "result": res}
    chosen = res["chosen"]
    sec = None
    if (finding.severity or "").lower() in ("critical","high"):
        s = pick_secondary(finding, profiles, workloads, chosen["username"])
        if s: sec = s["username"]
    expl = explain_assignment(finding, chosen, "automatic")
    scoring = dict(chosen)
    scoring["recommendations"] = res.get("recommendations", [])[:5]
    scoring["confidence"] = "high" if res.get("confident") else "low"
    scoring["suggested_secondary_reviewer"] = sec or ""
    if not finalize or not res.get("confident"):
        reason = "Recommendation generated (awaiting admin approval)" if finalize or mode in ("admin_approval","recommended") else "Assignment recommendation generated"
        if not res.get("confident"):
            reason = "Automatic assignment confidence low; recommendations provided for admin review"
        assignment = storage.upsert_assignment(finding.id, actor, reason=reason, action="recommended",
                                               primary_owner=chosen["username"], secondary_reviewer=sec or "",
                                               status="recommended", method="automatic", explanation=expl,
                                               scoring=scoring, assigned_by=actor, assigned_at=now_iso())
        _notify(storage, router, finding, "assignment.recommended", f"Recommendation for {finding.id}: {chosen['username']}" + (f" (reviewer {sec})" if sec else "") + f". {expl}", actor)
        return {"ok": False, "recommended": True, "assignment": assignment, "chosen": chosen, "secondary": sec, "recommendations": res.get("recommendations",[])[:5], "result": res}
    due = compute_due_dates(finding.severity, now_iso(), sla_cfg)
    assignment = storage.upsert_assignment(finding.id, actor, reason=expl, action="auto_assigned",
                                           primary_owner=chosen["username"], secondary_reviewer=sec or "",
                                           status="assigned", method="automatic", explanation=expl,
                                           scoring=scoring, assigned_by=actor, assigned_at=now_iso(),
                                           ack_due_at=due["ack_due_at"], due_at=due["due_at"], sla_config=sla_cfg)
    if (finding.severity or "").lower() == "critical":
        _notify(storage, router, finding, "assignment.critical", f"Critical finding {finding.id} assigned to {chosen['username']}" + (f" with reviewer {sec}" if sec else "") + f" by automatic assignment.", actor)
    _notify(storage, router, finding, "assignment.assigned", f"Finding {finding.id} assigned to {chosen['username']} (primary)" + (f", reviewer {sec}" if sec else "") + f".", actor)
    return {"ok": True, "assignment": assignment, "chosen": chosen, "secondary": sec, "result": res}


def approve_recommendation(storage, finding, actor, primary_owner=None, secondary_reviewer=None, reason="", router=None):
    a = storage.get_assignment(finding.id)
    if (a.get("status") or "") not in ("recommended","unassigned"):
        # allow approving/re-applying if admin insists? keep safe
        pass
    owner = (primary_owner or a.get("primary_owner") or "").strip()
    reviewer = (secondary_reviewer if secondary_reviewer is not None else a.get("secondary_reviewer") or "").strip()
    if not owner:
        return {"ok": False, "error": "No recommended owner to approve"}
    return manual_assign(storage, finding, actor, owner, reviewer, reason=reason or "Approved assignment recommendation", method="manual", router=router, admin_override=False)

def manual_assign(storage, finding, actor, primary_owner, secondary_reviewer="", reason="", due_at="", instructions="", method="manual", router=None, admin_override=False, priority=""):
    if not primary_owner:
        return {"ok": False, "error": "primary_owner required"}
    if primary_owner == secondary_reviewer:
        return {"ok": False, "error": "Primary owner and secondary reviewer must be different"}
    users = {u["username"]: u for u in storage.list_users()}
    if primary_owner not in users:
        return {"ok": False, "error": "Primary owner not found"}
    if secondary_reviewer and secondary_reviewer not in users:
        return {"ok": False, "error": "Secondary reviewer not found"}
    ensure_profiles(storage)
    p_owner = storage.get_employee_profile(primary_owner) or {}
    if users[primary_owner].get("disabled"):
        return {"ok": False, "error": "Primary owner account is disabled"}
    # Eligibility/suitability checks (admin override requires reason and is audited)
    if not admin_override:
        role = users[primary_owner].get("role", "")
        is_admin_target = role in ("super_admin","security_admin") or primary_owner == "admin"
        if not p_owner.get("assignment_eligible", True) and not is_admin_target:
            return {"ok": False, "error": "Primary owner is not assignment-eligible"}
        if (p_owner.get("availability_status") or "available") != "available":
            return {"ok": False, "error": f"Primary owner unavailable ({p_owner.get('availability_status')})"}
        # role/severity suitability
        sev = (getattr(finding, "severity", "") or "").lower()
        if sev in ("critical", "high") and role == "developer":
            return {"ok": False, "error": "Developer cannot be primary owner for critical/high findings without admin override and oversight context"}
        workloads = build_workloads(storage)
        w = workloads.get(primary_owner, {})
        if float(w.get("workload_points") or 0) >= float(p_owner.get("max_capacity") or 20):
            return {"ok": False, "error": "Primary owner is at or over workload capacity"}
    else:
        if not (reason or "").strip():
            return {"ok": False, "error": "Admin override requires a mandatory reason"}
    if secondary_reviewer:
        p_rev = storage.get_employee_profile(secondary_reviewer) or {}
        if users[secondary_reviewer].get("disabled"):
            return {"ok": False, "error": "Secondary reviewer account is disabled"}
        if not admin_override and not p_rev.get("assignment_eligible", True):
            return {"ok": False, "error": "Secondary reviewer is not assignment-eligible"}
    sla_cfg = storage.get_assignment_sla_config()
    due = compute_due_dates(finding.severity, now_iso(), sla_cfg)
    if due_at: due["due_at"] = due_at
    wls = build_workloads(storage)
    expl = reason or explain_assignment(finding, {"username": primary_owner, "matched_skills": [], "capacity_pct": (wls.get(primary_owner) or {}).get("workload_pct", 0)}, method)
    action = "admin_override" if admin_override else ("manual_assigned" if method=="manual" else "assigned")
    a = storage.upsert_assignment(finding.id, actor, reason=reason or expl, action=action,
                                  primary_owner=primary_owner, secondary_reviewer=secondary_reviewer or "",
                                  status="assigned", method=method, explanation=expl,
                                  assigned_by=actor, assigned_at=now_iso(), acknowledged_at="", secondary_acknowledged_at="",
                                  ack_due_at=due["ack_due_at"],
                                  due_at=due["due_at"], priority=(priority or "")[:50], assignment_instructions=(instructions or "")[:2000],
                                  assistance_requested_at="", assistance_reason="",
                                  verification_requested_at="", verification_decision="", verification_rejection_reason="",
                                  sla_config=sla_cfg,
                                  scoring={"admin_override": admin_override, "instructions": (instructions or "")[:500], "priority": priority or ""})
    _notify(storage, router, finding, "assignment.assigned", f"Finding {finding.id} {action.replace('_',' ')} to {primary_owner}" + (f" (reviewer {secondary_reviewer})" if secondary_reviewer else "") + f" by {actor}.", actor)
    if admin_override:
        try:
            storage.add_log("warn","assignment", f"Admin override assignment {finding.id} -> {primary_owner}", component="assignment", event_type="admin_override", resource=finding.id, status="override")
        except Exception: pass
    return {"ok": True, "assignment": a}
