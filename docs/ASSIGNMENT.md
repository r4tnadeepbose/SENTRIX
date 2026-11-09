# SENTRIX Intelligent Assignment & Workload Management

This document describes the production-oriented **Intelligent Finding Assignment, Employee Workload Management, and Accountability** system implemented in SENTRIX. The implementation is additive and preserves the existing finding lifecycle, RBAC, authentication/session security, and the fixed six-person demo roster.

## Goals

- Give every finding a clear, explainable ownership path.
- Route work by severity, technical domain, eligibility, skills, workload, availability, and ownership context.
- Keep assignment accountability separate from the finding lifecycle state machine.
- Enforce RBAC and sensitive-action authorization on the backend.
- Record actor, timestamp, and reason for sensitive operations.

## Fixed roster (compatible with existing RBAC)

The system uses the existing six demo accounts/roles and does not create, rename, or change their credentials:

| Employee | Role | Primary responsibility | Default assignment eligibility |
|---|---|---|---|
| Admin | `super_admin` | Platform administration and assignment oversight | Oversight (not a default assignee) |
| R. Sharma | `appsec_engineer` | Application security and vulnerability analysis | Eligible |
| P. Patel | `security_analyst` | SOC operations, monitoring and alert triage | Eligible |
| A. Kumar | `devsecops_engineer` | Incident response, infrastructure and DevSecOps | Eligible |
| N. Singh | `auditor` | Compliance, audit and verification | Eligible for review/compliance-appropriate low/info contexts; not default technical remediation owner |
| V. Iyer | `developer` | Application code and development remediation | Eligible for code-level remediation (medium/low/info as appropriate); **not** default incident owner for critical/high |

**Skills influence assignment suitability; RBAC determines authorization.** Gaining a skill does not grant additional application permissions.

## Assignment engine

Implemented in `sentrix/core/assignment.py` with API/persistence helpers in `sentrix/core/assignment_api.py`.

### Inputs

1. **Finding severity** (urgency).
2. **Finding category/technical domain** inferred from surface, detector, title and metadata (e.g., Application Security, API Security, Cloud/AWS Security, Credential Exposure/Secret Scanning, DevSecOps/CI-CD, Incident Response, Security Monitoring, Compliance).
3. **Employee role and permissions** (RBAC/eligibility constraints).
4. **Employee expertise and skills** (profile skills + expertise levels).
5. **Current active workload** (severity-weighted workload points, not raw finding counts).
6. **Employee availability** (`available`, `unavailable`, `leave`) and assignment eligibility.
7. **Asset/repository/finding ownership context** (bonus when matching existing owner context).
8. **Existing assignments and conflicts** (active assignment state, primary/secondary separation).

### Decision rules

- **Never random.** Candidates are scored; ineligible candidates are excluded.
- **Explainable.** Every automated/recommended/manual decision stores an explanation and scoring details.
- **Critical findings:** never assigned solely because an employee has the lowest workload. Eligible senior/security or incident-response ownership is prioritized; developer is not the default critical incident owner. Critical/high can receive a secondary reviewer.
- **Workload weighting:** critical findings carry more workload weight than informational findings (configurable defaults in engine/profile capacity model).
- **No eligible employee:** the finding remains unassigned/recommended for admin attention; it is never silently discarded or closed.

### Assignment methods

- **Automatic:** engine selects the best eligible employee (and reviewer when appropriate) with explanation.
- **Manual:** authorized managers/admins select primary owner and/or secondary reviewer, provide reason, optional due date/instructions. Backend validates eligibility/suitability unless admin override is explicitly requested.
- **Recommended:** when confidence is low or no confident eligible owner is found, recommendations are provided and the finding is not silently assigned to an unsuitable employee.

### Assignment lifecycle (separate from finding lifecycle)

`unassigned → recommended → assigned → acknowledged → in_progress → blocked → reassignment_requested → reassigned → completed → verified`

The finding lifecycle (`open`, `triaged`, `assigned`, `in_progress`, etc.) remains intact for compatibility. Assignment status is stored in `finding_assignments.status`.

## Primary owner and secondary reviewer

- **Primary owner:** accountable for investigation/remediation coordination, receives assignment notifications, must acknowledge.
- **Secondary reviewer:** provides oversight/independent verification; can review evidence and request additional investigation. Secondary reviewer does **not** automatically inherit primary-owner permissions. Primary and secondary must be different.

## SLA, acknowledgement, escalation

- SLA/ack deadlines are **configurable** (per severity ack/remediation hours) via `assignment_sla_config` / `GET|POST /api/assignment/sla-config` (admin).
- Due dates are computed at assignment; breached/overdue state is surfaced in dashboards and finding details.
- Deduplicated SLA escalation notifications are emitted via `check_sla_escalations` (also triggered from dashboard access and `POST /api/assignment/escalate-check`).
- Notifications integrate with existing alerting/storage patterns (system log + alert/outbox records) without storing raw secrets.

## RBAC and security

- **Backend-enforced authorization** for all assignment APIs (not UI-only).
- Team Workload dashboard/profiles: `super_admin`, `security_admin`, `security_analyst`, `appsec_engineer`, `devsecops_engineer`.
- Profile/SLA administration: `super_admin`, `security_admin`.
- Acknowledge/start/block/complete/request-reassign: primary owner or admin (as applicable).
- Verify: secondary reviewer or authorized manager/admin.
- Reassign/manual assign/bulk/auto: authorized managers/admins.
- **Admin override requires a mandatory reason** and is audited/logged.
- Read-only roles remain read-only; cross-user mutations are rejected (403).
- CSRF/origin protections remain those of the existing server; assignment endpoints use existing POST protections.
- No raw credentials/secret values are written to assignment metadata, explanations, audit details, or notifications.

## Notifications

Assignment events generate system-log and alert/outbox notifications (deduplicated for SLA escalations), including assignment, acknowledgement, reassignment/reassignment request, critical assignment/escalation, and SLA breach attention. Existing alerting infrastructure and preferences are respected where applicable.

## Data model (additive migration v4)

Tables added in `sentrix/core/extensions.py`:

- `employee_profiles` — username, skills (JSON), expertise (JSON), max_capacity, availability_status, assignment_eligible, updated_by/at.
- `finding_assignments` — finding_id (PK), primary_owner, secondary_reviewer, status, method, explanation, scoring (JSON), assigned_by/at, acknowledged_at, ack_due_at, due_at, blocked/reassignment/completion/verification fields, sla_config snapshot.
- `assignment_history` — immutable-style history records with action, from/to owner/reviewer, status, reason, actor, details, timestamp.
- `assignment_sla_config` — singleton configurable SLA/ack hours.

Compatibility: `finding_extra.assignee` and `findings.owner` are synchronized with the primary owner.

## Key files

- `sentrix/core/assignment.py` — engine, scoring, explanations, domains, workload points, SLA computation, roster defaults.
- `sentrix/core/assignment_api.py` — dashboard/my queues, RBAC helpers, auto/manual/bulk, notifications, SLA escalation checks.
- `sentrix/core/extensions.py` — schema migration v4, CRUD for profiles/assignments/history/SLA.
- `sentrix/server.py` — `/api/assignment/*`, `/api/help`, finding detail enrichment, legacy assign sync.
- `sentrix/dashboard/app.js`, `sentrix/dashboard/styles.css` — Team Workload & Assignment, My Assignments, finding Assignment tab, contextual help.
- `tests/test_assignment.py` — engine, storage, API/RBAC workflow tests.
