# SENTRIX Contextual Help System

SENTRIX includes a consistent contextual help system (`?`) for important sections, metrics, labels, and controls. Help content is **specific and actionable** (not generic placeholders) and is delivered through a centralized registry.

## Components

- **Backend registry:** `GET /api/help` and `GET /api/help/<key>` (served by `_help_registry()` in `sentrix/server.py`). Returns structured entries with `title`, `what`, `solves`, `how`, `who`, `action`, and optional `example`.
- **Frontend registry/helpers:** `sentrix/dashboard/app.js` defines `HELP` (legacy view help), `HELP_SPEC`/fetched registry cache, `getHelpRegistry()`, `showHelp(key)`, and click handling for `[data-help]` buttons.
- **UI pattern:** `.helpbtn` icons trigger an accessible popover/panel (`#help-pop`) positioned near the control; closes on outside click and `Escape`; keyboard-focusable button with `aria-label`.

## Coverage

Help is integrated in:

- **Assignment & workload:** Team Workload & Assignment dashboard, My Assignments, finding drawer Assignment tab (automatic assignment, primary owner, secondary reviewer, workload, SLA, acknowledgement, reassignment, escalation, override, read-only).
- **Existing application:** page headers use `helpbtn(state.view)` and the legacy `HELP` map provides contextual explanations for existing views (Overview, Findings, Sources, Remediation, Alerts, Integrations, Access, Compliance, etc.). The popover renders structured registry entries when available, otherwise legacy view help.

## Adding help content

1. Add/extend a key in `_help_registry()` (`server.py`) for cross-UI structured help.
2. Reference it with `<button class="helpbtn" data-help="<key>">?</button>` in dashboard templates.
3. Keep explanations concise by default; include practical examples for complex/security-sensitive concepts (assignment, critical ownership, override, SLA).

## Assignment-specific help keys

`auto_assignment`, `primary_owner`, `secondary_reviewer`, `workload`, `sla`, `acknowledgement`, `reassignment`, `severity`, `escalation`, `override`, `read_only`, `finding_lifecycle`, `assignment_lifecycle`, `bulk_operations`, plus `risk_score` and `integration_state` for broader SENTRIX concepts.
