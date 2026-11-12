<div align="center">

<img src="assets/logo.svg" alt="SENTRIX logo" width="96">

# SENTRIX

**Secret Exposure & Network Threat Response Intelligence eXchange**

> One Intelligence. Every Exposure. Total Control.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Runtime dependencies](https://img.shields.io/badge/runtime%20dependencies-stdlib--only-brightgreen.svg)](docs/DEPLOYMENT.md)
[![Version](https://img.shields.io/badge/version-2.0.0-informational.svg)](pyproject.toml)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%C2%B7%20Linux%20%C2%B7%20macOS-lightgrey.svg)](#installation--quick-start)

A self-hosted, offline-first security intelligence platform that **finds, explains, prioritizes, routes, remediates, and verifies** exposed secrets across your engineering footprint — delivered as a single Python application with **no required runtime dependencies**.

[What is SENTRIX?](#what-is-sentrix) • [Problem it solves](#the-problem-sentrix-solves) • [Screenshots](#product-tour-screenshots) • [Architecture](#architecture) • [Quick start](#installation--quick-start) • [Documentation](#documentation)

</div>

---

## What is SENTRIX?

SENTRIX is an enterprise-oriented **secret exposure and response platform** built as a local modular monolith: one Python 3.11+ process serves the **Command Center (web console)**, **JSON API**, **detection engine**, **alert router**, **background job/scheduler**, and **SQLite-backed storage**.

It detects credentials, API keys, tokens, private keys, connection strings, and other sensitive values wherever they appear (source, git/CI, developer surfaces, cloud artifacts, and supported SaaS/collaboration exports or live polls), then turns raw detections into an operational workflow:

- **Detect** with a shared intelligence core (26 built-in detectors, custom rules, entropy/format heuristics)
- **Contextualize** with provenance, environment hints, explainable risk scoring, and deduplication
- **Assign & review** with accountable ownership, workload-aware routing, and structured review stages
- **Respond** with alerts, rotation playbooks, redaction/quarantine/ticketing, and verification rescans
- **Govern** with audit trails, structured logs, reports, compliance evidence mapping, and retention/backup controls

### Core safety & honesty principles

- **Raw secrets never persist.** Storage, logs, alerts, exports, and AI prompts carry **masked previews** and **SHA-256 fingerprints** only.
- **Offline-first by default.** Core detection, lifecycle management, jobs, alert outbox, reporting, and governance work without network access or third-party services.
- **Honest system states.** Integrations report `connected` / `demo` / `disconnected` truthfully; risk scores do **not** claim provider-confirmed validity; compliance views are evidence mappings (not certifications).
- **No silent closure.** A secret disappearing from a file is not proof of rotation. Verification is an explicit rescan, and closure/verification decisions are human-accountable actions.

---

## The problem SENTRIX solves

Modern teams leak secrets in many places at once: local files and IDEs, git history and pull/merge diffs, CI pipelines, cloud function configs, and collaboration/SaaS tools. That creates recurring operational pain:

- **Fragmented visibility:** different scanners and ad-hoc checks produce isolated findings with no single source of truth.
- **Duplicate noise:** the same credential appears across files/surfaces/scans, overwhelming responders.
- **Unclear priority:** teams lack explainable context (severity, exposure surface, environment, confidence, repetition) to decide what to fix first.
- **Weak ownership and accountability:** findings are discovered but not reliably assigned, acknowledged, reviewed, or tracked to closure.
- **Unverified remediation:** secrets are “removed” from code without proof of rotation/revocation or re-exposure checks.
- **Governance gaps:** organizations struggle to produce auditable evidence of detection, response, and control operation.

SENTRIX addresses this by unifying **collection, intelligence, workflow, response, and governance** in one platform that can run entirely locally, while supporting optional live integrations and AI-assisted triage where explicitly configured.

---

## Product tour (screenshots)

A walkthrough of SENTRIX from sign-in to key operational views.

| View | Screenshot |
| --- | --- |
| **1. Sign In**<br>Secure entry point to the SENTRIX Command Center. | ![Sign In](docs/screenshots/01-login.png) |
| **2. Home Dashboard**<br>At-a-glance posture, activity, and navigation hub. | ![Home Dashboard](docs/screenshots/02-home.png) |
| **3. Overview**<br>Executive rollup of findings, sources, and outcomes. | ![Overview](docs/screenshots/03-overview.png) |
| **4. Intelligence Dashboard**<br>Prioritized intelligence and risk context. | ![Intelligence Dashboard](docs/screenshots/04-intelligence.png) |
| **5. Findings Queue**<br>Central queue for triage and workflow actions. | ![Findings Queue](docs/screenshots/05-findings.png) |
| **6. Integrations**<br>SENTRIX Connect providers and connection states. | ![Integrations](docs/screenshots/06-integrations.png) |
| **7. Detection Sources**<br>Coverage across repositories, surfaces, and inputs. | ![Detection Sources](docs/screenshots/07-sources.png) |
| **8. Hubs**<br>Collaboration via company chat and direct messages. | ![Hubs](docs/screenshots/08-hubs.png) |
| **9. Employee Operations**<br>Assignments, workload balancing, and accountability. | ![Employee Operations](docs/screenshots/09-employee-operations.png) |
| **10. Remediation Center**<br>Playbooks, tasks, verification, and closure tracking. | ![Remediation Center](docs/screenshots/10-remediation.png) |

---

## Capabilities at a glance

| Area | What SENTRIX provides |
| --- | --- |
| **Detection intelligence** | 26 built-in detectors (cloud/crypto/SaaS/AI/generic), custom rules (config/runtime), keyword-prefiltered regex matching, Shannon entropy, format/validator checks, masking, stable fingerprinting, allowlisting |
| **Surface coverage** | IDE/watch, filesystem scans, git diff/history-aware gates, pre-commit/pre-push, CI diffs, cloud/Lambda artifacts (local or optional live AWS), Slack/Confluence/Jira (export + live REST when configured), Postman exports |
| **Risk & deduplication** | Explainable 0–100 risk score with factor breakdown (severity, category, exposure, confidence, validation, environment, age, repetition), cross-scan dedupe by fingerprint+path+line, occurrence/last-seen tracking, no alert storms on known sightings |
| **Workflow & governance** | 12-state finding lifecycle (compatibility superset), notes/tags/history/checklists/bulk actions/saved filters, exceptions, structured logs + audit trail, 11 report types (CSV/JSON), retention purge/vacuum, backup/restore/import/export |
| **Assignment & review** | Explainable auto/recommended/manual assignment, primary owner + secondary reviewer, RBAC-aware routing, skill/domain/workload/capacity/availability/SLA considerations, enforced multi-stage review path with admin final disposition and audited transitions |
| **Remediation & response** | 11 rotation playbooks, rotate guidance, preview/redact, quarantine/restore, ticketing (live Jira or outbox draft), verification rescans, alert routing (console/outbox/slack/webhook) with rules/quiet hours/dedupe/retries, SLA/escalation support |
| **Integrations** | SENTRIX Connect hub for 9 providers with honest states; live-capable where configured (e.g. Slack/Jira/Confluence polling, Jira tickets, optional AWS Lambda), export-based/coverage paths for others; sync events are audited (sync does not implicitly fetch provider data) |
| **Collaboration** | Hubs with Open Chat and private 1:1 DMs, presence/heartbeats, read markers, notifications/pings, per-user preferences; DM privacy scoped to participants |
| **Security model** | 8-role RBAC (server-enforced), PBKDF2-HMAC-SHA256 passwords, HttpOnly SameSite sessions, CSRF/origin checks for cookie-auth mutations, per-IP login rate limiting, hashed bearer API tokens, hardened response headers, outbound SSRF guard for configured targets |

---

## Architecture

SENTRIX is implemented as a **stdlib-only modular monolith** (no build step) with clear internal boundaries:

- **Process model:** `ThreadingHTTPServer` (thread-per-request) + daemon job/scheduler threads
- **Storage:** single SQLite database (`data/sentrix.db`) with thread-local connections and a global write lock
- **Concurrency controls:** background scan execution bounded by a two-slot semaphore; cooperative job cancellation
- **Schema evolution:** additive, idempotent migrations with legacy compatibility handling

### Seven logical layers

| # | Layer | Responsibility | Primary implementation |
| --- | --- | --- | --- |
| 1 | **Collection** | Capture text where secrets appear (edits, diffs, scans, exports, polls) | `sentrix/surfaces/*`, `sentrix/watch.py`, `hooks/`, `ci/`, `editors/vscode/` |
| 2 | **Ingestion** | Normalize and persist detections through one pipeline | `sentrix/core/pipeline.py` |
| 3 | **Intelligence Core** | Detect, validate, mask, fingerprint, score, and triage | `sentrix/detectors/*`, `sentrix/core/{engine,entropy,risk,allowlist}.py`, `sentrix/ai/*` |
| 4 | **Security Management** | Lifecycle operations, notes/tags/filters, history, workflow state | `sentrix/core/extensions.py`, finding endpoints in `sentrix/server.py` |
| 5 | **Response** | Alerting, escalation, remediation actions/playbooks, verification | `sentrix/alerting/router.py`, `sentrix/remediation/playbooks.py`, `sentrix/core/jobs.py` |
| 6 | **Control Plane** | API/console, auth/RBAC, jobs/schedules, integrations, reports, ops | `sentrix/{server,auth,cli}.py`, `sentrix/core/{jobs,reports,integrations}.py`, `sentrix/dashboard/` |
| 7 | **Storage** | Durable state, schema/migrations, dedupe and query primitives | `sentrix/core/{storage,extensions}.py`, `sql/schema.sql` |

### End-to-end flow

```text
Surface event (save / hook / CI diff / schedule / export / poll / API)
        │
        ▼
Collection adapter extracts text or diff lines
        │
        ▼
Intelligence Core (engine)
  detectors → entropy → validation → allowlist → mask + fingerprint
        │
        ▼
Pipeline ingest
  provenance + risk score → dedupe upsert → event
    • new finding  → alerting / auto-ticket (policy-driven)
    • known finding → occurrences & last_seen updated (no alert storm)
        │
        ▼
Security Management
  triage, assignment, review stages, notes/checklists/history
        │
        ▼
Response
  rotate guidance / redact / quarantine / ticket → verification rescan
        │
        ▼
Closure (human-accountable decisions, audited)
```

---

## Detection engine

### How scanning works

- **Single scan path:** `scan_text`, `scan_file`, and `scan_tree` power IDE/watch, filesystem, git/CI gates, jobs/schedules, and ingestion flows.
- **Per-detector evaluation:** keyword prefilter → regex match → optional validator/format checks → masking → SHA-256 fingerprint → allowlist checks → finding emission with metadata.
- **In-scan dedupe:** suppresses duplicates by `(detector_id, fingerprint, path, line)` within the same scan.
- **Cross-scan dedupe:** pipeline upserts by `fingerprint + path + line`, preserving identity/status while incrementing occurrences and `last_seen`.
- **File hygiene:** UTF-8 decode with replacement, binary-file skip (NUL heuristic), max file size guard (default 1,000,000 bytes), ignore dirs/files (configurable, fnmatch-supported).
- **Incremental scans:** background jobs can reuse cached file state (mtime/size) for efficiency.

### Detectors (26 built-in)

| Family | Count | Detectors |
| --- | ---: | --- |
| **Cloud** | 6 | `aws-access-key-id`, `aws-secret-access-key`, `gcp-api-key`, `gcp-service-account`, `azure-storage-connection`, `azure-client-secret` |
| **Crypto** | 5 | `private-key`, `jwt`, `basic-auth-url`, `postgres-uri` (DB URI with password: postgres/postgresql/mysql/mongodb(+srv)/redis/amqp), `ssh-private-key-body` |
| **SaaS / Dev** | 10 | `github-token`, `gitlab-token`, `slack-token`, `slack-webhook`, `stripe-key`, `sendgrid-key`, `twilio-key`, `npm-token`, `pypi-token`, `mailchimp-key` |
| **AI** | 2 | `openai-key`, `anthropic-key` |
| **Generic** | 3 | `generic-secret-assignment`, `high-entropy-string` (entropy-gated), `env-secret` |

**Custom detection:** supports config-defined `[[custom_detectors]]` and runtime detection rules (validated regex) for organization-specific patterns.

### Risk scoring, confidence, and environment context

SENTRIX computes an **explainable 0–100 risk score** with factor breakdown:

- Severity baseline, secret category, and exposure surface
- Confidence and format-validation signals
- Environment heuristic (e.g. production-like paths increase risk)
- Exposure age and repetition/occurrence signals

Risk bands are surfaced in the UI/API (critical/high/medium/low/info). Scores are explainable and intentionally do **not** claim external provider-confirmed validity.

### Allowlisting and false-positive control

- Fingerprint allowlist (API/CLI/UI workflows) to suppress confirmed safe matches
- Built-in safe/example placeholder filtering and configurable `scan.allowlist_patterns` (regex)
- Exceptions/false-positive workflow states with auditability

---

## Surfaces and ingestion coverage

| Surface | Coverage mode | Notes |
| --- | --- | --- |
| **Filesystem** | Live/local | On-demand file/tree scans with ignore/size/binary protections |
| **IDE / Watch** | Live/local | On-save scans and polling watcher for changed files |
| **Git / Pre-commit / Pre-push** | Live/local (diff-only) | Scans added lines in diffs/ranges; blocking gates based on `scan.fail_on` threshold |
| **CI** | Live/local (diff-only) | Pipeline diff gates (templates/examples provided for GitLab/Jenkins integration patterns) |
| **Cloud (Lambda artifacts)** | Local by default; optional live AWS | Scans local exported artifacts; optional live AWS Lambda config/env scan with `boto3` + ambient credentials (read-only) |
| **Slack** | Export and/or live REST (configured) | Export JSON ingestion and live channel history polling when configured |
| **Confluence** | Export and/or live REST (configured) | Export ingestion and live content polling when configured |
| **Jira** | Export and/or live REST (configured) | Export ingestion, live issue polling, and ticket creation path (when configured) |
| **Postman** | Export-based | Collection/environment JSON ingestion (live connector not implemented) |

> **Honesty note:** some providers in SENTRIX Connect are represented for inventory/coverage tracking even when live connector ingestion is not implemented (e.g. GitHub/GitLab/Bitbucket/Jenkins). Coverage for those is achieved through hooks, CI gates, scans, and exports.

---

## Workflow: assignment, review, remediation, verification

### Finding lifecycle (management states)

SENTRIX tracks a compatibility-oriented lifecycle (12-state superset) including intake, active handling, resolved, and exception states (e.g. `open/new`, `triaged/assigned/in_progress/reopened`, `remediated/verified/closed`, `false_positive/accepted_risk/suppressed`). Status history, notes, tags, checklists, bulk actions, and saved filters support day-to-day operations.

### Intelligent assignment and accountability

Assignment is a first-class workflow layer (separate from finding lifecycle state) with explainable decisions and audited changes:

- **Methods:** automatic, recommended, and manual assignment
- **Ownership model:** primary owner (accountable) + secondary reviewer (independent oversight)
- **Inputs considered:** severity/urgency, technical domain inference, RBAC eligibility, skills/expertise, severity-weighted workload vs capacity, availability, ownership context, conflicts/existing assignments
- **Operational controls:** acknowledgements, in-progress/blocked states, reassignment requests, SLA targets and escalation checks, bulk and approve/reject flows for recommendations
- **RBAC-aware behavior:** read-only roles cannot mutate; admin override requires reason and is audited

### Structured review flow

SENTRIX enforces a multi-stage review path (as implemented in server/UI workflows): assignment → primary assessment → secondary review → admin final decision, with reassessment loops where required. Key properties:

- Independent assessments with reasoning/evidence capture
- Admin performs final disposition (not primary/secondary assessment roles)
- True-positive decisions route to remediation/verification; false-positive decisions can be closed with recorded rationale
- All transitions are recorded with actor/timestamp/reason and surfaced in history

### Remediation and verification

**Remediation actions** include rotate guidance, redaction preview/redaction, quarantine/restore, ticket creation, and verification rescans.

**Playbooks (11):** `rotate-aws`, `rotate-gcp`, `rotate-azure`, `rotate-github`, `rotate-gitlab`, `rotate-slack`, `rotate-stripe`, `rotate-openai`, `rotate-db`, `rotate-keypair`, `rotate` (generic).

**Important operational truth:** redaction/quarantine reduces exposure, but **credential rotation/revocation at the provider** is what neutralizes the secret. SENTRIX supports guided response and verification; it does not auto-revoke provider credentials.

---

## Integrations (SENTRIX Connect)

SENTRIX Connect tracks **9 providers** with explicit, honest states (`connected`, `demo`, `disconnected`).

| Provider | Surface | State / capability notes |
| --- | --- | --- |
| **GitHub** | git | Inventory/coverage via hooks, CI gates, scans/exports (no live API connector) |
| **GitLab** | git | Inventory/coverage via hooks, CI gates, scans/exports (no live API connector) |
| **Bitbucket** | git | Inventory/coverage via hooks/scans/exports (no live API connector) |
| **Jenkins** | ci | Inventory/coverage via CI/gate workflows (no live API connector) |
| **AWS** | cloud | Local artifact scans by default; optional live Lambda config/env scan with `boto3` + ambient credentials |
| **Slack** | slack | Export ingestion and/or live polling when configured; alert channel support available |
| **Jira** | jira | Export ingestion and/or live polling when configured; ticket creation live-capable or outbox draft |
| **Confluence** | confluence | Export ingestion and/or live polling when configured |
| **Postman** | postman | Export-based collection/environment scanning |

- **Sync semantics:** `POST /api/integrations/{id}/sync` records an audited sync event/log entry; it does **not** itself fetch provider data.
- **Credentials:** sourced from environment variables named in config (e.g. `SENTRIX_SLACK_TOKEN`, `SENTRIX_JIRA_TOKEN`, `SENTRIX_CONFLUENCE_TOKEN`, `SENTRIX_POSTMAN_KEY`) and/or standard AWS credential chain.

---

## Hubs (collaboration)

SENTRIX includes **Hubs** for team collaboration directly in the console:

- **Open Chat** (shared channel) and **private 1:1 direct messages**
- Presence/heartbeat-based online indicators
- Read markers, notifications, and pings (audited actions)
- Per-user preferences (sound/desktop notification behavior, mutes)
- Message posting with edit/delete support in the API layer

**Privacy model:** DMs are scoped to participants. Access is controlled server-side; read-only roles are restricted from content-writing operations but can manage personal read/notification/prefs/heartbeat actions.

---

## Security, privacy, and access control

### Authentication and sessions

- **Password hashing:** PBKDF2-HMAC-SHA256 (200,000 iterations, random salt), constant-time verification
- **Sessions:** server-side session records, `HttpOnly` + `SameSite=Strict` cookie (`sx_session`), configurable expiry (default 12h), optional remember-me extension (server-side)
- **Login protection:** per-IP failed-login rate limiting (rolling window, default 5 attempts/minute)
- **Initial bootstrap:** creates initial admin on first run (from `SENTRIX_ADMIN_PASSWORD` or demo/random bootstrap path; protect/delete generated initial password files if created)

### RBAC (8 roles)

`super_admin`, `security_admin`, `security_analyst`, `appsec_engineer`, `devsecops_engineer`, `developer`, `auditor`, `viewer`

- Server-enforced route/operation authorization
- Write-capable operational roles vs read-only roles (UI and API enforcement)
- Admin-only operations for user/token and sensitive ops endpoints
- Legacy role migration support for older databases

### API tokens and request protections

- **Bearer tokens:** admin-created, `sxt_`-prefixed, raw token shown once, only hash stored; revocable
- **CSRF/origin controls:** cookie-authenticated mutations require matching Origin/Host; Bearer-auth flows exempt
- **Response hardening:** `no-store`, `nosniff`, `DENY` frame policy, restrictive referrer/CSP/permissions/COOP/CORP headers
- **Outbound safety:** explicit configured targets only; SSRF guard blocks loopback/private/link-local/multicast/reserved resolved hosts for outbound requests

### Data handling and privacy

- No raw secret persistence (masked values + fingerprints only)
- No external credential validation calls to providers
- Alerts, logs, reports, and AI triage inputs (when enabled) use masked data
- Quarantine files may retain original content for operator-controlled remediation workflows and must be protected accordingly

### Production posture (summary)

- Disable demo mode (`auth.demo_mode = false`) and use `config.local.toml`
- Set a strong `SENTRIX_ADMIN_PASSWORD`
- Keep the service on loopback or behind a TLS-terminating reverse proxy
- Change/remove/disable demo accounts and protect `data/` (DB, backups, quarantine, generated initial password files)
- Review `docs/SECURITY.md` hardening checklist before exposure beyond local/dev use

---

## Command Center (web console)

SENTRIX ships a hash-routed SPA (no frontend build step) with dark/light themes, role-aware controls, contextual help, and live operational views.

**Primary navigation groups and views (27):**

- **Command Center:** Home, Overview, My Workspace, Security Posture, Intelligence Dashboard
- **Detection:** Findings Queue, Closed Findings, Vulnerabilities / Exposures, Detection Sources, Detection Rules, Detection Playground, Scan Management
- **Attack Surface:** Repository Security, Developer Security, Cloud Security, CI/CD Security, SaaS Security, Asset Inventory, Technologies, Groups
- **Response:** Employee Operations, Remediation Center, Security Alerts, Investigation Center, Exception Management
- **Collaboration:** Hubs
- **Operations:** Architecture, Workers & Agents, AI Agents, MCP, Tools & Connectors, Integrations, Job Registry, System Logs, Activity & Audit, System Health
- **Governance:** Reports, Compliance, Access Management, Settings

The console includes finding drill-down/detail workflows, bulk actions, saved filters, assignment/review/remediation interactions, report/export actions, and operational telemetry views.

---

## Installation & quick start

### Prerequisites

- **Python 3.11+**
- **Windows, Linux, or macOS** (Kali supported for local/dev workflows)
- No required runtime pip dependencies (`boto3` optional for live AWS Lambda scanning)

### Run locally

**Windows**

```bat
run.bat
```

**Linux / macOS**

```sh
chmod +x run.sh
./run.sh
# or
python3 run.py
```

**Any platform**

```sh
python run.py serve --port 8710
```

Open: **http://127.0.0.1:8710**

On first run (demo mode enabled by default), SENTRIX can bootstrap a local demo environment (admin/team accounts and demo data) for exploration.

### Local demo accounts (loopback/demo installs only)

| Username | Role | Demo password |
| --- | --- | --- |
| `admin` | `super_admin` | `sentrix-demo` |
| `r.sharma` | `appsec_engineer` | `r.sharma-demo` |
| `p.patel` | `security_analyst` | `p.patel-demo` |
| `a.kumar` | `devsecops_engineer` | `a.kumar-demo` |
| `n.singh` | `auditor` (read-only) | `n.singh-demo` |
| `v.iyer` | `developer` (read-only) | `v.iyer-demo` |

> Demo credentials are intended only for local demonstration installs and are hidden/invalidated by production-mode and non-loopback conditions as implemented. Change passwords immediately and disable/remove demo accounts before any non-demo use.

### Optional extras

```sh
# Optional: live AWS Lambda scanning support
pip install boto3
# or, if installing as a package
pip install .[aws]
```

---

## CLI reference (overview)

SENTRIX provides a single CLI entry point (`sentrix` / `python run.py ...`).

| Command | Purpose |
| --- | --- |
| `serve [--port N]` | Start Command Center + API server |
| `scan PATH [--surface S] [--json] [--no-store] [--strict]` | Scan files/trees (optionally fail on threshold) |
| `gate [--staged \| --range BASE..HEAD \| --base B --head H] [--repo R] [--json]` | Diff-only blocking gate for hooks/CI |
| `hooks {install\|uninstall} [--repo R]` | Install/uninstall git pre-commit/pre-push gates |
| `watch PATH [--interval SEC]` | Poll files and ingest IDE/watch findings |
| `demo` | Seed synthetic demo findings |
| `selftest` | Run basic sanity checks (registry, detection, allowlist, dedupe) |
| `report [--format md\|json]` | Generate findings report |
| `ingest --surface ... [--file PATH] [--json]` | Ingest exports/live-capable surface inputs (`slack`, `confluence`, `jira`, `postman`, `postman-env`, `cloud`, `ide`) |
| `allowlist {add\|list} ...` | Manage fingerprint allowlist entries |
| `triage ID` | Run triage for a finding |
| `remediate ID --action ...` | Execute remediation action (`rotate-guide`, `redact`, `quarantine`, `ticket`) |
| `users {add\|list} ...` | Manage users (CLI utility) |
| `tokens {create\|list\|revoke} ...` | Manage API tokens |
| `backup [--dest PATH]` | Create SQLite backup |
| `schedules {add\|list} ...` | Manage recurring scan schedules |
| `jobs` | List scan jobs |
| `surfaces` | List supported surfaces |

> Run `python run.py --help` and `python run.py <command> --help` for exact flags and behavior in your version.

---

## Configuration

SENTRIX loads layered configuration: **defaults < `config.toml` < `config.local.toml`** (plus environment variables for secrets).

### Common configuration areas

- **`[server]`**: bind host/port (default `127.0.0.1:8710`)
- **`[auth]`**: session duration, login rate limit, demo/fixed-roster behavior
- **`[scan]`**: max file size, entropy threshold, fail-on severity, ignore dirs/files, allowlist regex patterns
- **`[storage]`**: SQLite path (default `data/sentrix.db`)
- **`[alerting]`**: channels (`console`, `outbox`, optional `slack`, `webhook`), dedupe window, escalation, quiet hours, auto-ticket policy
- **`[detectors]`**: disabled detectors, severity overrides, custom detector definitions
- **`[ai]`**: optional GPT-compatible triage (masked payloads only)
- **`[surfaces.*]`**: Slack/Confluence/Jira/Postman/Cloud configuration (env-sourced tokens/keys)

### Notable environment variables

| Variable | Purpose |
| --- | --- |
| `SENTRIX_ADMIN_PASSWORD` | Initial/admin bootstrap password (recommended for non-demo setups) |
| `SENTRIX_TEAM_PASSWORD` | Team bootstrap path (where applicable) |
| `SENTRIX_SLACK_TOKEN` | Slack API token (when Slack surface/alerts configured) |
| `SENTRIX_JIRA_TOKEN` | Jira API token (polling/ticketing) |
| `SENTRIX_CONFLUENCE_TOKEN` | Confluence API token |
| `SENTRIX_POSTMAN_KEY` | Postman API key (if configured/reserved paths) |
| `SENTRIX_AI_KEY` | Optional AI triage API key (masked-only usage) |
| `SENTRIX_HOME` | Hook/runtime resolution support for git hooks |

---

## API and integrations (developer/operator overview)

- **API style:** JSON-first HTTP API served by the same process/port as the console (stdlib server)
- **Auth:** session cookie and/or per-tab session token and/or `Authorization: Bearer sxt_...`
- **Coverage (high level):** auth/identity, dashboard/telemetry aggregates, findings/lifecycle, scan/detection rules/triage/allowlist, jobs/schedules, alerts/events/logs/audit, integrations, remediation, reports/compliance/exports, ops/admin, assignment/help, Hubs, and static console assets
- **Metrics:** Prometheus endpoint available (`/api/metrics`)
- **Reports:** 11 report types generated as CSV/JSON and stored in report history

See [`docs/API.md`](docs/API.md) for endpoint-level details and request/response behavior.

---

## Data, storage, and operations

- **Database:** SQLite (`data/sentrix.db` by default), additive schema/migrations, UTC timestamps
- **Schema footprint:** 23 tables covering findings/events/alerts/remediations, identity/access, audit/logs, workflow/assignment, jobs/schedules/rules, reports/custom rules, hubs-related and operational metadata (see `docs/DATABASE.md`)
- **Backups:** online SQLite backup via CLI/API; full DB backup recommended for complete fidelity
- **Retention/maintenance:** purge (policy-driven), vacuum, import/export utilities
- **Operational artifacts:** quarantine and remediation artifacts are written under `data/` paths; protect them appropriately

---

## Deployment notes

- **Default bind:** `127.0.0.1:8710` (local HTTP). Do not expose directly to untrusted networks without a hardened deployment model.
- **Recommended production pattern:** loopback bind + TLS reverse proxy, `demo_mode=false`, strong admin credentials, demo accounts removed/disabled, protected `data/` directory, least-privilege integration tokens.
- **Process model:** single-node application process per storage path (SQLite). Distributed workers / PostgreSQL are not implemented.

See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md), [`docs/INSTALL.md`](docs/INSTALL.md), and [`docs/SECURITY.md`](docs/SECURITY.md).

---

## Testing and quality checks

```sh
# Built-in sanity checks
python run.py selftest

# Unit/integration tests (unittest)
python -m unittest discover -s tests -v

# Pytest (if installed)
python -m pytest tests -q
```

The repository includes test suites covering core behavior, assignment/workflows, integrations, Hubs, browser/smoke flows, posture/scans, and review/remediation-related scenarios (see `tests/`).

---

## Repository structure

```text
SENTRIX/
├── sentrix/                 # Application package (server, CLI, core engine, dashboard, APIs)
│   ├── core/                # Engine, pipeline, storage, risk, jobs, assignment, integrations, reports
│   ├── detectors/           # Built-in detector registry and detector implementations
│   ├── surfaces/            # Collection adapters (IDE, git, filesystem, cloud, SaaS exports/live)
│   ├── alerting/            # Alert routing, rules, dedupe, delivery channels
│   ├── remediation/         # Playbooks and remediation actions
│   ├── ai/                  # Heuristic and optional masked GPT triage
│   ├── hubs/                # Collaboration (chat/DM/presence/notifications)
│   └── dashboard/           # SPA console (HTML/CSS/JS)
├── hooks/                   # Git pre-commit/pre-push gates
├── ci/                      # CI templates/examples (GitLab, Jenkins)
├── editors/vscode/          # VS Code on-save integration
├── docs/                    # Product, architecture, API, security, deployment, and feature docs
├── examples/                # Sample data/exports and demo fixtures
├── sql/                     # Schema/reference SQL assets
├── tests/                   # Automated test suites
├── assets/                  # Branding and static assets
├── config.toml              # Default configuration
├── run.py / run.bat / run.sh
└── pyproject.toml
```

---

## Documentation

| Document | Description |
| --- | --- |
| [docs/OVERVIEW.md](docs/OVERVIEW.md) | Product overview, layers, lifecycle, design principles |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Modular monolith design, boundaries, concurrency, flow |
| [docs/INSTALL.md](docs/INSTALL.md) | Installation guidance |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Deployment, production mode, backups, upgrades |
| [docs/API.md](docs/API.md) | API reference and endpoint behavior |
| [docs/DATABASE.md](docs/DATABASE.md) | Schema, tables, migrations, retention semantics |
| [docs/DETECTION_ENGINE.md](docs/DETECTION_ENGINE.md) | Scan pipeline, masking/fingerprinting, entropy, risk, dedupe |
| [docs/DETECTORS.md](docs/DETECTORS.md) | Detector catalog and behavior notes |
| [docs/SURFACES.md](docs/SURFACES.md) | Surface adapters and ingestion modes |
| [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) | SENTRIX Connect providers, states, sync semantics |
| [docs/ASSIGNMENT.md](docs/ASSIGNMENT.md) | Assignment engine, workload, SLA, accountability model |
| [docs/REMEDIATION.md](docs/REMEDIATION.md) | Playbooks, remediation actions, verification |
| [docs/AI_TRIAGE.md](docs/AI_TRIAGE.md) | Heuristic and optional GPT triage behavior |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, controls, hardening, disclosure posture |
| [docs/PRIVACY.md](docs/PRIVACY.md) | Data handling and privacy principles |
| [docs/FLOWCHART.md](docs/FLOWCHART.md) | Flow diagrams and process views |
| [docs/HELP_REGISTRY.md](docs/HELP_REGISTRY.md) | Contextual help definitions/registry |
| [docs/RESEARCH_SYNTHESIS.md](docs/RESEARCH_SYNTHESIS.md) | Research/background synthesis |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues and fixes (if present in your checkout/docs set) |

---

## Responsible use and disclosure

- **Do not use live secrets for testing.** Use synthetic fixtures and examples.
- **Do not paste real credentials** into issues, reports, or shared logs.
- **Report vulnerabilities privately** through the project’s security/disclosure process (see [SECURITY.md](SECURITY.md) and [docs/SECURITY.md](docs/SECURITY.md)).

SENTRIX is designed to reduce exposure risk and improve response accountability, but it does not replace organizational processes for secret rotation/revocation, incident response, or compliance certification.

---

## License

SENTRIX is released under the [MIT License](LICENSE).

**Third-party/demo assets:** demo avatars and certain bundled demo materials are for demonstration purposes only and should be reviewed/replaced for production deployments as appropriate. See repository assets and documentation for details.

---

<div align="center">

**SENTRIX** · Secret Exposure & Network Threat Response Intelligence eXchange  
*One Intelligence. Every Exposure. Total Control.*

</div>
