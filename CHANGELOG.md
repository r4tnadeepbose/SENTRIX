## 1.3.0 - 2026-11-08

- Workflow parity with the reference diagrams: provenance chain per finding
  ("how did that get there?"), SaaS confirm/ignore-for-audit branch, automatic
  Jira tickets from the findings store, Slack post + user mention per secret,
  triage_alerts feedback sweep, git author capture on gates, matching flowcharts.

## 1.2.0 - 2026-11-08

- Renamed the project to **Wintermute** (package, CLI, environment variables, session cookie and token prefixes).
- Demo credentials are now `admin` / `wintermute-demo` while demo mode is active.

# Changelog

All notable changes to Wintermute are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-11-08

Major upgrade: authenticated operations platform around the unified pipeline —
100 features cataloged in docs/OVERVIEW.md.

### Added

- Authentication: login page, HttpOnly SameSite=Strict session cookies (12h
  default), PBKDF2-HMAC-SHA256 password hashing with 200,000 iterations and
  per-user salts, per-IP login rate limiting (default 5/minute), and initial
  admin bootstrap via `data/INITIAL_ADMIN_PASSWORD.txt` or
  `WINTERMUTE_ADMIN_PASSWORD`.
- RBAC with admin/analyst/viewer roles; viewer read-only enforcement; admin-only
  user management, tokens, restore, import, and purge; self-service password
  change; account disable/enable.
- API tokens for CI and scripts: named `wmt_...` Bearer tokens with a role,
  hash-only storage, one-time display, and instant revocation; CLI `users`,
  `tokens`, `backup`, `schedules`, and `jobs` commands.
- Audit trail for security-relevant actions plus a system log written by
  auth/http/scan/jobs/scheduler/escalation/remediation/demo; live Logs view with
  level filtering and pause.
- Findings management: notes, tags, assignee, severity override, pin, mute,
  occurrence counting, first/last seen, status history, related findings, bulk
  status/allowlist/assign/tag, per-user saved filters, sorting, pagination, and
  search.
- Background scan jobs with incremental mtime+size cache, cooperative cancel,
  concurrency cap of two, and persisted job history; scheduled scans with CRUD,
  enable toggle, and a 10-second scheduler loop.
- Custom detectors from `[[custom_detectors]]` config; per-detector disable and
  severity overrides via config or the audited runtime tuning API.
- Alerting upgrades: per-channel severity rules, quiet hours (UTC, wrap-around),
  retry backoff (three attempts), acknowledgement, mute integration, SLA
  escalation for stale open findings, and a 24-hour digest endpoint.
- Remediation upgrades: preview-redact (before/after without writing), restore
  from quarantine, verification rescan, and persisted per-finding checklists
  with actor and timestamp.
- Operations: online backup, admin restore, retention purge, vacuum, JSON
  dump/import, CSV and JSON export, Prometheus-format `/api/metrics`, and
  database size stats.
- Graphite minimalist single-theme dashboard with login, per-section "?" help
  popovers, pipeline Overview and how-it-works, Jobs and Logs views, command
  palette (Ctrl+K), keyboard shortcuts, tabbed drawer, bulk bar, skeletons,
  confirm dialogs, toasts, empty states, mobile cards, user menu, relative
  timestamps, reorganized Settings, and a modern monochrome favicon.
- Security headers on every response: `Cache-Control: no-store`,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`.
- docs/OVERVIEW.md centerpiece with module map, auth flow, v1+v2 storage schema,
  logging sources, and the 100-feature catalog; expanded API, architecture,
  install, detector, and security documentation.

### Changed

- Dashboard and JSON API now require authentication (session cookie or Bearer
  token) on all non-public routes; loopback binding remains the default.
- Single graphite theme replaces the previous dark/light theme pair; README
  screenshots now reference `docs/screenshots/dashboard-dark.png` and
  `docs/screenshots/login.png`.
- `GET /api/findings` returns paginated results merged with management extras;
  `GET /api/findings/{id}` includes notes, history, checklist, and extras;
  `GET /api/alerts` includes acknowledgements.
- Storage schema v2: sixteen new tables (users, sessions, tokens, audit,
  system_log, notes, finding_extra, status_history, saved_filters, schedules,
  scan_jobs, scan_cache, alert_rules, alert_acks, checklists, migrations) added
  alongside the unchanged v1 detection tables.

## [1.0.0] - 2026-11-08

Initial release.

### Added

- Unified flow — event → scan → alert → remediation — shared by every layer.
- Detector registry with 26 detectors (regex + entropy + validators) covering cloud
  credentials, SaaS and developer-platform tokens, private key material, connection
  URIs, and generic/high-entropy assignments.
- Layers: local-only IDE on-save scanning, pre-commit/pre-push git hooks, CI diff
  gates (GitHub Actions, GitLab CI, Jenkins), cloud/Lambda code and environment
  scanning, SaaS monitoring (Slack, Confluence, Jira, Postman), and filesystem watch.
- Surface adapters with export/file mode for all SaaS sources and optional
  rate-limited live mode (Slack, Confluence, Jira, AWS via optional boto3).
- SQLite storage with dedupe by fingerprint + path + line; raw secrets never stored
  (masked previews and SHA-256 fingerprints only).
- Allowlist/false-positive registry: built-in safe values and patterns, configurable
  regex patterns, and per-fingerprint suppression across all layers.
- Alert channels: console, file outbox (`data/outbox`), Slack webhook, generic
  webhook; alert dedupe window and dry-run behavior when unconfigured.
- Remediation actions: rotate-guide (per-family markdown playbooks), redact
  (in-place replacement), quarantine (move to `data/quarantine`), ticket (Jira or
  outbox draft); status lifecycle open → triaged → false_positive/remediated.
- Optional GPT triage via any OpenAI-compatible endpoint (`[ai]`,
  `WINTERMUTE_AI_KEY`) with deterministic heuristic fallback; prompts carry masked
  values only.
- Stdlib dashboard at `http://127.0.0.1:8710` with dark and light themes and views
  for Overview, Findings, Playground, Activity, Allowlist, and Settings.
- JSON REST API for findings, events, alerts, allowlist, stats, config, scanning,
  demo seeding, triage, remediation, and status updates.
- CLI: serve, scan, gate, hooks, demo, selftest, report, watch, surfaces, allowlist,
  triage, remediate, ingest; one-click launchers `run.bat` (Windows) and `run.sh`
  (Linux/macOS); Make targets serve, scan, demo, test, selftest, hooks, report.
- Layered configuration: defaults < config.toml < config.local.toml < environment;
  zero required dependencies (Python 3.11+ standard library only).
- Documentation: architecture, flowcharts, install, detectors, surfaces, API,
  remediation, privacy, AI triage; contributing guide and security policy.