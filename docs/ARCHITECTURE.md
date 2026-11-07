# Architecture

KeySentry is a stdlib-only Python 3.11+ system built around one idea: **every layer feeds the same pipeline**. A finding produced by an IDE on-save check, a CI gate, a chat export, or a cloud function environment scan is the same object, scanned by the same detectors, deduplicated the same way, and remediated with the same playbooks.

v1.1 wraps that pipeline in an operational shell: an auth layer (sessions, RBAC, API tokens), extended storage for finding management, background jobs and a scheduler, alert channel rules, and an audit/system-log pair — all surfaced in a minimalist graphite dashboard. See [OVERVIEW.md](OVERVIEW.md) for the full feature catalog.

## Module map

| Module | Responsibility |
| --- | --- |
| `keysentry/core/models.py` | Dataclasses shared by all layers: `Finding`, `Event`, `Alert`, `Remediation`; severity/status/surface enums |
| `keysentry/core/engine.py` | Scanning engine: `scan_text`, `scan_file`, `scan_tree`; applies the detector registry, config tuning and custom detectors, allowlist, masking, entropy, and fingerprinting |
| `keysentry/core/pipeline.py` | Unified flow orchestration: ingest findings, filter allowlist, upsert with dedupe, record events, route alerts |
| `keysentry/core/storage.py` | v1 SQLite persistence for findings, events, alerts, allowlist, remediations; thread-safe writes |
| `keysentry/core/extensions.py` | v2 extended storage (`ExtStorage`): users, sessions, tokens, audit, system log, finding extras/notes/history, saved filters, jobs, cache, schedules, rules, acks, checklists, backup/purge/vacuum/dump/import |
| `keysentry/core/jobs.py` | `JobRunner`: background scans with incremental cache, cooperative cancel, concurrency cap of 2; `start_scheduler`: 10-second loop for due schedules and SLA escalation |
| `keysentry/core/allowlist.py` | False-positive registry: fingerprint set, built-in safe values/patterns, configurable regex patterns |
| `keysentry/core/entropy.py` | Shannon entropy scoring (`shannon`, `looks_random`) |
| `keysentry/core/util.py` | Masking (`mask_secret`), fingerprinting (`fingerprint`), severity comparison (`at_least`) |
| `keysentry/auth.py` | `AuthManager`: PBKDF2 hashing (200k iterations), sessions, login rate limiting, RBAC helpers, API tokens, initial admin bootstrap, audit and system-log writers |
| `keysentry/detectors/` | One shared registry (`base.py`: `Detector`, `register`, `REGISTRY`); pattern modules `cloud.py`, `saas.py`, `crypto.py`, `generic.py`; custom detectors registered from config at startup |
| `keysentry/surfaces/` | Adapters that turn each layer's input into text for the engine: `filesystem`, `git` (diff-only), `ide`, `slack`, `confluence`, `jira`, `postman`, `cloud` (serverless functions); `common.py` provides REST, pagination, and rate-limit helpers |
| `keysentry/alerting/router.py` | Channel routing (console, outbox, webhook channels) with per-channel severity rules, quiet hours, mute, dedupe window, retry backoff, dry-run when unconfigured |
| `keysentry/remediation/playbooks.py` | Rotation guides per family plus `redact`, `preview-redact`, `quarantine`, `restore`, `ticket`, `verify` actions; records remediations and advances status |
| `keysentry/ai/` | `gpt.py` (GPT-compatible chat client), `prompts.py` (masked-only prompt construction), `triage.py` (GPT with deterministic heuristic fallback) |
| `keysentry/server.py` | Stdlib `http.server`: login page, static dashboard, authenticated JSON API with role enforcement and security headers, bound to `127.0.0.1:8710` by default; wires storage, auth, router, pipeline, jobs, scheduler in `AppState` |
| `keysentry/cli.py` | One entry point for every layer: `serve`, `scan`, `gate`, `hooks`, `demo`, `selftest`, `report`, `watch`, `surfaces`, `allowlist`, `triage`, `remediate`, `ingest`, plus v1.1 `users`, `tokens`, `backup`, `schedules`, `jobs` |
| `keysentry/watch.py` | Polling filesystem watcher: mtime comparison, scan-on-change, ingest into the pipeline |
| `keysentry/config.py` | Layered config: defaults < `config.toml` < `config.local.toml` < environment (for secrets, via `*_env` indirection) |
| `keysentry/demo.py` | Synthetic findings across all surfaces for first-run exploration |
| `keysentry/dashboard/` | Graphite single-theme dashboard + login page: Overview, Findings, Jobs, Logs, Playground, Activity, Allowlist, Settings; command palette, keyboard shortcuts, help popovers |

## Auth layer

`AppState` constructs one `AuthManager` over the extended storage. Request handling in `server.py`:

1. **Public routes** — `GET /`, `/login`, `/favicon.svg`, `/logo.svg`, `/api/health`, `/static/*`, and `POST /api/auth/login` need no identity.
2. **Identity** — the `ks_session` cookie is resolved against the `sessions` table (expiry checked, disabled accounts rejected on every request); otherwise `Authorization: Bearer kst_...` is matched by SHA-256 hash against `tokens` (revoked tokens rejected). Missing identity → `401`.
3. **Roles** — `viewer` is read-only (mutations → `403`, except logout and own password change); admin-only prefixes are `/api/users`, `/api/tokens`, `/api/ops/restore`, `/api/ops/import`, `/api/ops/purge`; `analyst` covers everything else.
4. **Login** — per-IP rolling-window rate limit (`auth.login_rate_limit`, default 5/minute), PBKDF2-HMAC-SHA256 with 200,000 iterations and per-user salt, constant-time comparison; success issues a random session token as an `HttpOnly; SameSite=Strict` cookie (`auth.session_hours`, default 12).
5. **Bootstrap** — on first run (no users), an `admin` account is created from `KEYSENTRY_ADMIN_PASSWORD` or a random value, written to `data/INITIAL_ADMIN_PASSWORD.txt`.
6. **Headers** — every response carries `no-store`, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.

Passwords are never stored in plaintext; API tokens are stored only as SHA-256 hashes and the raw `kst_` value is returned exactly once at creation.

## Data flow: event → scan → alert → remediation

1. **Event.** A surface adapter observes a change: a file save (`ide`), a staged diff or push range (`git`), a CI diff (`ci`), a SaaS export or live API page (`slack`, `confluence`, `jira`, `postman`), a Lambda config/code artifact (`cloud`), or a watched file mtime change (`filesystem`/`watch`).
2. **Scan.** The adapter hands text (or file paths) to `core/engine.py`. The engine runs every registered detector — keyword pre-filter, regex match, optional validator — then applies the allowlist, computes Shannon entropy, masks the secret, and derives a SHA-256 fingerprint. The result is a list of `Finding` objects. Diff-based surfaces scan only added lines and map findings back to real file/line positions.
3. **Ingest.** `Pipeline.ingest` re-checks the allowlist, upserts each finding into SQLite keyed by `(fingerprint, path, line)`, and splits results into `new` vs `known`. Re-detections bump the `finding_extra` occurrence counter and `last_seen` while preserving status and triage state. An `Event` row records the batch (kind, surface, counts, paths). Only **new** findings proceed to alerting.
4. **Alert.** `AlertRouter.send` checks the per-finding dedupe window (`alerting.dedupe_window_seconds`, default 3600) and the finding's mute flag, then evaluates per-channel rules (`alert_rules`: minimum severity, enable toggle). Network channels are deferred inside quiet hours (UTC, wrap-around supported) and posted with up to three attempts and 1s/2s backoff; console and outbox always deliver. Missing URLs produce `dry-run` alerts instead of network calls. Every attempt is recorded in the `alerts` table; operators acknowledge alerts (`alert_acks`), and the scheduler re-alerts findings still open past `alerting.escalate_after_hours` (default 24).
5. **Remediation.** An operator (dashboard, CLI, or API) triages a finding — GPT when configured, deterministic heuristic otherwise — then runs an action: `rotate-guide` (markdown playbook), `preview-redact` (before/after, no write), `redact` (in-place `<REDACTED:detector>` replacement), `quarantine` (move to `data/quarantine`), `restore` (move back), `ticket` (ticketing surface or an outbox draft), or `verify` (rescan the recorded location; mark remediated only when clean). The action is recorded in `remediations`, checklist progress persists per step, and the finding status advances (`open → triaged → remediated`, or `false_positive` via the allowlist) with every transition written to `status_history`.

The dashboard and REST API sit on top of the same storage and pipeline behind the auth layer; the Playground endpoint scans ad-hoc text without storing it.

### Jobs and scheduler

`JobRunner` accepts scan submissions (`POST /api/jobs`), persists a `scan_jobs` row, and runs the scan on a daemon thread gated by a semaphore (at most two concurrent jobs). Each file is checked against `scan_cache` (path + mtime + size); unchanged files reuse cached findings, changed files are rescanned and re-cached. Cancellation is cooperative — the flag is checked between files — and jobs end as `done`, `cancelled`, or `failed` with counts and error detail. `start_scheduler` ticks every 10 seconds: it submits jobs for due `schedules` (interval-based, toggleable) and performs the escalation pass described above. Both write system-log entries (`jobs`, `scan`, `scheduler`, `escalation` sources).

## Storage schema summary

SQLite database at `data/keysentry.db` (configurable via `storage.path`). All timestamps are UTC ISO strings. `core/storage.py` creates the v1 tables; `core/extensions.py` (`ExtStorage`) adds the v2 tables on top and records version 2 in `migrations`.

### v1 tables

| Table | Key columns | Notes |
| --- | --- | --- |
| `findings` | `id` (PK), `detector_id`, `title`, `severity`, `surface`, `path`, `line`, `secret_masked`, `entropy`, `fingerprint`, `status`, `owner`, `created_at`, `updated_at`, `meta` (JSON) | Indexed on `status` and `fingerprint`; `meta` holds family, remediation hint, triage result, surface extras |
| `events` | `id` (PK), `kind`, `surface`, `payload` (JSON), `ts` | Batch record of scans, gates, ingests, jobs, demo seeding |
| `alerts` | `id` (PK), `finding_id`, `channel`, `message`, `status`, `ts` | `status` is `sent`, `dry-run`, `deferred-quiet-hours`, `http-<code>`, or `failed: ...` |
| `allowlist` | `fingerprint` (PK), `reason`, `created_at` | False-positive registry shared by every layer |
| `remediations` | `id` (PK), `finding_id`, `action`, `detail`, `ts` | One row per executed action |

### v2 tables (extensions)

| Table | Key columns | Notes |
| --- | --- | --- |
| `users` | `username` (PK), `pw_hash`, `salt`, `role`, `disabled`, `created_at` | PBKDF2-HMAC-SHA256, 200k iterations |
| `sessions` | `token` (PK), `username`, `role`, `expires_at` | Cookie sessions; expired rows purged on login |
| `tokens` | `id` (PK), `name`, `token_hash`, `role`, `created_by`, `created_at`, `revoked` | API tokens stored as SHA-256 hashes only |
| `audit` | `id`, `ts`, `username`, `action`, `detail` | Security-relevant actions |
| `system_log` | `id`, `ts`, `level`, `source`, `message` | Operational log from auth/http/scan/jobs/scheduler/escalation/remediation/demo |
| `notes` | `id`, `finding_id`, `username`, `body`, `ts` | Per-finding notes |
| `finding_extra` | `finding_id` (PK), `assignee`, `tags` (JSON), `severity_override`, `pinned`, `muted`, `occurrences`, `first_seen`, `last_seen` | Management metadata |
| `status_history` | `id`, `finding_id`, `old`, `new`, `username`, `ts` | Every status transition |
| `saved_filters` | `id` (PK), `username`, `name`, `params` (JSON), `ts` | Per-user presets |
| `schedules` | `id` (PK), `path`, `surface`, `interval_seconds`, `enabled`, `last_run` | Recurring scans |
| `scan_jobs` | `id` (PK), `path`, `surface`, `status`, `triggered_by`, `started`, `finished`, `files`, `findings`, `error` | Job lifecycle and results |
| `scan_cache` | `path` (PK), `mtime`, `size`, `findings` (JSON), `scanned_at` | Incremental scan cache |
| `alert_rules` | `id` (PK), `channel`, `min_severity`, `enabled` | Per-channel severity gates |
| `alert_acks` | `alert_id` (PK), `username`, `ts` | Acknowledgements |
| `checklists` | `id`, `finding_id`, `step_idx`, `done`, `username`, `ts` | Unique per (finding, step) |
| `migrations` | `version` (PK), `applied_at` | Schema version marker |

Identity rules:

- **Fingerprint** = `SHA-256(detector_id + "|" + secret.strip())` — stable across surfaces, derived from the raw value which is then discarded.
- **Finding id** = first 12 hex chars of `SHA-256(fingerprint + "|" + path + "|" + line)`.
- **Dedupe** = upsert on `(fingerprint, path, line)`; re-detections refresh `updated_at` and preserve the existing status.

## Design decisions

### One pattern set, many layers

Detectors live in a single registry and are imported once at startup. Surfaces are thin adapters: they extract text and label the surface, nothing more. This guarantees that a token caught in the IDE is caught identically in CI, Slack, and Lambda env vars, and that allowlist decisions apply everywhere. Adding a detector or tuning a pattern improves every layer at once.

### Masking instead of storage

The raw secret is used only in memory: to validate, fingerprint, and mask. Storage, alerts, tickets, dashboards, and AI prompts carry `secret_masked` (first four + last four characters for values longer than 8; shorter values keep only a two-character prefix) plus the fingerprint. This keeps the database and every downstream channel safe to share, while still letting an operator recognize the credential.

### Dedupe at two levels

Finding-level dedupe (`fingerprint + path + line`) prevents repeated scans from flooding the dashboard and preserves triage state across re-detections. Alert-level dedupe (per finding, within `dedupe_window_seconds`) prevents notification storms when a watcher or poller re-reports the same exposure.

### Offline-first, zero required dependencies

The default configuration uses only the Python standard library: `sqlite3`, `http.server`, `urllib`, `tomllib`, `re`, `hashlib`, `secrets`, `threading`. Console and outbox alerting work with no network at all; unconfigured webhook channels record `dry-run` alerts. AI triage falls back to a deterministic heuristic when disabled, unkeyed, or unreachable. Live cloud scanning is the only feature that needs a third-party package (`boto3`), and it is strictly optional. The server binds to loopback by default and requires authentication on every non-public route, so nothing is exposed beyond the local machine unless an operator deliberately changes it.

### Fail-closed auth, two log streams

Unauthenticated requests get `401`; role violations get `403`; there is no anonymous API access beyond the health check and static assets. Operational events go to `system_log` (live-tailed in the Logs view), while security-relevant actions — logins, account and token changes, bulk operations, ops actions, detector tuning — additionally go to the append-only `audit` table. Keeping the streams separate lets operators debug scans without scrolling past security events, and auditors review security events without operational noise.

### Minimalist graphite interface

The dashboard is a single monochrome graphite theme served as static files by the same stdlib server — no build step, no framework, no theme switcher. Density is reserved for data: a pipeline Overview, tabbed finding drawer, bulk bar, live Logs, command palette (Ctrl+K), keyboard shortcuts, and per-section help popovers. The same restraint applies to the login page and the monochrome favicon.