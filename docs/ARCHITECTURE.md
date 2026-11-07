# Architecture

KeySentry is a stdlib-only Python 3.11+ system built around one idea: **every layer feeds the same pipeline**. A finding produced by an IDE on-save check, a CI gate, a Slack export, or a Lambda environment scan is the same object, scanned by the same detectors, deduplicated the same way, and remediated with the same playbooks.

## Module map

| Module | Responsibility |
| --- | --- |
| `keysentry/core/models.py` | Dataclasses shared by all layers: `Finding`, `Event`, `Alert`, `Remediation`; severity/status/surface enums |
| `keysentry/core/engine.py` | Scanning engine: `scan_text`, `scan_file`, `scan_tree`; applies the detector registry, allowlist, masking, entropy, and fingerprinting |
| `keysentry/core/pipeline.py` | Unified flow orchestration: ingest findings, filter allowlist, upsert with dedupe, record events, route alerts |
| `keysentry/core/storage.py` | SQLite persistence for findings, events, alerts, allowlist, remediations; thread-safe writes |
| `keysentry/core/allowlist.py` | False-positive registry: fingerprint set, built-in safe values/patterns, configurable regex patterns |
| `keysentry/core/entropy.py` | Shannon entropy scoring (`shannon`, `looks_random`) |
| `keysentry/core/util.py` | Masking (`mask_secret`), fingerprinting (`fingerprint`), severity comparison |
| `keysentry/detectors/` | One shared registry (`base.py`: `Detector`, `register`, `REGISTRY`); pattern modules `cloud.py`, `saas.py`, `crypto.py`, `generic.py` |
| `keysentry/surfaces/` | Adapters that turn each layer's input into text for the engine: `filesystem`, `git` (diff-only), `ide`, `slack`, `confluence`, `jira`, `postman`, `cloud` (Lambda); `common.py` provides REST, pagination, and rate-limit helpers |
| `keysentry/alerting/router.py` | Channel routing (console, outbox, Slack webhook, generic webhook), alert dedupe window, dry-run when unconfigured |
| `keysentry/remediation/playbooks.py` | Rotation guides per family plus `redact`, `quarantine`, `ticket` actions; records remediations and advances status |
| `keysentry/ai/` | `gpt.py` (OpenAI-compatible chat client), `prompts.py` (masked-only prompt construction), `triage.py` (GPT with deterministic heuristic fallback) |
| `keysentry/server.py` | Stdlib `http.server`: static dashboard plus JSON API, bound to `127.0.0.1:8710` by default |
| `keysentry/cli.py` | One entry point for every layer: `serve`, `scan`, `gate`, `hooks`, `demo`, `selftest`, `report`, `watch`, `surfaces`, `allowlist`, `triage`, `remediate`, `ingest` |
| `keysentry/watch.py` | Polling filesystem watcher: mtime comparison, scan-on-change, ingest into the pipeline |
| `keysentry/config.py` | Layered config: defaults < `config.toml` < `config.local.toml` < environment (for secrets, via `*_env` indirection) |
| `keysentry/demo.py` | Synthetic findings across all surfaces for first-run exploration |
| `keysentry/dashboard/` | Static HTML/CSS/JS dashboard: Overview, Findings, Playground, Activity, Allowlist, Settings; dark + light themes |

## Data flow: event → scan → alert → remediation

1. **Event.** A surface adapter observes a change: a file save (`ide`), a staged diff or push range (`git`), a CI diff (`ci`), a SaaS export or live API page (`slack`, `confluence`, `jira`, `postman`), a Lambda config/code artifact (`cloud`), or a watched file mtime change (`filesystem`/`watch`).
2. **Scan.** The adapter hands text (or file paths) to `core/engine.py`. The engine runs every registered detector — keyword pre-filter, regex match, optional validator — then applies the allowlist, computes Shannon entropy, masks the secret, and derives a SHA-256 fingerprint. The result is a list of `Finding` objects. Diff-based surfaces scan only added lines and map findings back to real file/line positions.
3. **Ingest.** `Pipeline.ingest` re-checks the allowlist, upserts each finding into SQLite keyed by `(fingerprint, path, line)`, and splits results into `new` vs `known`. An `Event` row records the batch (kind, surface, counts, paths). Only **new** findings proceed to alerting.
4. **Alert.** `AlertRouter.send` checks the per-finding dedupe window (`alerting.dedupe_window_seconds`, default 3600) and dispatches to configured channels: console print, JSON file in `data/outbox`, Slack webhook, or generic webhook. Missing URLs produce `dry-run` alerts instead of network calls. Every attempt is recorded in the `alerts` table.
5. **Remediation.** An operator (dashboard, CLI, or API) triages a finding — GPT when configured, deterministic heuristic otherwise — then runs an action: `rotate-guide` (markdown playbook), `redact` (in-place `<REDACTED:detector>` replacement), `quarantine` (move to `data/quarantine`), or `ticket` (Jira, or an outbox draft). The action is recorded in `remediations` and the finding status advances (`open → triaged → remediated`, or `false_positive` via the allowlist).

The dashboard and REST API sit on top of the same storage and pipeline; the Playground endpoint scans ad-hoc text without storing it.

## Storage schema summary

SQLite database at `data/keysentry.db` (configurable via `storage.path`). All timestamps are UTC ISO strings.

| Table | Key columns | Notes |
| --- | --- | --- |
| `findings` | `id` (PK), `detector_id`, `title`, `severity`, `surface`, `path`, `line`, `secret_masked`, `entropy`, `fingerprint`, `status`, `owner`, `created_at`, `updated_at`, `meta` (JSON) | Indexed on `status` and `fingerprint`; `meta` holds family, remediation hint, triage result, surface extras |
| `events` | `id` (PK), `kind`, `surface`, `payload` (JSON), `ts` | Audit trail of scans, gates, ingests, demo seeding |
| `alerts` | `id` (PK), `finding_id`, `channel`, `message`, `status`, `ts` | `status` is `sent`, `dry-run`, `http-<code>`, or `failed: ...` |
| `allowlist` | `fingerprint` (PK), `reason`, `created_at` | False-positive registry shared by every layer |
| `remediations` | `id` (PK), `finding_id`, `action`, `detail`, `ts` | One row per executed action |

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

The default configuration uses only the Python standard library: `sqlite3`, `http.server`, `urllib`, `tomllib`, `re`, `hashlib`. Console and outbox alerting work with no network at all; unconfigured webhook channels record `dry-run` alerts. AI triage falls back to a deterministic heuristic when disabled, unkeyed, or unreachable. Live AWS scanning is the only feature that needs a third-party package (`boto3`), and it is strictly optional. The server binds to loopback by default so nothing is exposed beyond the local machine unless an operator deliberately changes it.