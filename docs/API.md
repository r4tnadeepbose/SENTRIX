# SENTRIX API Reference

The JSON API is served by `sentrix/server.py` (stdlib `ThreadingHTTPServer`) on the same host/port as the Command Center (default `http://127.0.0.1:8710`). All request and response bodies are JSON unless noted (CSV, Prometheus text, static files). There are no `PUT`/`PATCH`/`DELETE` verbs: mutations are `POST`, including deletions (`POST /api/<kind>/<id>/delete`).

## Authentication

Every non-public route requires one of:

1. **Session cookie** — `sx_session=<token>`, issued by `POST /api/auth/login`. `HttpOnly; Path=/; SameSite=Strict`. Server-side expiry: `auth.session_hours` (default 12 h), or 30 days when `remember` is true.
2. **Bearer token** — `Authorization: Bearer sxt_...`, created via `POST /api/tokens`. Only the SHA-256 hash is stored; revocation is checked on every request. The authenticated identity is `token:<name>` with the token's role.

**Public routes** (no auth): `GET /`, `GET /login`, `GET /static/*`, `GET /favicon.svg`, `GET /logo.svg`, `GET /api/health`, `GET /api/auth/demo-info`, and `POST /api/auth/login`. `GET /` redirects unauthenticated browsers to `/login`.

**CSRF / origin check:** a cookie-authenticated `POST` that carries an `Origin` header must match the `Host` header, otherwise `403 {"error": "cross-origin request rejected"}`. Bearer-authenticated requests are exempt.

**Error shape:** `{"error": "<message>"}` with `400` (validation/AuthError), `401` (authentication required), `403` (read-only role, admin required, or cross-origin), `404` (unknown route or id).

**Response headers on every reply:** `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.

## Roles matrix

Eight roles are defined in `sentrix/auth.py`:

| Role | Read (GET) | Write (POST) | Admin routes |
| --- | --- | --- | --- |
| `super_admin` | yes | yes | yes |
| `security_admin` | yes | yes | yes |
| `security_analyst` | yes | yes | no |
| `appsec_engineer` | yes | yes | no |
| `devsecops_engineer` | yes | yes | no |
| `developer` | yes | no (except logout / own password) | no |
| `auditor` | yes | no (except logout / own password) | no |
| `viewer` | yes | no (except logout / own password) | no |

- **Write roles** = the first five. Any other role receives `403 {"error": "role is read-only"}` on POST, except `POST /api/auth/logout` and `POST /api/auth/password`, which every authenticated role may call.
- **Admin routes** = any path starting with `/api/users`, `/api/tokens`, `/api/ops/restore`, `/api/ops/import`, `/api/ops/purge` (GET included). Non-admin roles receive `403 {"error": "security administrator role required"}`.
- Legacy roles are migrated on database open: `admin` -> `super_admin`, `analyst` -> `security_analyst`.

## Endpoint inventory

### Auth and identity

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| POST | `/api/auth/login` | public | Sign in, issue session cookie |
| POST | `/api/auth/logout` | any role | Delete current session |
| GET | `/api/auth/me` | session/token | Current user |
| POST | `/api/auth/password` | any role | Change own password |
| GET | `/api/auth/demo-info` | public | Local demo roster (loopback + demo mode only) |

**POST /api/auth/login** — body `{"username": "admin", "password": "...", "remember": false}`. Success: `200 {"ok": true, "user": {"username", "role", "title"}}` plus `Set-Cookie: sx_session=...; HttpOnly; Path=/; SameSite=Strict; Max-Age=<session_hours*3600>`. With `remember: true` the server-side session expires after 30 days. Failures: `400 {"error": "Invalid credentials."}` or `{"error": "Too many failed attempts; wait a minute."}` — the per-IP limit (default 5) counts **failed attempts only** in a rolling 60-second window.

**GET /api/auth/me** — `{"user": {"username", "role", "title"}}`; `401 {"error": "unauthenticated"}` when no valid credentials.

**POST /api/auth/password** — body `{"old": "...", "new": "..."}`; new password must be at least 10 characters; `{"ok": true}`.

**GET /api/auth/demo-info** — `{"enabled": bool, "accounts": [{"username", "password", "role", "title"}], "username": "...", "password": "..."}`. `enabled` is true only when `auth.demo_mode` is on, the server host is `127.0.0.1`/`localhost`, and at least one account still has its unchanged demo password. Otherwise `{"enabled": false, "accounts": []}`.

### Console aggregates

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Public liveness probe |
| GET | `/api/stats` | Store-wide counters |
| GET | `/api/dashboard` | KPIs and chart series for the Overview |
| GET | `/api/overview` | Pipeline stage counters + how-it-works |
| GET | `/api/pipeline` | Per-stage operational monitor |
| GET | `/api/posture` | Posture analytics |
| GET | `/api/intelligence` | Risk prioritization |
| GET | `/api/digest` | 24-hour summary |
| GET | `/api/metrics` | Prometheus text exposition |

**GET /api/health** — `{"status": "ok", "product": "SENTRIX", "version": "2.0.0", "uptime_seconds": int, "python": "3.x.y"}`.

**GET /api/stats** — `{"total", "open", "by_severity": {}, "by_surface": {}, "by_status": {}, "alerts_sent", "events_processed", "remediations"}`. `open` counts status `open` only.

**GET /api/dashboard** — `{"kpis": {"total", "open", "critical_high", "alerts", "remediations", "false_positives"}, "severity": [{"label","value"}], "status": [...], "surfaces": [...], "timeline": [{"date","count"} x 14 days], "channels": [...], "scatter": [{"entropy","occurrences","severity","title"} up to 300], "team": [{"username","title","role","owned","assigned"}]}`.

**GET /api/overview** — `{"stages": {"events", "scans", "findings", "alerts", "remediations"}, "detectors": <registry size>, "surfaces": [10 surface ids], "how": [6 explanatory strings]}`.

**GET /api/pipeline** — `{"stages": [{"id", "name", "status": "operational", "events", "failed", "avg_ms", "last_run", "logs_source"}]}` for eleven stages: `source`, `ingestion`, `normalization`, `detection`, `validation`, `dedup`, `risk`, `finding`, `alerting`, `remediation`, `verification`. Counts are derived from live storage; `avg_ms` is the mean job duration; `failed` reflects failed jobs on ingestion/detection.

**GET /api/posture** — `{"trend", "severity", "sources", "categories": [{"label","value"}], "environments": [...], "remediation_performance": {"mttr_hours", "mttd_hours", "remediated_rate"}, "age_buckets": [{"label": "<1d"|"1-7d"|"7-30d"|">30d","value"}], "integration_health": [{"label","value","status"}]}`. MTTR is computed from status history entries reaching `remediated`/`verified`/`closed`; `mttd_hours` is currently `0.0` (not measured).

**GET /api/intelligence** — `{"risk_distribution": [{"label": band,"value"}], "concentration": [top 8 assets by open findings], "high_risk_assets": [top 6 by max risk], "priorities": [{"id","title","score","band","severity"} top 10 unresolved], "coverage_gaps": [surfaces with no findings], "repeated": [{"title","masked","count"} up to 8]}`.

**GET /api/digest** — `{"period_hours": 24, "total", "open", "by_severity", "alerts_sent", "open_critical"}`.

**GET /api/metrics** — `text/plain; version=0.0.4` with `sentrix_findings_total`, `sentrix_findings_open`, `sentrix_alerts_sent_total`, `sentrix_events_processed_total`, `sentrix_remediations_total`, `sentrix_uptime_seconds`.

### Findings and lifecycle

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/findings` | Filtered, sorted, paginated list |
| GET | `/api/findings/{id}` | Full detail bundle |
| GET | `/api/findings/{id}/related` | Same-fingerprint findings elsewhere |
| GET | `/api/findings/{id}/notes` | Notes |
| GET | `/api/findings/{id}/history` | Status history |
| GET | `/api/findings/{id}/checklist` | Remediation checklist state |
| POST | `/api/findings/{id}/status` | Set lifecycle status |
| POST | `/api/findings/{id}/notes` | Add note |
| POST | `/api/findings/{id}/tags` | Replace tags |
| POST | `/api/findings/{id}/assign` | Set assignee |
| POST | `/api/findings/{id}/severity` | Severity override |
| POST | `/api/findings/{id}/pin` | Pin/unpin |
| POST | `/api/findings/{id}/mute` | Mute/unmute alerts |
| POST | `/api/findings/{id}/checklist` | Tick a checklist step |
| POST | `/api/bulk` | Bulk status/allowlist/assign/tag |
| GET | `/api/filters` | Current user's saved filters |
| POST | `/api/filters` | Save a filter |
| POST | `/api/filters/{id}/delete` | Delete a saved filter |

**GET /api/findings** — query: `status`, `severity`, `surface`, `q` (matches title/path/detector_id), `limit` (default 500), `sort` = `created` (default) | `severity` | `occurrences` | `pinned`, `page` (default 1), `page_size` (default 50). Response: `{"findings": [Finding + extras], "total", "page", "page_size"}` where each item is the finding dict (`id, detector_id, title, severity, surface, path, line, secret_masked, entropy, fingerprint, status, owner, created_at, updated_at, meta`) merged with `assignee, tags, pinned, muted, occurrences, severity_override, last_seen` and meta projections `confidence, validation, environment, risk`.

**GET /api/findings/{id}** — `{"finding": {...}, "extra": {...}, "notes": [...], "history": [...], "checklist": {"0": {"step_idx","done","username","ts"}, ...}, "remediations": [...], "triage": {...}|null}`; `404` when unknown.

**POST /api/findings/{id}/status** — body `{"status": "<one of 12>"}`. Valid statuses: `open, new, triaged, assigned, in_progress, remediated, verified, closed, false_positive, accepted_risk, suppressed, reopened`. Response `{"ok": true, "finding": {...}}`; invalid value -> `400`. Every change appends `status_history` (old, new, username, ts).

Other subresource bodies: notes `{"body": "..."}`; tags `{"tags": ["a","b"]}`; assign `{"assignee": "m.ross"}`; severity `{"severity": "high"|""}` (empty clears the override); pin `{"pinned": true|false}`; mute `{"muted": true|false}`; checklist `{"idx": 0..4, "done": true|false}`. All return `{"ok": true}`.

**POST /api/bulk** — body `{"ids": [...], "action": "status"|"allowlist"|"assign"|"tag", "value": "..."}`. `status` applies a valid status to each id; `allowlist` registers each finding's fingerprint (reason = value) and marks it `false_positive`; `assign` sets assignee; `tag` appends a tag. Response `{"ok": true, "affected": <len(ids)>}`; audited as `bulk.<action>`.

**Saved filters** — `POST /api/filters` body `{"name": "...", "params": {"severity","surface","status","q"}}` -> `{"ok": true, "id": "flt-..."}`. `GET /api/filters` -> `{"filters": [{"id","name","params"}]}` (per user). `POST /api/filters/{id}/delete` -> `{"ok": true}`.

### Detection and scanning

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/scan` | Playground text scan (not stored) or path scan (ingested) |
| GET | `/api/detectors` | Registry with tuning applied |
| POST | `/api/detectors/tuning` | Disable detectors / override severities |
| GET | `/api/detection-rules` | Persisted custom rules |
| POST | `/api/detection-rules` | Create + register a custom rule |
| POST | `/api/detection-rules/{id}/delete` | Delete a custom rule |
| POST | `/api/triage` | Run triage for one finding |
| GET | `/api/allowlist` | Fingerprint registry |
| POST | `/api/allowlist` | Add fingerprint, mark matches false positive |
| POST | `/api/demo` | Seed synthetic findings |
| POST | `/api/demo/reset` | Close demo findings and reseed |

**POST /api/scan** — with `{"text": "...", "path": "playground.txt", "surface": "filesystem"}`: runs the engine only, returns `{"findings": [...], "scanned_files": 1}` and stores nothing. With `{"path": "some/dir"}`: scans the tree (relative paths resolve against the SENTRIX root), ingests results, returns the same shape with the real file count. Missing both -> `400`; nonexistent path -> `400`.

**GET /api/detectors** — `{"detectors": [{"id","title","severity","family","enabled"}]}` with current tuning applied.

**POST /api/detectors/tuning** — body `{"disabled": ["id", ...], "severity_overrides": {"id": "high"}}`; applies immediately via `engine.configure`, audited. Note: tuning is runtime state; persist the same values in `config.toml` to survive restarts.

**POST /api/detection-rules** — body `{"id"?: "custom-...", "title": "...", "severity": "medium", "pattern": "<regex>"}`. The pattern is compiled first; invalid regex -> `400 {"error": "invalid pattern: ..."}`. Success registers the detector immediately (family `custom`) and persists it: `{"ok": true, "id": "..."}`. `GET` returns `{"rules": [{"id","title","severity","pattern","created_by","created_at","enabled"}]}`. `POST /api/detection-rules/{id}/delete` removes the stored row (the in-memory detector remains until restart; see [DETECTION_ENGINE.md](DETECTION_ENGINE.md)).

**POST /api/triage** — body `{"id": "<finding id>"}` -> `{"ok": true, "triage": {"source": "heuristic"|"gpt", "confidence": 0..1, "verdict", "reasons": [...], "recommendation"}}`; stored in `finding.meta.triage`.

**POST /api/allowlist** — body `{"fingerprint": "<sha256>", "reason": "..."}`; registers the fingerprint, refreshes the pipeline allowlist and marks matching stored findings `false_positive`. Missing fingerprint -> `400`.

**POST /api/demo** — `{"ok": true, "seeded": <count>}`. **POST /api/demo/reset** — closes existing findings flagged `meta.demo` and reseeds: `{"ok": true, "closed": n, "seeded": m}`.

### Exposure surface and Connect

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/sources` | Per-surface coverage |
| GET | `/api/assets` | Asset inventory derived from findings |
| GET | `/api/integrations` | Nine-provider hub inventory |
| POST | `/api/integrations/{pid}/sync` | Record a manual sync request |
| POST | `/api/integrations/{pid}/toggle` | Re-enable provider (audit recorded) |
| POST | `/api/integrations/{pid}/disconnect` | Disable provider (audit recorded) |

**GET /api/sources** — `{"sources": [{"surface", "findings", "last_event", "status": "monitored"|"idle"}]}` for the ten surfaces (`ide, pre_push, ci, git, cloud, slack, confluence, jira, postman, filesystem`).

**GET /api/assets** — `{"assets": [{"id": "asset-<key>", "name", "type", "owner", "environment", "integration", "monitored": true, "last_scan", "findings", "critical", "risk"}]}` sorted by risk. Assets are keyed by the first path segment of finding locations (repository/host prefix); they are a derived view, not a separate registry.

**GET /api/integrations** — `{"integrations": [{"id","name","surface","status":"connected"|"demo"|"disconnected","auth","permissions":[...],"rate_limit","last_sync","last_scan","resources":[...],"findings","errors":[...],"enabled":true}]}`. See [INTEGRATIONS.md](INTEGRATIONS.md) for the state model.

**POST /api/integrations/{pid}/sync** — records an `integration.sync` event and a structured log entry; returns `{"ok": true, "status": "sync-recorded"}`. It does not fetch provider data itself. `toggle`/`disconnect` update an in-memory disabled set and write an audit row (`integration.toggle` / `integration.disconnect`); return `{"ok": true}`.

### Response

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/remediation` | SLA task board + playbooks |
| POST | `/api/remediate` | Execute a response action |
| GET | `/api/investigations` | Active investigations |
| GET | `/api/alerts` | Alert feed with acknowledgements |
| POST | `/api/alerts/{id}/ack` | Acknowledge an alert |
| GET | `/api/events` | Pipeline event feed |
| GET | `/api/rules` | Alert channel rules |
| POST | `/api/rules` | Add channel rule |
| POST | `/api/rules/{id}/toggle` / `delete` | Manage a rule |

**GET /api/remediation** — `{"tasks": [{"finding_id","title","severity","assignee","status","sla_hours","age_hours","breached","checklist_done","checklist_total":5}], "playbooks": [{"family","steps":[...]} x 11], "sla": {"breached", "at_risk"}}`. Tasks cover unresolved findings; SLA hours by severity: critical 24, high 72, medium 168, low 336, info 720. `at_risk` = age beyond 70% of SLA; tasks sort breached-first.

**POST /api/remediate** — body `{"id": "<finding id>", "action": "rotate-guide"|"preview-redact"|"redact"|"quarantine"|"restore"|"ticket"|"verify"}` -> `{"ok": true, "detail": "<result text>"}`. Actions, status effects and file effects are documented in [OPERATIONS.md](OPERATIONS.md); unknown action -> `400`.

**GET /api/investigations** — `{"investigations": [{"id","title","severity","status","assignee","notes","related"}]}` for unresolved findings that have notes or an assignee.

**GET /api/alerts?limit=50** — `{"alerts": [{"id","finding_id","channel","message","status","ts","ack": {"alert_id","username","ts"}|null}]}`. Alert statuses: `sent`, `deferred-quiet-hours`, `dry-run`, `http-<code>`, `failed: <reason>`.

**POST /api/alerts/{id}/ack** — `{"ok": true}`; records actor and time.

**GET /api/events?limit=50** — `{"events": [{"id","kind","surface","payload","ts"}]}`.

**Alert rules** — `POST /api/rules` body `{"channel": "console"|"outbox"|"slack"|"webhook", "min_severity": "high"}` -> `{"ok": true, "id": "rule-..."}`. `GET /api/rules` -> `{"rules": [{"id","channel","min_severity","enabled"}]}`. Toggle/delete via `POST /api/rules/{id}/toggle|delete`.

### Jobs and schedules

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/jobs` | Submit a background scan |
| GET | `/api/jobs` | Recent jobs (50) |
| GET | `/api/jobs/{id}` | One job |
| POST | `/api/jobs/{id}/cancel` | Cooperative cancel |
| GET | `/api/schedules` | List schedules |
| POST | `/api/schedules` | Add schedule |
| POST | `/api/schedules/{id}/toggle` / `delete` | Manage a schedule |

**POST /api/jobs** — body `{"path": ".", "surface": "filesystem"}` -> `{"ok": true, "id": "job-..."}`. Job rows: `{"id","path","surface","status","triggered_by","started","finished","files","findings","error"}`; statuses `queued -> running -> done | cancelled | failed`. At most two jobs run concurrently.

**POST /api/schedules** — body `{"path": ".", "surface": "filesystem", "interval_seconds": 3600}` -> `{"ok": true, "id": "sch-..."}`. Rows add `enabled`, `last_run` (epoch). The scheduler loop checks every 10 seconds.

### Governance, reports and compliance

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/exceptions` | Allowlist + exception findings |
| POST | `/api/exceptions` | Record an exception with reason |
| GET | `/api/compliance` | Control-to-evidence mapping |
| GET | `/api/reports` | Report history + available types |
| POST | `/api/reports` | Generate a report |
| GET | `/api/reports/{id}/download` | Download stored report body |
| GET | `/api/audit?limit=200` | Audit trail |
| GET | `/api/logs?limit=200&level=` | Structured system log |
| GET | `/api/logs/export?limit=1000&level=` | CSV log export |
| GET | `/api/export?format=csv\|json` | Findings export (up to 5000) |

**GET /api/exceptions** — `{"allowlist": [{"fingerprint","reason","created_at"}], "exceptions": [findings with status accepted_risk | suppressed | false_positive]}`.

**POST /api/exceptions** — body `{"finding_id": "...", "kind": "accepted_risk"|"suppressed", "reason": "..."}`; sets the status, adds a note `Exception <kind>: <reason>`, writes audit `exception.<kind>`. Invalid kind -> `400`; unknown finding -> `404`.

**GET /api/compliance** — `{"mappings": [{"framework","control","title","evidence":[...],"status":"supported"|"partial"} x 6], "note": "Evidence mapping only. Generating a report does not certify compliance."}`. Full table in [COMPLIANCE.md](COMPLIANCE.md).

**POST /api/reports** — body `{"type": "<one of 11>", "format": "csv"|"json"}` -> `{"ok": true, "id": "rpt-...", "rows": n, "download": "/api/reports/<id>/download"}`. Types: `executive, exposure, critical, repository, cloud, saas, remediation, effectiveness, false_positive, integration_health, audit`. Unknown type -> `400`. **GET /api/reports** -> `{"reports": [{"id","type","format","created_by","rows","created_at"} up to 100], "types": [{"id","title"}]}`. **Download** returns the stored body as `text/csv` or `application/json`.

**GET /api/logs** — `{"logs": [{"id","ts","level","source","message","component","event_type","exec_id","resource","status","correlation_id"}]}` newest first; optional `level` filter (`info|warn|error`). **GET /api/logs/export** returns the same fields as CSV with a header row.

**GET /api/audit** — `{"audit": [{"id","ts","username","action","detail"}]}` newest first.

**GET /api/export** — CSV columns `id,severity,title,surface,path,line,status,assignee,created_at`; JSON `{"findings": [...]}` (default).

### Administration and operations

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| GET | `/api/users` | admin | List accounts (no hashes) |
| POST | `/api/users` | admin | Create account |
| POST | `/api/users/{username}/role` | admin | Change role |
| POST | `/api/users/{username}/disable` | admin | Disable/enable |
| GET | `/api/tokens` | admin | List tokens (no hashes) |
| POST | `/api/tokens` | admin | Create token (raw shown once) |
| POST | `/api/tokens/{id}/revoke` | admin | Revoke token |
| GET | `/api/config` | any | Effective configuration |
| GET | `/api/system/health` | any | Detailed health |
| GET | `/api/ops/stats` | any | DB size and object counts |
| GET | `/api/ops/dump` | any | JSON dump (10 tables) |
| POST | `/api/ops/backup` | write | Online SQLite backup |
| POST | `/api/ops/restore` | admin | Restore from a backup file |
| POST | `/api/ops/purge` | admin | Retention purge |
| POST | `/api/ops/vacuum` | write | Reclaim space |
| POST | `/api/ops/import` | admin | Import a JSON dump |

**POST /api/users** — body `{"username", "password" (10+ chars), "role" (one of the 8)}` -> `{"ok": true}`; duplicate user or invalid role -> `400`. **Role** — `{"role": "..."}`. **Disable** — `{"disabled": true|false}`; disabling yourself -> `400`.

**POST /api/tokens** — body `{"name": "ci", "role": "security_analyst"}` -> `{"ok": true, "token": "sxt_<40 hex>"}` (only time the raw value is returned). Listing never exposes hashes or raw values.

**GET /api/system/health** — `{"uptime_seconds", "version", "db_bytes", "storage", "jobs": {"queued": n, "running": n, ...}, "users", "threads", "python"}`.

**GET /api/ops/stats** — `{"db_bytes", "jobs", "schedules", "users"}`. **GET /api/ops/dump** — JSON object keyed by table for `findings, events, alerts, allowlist, remediations, notes, finding_extra, saved_filters, schedules, alert_rules`.

**POST /api/ops/backup** — `{"ok": true, "path": "data/backups/sentrix-<epoch>.db"}`. **POST /api/ops/restore** — body `{"path": "<backup file>"}`; closes the store, copies the file over `storage.path`, reopens and rewires pipeline/auth; missing file -> `400`. **POST /api/ops/purge** — body `{"days": 90}` -> `{"ok": true, "removed": n}` (remediated/false-positive findings older than the cutoff plus old log lines). **POST /api/ops/vacuum** — `{"ok": true}`. **POST /api/ops/import** — body = a dump object -> `{"ok": true, "imported": <rows>}` (whitelisted tables, `INSERT OR REPLACE`).

### Static console routes

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | Console shell (redirects to `/login` when unauthenticated) |
| GET | `/login` | Sign-in page |
| GET | `/static/{index.html,app.js,styles.css,login.html}` | Whitelisted static files only |
| GET | `/favicon.svg`, `/logo.svg` | Brand assets |

## Usage examples

```sh
# Sign in and keep the cookie
curl -c jar.txt -X POST http://127.0.0.1:8710/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"sentrix-demo"}'

# List critical open findings
curl -b jar.txt "http://127.0.0.1:8710/api/findings?severity=critical&status=open"

# CI gate usage with a Bearer token
curl -H "Authorization: Bearer sxt_..." \
  -X POST http://127.0.0.1:8710/api/jobs \
  -H "Content-Type: application/json" -d '{"path":".","surface":"ci"}'

# Generate and download a report
curl -b jar.txt -X POST http://127.0.0.1:8710/api/reports \
  -H "Content-Type: application/json" -d '{"type":"executive","format":"csv"}'
curl -b jar.txt -o report.csv http://127.0.0.1:8710/api/reports/rpt-.../download
```