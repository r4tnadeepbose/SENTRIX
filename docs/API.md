# REST API

The dashboard server (`python run.py serve`, default `http://127.0.0.1:8710`) exposes a JSON API alongside the static UI. All responses are `application/json` (except CSV and metrics exports) with `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer`. POST bodies are JSON. Errors use `{"error": "..."}` with an appropriate status code (`400` invalid input, `401` unauthenticated, `403` role violation, `404` unknown path or id).

**Authentication (v1.1):** every endpoint except the public routes below requires either the `ks_session` cookie (set by `POST /api/auth/login`) or an `Authorization: Bearer kst_...` API token. Roles: `admin` (everything), `analyst` (everything except the admin-only routes noted below), `viewer` (read-only; mutations return `403` except logout and own password change). The server binds to loopback by default.

Public routes (no auth): `GET /`, `/login`, `/favicon.svg`, `/logo.svg`, `/api/health`, `/static/{index.html,app.js,styles.css,login.html}`, and `POST /api/auth/login`.

Admin-only routes: anything under `/api/users` and `/api/tokens`, plus `POST /api/ops/restore`, `/api/ops/import`, `/api/ops/purge`.

The v1.0 endpoints below remain valid (now behind auth); see [v1.1 endpoints](#v11-endpoints) for everything added in v1.1.0.

## Finding object

Every finding endpoint returns this shape:

```json
{
  "id": "a1b2c3d4e5f6",
  "detector_id": "aws-access-key-id",
  "title": "AWS Access Key ID",
  "severity": "high",
  "surface": "ide",
  "path": "src/settings.py",
  "line": 12,
  "secret_masked": "AKIA********3456",
  "entropy": 4.31,
  "fingerprint": "9f2c...64-hex-chars...1a",
  "status": "open",
  "owner": "demo-user",
  "created_at": "2026-11-08T09:15:00",
  "updated_at": "2026-11-08T09:15:00",
  "meta": {"family": "cloud", "remediation": "rotate-aws"}
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `id` | string | 12 hex chars, derived from fingerprint + path + line |
| `detector_id` | string | Registry id (see [DETECTORS.md](DETECTORS.md)) |
| `title` | string | Human-readable detector title |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `surface` | string | `ide`, `pre_push`, `ci`, `git`, `cloud`, `slack`, `confluence`, `jira`, `postman`, `filesystem` |
| `path` | string | File path or source location (e.g. `slack:#eng/1712345678.001`) |
| `line` | integer | 1-based line number |
| `secret_masked` | string | Masked preview only; raw secrets are never stored |
| `entropy` | number | Shannon entropy of the value, rounded to 2 decimals |
| `fingerprint` | string | SHA-256 of `detector_id|secret`; stable dedupe/allowlist key |
| `status` | string | `open`, `triaged`, `false_positive`, `remediated` |
| `owner` | string | Source author when known (e.g. Slack user), else empty |
| `created_at` / `updated_at` | string | UTC ISO timestamps (`YYYY-MM-DDTHH:MM:SS`) |
| `meta` | object | Family, remediation hint, `triage` result, surface extras (`env_key`, `json_path`, `demo`) |

## GET endpoints

### `GET /api/health`

```json
{"status": "ok", "product": "KeySentry", "version": "1.1.0", "uptime_seconds": 123, "python": "3.12.0"}
```

### `GET /api/stats`

```json
{
  "total": 12, "open": 9,
  "by_severity": {"high": 5, "critical": 4, "medium": 3},
  "by_surface": {"ide": 2, "slack": 3, "ci": 1},
  "by_status": {"open": 9, "triaged": 2, "remediated": 1},
  "alerts_sent": 12, "events_processed": 8, "remediations": 2
}
```

### `GET /api/findings`

Query filters (all optional, combined with AND): `status`, `severity`, `surface`, `q` (substring match on title, path, or detector id), `limit` (default 500). v1.1 adds `sort` (`created` default, `severity`, `occurrences`, `pinned`), `page` (default 1), and `page_size` (default 50). Each returned finding is merged with its management extras (`assignee`, `tags`, `pinned`, `muted`, `occurrences`, `severity_override`).

```json
{"findings": [ { "...": "Finding object + extras" } ], "total": 123, "page": 1, "page_size": 50}
```

Example: `GET /api/findings?severity=critical&status=open&sort=occurrences&page=1&page_size=50`

### `GET /api/findings/{id}`

```json
{
  "finding": { "...": "Finding object" },
  "extra": {"assignee": "", "tags": [], "severity_override": "", "pinned": 0,
            "muted": 0, "occurrences": 3, "first_seen": "2026-11-08T09:15:00",
            "last_seen": "2026-11-08T11:02:00"},
  "notes": [ {"id": 1, "finding_id": "a1b2c3d4e5f6", "username": "admin", "body": "...", "ts": "..."} ],
  "history": [ {"id": 1, "finding_id": "a1b2c3d4e5f6", "old": "open", "new": "triaged", "username": "admin", "ts": "..."} ],
  "checklist": { "0": {"step_idx": 0, "done": 1, "username": "admin", "ts": "..."} },
  "remediations": [
    {"id": "rm-18f...", "finding_id": "a1b2c3d4e5f6", "action": "rotate-guide",
     "detail": "Rotation guide written to data/remediation/a1b2c3d4e5f6.md", "ts": "2026-11-08T09:20:00"}
  ],
  "triage": {"source": "heuristic", "confidence": 0.85, "verdict": "likely_true_positive",
             "reasons": ["..."], "recommendation": "..."}
}
```

`triage` is `null` until triage runs. `extra`, `notes`, `history`, and `checklist` are new in v1.1. `404` if the id is unknown.

### `GET /api/events?limit=50`

```json
{"events": [
  {"id": "ev-18f...", "kind": "scan.cli", "surface": "filesystem",
   "payload": {"new": 2, "known": 1, "paths": ["src/settings.py"]}, "ts": "2026-11-08T09:15:00"}
]}
```

Event kinds include `scan.cli`, `scan.path`, `gate.blocked`, `gate.passed`, `ingest.<surface>`, `demo.seeded`, `selftest`, `watch.changed`.

### `GET /api/alerts?limit=50`

```json
{"alerts": [
  {"id": "al-18f...", "finding_id": "a1b2c3d4e5f6", "channel": "outbox",
   "message": "[HIGH] AWS Access Key ID on ide at src/settings.py:12 (masked: AKIA********3456)",
   "status": "sent", "ts": "2026-11-08T09:15:01",
   "ack": {"alert_id": "al-18f...", "username": "admin", "ts": "2026-11-08T09:40:00"} }
]}
```

`status` is `sent`, `dry-run`, `deferred-quiet-hours`, `http-<code>`, or `failed: <reason>`. `ack` is `null` until acknowledged (v1.1).

### `GET /api/allowlist`

```json
{"entries": [
  {"fingerprint": "9f2c...1a", "reason": "Synthetic fixture in docs", "created_at": "2026-11-08T09:30:00"}
]}
```

### `GET /api/config`

Returns the full merged configuration (defaults + `config.toml` + `config.local.toml`). Secret values are never included — only the names of environment variables to read.

## POST endpoints

### `POST /api/scan`

Two modes:

- **Text (Playground):** scans ad-hoc text without storing anything.

  ```json
  {"text": "key = \"AWS_KEY_REDACTED\"", "path": "playground.txt", "surface": "filesystem"}
  ```

  `path` and `surface` are optional (defaults `playground.txt`, `filesystem`).

- **Path:** scans a file or tree (relative paths resolve against the project root) and ingests findings.

  ```json
  {"path": "examples/lambda"}
  ```

Response:

```json
{"findings": [ { "...": "Finding object" } ], "scanned_files": 3}
```

`400` if the path does not exist.

### `POST /api/demo`

Seeds synthetic demo findings. Body ignored.

```json
{"ok": true, "seeded": 10}
```

### `POST /api/allowlist`

Adds a fingerprint to the false-positive registry and marks all matching stored findings `false_positive`.

```json
{"fingerprint": "9f2c...1a", "reason": "Synthetic fixture in docs"}
```

Response: `{"ok": true}`. `400` if `fingerprint` is missing.

### `POST /api/triage`

Runs GPT triage when configured, otherwise the deterministic heuristic. The result is stored in `finding.meta.triage`.

```json
{"id": "a1b2c3d4e5f6"}
```

Response:

```json
{"ok": true, "triage": {
  "source": "heuristic",
  "confidence": 0.85,
  "verdict": "likely_true_positive",
  "reasons": ["High Shannon entropy consistent with a generated credential."],
  "recommendation": "Rotate the credential and remove the exposure; follow the rotation guide."
}}
```

`verdict` is `likely_true_positive`, `likely_false_positive`, or `needs_review`; `source` is `gpt` or `heuristic`. `404` if the id is unknown.

### `POST /api/remediate`

```json
{"id": "a1b2c3d4e5f6", "action": "rotate-guide"}
```

`action` is one of `rotate-guide`, `redact`, `preview-redact`, `quarantine`, `restore`, `ticket`, `verify` (the last three additions are new in v1.1). Response:

```json
{"ok": true, "detail": "Rotation guide written to data/remediation/a1b2c3d4e5f6.md"}
```

Status transitions: `rotate-guide`/`ticket` → `triaged`; `redact`/`quarantine` → `remediated`; `verify` → `remediated` only when the rescan finds nothing at the recorded location. `preview-redact` returns a before/after preview and changes nothing; `restore` moves a quarantined file back. `400` for unknown actions, `404` for unknown ids. See [REMEDIATION.md](REMEDIATION.md).

### `POST /api/findings/{id}/status`

```json
{"status": "triaged"}
```

`status` must be one of `open`, `triaged`, `false_positive`, `remediated`. Response:

```json
{"ok": true, "finding": { "...": "updated Finding object" }}
```

`400` for invalid status values, `404` for unknown ids.

## v1.1 endpoints

Everything below was added in v1.1.0. Unless marked public or admin-only, routes require a session cookie or Bearer token and accept `analyst` and `admin`; `viewer` is limited to the GET routes. Deletions use `POST .../delete` (the server implements GET and POST only). Every mutation except login is written to the system log; security-relevant actions also land in the audit trail.

### Auth

#### `POST /api/auth/login` (public)

```json
{"username": "admin", "password": "..."}
```

Success: `{"ok": true, "user": {"username": "admin", "role": "admin"}}` plus `Set-Cookie: ks_session=<token>; HttpOnly; Path=/; SameSite=Strict; Max-Age=<session_hours*3600>`. Failures return `400` with `{"error": "Invalid credentials."}`; exceeding the per-IP rate limit (default 5 attempts per rolling 60s) returns `400` with `{"error": "Too many attempts; wait a minute."}`. Failed logins are audited.

#### `POST /api/auth/logout`

Body ignored. Deletes the current session. `{"ok": true}`. Allowed for all roles.

#### `POST /api/auth/password`

```json
{"old": "current-password", "new": "new-password-10-chars-min"}
```

Verifies the current password; new password must be at least 10 characters. Re-salts and re-hashes; audited. `{"ok": true}`. Allowed for all roles.

#### `GET /api/auth/me`

```json
{"user": {"username": "admin", "role": "admin"}}
```

`401` when unauthenticated. For Bearer tokens the username is `token:<name>`.

### Users (admin-only)

| Method and path | Payload | Effect |
| --- | --- | --- |
| `GET /api/users` | — | `{"users": [{"username", "role", "disabled", "created_at"}]}` (hashes never returned) |
| `POST /api/users` | `{"username": "ana", "password": "min-10-chars", "role": "analyst"}` | Create account; roles `admin`/`analyst`/`viewer`; audited |
| `POST /api/users/{username}/role` | `{"role": "viewer"}` | Change role; audited |
| `POST /api/users/{username}/disable` | `{"disabled": true}` | Disable (`false` re-enables); cannot disable yourself; audited |

### API tokens (admin-only)

| Method and path | Payload | Effect |
| --- | --- | --- |
| `GET /api/tokens` | — | `{"tokens": [{"id", "name", "role", "created_by", "created_at", "revoked"}]}` (hashes never returned) |
| `POST /api/tokens` | `{"name": "ci", "role": "analyst"}` | `{"ok": true, "token": "kst_..."}` — raw value shown once; only its SHA-256 hash is stored; audited |
| `POST /api/tokens/{id}/revoke` | `{}` | Revoke immediately; audited |

Use tokens as `Authorization: Bearer kst_...`. The token's role applies to every request it authenticates.

### Finding subroutes

All take the finding id in the path; `404` for unknown ids. GET variants are readable by all roles; POST variants require analyst/admin.

| Method and path | Payload | Effect |
| --- | --- | --- |
| `GET /api/findings/{id}/notes` | — | `{"notes": [...]}` |
| `POST /api/findings/{id}/notes` | `{"body": "Reviewed with the team."}` | Add a note attributed to the caller |
| `GET /api/findings/{id}/history` | — | `{"history": [...]}` status transitions |
| `GET /api/findings/{id}/related` | — | `{"findings": [...]}` other findings with the same fingerprint |
| `GET /api/findings/{id}/checklist` | — | `{"checklist": {"0": {"step_idx", "done", "username", "ts"}, ...}}` |
| `POST /api/findings/{id}/checklist` | `{"idx": 0, "done": true}` | Persist one checklist step with actor and timestamp |
| `POST /api/findings/{id}/tags` | `{"tags": ["prod", "rotate"]}` | Replace the tag list |
| `POST /api/findings/{id}/assign` | `{"assignee": "ana"}` | Set assignee (empty string clears) |
| `POST /api/findings/{id}/severity` | `{"severity": "critical"}` | Per-finding override; empty string clears; invalid values → `400` |
| `POST /api/findings/{id}/pin` | `{"pinned": true}` | Pin/unpin |
| `POST /api/findings/{id}/mute` | `{"muted": true}` | Mute/unmute alerting for this finding |

`POST /api/findings/{id}/status` is unchanged from v1.0 but now records a `status_history` row with the acting user.

### Bulk actions

#### `POST /api/bulk`

```json
{"ids": ["a1b2c3d4e5f6", "b2c3d4e5f6a1"], "action": "status", "value": "triaged"}
```

`action` is one of:

- `status` — set `value` (must be a valid status) on every id
- `allowlist` — allowlist each finding's fingerprint with `value` as the reason (default "bulk allowlist") and mark it `false_positive`
- `assign` — set assignee to `value`
- `tag` — append `value` to each finding's tags (deduplicated)

Response: `{"ok": true, "affected": 2}`. Audited as `bulk.<action>`.

### Saved filters

| Method and path | Payload | Effect |
| --- | --- | --- |
| `GET /api/filters` | — | Caller's presets: `{"filters": [{"id", "name", "params"}]}` |
| `POST /api/filters` | `{"name": "Critical open", "params": {"severity": "critical", "status": "open"}}` | `{"ok": true, "id": "flt-..."}` |
| `POST /api/filters/{id}/delete` | `{}` | Delete a preset |

### Jobs

| Method and path | Payload | Effect |
| --- | --- | --- |
| `GET /api/jobs` | — | `{"jobs": [...]}` latest 50: `id`, `path`, `surface`, `status`, `triggered_by`, `started`, `finished`, `files`, `findings`, `error` |
| `GET /api/jobs/{id}` | — | `{"job": {...}}`; `404` if unknown |
| `POST /api/jobs` | `{"path": "examples/lambda", "surface": "filesystem"}` | Queue a background scan; `{"ok": true, "id": "job-..."}` |
| `POST /api/jobs/{id}/cancel` | `{}` | Cooperative cancel (checked between files) |

Job statuses: `queued`, `running`, `done`, `cancelled`, `failed`. At most two jobs run concurrently; unchanged files (mtime + size) are served from the incremental cache. Relative paths resolve against the project root.

### Schedules

| Method and path | Payload | Effect |
| --- | --- | --- |
| `GET /api/schedules` | — | `{"schedules": [{"id", "path", "surface", "interval_seconds", "enabled", "last_run"}]}` |
| `POST /api/schedules` | `{"path": ".", "surface": "filesystem", "interval_seconds": 3600}` | `{"ok": true, "id": "sch-..."}` |
| `POST /api/schedules/{id}/toggle` | `{}` | Flip `enabled` |
| `POST /api/schedules/{id}/delete` | `{}` | Delete |

The scheduler loop ticks every 10 seconds and submits a job for each due schedule.

### Alert rules and acknowledgement

| Method and path | Payload | Effect |
| --- | --- | --- |
| `GET /api/rules` | — | `{"rules": [{"id", "channel", "min_severity", "enabled"}]}` |
| `POST /api/rules` | `{"channel": "slack", "min_severity": "high"}` | `{"ok": true, "id": "rule-..."}` |
| `POST /api/rules/{id}/toggle` | `{}` | Flip `enabled` |
| `POST /api/rules/{id}/delete` | `{}` | Delete |
| `POST /api/alerts/{id}/ack` | `{}` | Record acknowledgement (actor + timestamp); appears as `ack` on `GET /api/alerts` |

A rule gates its channel: alerts below `min_severity` are skipped for that channel. With no enabled rule for a channel, all severities pass.

### Logs and audit

| Method and path | Query | Response |
| --- | --- | --- |
| `GET /api/logs` | `limit` (default 200), `level` (`info`/`warn`/`error`) | `{"logs": [{"id", "ts", "level", "source", "message"}]}` newest first |
| `GET /api/audit` | `limit` (default 200) | `{"audit": [{"id", "ts", "username", "action", "detail"}]}` newest first |

System log sources: `auth`, `http`, `scan`, `jobs`, `scheduler`, `escalation`, `remediation`, `demo`. Audit actions include `login.ok`, `login.failed`, `logout`, `password.changed`, `user.*`, `token.*`, `bulk.*`, `ops.*`, `detectors.tuning`.

### Detectors and tuning

#### `GET /api/detectors`

```json
{"detectors": [
  {"id": "aws-access-key-id", "title": "AWS Access Key ID", "severity": "high",
   "family": "cloud", "enabled": true}
]}
```

`severity` reflects overrides; `enabled` is false for disabled ids. Includes custom detectors registered from config.

#### `POST /api/detectors/tuning`

```json
{"disabled": ["high-entropy-string"], "severity_overrides": {"jwt": "low"}}
```

Applies immediately to the running engine (runtime only — persist durable changes in `config.local.toml`; see [DETECTORS.md](DETECTORS.md)). Audited as `detectors.tuning`. `{"ok": true}`.

### Overview and digest

#### `GET /api/overview`

```json
{
  "stages": {"events": 8, "scans": 3, "findings": 12, "alerts": 12, "remediations": 2},
  "detectors": 26,
  "surfaces": ["ide", "pre_push", "ci", "git", "cloud", "slack", "confluence", "jira", "postman", "filesystem"],
  "how": ["1. Events arrive from a surface...", "..."]
}
```

#### `GET /api/digest`

```json
{"period_hours": 24, "total": 12, "open": 9,
 "by_severity": {"critical": 4, "high": 5, "medium": 3},
 "alerts_sent": 12, "open_critical": 4}
```

### Export and metrics

| Method and path | Query/payload | Response |
| --- | --- | --- |
| `GET /api/export` | `format=csv` | CSV with columns `id,severity,title,surface,path,line,status,assignee,created_at` (up to 5000 findings) |
| `GET /api/export` | omitted or `format=json` | `{"findings": [...]}` (up to 5000) |
| `GET /api/metrics` | — | Prometheus text format (`text/plain; version=0.0.4`): `keysentry_findings_total`, `keysentry_findings_open`, `keysentry_alerts_sent_total`, `keysentry_events_processed_total`, `keysentry_remediations_total`, `keysentry_uptime_seconds` |

### Ops

| Method and path | Payload | Role | Effect |
| --- | --- | --- | --- |
| `GET /api/ops/stats` | — | any | `{"db_bytes": 123456, "jobs": 3, "schedules": 1, "users": 2}` |
| `GET /api/ops/dump` | — | any | JSON dump of `findings`, `events`, `alerts`, `allowlist`, `remediations`, `notes`, `finding_extra`, `saved_filters`, `schedules`, `alert_rules` |
| `POST /api/ops/backup` | `{}` | analyst+ | Online SQLite backup to `data/backups/keysentry-<epoch>.db`; `{"ok": true, "path": "..."}`; audited |
| `POST /api/ops/restore` | `{"path": "data/backups/keysentry-1762...db"}` | admin | Replace the live database from a backup file and reopen storage; audited |
| `POST /api/ops/purge` | `{"days": 90}` | admin | Delete `remediated`/`false_positive` findings older than N days plus their notes/history/extras/checklists and old system-log rows; `{"ok": true, "removed": 4}`; audited |
| `POST /api/ops/vacuum` | `{}` | analyst+ | Reclaim database space; `{"ok": true}` |
| `POST /api/ops/import` | `{"findings": [...], "allowlist": [...]}` | admin | Import rows into whitelisted tables (`findings`, `allowlist`, `notes`, `finding_extra`, `schedules`, `alert_rules`, `saved_filters`); `{"ok": true, "imported": 12}`; audited |