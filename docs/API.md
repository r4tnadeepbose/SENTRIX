# REST API

The dashboard server (`python run.py serve`, default `http://127.0.0.1:8710`) exposes a JSON API alongside the static UI. All responses are `application/json` with `Cache-Control: no-store`. POST bodies are JSON. Errors use `{"error": "..."}` with an appropriate status code (`400` invalid input, `404` unknown path or id). The server binds to loopback by default and has no authentication — keep it local.

Static routes: `/` (dashboard), `/static/{index.html,app.js,styles.css}`, `/logo.svg`.

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
{"status": "ok", "product": "KeySentry", "version": "1.0.0", "uptime_seconds": 123, "python": "3.12.0"}
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

Query filters (all optional, combined with AND): `status`, `severity`, `surface`, `q` (substring match on title, path, or detector id), `limit` (default 500). Ordered by `created_at` descending.

```json
{"findings": [ { "...": "Finding object" } ]}
```

Example: `GET /api/findings?severity=critical&status=open&limit=50`

### `GET /api/findings/{id}`

```json
{
  "finding": { "...": "Finding object" },
  "remediations": [
    {"id": "rm-18f...", "finding_id": "a1b2c3d4e5f6", "action": "rotate-guide",
     "detail": "Rotation guide written to data/remediation/a1b2c3d4e5f6.md", "ts": "2026-11-08T09:20:00"}
  ],
  "triage": {"source": "heuristic", "confidence": 0.85, "verdict": "likely_true_positive",
             "reasons": ["..."], "recommendation": "..."}
}
```

`triage` is `null` until triage runs. `404` if the id is unknown.

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
   "status": "sent", "ts": "2026-11-08T09:15:01"}
]}
```

`status` is `sent`, `dry-run`, `http-<code>`, or `failed: <reason>`.

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

`action` is one of `rotate-guide`, `redact`, `quarantine`, `ticket`. Response:

```json
{"ok": true, "detail": "Rotation guide written to data/remediation/a1b2c3d4e5f6.md"}
```

Status transitions: `rotate-guide`/`ticket` → `triaged`; `redact`/`quarantine` → `remediated`. `400` for unknown actions, `404` for unknown ids. See [REMEDIATION.md](REMEDIATION.md).

### `POST /api/findings/{id}/status`

```json
{"status": "triaged"}
```

`status` must be one of `open`, `triaged`, `false_positive`, `remediated`. Response:

```json
{"ok": true, "finding": { "...": "updated Finding object" }}
```

`400` for invalid status values, `404` for unknown ids.