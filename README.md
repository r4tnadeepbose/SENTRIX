# Wintermute

![Wintermute logo](assets/logo.svg)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Stdlib only](https://img.shields.io/badge/dependencies-stdlib--only-brightgreen.svg)](docs/INSTALL.md)

Wintermute - named after the orchestrating AI in William Gibson's *Neuromancer* - is a layered secret-detection system that follows one unified flow — **event → scan → alert → remediation** — from the editor to the cloud. A single shared detector registry (regex + entropy + validators) powers every layer: local IDE on-save checks, git hooks, CI diff gates, cloud function code and environment scanning, SaaS monitoring, and filesystem watching. Findings are masked, fingerprinted, deduplicated, and stored in SQLite; raw secrets are never persisted. Everything works offline with zero required dependencies.

**New in v1.1:** an authenticated graphite dashboard with a login page, role-based access (admin/analyst/viewer), API tokens for CI, audit trail and live system log, full findings management, background scan jobs and schedules, alert rules with quiet hours and escalation, previewable remediation with verification, and backup/export/metrics operations — **100 features in v1.1**, cataloged in [docs/OVERVIEW.md](docs/OVERVIEW.md).

## Features

- **One pattern set, many layers.** 26 built-in detectors for cloud keys, SaaS tokens, private keys, connection URIs, and generic high-entropy assignments — reused identically everywhere, plus custom detectors from config.
- **Unified pipeline.** Every surface feeds the same engine, allowlist, storage, alert router, and remediation playbooks.
- **Authenticated access.** Login page with HttpOnly SameSite session cookies, PBKDF2 hashing (200k iterations), login rate limiting, three-role RBAC, and revocable `wmt_` API tokens for CI (Bearer auth).
- **Privacy by default.** Raw secrets are never stored: only a masked preview and a SHA-256 fingerprint. IDE and git-hook layers are fully local.
- **Findings management.** Notes, tags, assignee, severity override, pin, mute, occurrences, first/last seen, status history, related findings, bulk actions, saved filters, sorting, pagination, and search.
- **Background jobs and schedules.** Incremental scan cache, cancellation, a concurrency cap, job history, and recurring scheduled scans.
- **Dedupe everywhere.** Findings dedupe by fingerprint + path + line; alerts dedupe within a configurable window.
- **Alert channels with rules.** Console, file outbox (`data/outbox`), and webhook channels (`slack`, `webhook`), governed by per-channel severity rules, quiet hours, retry backoff, acknowledgement, mute, escalation, and a digest endpoint. Unconfigured network channels run in dry-run mode.
- **Actionable remediation.** Rotation playbooks, redaction with before/after preview, quarantine and restore, ticketing, verification rescans, and persisted checklists.
- **Audit and live logs.** Security-relevant actions land in an audit trail; every subsystem writes a system log you can tail live, filter by level, and pause.
- **Operations.** Backup/restore, retention purge, vacuum, JSON dump/import, CSV and JSON export, Prometheus metrics, and database size stats.
- **Optional GPT triage.** Any GPT-compatible chat endpoint; deterministic heuristic fallback when offline or unconfigured. Only masked values are ever sent.
- **Graphite dashboard.** Stdlib `http.server` at `http://127.0.0.1:8710` with a minimalist single-theme graphite UI, login, and views for Overview, Findings, Jobs, Logs, Playground, Activity, Allowlist, and Settings — plus help popovers, a Ctrl+K command palette, and keyboard shortcuts.
- **Zero required dependencies.** Python 3.11+ standard library only; optional `boto3` for live cloud scanning.

## Quickstart

### Windows

```bat
run.bat
```

Or explicitly:

```bat
python run.py
```

### Kali / Linux / macOS

```sh
./run.sh
```

Or explicitly:

```sh
python3 run.py
```

With no arguments, Wintermute starts the dashboard at **http://127.0.0.1:8710**. On first run it creates an `admin` account and writes the initial password to **`data/INITIAL_ADMIN_PASSWORD.txt`** (or uses `WINTERMUTE_ADMIN_PASSWORD` from the environment when set). Open the dashboard, sign in at the login page, and change the password in Settings. See [docs/INSTALL.md](docs/INSTALL.md) for platform setup, first-run login, optional installs, and environment variables.

### First-run demo

```sh
python run.py demo     # seed synthetic findings across every surface
python run.py serve    # then open http://127.0.0.1:8710 and sign in
```

The demo uses synthetic values only. Explore the Findings view, run triage, and try a remediation action safely.

## Authentication

The dashboard and JSON API require sign-in (session cookie) or an API token (Bearer). The server still binds to loopback by default.

| Role | Can do |
| --- | --- |
| `admin` | Everything, including user management, API tokens, restore, import, and retention purge |
| `analyst` | Scan, manage findings, run jobs and schedules, configure rules and detector tuning, remediate, back up, export |
| `viewer` | Read-only browsing (plus logout and own password change) |

- **Sessions:** `HttpOnly`, `SameSite=Strict` cookie, 12-hour default lifetime (`auth.session_hours`); login attempts are rate-limited per IP (`auth.login_rate_limit`, default 5 per minute).
- **Initial admin:** password in `data/INITIAL_ADMIN_PASSWORD.txt` on first run, or set `WINTERMUTE_ADMIN_PASSWORD` beforehand. Change it after first login; delete the file once stored safely.
- **API tokens for CI:** admins create named `wmt_...` tokens with a role; only a SHA-256 hash is stored and the raw value is shown once. Use `Authorization: Bearer wmt_...` against the API; revoke tokens at any time.

```sh
curl -H "Authorization: Bearer wmt_..." http://127.0.0.1:8710/api/findings
```

Details: [docs/API.md](docs/API.md) and [SECURITY.md](SECURITY.md).

## CLI

All commands run as `python run.py <cmd>` (or `python3` on Linux/macOS). No arguments starts `serve`.

| Command | Purpose |
| --- | --- |
| `serve [--port N]` | Run the dashboard and JSON API (default port 8710) |
| `scan PATH [--surface S] [--json] [--no-store] [--strict]` | Scan a file or tree; `--strict` exits 1 at/above `fail_on` |
| `gate [--staged \| --range BASE..HEAD \| --base B --head H] [--repo PATH]` | Diff-only gate for hooks and CI; exits 1 when blocking findings exist |
| `hooks install\|uninstall [--repo PATH]` | Install or remove the pre-commit and pre-push git hooks |
| `demo` | Seed synthetic demo findings |
| `selftest` | Run internal sanity checks (registry, detection, allowlist, dedupe) |
| `report [--format md\|json]` | Print a findings report |
| `watch PATH [--interval S]` | Poll a tree and scan files on change |
| `surfaces` | List available surface adapters |
| `allowlist add FP --reason R` / `allowlist list` | Manage the false-positive registry by fingerprint |
| `triage ID` | AI/heuristic triage for one finding |
| `remediate ID --action redact\|quarantine\|ticket\|rotate-guide` | Run a remediation action (preview-redact, restore, and verify are available in the dashboard/API) |
| `ingest --surface slack\|confluence\|jira\|postman\|postman-env\|cloud\|ide [--file PATH]` | Scan a SaaS/cloud export or live source |
| `users add USERNAME --password P --role R` / `users list` | Manage local accounts (admin/analyst/viewer) |
| `tokens create --name N --role R` / `tokens list` / `tokens revoke --id ID` | Manage `wmt_` API tokens for CI and scripts |
| `backup [--dest PATH]` | Write a SQLite backup (default `data/backups/`) |
| `schedules add --path P --interval S` / `schedules list` | Manage scheduled scans |
| `jobs` | List background scan jobs and their status |

Make targets: `serve`, `scan`, `demo`, `test`, `selftest`, `hooks`, `report`.

## Layers

| Layer | Where it runs | How it is triggered |
| --- | --- | --- |
| IDE on-save | Local machine only | `ingest --surface ide --file PATH`, or `watch PATH` for any editor |
| Git hooks | Local machine only | `hooks install`, then pre-commit (`gate --staged`) and pre-push (`gate --range`) |
| CI diff gate | Any CI system | `gate --base origin/main --head HEAD` (or `--range`); non-zero exit blocks the pipeline |
| Cloud / serverless | Local exports or live provider scans | `ingest --surface cloud`; scans function code and environment variables |
| SaaS monitoring | `slack`, `confluence`, `jira`, `postman` surfaces | `ingest --surface ... --file export.json`, or live mode with tokens |
| Filesystem watch | Local machine only | `watch PATH --interval 2` |

In v1.1, background jobs and scheduled scans add two more event sources from the dashboard itself (Jobs view).

## Screenshots

| Dashboard (graphite) | Dashboard (white) |
| --- | --- |
| ![Dashboard, graphite theme](docs/screenshots/dashboard-dark.png) | ![Dashboard, white theme](docs/screenshots/dashboard-light.png) |

| Login with company demo roster | Findings detail drawer |
| --- | --- |
| ![Login page](docs/screenshots/login.png) | ![Finding drawer](docs/screenshots/findings-drawer.png) |

## Configuration

Wintermute reads `config.toml`, then optional `config.local.toml` (gitignored), then environment variables for secrets. Safe defaults work out of the box:

```toml
[server]
host = "127.0.0.1"
port = 8710

[auth]
session_hours = 12
login_rate_limit = 5      # attempts per IP per rolling minute

[scan]
entropy_threshold = 4.5
fail_on = "high"          # gate/strict threshold: critical | high | medium | low | info

[alerting]
channels = ["console", "outbox"]   # add "slack" or "webhook" when configured
slack_webhook = ""
webhook_url = ""
dedupe_window_seconds = 3600
escalate_after_hours = 24

[detectors]
disabled = []             # detector ids to turn off
severity_overrides = {}   # detector id -> severity

[ai]
enabled = false
model = "gpt-4o-mini"     # any GPT-compatible chat endpoint via base_url
api_key_env = "WINTERMUTE_AI_KEY"
```

See [docs/AI_TRIAGE.md](docs/AI_TRIAGE.md), [docs/SURFACES.md](docs/SURFACES.md), and [docs/PRIVACY.md](docs/PRIVACY.md) for the full picture.

## Project layout

```text
Wintermute/
├── run.py                  # entry point (no args = serve)
├── run.bat / run.sh        # one-click launchers (Windows / Linux+macOS)
├── config.toml             # safe defaults; override in config.local.toml
├── pyproject.toml          # packaging; zero required dependencies
├── Makefile                # serve scan demo test selftest hooks report
├── assets/                 # logo.svg + monochrome favicon.svg
├── hooks/                  # pre-commit and pre-push hook scripts
├── wintermute/
│   ├── cli.py              # command line
│   ├── config.py           # layered config loading
│   ├── server.py           # stdlib HTTP server: login, dashboard + authenticated JSON API
│   ├── auth.py             # sessions, RBAC, API tokens, rate limits, audit + system log
│   ├── watch.py            # polling filesystem watcher
│   ├── demo.py             # synthetic demo seeding
│   ├── core/               # models, engine, pipeline, storage, extensions, jobs, allowlist, entropy, util
│   ├── detectors/          # shared registry: cloud, saas, crypto, generic (+ config-defined custom)
│   ├── surfaces/           # filesystem, git, ide, slack, confluence, jira, postman, cloud
│   ├── alerting/           # channel router: rules, quiet hours, dedupe, retries, dry-run
│   ├── remediation/        # playbooks: rotate-guide, redact, preview, quarantine, restore, ticket, verify
│   ├── ai/                 # GPT client, prompts, heuristic triage
│   └── dashboard/          # graphite single-theme UI + login page
├── examples/               # synthetic fixtures for ingest and demos
├── docs/                   # overview, architecture, install, detectors, surfaces, API, privacy
└── data/                   # runtime state (gitignored): SQLite DB, outbox, quarantine, backups,
                            # INITIAL_ADMIN_PASSWORD.txt (first run only)
```

## Privacy

Raw secrets are never stored or transmitted by default. Findings keep only a masked preview (first/last four characters) and a SHA-256 fingerprint. Network activity happens only when you explicitly configure it: alert webhooks, live SaaS reads, security ticket creation, and optional GPT triage (masked values only). Details: [docs/PRIVACY.md](docs/PRIVACY.md).

## Documentation

- [Overview](docs/OVERVIEW.md) — purpose, layers, pipeline, module map, auth flow, storage, and the 100-feature catalog
- [Architecture](docs/ARCHITECTURE.md) — module map, data flow, storage schema, design decisions
- [Flowcharts](docs/FLOWCHART.md) — event → scan → alert → remediation, per layer
- [Install](docs/INSTALL.md) — Windows, Kali/Debian, macOS, optional extras, env vars
- [Detectors](docs/DETECTORS.md) — full registry, adding detectors, tuning
- [Surfaces](docs/SURFACES.md) — per-surface usage, fixtures, live mode, rate limiting
- [API](docs/API.md) — REST contract and JSON shapes
- [Remediation](docs/REMEDIATION.md) — playbooks, actions, status lifecycle
- [Privacy](docs/PRIVACY.md) — what stays local, what can leave, and when
- [AI triage](docs/AI_TRIAGE.md) — enabling GPT triage, fallback, prompt privacy
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)

## License

[MIT](LICENSE)