# KeySentry

![KeySentry logo](assets/logo.svg)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Stdlib only](https://img.shields.io/badge/dependencies-stdlib--only-brightgreen.svg)](docs/INSTALL.md)

KeySentry is a layered secret-detection system that follows one unified flow — **event → scan → alert → remediation** — from the editor to the cloud. A single shared detector registry (regex + entropy + validators) powers every layer: local IDE on-save checks, git hooks, CI diff gates, Lambda code and environment scanning, SaaS monitoring, and filesystem watching. Findings are masked, fingerprinted, deduplicated, and stored in SQLite; raw secrets are never persisted. Everything works offline with zero required dependencies.

## Features

- **One pattern set, many layers.** 26 detectors for cloud keys, SaaS tokens, private keys, connection URIs, and generic high-entropy assignments — reused identically everywhere.
- **Unified pipeline.** Every surface feeds the same engine, allowlist, storage, alert router, and remediation playbooks.
- **Privacy by default.** Raw secrets are never stored: only a masked preview and a SHA-256 fingerprint. IDE and git-hook layers are fully local.
- **Dedupe everywhere.** Findings dedupe by fingerprint + path + line; alerts dedupe within a configurable window.
- **Alert channels.** Console, file outbox (`data/outbox`), Slack webhook, generic webhook. Unconfigured network channels run in dry-run mode.
- **Actionable remediation.** Rotation playbooks, in-place redaction, file quarantine, and Jira/outbox ticketing.
- **Optional GPT triage.** Any OpenAI-compatible endpoint; deterministic heuristic fallback when offline or unconfigured. Only masked values are ever sent.
- **Local dashboard.** Stdlib `http.server` at `http://127.0.0.1:8710` with dark and light themes and views for Overview, Findings, Playground, Activity, Allowlist, and Settings.
- **Zero required dependencies.** Python 3.11+ standard library only; optional `boto3` for live AWS scanning.

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

With no arguments, KeySentry starts the dashboard at **http://127.0.0.1:8710**. See [docs/INSTALL.md](docs/INSTALL.md) for platform setup, optional installs, and environment variables.

### First-run demo

```sh
python run.py demo     # seed synthetic findings across every surface
python run.py serve    # then open http://127.0.0.1:8710
```

The demo uses synthetic values only. Explore the Findings view, run triage, and try a remediation action safely.

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
| `remediate ID --action redact\|quarantine\|ticket\|rotate-guide` | Run a remediation action |
| `ingest --surface slack\|confluence\|jira\|postman\|postman-env\|cloud\|ide [--file PATH]` | Scan a SaaS/cloud export or live source |

Make targets: `serve`, `scan`, `demo`, `test`, `selftest`, `hooks`, `report`.

## Layers

| Layer | Where it runs | How it is triggered |
| --- | --- | --- |
| IDE on-save | Local machine only | `ingest --surface ide --file PATH`, or `watch PATH` for any editor |
| Git hooks | Local machine only | `hooks install`, then pre-commit (`gate --staged`) and pre-push (`gate --range`) |
| CI diff gate | GitHub Actions, GitLab CI, Jenkins | `gate --base origin/main --head HEAD` (or `--range`); non-zero exit blocks the pipeline |
| Cloud / Lambda | Local exports or live AWS | `ingest --surface cloud`; scans function code and environment variables |
| SaaS monitoring | Slack, Confluence, Jira, Postman | `ingest --surface ... --file export.json`, or live mode with tokens |
| Filesystem watch | Local machine only | `watch PATH --interval 2` |

## Screenshots

| Dark theme | Light theme |
| --- | --- |
| ![Dashboard, dark theme](docs/screenshots/dashboard-dark.png) | ![Dashboard, light theme](docs/screenshots/dashboard-light.png) |

## Configuration

KeySentry reads `config.toml`, then optional `config.local.toml` (gitignored), then environment variables for secrets. Safe defaults work out of the box:

```toml
[server]
host = "127.0.0.1"
port = 8710

[scan]
entropy_threshold = 4.5
fail_on = "high"          # gate/strict threshold: critical | high | medium | low | info

[alerting]
channels = ["console", "outbox"]   # add "slack" or "webhook" when configured
slack_webhook = ""
webhook_url = ""

[ai]
enabled = false
base_url = "https://api.openai.com/v1"   # any OpenAI-compatible endpoint
model = "gpt-4o-mini"
api_key_env = "KEYSENTRY_AI_KEY"
```

See [docs/AI_TRIAGE.md](docs/AI_TRIAGE.md), [docs/SURFACES.md](docs/SURFACES.md), and [docs/PRIVACY.md](docs/PRIVACY.md) for the full picture.

## Project layout

```text
KeySentry/
├── run.py                  # entry point (no args = serve)
├── run.bat / run.sh        # one-click launchers (Windows / Linux+macOS)
├── config.toml             # safe defaults; override in config.local.toml
├── pyproject.toml          # packaging; zero required dependencies
├── Makefile                # serve scan demo test selftest hooks report
├── assets/logo.svg
├── hooks/                  # pre-commit and pre-push hook scripts
├── keysentry/
│   ├── cli.py              # command line
│   ├── config.py           # layered config loading
│   ├── server.py           # stdlib HTTP server: dashboard + JSON API
│   ├── watch.py            # polling filesystem watcher
│   ├── demo.py             # synthetic demo seeding
│   ├── core/               # models, engine, pipeline, storage, allowlist, entropy, util
│   ├── detectors/          # shared registry: cloud, saas, crypto, generic
│   ├── surfaces/           # filesystem, git, ide, slack, confluence, jira, postman, cloud
│   ├── alerting/           # channel router with dedupe and dry-run
│   ├── remediation/        # playbooks: rotate-guide, redact, quarantine, ticket
│   ├── ai/                 # GPT client, prompts, heuristic triage
│   └── dashboard/          # static dashboard (dark + light themes)
├── examples/               # synthetic fixtures for ingest and demos
├── docs/                   # architecture, install, detectors, surfaces, API, privacy
└── data/                   # runtime state (gitignored): SQLite DB, outbox, quarantine
```

## Privacy

Raw secrets are never stored or transmitted by default. Findings keep only a masked preview (first/last four characters) and a SHA-256 fingerprint. Network activity happens only when you explicitly configure it: alert webhooks, live SaaS reads, Jira ticket creation, and optional GPT triage (masked values only). Details: [docs/PRIVACY.md](docs/PRIVACY.md).

## Documentation

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