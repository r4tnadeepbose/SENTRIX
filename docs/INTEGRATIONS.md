# SENTRIX Connect — Integrations

SENTRIX Connect is the integrations hub: one registry (`sentrix/core/integrations.py`) describing nine providers, their connection state, required permissions, rate limits and related findings. The hub is deliberately honest — it never claims a live connection that does not exist, and it never contacts a provider just to render a status card.

## The nine providers

| ID | Name | Surface | Declared permissions | Rate limit | Data path |
| --- | --- | --- | --- | --- | --- |
| `github` | GitHub | git | `repo:read`, `pull_request:read` | 60 req/min | CI gates, git hooks, repository exports |
| `gitlab` | GitLab | git | `read_api`, `read_repository` | 60 req/min | CI gates (`ci/gitlab-ci.yml`), hooks, exports |
| `bitbucket` | Bitbucket | git | `repository:read` | 60 req/min | Hooks and exports; no live API connector |
| `jenkins` | Jenkins | ci | `job:read`, `build:read` | 30 req/min | Pipeline gate (`ci/Jenkinsfile`), build diffs |
| `aws` | AWS | cloud | `lambda:ListFunctions`, `lambda:GetFunctionConfiguration` | SDK default | Optional live Lambda scan (boto3) or exported artifacts |
| `slack` | Slack | slack | `channels:history`, `channels:read` | 50 req/min | Live REST polling or export JSON |
| `jira` | Jira | jira | `read:jira-work`, `write:jira-work` | 60 req/min | Live JQL polling + ticket creation, or issue export |
| `confluence` | Confluence | confluence | `read:confluence-content` | 60 req/min | Live REST polling or page export |
| `postman` | Postman | postman | `collections:read`, `environments:read` | 30 req/min | Export-based only (collection/environment JSON) |

Permissions and rate limits are the declared contract shown in the hub; the live adapters implement conservative pacing (a 0.25 s pause between pages/requests via `surfaces/common.rate_limit`) and pagination caps well inside those limits.

## Honest status model

`GET /api/integrations` computes each provider's state from configuration and mode — nothing else:

| Status | Meaning | When |
| --- | --- | --- |
| `connected` | Credentials/configuration are present; live ingestion is possible | AWS: `surfaces.cloud.provider = "aws"`. Slack/Jira/Confluence: token env var set **or** `base_url` configured. Postman: API key env var set or base URL configured |
| `demo` | Synthetic connector — no live credentials; findings come from the demo seeder or exports | `auth.demo_mode = true` and the provider is not configured |
| `disconnected` | Authentication required; no data path is active | Not configured and demo mode off |

Important honesty notes:

- `connected` means **configuration present**, not a verified handshake. The hub does not call provider APIs to test credentials.
- GitHub, GitLab, Bitbucket and Jenkins have **no live connector** in this release: their `_configured` check is always false, so they show `demo` (demo mode) or `disconnected`. Their real coverage runs through git hooks, CI diff gates and exports — which work regardless of the hub card's state.
- Each card carries `auth` (a human-readable explanation), `last_sync`/`last_scan` (timestamp of the most recent event for that surface), `resources` (up to 12 location prefixes), `findings` count and recent integration `errors` from the system log.

## Live-capable vs export-based

### Live-capable (with credentials)

- **Slack** — `surfaces/slack.py::live_scan`: bearer token from `SENTRIX_SLACK_TOKEN`, iterates `surfaces.slack.channels`, pages `conversations.history` (200/page, cursor pagination), owner = message user. Run via `python run.py ingest --surface slack`.
- **Jira** — `surfaces/jira.py::live_scan`: `base_url` + `SENTRIX_JIRA_TOKEN`, JQL `updated>=-1d`, pages of 50. Also `create_security_ticket` posts a Task to the configured project (default `SEC`) for the `ticket`/auto-ticket actions. Run via `ingest --surface jira`.
- **Confluence** — `surfaces/confluence.py::live_scan`: `base_url` + `SENTRIX_CONFLUENCE_TOKEN`, pages `/rest/api/content` (50/page) with storage bodies stripped of HTML. Run via `ingest --surface confluence`.
- **AWS** — `surfaces/cloud.py::live_scan`: activates only when `provider = "aws"`, `boto3` is installed and ambient AWS credentials exist; paginates `list_functions` and scans each function's environment variables. Missing boto3 or credentials degrades silently to the local artifact scan — deploys are never blocked.

### Export-based

- **Postman** — collection and environment JSON exports only (`scan_collection`, `scan_environment`); walks every string value (8+ chars) with its JSON path. No live API calls.
- **Slack / Jira / Confluence** — all three also accept exports (`scan_export`) so air-gapped or consent-limited teams can scan without tokens. Example fixtures ship in `examples/slack`, `examples/jira`, `examples/confluence`, `examples/postman`.
- **AWS local mode** (default) — scans exported function artifacts: `*/config.json` environment variables plus `.py`/`.js` code under `surfaces.cloud.lambda_dir` (default `examples/lambda`).
- **GitHub / GitLab / Bitbucket / Jenkins** — repository content reaches the engine through `gate` (diff-only), hooks, scheduled tree scans of checkouts, or `scan` on an exported/cloned tree.

## Sync semantics

- `POST /api/integrations/{pid}/sync` records an `integration.sync` event plus a structured log entry (`component=integrations`, `event_type=sync`, `exec_id=sync-<pid>`, `status=requested`) and returns `{"ok": true, "status": "sync-recorded"}`. **It does not fetch provider data.** Actual ingestion happens through `sentrix ingest`, hooks, CI, jobs and schedules; the recorded sync gives the hub a visible, auditable request trail and updates `last_sync` via the event feed.
- `POST /api/integrations/{pid}/disconnect` and `/toggle` maintain an in-memory disabled set and write audit rows (`integration.disconnect` / `integration.toggle`). Live polling itself is driven by configuration and CLI invocation, so removing credentials/base URLs in config is the durable way to stop a connector.
- Findings from every path flow through the same `Pipeline.ingest`: provenance records the surface and event kind, SaaS findings pass the confirm/ignore triage branch (unconfirmed SaaS matches are marked `false_positive` and logged for audit rather than alerted), and dedupe prevents repeat alerts.

## Configuration and credentials

Tokens are read **only from environment variables** named by config — never stored in the database or config files:

| Provider | Config keys | Environment variable |
| --- | --- | --- |
| Slack | `surfaces.slack.token_env`, `channels`, `poll_seconds` | `SENTRIX_SLACK_TOKEN` |
| Jira | `surfaces.jira.base_url`, `token_env`, `project` | `SENTRIX_JIRA_TOKEN` |
| Confluence | `surfaces.confluence.base_url`, `token_env` | `SENTRIX_CONFLUENCE_TOKEN` |
| Postman | `surfaces.postman.api_key_env`, `workspaces` | `SENTRIX_POSTMAN_KEY` |
| AWS | `surfaces.cloud.provider`, `lambda_dir` | Standard AWS credential chain (boto3) |

`poll_seconds` documents the intended polling cadence; scheduling live polls is done with SENTRIX schedules/jobs or an external cron invoking `sentrix ingest` — the server does not itself run a SaaS polling daemon.

## Privacy and consent

- **Least privilege:** request only the read scopes listed above (plus Jira write for ticketing). Use dedicated service accounts/bot users, not personal admin tokens.
- **Consent before polling:** only configure channels, spaces and projects your organization is authorized to monitor. Export mode exists precisely for situations where live access is not approved.
- **Data minimization:** ingestion stores masked previews and fingerprints only; raw message bodies, page content and environment values are never persisted. Owner attribution (Slack user id, Jira reporter, commit author) is kept for routing and accountability.
- **No secret egress:** detected values are never sent back to providers for validation, and never leave the machine except masked content in configured alert channels and optional triage (see [SECURITY.md](SECURITY.md)).
- **Outbound calls are explicit:** live scans, Jira tickets and webhook alerts are the only provider-facing requests, each triggered by operator configuration or an operator action, with timeouts and bounded retries.