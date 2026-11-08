# Privacy

SENTRIX is designed so that using it never creates a second exposure. This page states exactly what stays on your machine, what is stored, and what can leave — and under whose control.

## Local-only layers

- **IDE on-save** (`ingest --surface ide`, `watch`): reads local files, scans in memory, writes only to the local SQLite database and outbox. No network calls.
- **Git hooks** (pre-commit / pre-push): run `gate` locally against your diffs. Nothing is transmitted; a missing SENTRIX install fails open rather than calling home.
- **Filesystem scans and exports**: `scan`, and `ingest --file ...` for Slack/Confluence/Jira/Postman/Lambda exports, are fully offline.
- **Dashboard**: binds to `127.0.0.1:8710` by default with no authentication and no telemetry. It is reachable only from your machine unless you deliberately change `server.host`.

## Raw secrets are never stored

The raw value exists only in memory during scanning. What is persisted, displayed, alerted, and ticketed:

- **Masked preview** (`secret_masked`): first four and last four characters for values longer than 8 characters; shorter values keep only a two-character prefix. Enough to recognize a credential, never enough to use it.
- **SHA-256 fingerprint**: `SHA-256(detector_id + "|" + value)`, used for dedupe and allowlisting. It is one-way; the secret cannot be recovered from it.
- **Context metadata**: file path or source location, line number, surface, owner (e.g. message author), entropy score.

The database (`data/sentrix.db`), outbox alerts, quarantine copies, and remediation guides therefore contain no usable credentials. Note that **quarantine moves the original file** — the moved file itself still contains the secret, so treat `data/quarantine` as sensitive and rotate the credential regardless.

## What leaves the machine — only when you configure it

| Feature | Trigger | What is sent |
| --- | --- | --- |
| Slack webhook alerts | `alerting.channels` includes `slack` and `slack_webhook` is set | Alert text: severity, title, surface, location, **masked** value |
| Generic webhook alerts | `alerting.channels` includes `webhook` and `webhook_url` is set | Finding object (masked value, fingerprint, metadata) plus message |
| GPT triage | `[ai].enabled = true` and `SENTRIX_AI_KEY` set | Detector id, title, severity, surface, path, line, **masked** value, entropy — never the raw secret |
| Live SaaS reads | Tokens + channels/base URLs configured | Outbound API reads to Slack/Confluence/Jira; content is scanned locally and only masked findings are stored |
| Jira ticket creation | `ticket` action with Jira configured | Summary, severity, masked value, rotation guidance |
| Live AWS scanning | `provider = "aws"` with boto3 + credentials | Read-only Lambda API calls |

Unconfigured channels never transmit: webhook alerts record `dry-run`, live surfaces return nothing, ticketing writes a local outbox draft, and triage uses the offline heuristic. There is no telemetry, update check, or analytics of any kind.

## Consent for private Slack channels

Live Slack scanning reads only the channel IDs you explicitly list in `[surfaces.slack].channels`. Before adding a **private** channel:

1. Obtain consent from the channel owner and workspace admin — monitoring private conversations is a policy decision, not a technical one.
2. Prefer export-mode scanning of specifically shared incidents over broad live reads when possible.
3. Remember that findings record the message author as `owner`; restrict dashboard/database access accordingly.

The same principle applies to Confluence spaces and Jira projects: scope tokens to the minimum content you are authorized to monitor.

## Operator responsibilities

- Keep `data/` (database, outbox, quarantine, remediation guides) access-controlled; it is gitignored by default.
- Keep tokens in environment variables, never in `config.toml` or commits; `config.local.toml` and `.env*` are gitignored.
- Rotate any credential that was exposed beyond your machine, even after redaction.
- Review `GET /api/config` output before sharing screenshots — it shows configuration, though never secret values.