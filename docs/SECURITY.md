# SENTRIX Security

This document describes the security model as implemented, the guarantees SENTRIX makes, and the operator responsibilities that remain. For reporting vulnerabilities, see [Responsible disclosure](#responsible-disclosure) at the end.

## Authentication model

### Passwords

- PBKDF2-HMAC-SHA256 with **200,000 iterations** and a random 16-byte hex salt per user (`sentrix/auth.py`).
- Verification uses constant-time comparison (`hmac.compare_digest`).
- New and changed passwords must be at least **10 characters**; changing requires the current password.
- Hashes and salts are never returned by any API (`GET /api/users` projects username, role, title, disabled, created_at only).

### Initial admin and demo roster

- On first run (no users), an `admin` account with role `super_admin` is created from `SENTRIX_ADMIN_PASSWORD` when set; otherwise from the demo password in demo mode, or a random value. When the password was generated (env var unset), it is written to `data/INITIAL_ADMIN_PASSWORD.txt` — change it after first login and protect or delete the file.
- In `auth.demo_mode`, five team accounts are seeded (`r.sharma`, `p.patel`, `a.kumar`, `n.singh`, `v.iyer`) with `<username>-demo` passwords. The login page roster (`GET /api/auth/demo-info`) is served **only** when demo mode is on, the server binds to `127.0.0.1`/`localhost`, and the account's password is still the unchanged demo default. Production mode (`auth.demo_mode = false`) seeds no demo accounts and exposes no credentials.

### Sessions

- Successful login issues a 24-byte random hex token stored in `sessions` and delivered as cookie `sx_session` with `HttpOnly; Path=/; SameSite=Strict` and `Max-Age = auth.session_hours * 3600` (default 12 h).
- `remember: true` extends the **server-side session expiry to 30 days** (`24 * 30` hours); the cookie Max-Age still follows `auth.session_hours`.
- Expiry, account existence and disabled state are re-checked on every request; expired rows are purged at login. Logout deletes the session server-side.

### Login rate limiting

- Per client IP, rolling 60-second window, default **5 failed attempts** (`auth.login_rate_limit`). Only failures count — successful logins never consume the budget, so switching between demo accounts is not blocked.
- Exceeding the limit returns `400 "Too many failed attempts; wait a minute."`, writes a `warn` system log and audits nothing further; each failure is audited as `login.failed`.

### CSRF / origin protection

- Cookie-authenticated POSTs carrying an `Origin` header are rejected with `403` unless the origin's host equals the request `Host`. Bearer-token requests are exempt (they are not ambient credentials).
- Combined with `SameSite=Strict` cookies and JSON-only mutation bodies, cross-site form posts cannot ride a session.

### API tokens

- Created by admin roles: `sxt_` + 20 random bytes hex. Only the **SHA-256 hash** is stored; the raw value is returned exactly once.
- `Authorization: Bearer sxt_...` authenticates as `token:<name>` with the token's role; revocation is checked on every request and takes effect immediately.
- Treat tokens like passwords: environment variables or CI secret stores, never config files or commits.

## RBAC matrix

Eight roles; enforcement happens server-side on every request (`Handler._authorized`), independent of what the UI shows.

| Capability | super_admin | security_admin | security_analyst | appsec_engineer | devsecops_engineer | developer | auditor | viewer |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Read all non-admin API routes | yes | yes | yes | yes | yes | yes | yes | yes |
| Mutations (findings, scans, jobs, rules, remediation, reports, tuning, backup, vacuum) | yes | yes | yes | yes | yes | no | no | no |
| Logout / own password change | yes | yes | yes | yes | yes | yes | yes | yes |
| User management (`/api/users*`) | yes | yes | no | no | no | no | no | no |
| Token management (`/api/tokens*`) | yes | yes | no | no | no | no | no | no |
| Restore / import / retention purge | yes | yes | no | no | no | no | no | no |

- Write attempts by read-only roles return `403 {"error": "role is read-only"}`; admin-prefix access by non-admins returns `403 {"error": "security administrator role required"}`.
- Accounts can be disabled (not by yourself); disabled users are rejected on every request including existing sessions.
- Legacy roles migrate automatically: `admin` -> `super_admin`, `analyst` -> `security_analyst`.

## Secret handling: masking and fingerprints

- **Raw secrets are never stored, logged, alerted, exported or transmitted.** The scanner keeps only a masked preview (`first4 + ******** + last4`, or `first2 + ***` for short values) and a SHA-256 fingerprint of `detector_id|secret`.
- Dedupe, allowlisting and cross-surface correlation use the fingerprint; the raw value exists only in memory during the scan.
- Optional GPT triage receives masked values and metadata only (`sentrix/ai/prompts.py`); the deterministic heuristic runs fully offline.
- Alert messages embed the masked value, never the secret.
- **Exception:** remediation actions that touch source files (`redact`, `quarantine`) necessarily read the original file, and quarantined files in `data/quarantine` still contain the original secrets — handle that directory as sensitive.

## Egress and SSRF policy

- **No automatic external credential validation.** SENTRIX never sends a detected value to its provider (or anywhere else) to test whether it is live. `format_validated` is a structural check; risk scores carry `confirmed_validity: false`.
- The server performs **no outbound requests on behalf of API input**: there is no fetch-by-URL endpoint, no URL-import feature, and scan paths are local filesystem paths. This removes the classic SSRF surface.
- Outbound traffic exists only where an operator explicitly configures it:
  - **Webhook / Slack alerts** — operator-set URLs in config (`alerting.webhook_url`, `alerting.slack_webhook`), POST JSON, 10-second timeout, at most three attempts (0/1/2 s backoff). Unconfigured URLs produce `dry-run` alerts, not requests.
  - **Live SaaS/AWS connectors** — operator-set base URLs and tokens; bounded pagination and pacing; 15-second REST timeouts.
  - **Jira ticket creation** — operator-set base URL/token; 15-second timeout; failure falls back to an outbox draft.
  - **Optional GPT triage** — operator-set `ai.base_url` with an API key from the environment; 30-second timeout; any failure falls back to the heuristic.
- Restrict egress at the host/network level if your policy requires it; SENTRIX works fully offline with channels `console` + `outbox`.

## Webhook handling

- Payloads: generic webhook receives `{"finding": <finding dict>, "message": ...}`; Slack receives `{"text": ...}` with an owner mention (`<@U...>` for Slack user ids, `cc @name` otherwise). All content is masked.
- Delivery results are persisted per alert: `sent`, `http-<code>`, `failed: <reason>`, `deferred-quiet-hours`, `dry-run`.
- Quiet hours (UTC, wrap-around supported) defer network channels only; console/outbox always record. Dedupe window (default 3600 s) and per-finding mute prevent storms.
- Treat webhook URLs as secrets: they grant posting access to your channels. Keep them in `config.local.toml` (gitignored) or environment-backed deployment config.

## Transport and response headers

- Default bind is `127.0.0.1:8710`, plain HTTP for loopback use. Exposing beyond loopback is an operator decision: terminate TLS at a reverse proxy, keep `SameSite=Strict` in mind, and disable demo mode first.
- Every response carries `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- Static serving is whitelisted (`index.html`, `app.js`, `styles.css`, `login.html`); no directory traversal or arbitrary file reads.

## Audit and logging

- Append-only `audit` table: login success/failure, logout, password changes, user creation/role/disable, token creation/revocation, bulk actions, ops (backup/restore/purge/import), detector tuning, exceptions, integration controls.
- `system_log` records operational events with structured fields (`component`, `event_type`, `exec_id`, `resource`, `status`, `correlation_id`); every mutation request logs actor + path. Both are reviewable in the console and via API, and exportable as CSV.
- `GET /api/config` returns the effective configuration to any authenticated user — keep webhook URLs and similar values out of shared configs if that is a concern in your deployment.

## Hardening checklist

1. Set `auth.demo_mode = false` (production mode) before any non-loopback exposure; verify the login roster is gone.
2. Set `SENTRIX_ADMIN_PASSWORD` for scripted installs; otherwise change the generated admin password immediately and delete `data/INITIAL_ADMIN_PASSWORD.txt`.
3. Change all demo team passwords or remove the accounts; disable unused accounts.
4. Keep the bind address on loopback or behind an authenticating TLS reverse proxy.
5. Issue least-privilege, named API tokens per pipeline; revoke retired ones; never commit tokens.
6. Store connector tokens only in environment variables; grant read-only scopes (Jira write only if ticketing is used).
7. Protect `data/` like a credential store: it holds password hashes, sessions, token hashes, and quarantined originals. Restrict filesystem permissions and backup access.
8. Configure retention purge + vacuum on a schedule; export audit/log evidence before purging if required.
9. Review `audit` and `system_log` (level `warn`/`error`) regularly; wire `/api/system/health` and `/api/metrics` into monitoring.
10. Run `python run.py selftest` and the unit suite after upgrades; verify migrations applied (`migrations` table).

## Scope notes

- SENTRIX detects and helps remediate exposures; it does not revoke credentials at providers. Rotation remains the operator's responsibility, and verification is an explicit rescan — never an auto-close on disappearance.
- Git hooks fail open when the SENTRIX installation cannot be found, by design; a missing install never blocks commits or pushes. Hooks and CLI run with the invoking user's permissions, outside the server's auth layer.
- The login rate limit is per-process memory; it resets on restart and is per-IP behind no proxy awareness — put a rate-limiting proxy in front for internet-facing deployments.

## Responsible disclosure

**Report privately.** Do not open public issues, pull requests or discussions for suspected vulnerabilities.

1. Use the repository's private vulnerability reporting channel (Security -> Report a vulnerability) to contact the maintainers.
2. Include: affected version, component (detector, surface, server, auth, pipeline), reproduction steps using **synthetic values only**, impact assessment, and any suggested fix.
3. You will receive an acknowledgment as soon as practical; coordination happens privately and credit is given in release notes unless you prefer otherwise.

Allow maintainers reasonable time to remediate before public disclosure. Never test with live credentials, and never paste real secrets into reports — use masked or synthetic values.