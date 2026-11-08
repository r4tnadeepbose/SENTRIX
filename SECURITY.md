# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.1.x | Yes |
| 1.0.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

**Report privately.** Do not open public issues, pull requests, or discussions for suspected vulnerabilities.

1. Use the repository's **private vulnerability reporting** channel (*Security → Report a vulnerability*) to contact the maintainers directly.
2. Include: affected version, component (detector, surface, server, auth, pipeline), reproduction steps using **synthetic values only**, impact assessment, and any suggested fix.
3. You will receive an acknowledgment as soon as practical. Coordination happens privately; credit is given in the release notes unless you prefer otherwise.

Please allow maintainers reasonable time to remediate before any public disclosure.

## Authentication model (v1.1)

The dashboard and JSON API require authentication on every non-public route. Public routes are limited to the login page, static assets, the favicon/logo, and `GET /api/health`.

- **Roles.** Three roles are enforced server-side on every request: `admin` (full access including users, tokens, restore, import, retention purge), `analyst` (all detection and operations work except the admin-only routes), `viewer` (read-only; mutations return `403` except logout and own password change).
- **Passwords.** PBKDF2-HMAC-SHA256 with 200,000 iterations and a random per-user salt; verification uses constant-time comparison. New and changed passwords must be at least 10 characters. Password hashes and salts are never returned by any API.
- **Initial admin.** On first run an `admin` account is bootstrapped from `SENTRIX_ADMIN_PASSWORD` (preferred) or a random value, written to `data/INITIAL_ADMIN_PASSWORD.txt`. Change the password after first login and remove or protect the plaintext file. The file is only created when no users exist.
- **Account lifecycle.** Admins can disable accounts; disabled users are rejected on every request, including existing sessions. Disabling your own account is blocked.

## Session and token handling

- **Sessions.** Successful login issues a cryptographically random token stored in the `sessions` table and delivered as a `sx_session` cookie with `HttpOnly`, `Path=/`, `SameSite=Strict`, and a `Max-Age` matching `auth.session_hours` (default 12). Expiry and account status are re-checked on every request; expired rows are purged at login. Logout deletes the session server-side.
- **API tokens.** Admin-created `sxt_...` tokens carry a name and a role. Only the SHA-256 hash is stored; the raw value is returned exactly once at creation. Tokens authenticate via `Authorization: Bearer sxt_...`, are checked for revocation on every request, and can be revoked instantly. Treat tokens like passwords: environment variables or CI secret stores, never config files or commits.
- **Transport.** The server binds to `127.0.0.1` by default and speaks plain HTTP for loopback use. If you expose it beyond loopback, terminate TLS at a reverse proxy and keep the `SameSite=Strict` cookie behavior in mind; exposing the server is an operator decision outside the default threat model.

## Rate limits

- **Login attempts** are limited per client IP: default 5 attempts per rolling 60-second window (`auth.login_rate_limit`). Exceeding the limit returns an error and writes a `warn` system-log entry; failed logins are audited (`login.failed`).
- **Alert delivery** retries failed webhook posts at most three times with 1s/2s backoff and a 10-second timeout, and dedupes per finding within `alerting.dedupe_window_seconds` (default 3600) to prevent notification storms.
- **Scan jobs** are capped at two concurrent runs; live SaaS adapters apply their own rate-limit helpers.

## Response headers

Every HTTP response carries:

| Header | Value | Purpose |
| --- | --- | --- |
| `Cache-Control` | `no-store` | Sensitive responses never linger in browser or proxy caches |
| `X-Content-Type-Options` | `nosniff` | Blocks MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Blocks framing/clickjacking |
| `Referrer-Policy` | `no-referrer` | Paths and query strings never leak via referrers |

The login response additionally sets the session cookie with `HttpOnly` and `SameSite=Strict`, which together mitigate script access and cross-site request forgery (all mutations are JSON POSTs).

## Audit and logging

Security-relevant actions are written to an append-only `audit` table: logins (success and failure), logout, password changes, user creation/role changes/disable, token creation/revocation, bulk finding actions, ops actions (backup/restore/purge/import), and detector tuning. Operational events go to `system_log`, including every mutation request (actor + path). Both are reviewable in the dashboard and via `GET /api/audit` / `GET /api/logs`. Logs contain masked values only.

## Scope notes

- SENTRIX detects and helps remediate exposures; it does not revoke credentials at providers. Rotation remains the operator's responsibility.
- Git hooks fail open when the SENTRIX installation cannot be found, by design; a missing install never blocks commits or pushes. Hooks and CLI commands run locally with the invoking user's permissions and do not use the server's auth layer.
- Quarantined files still contain original secrets — handle `data/quarantine` as sensitive.

## Handling secrets in this repository

- **Never commit real secrets** — not in code, fixtures, tests, docs, screenshots, issue reports, or commit history. If a real credential is ever committed, treat it as compromised: rotate it immediately at the provider, then remove it from history.
- **All fixtures are synthetic.** Everything under `examples/`, the demo seeder, and test material uses invented values that match credential formats but grant no access. Keep new fixtures obviously fake (placeholder markers are recognized by the built-in allowlist).
- Runtime state lives in the gitignored `data/` directory (SQLite database, outbox, quarantine, backups, remediation guides, and the first-run `INITIAL_ADMIN_PASSWORD.txt`). Never commit it. The database holds password hashes, session tokens, and token hashes — protect it like a credential store.
- Tokens and API keys belong in environment variables (`SENTRIX_*`), never in `config.toml`. `config.local.toml` and `.env*` files are gitignored.
- Findings store only masked previews and SHA-256 fingerprints; raw secret values must never be persisted, logged, or transmitted. Changes that would weaken this invariant will be rejected.

## Safe testing guidance

When verifying detection behavior, use the built-in resources:

```sh
python run.py selftest    # internal checks with synthetic values
python run.py demo        # synthetic findings across all surfaces
python run.py scan examples/ --no-store
```

Do not test with live credentials, even your own.