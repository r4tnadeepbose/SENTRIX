# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

**Report privately.** Do not open public issues, pull requests, or discussions for suspected vulnerabilities.

1. Use the repository's **private vulnerability reporting** channel (GitHub: *Security → Report a vulnerability*) to contact the maintainers directly.
2. Include: affected version, component (detector, surface, server, pipeline), reproduction steps using **synthetic values only**, impact assessment, and any suggested fix.
3. You will receive an acknowledgment as soon as practical. Coordination happens privately; credit is given in the release notes unless you prefer otherwise.

Please allow maintainers reasonable time to remediate before any public disclosure.

## Scope notes

- The dashboard/API server binds to `127.0.0.1` by default and has **no authentication**. Exposing it beyond loopback (changing `server.host`, port forwarding, reverse proxies) is an operator decision and outside the supported threat model.
- KeySentry detects and helps remediate exposures; it does not revoke credentials at providers. Rotation remains the operator's responsibility.
- Git hooks fail open when the KeySentry installation cannot be found, by design; a missing install never blocks commits or pushes.

## Handling secrets in this repository

- **Never commit real secrets** — not in code, fixtures, tests, docs, screenshots, issue reports, or commit history. If a real credential is ever committed, treat it as compromised: rotate it immediately at the provider, then remove it from history.
- **All fixtures are synthetic.** Everything under `examples/`, the demo seeder, and test material uses invented values that match credential formats but grant no access. Keep new fixtures obviously fake (placeholder markers are recognized by the built-in allowlist).
- Runtime state lives in the gitignored `data/` directory (SQLite database, outbox, quarantine, remediation guides). Never commit it. Quarantined files still contain original secrets — handle that directory as sensitive.
- Tokens and API keys belong in environment variables (`KEYSENTRY_*`), never in `config.toml`. `config.local.toml` and `.env*` files are gitignored.
- Findings store only masked previews and SHA-256 fingerprints; raw secret values must never be persisted, logged, or transmitted. Changes that would weaken this invariant will be rejected.

## Safe testing guidance

When verifying detection behavior, use the built-in resources:

```sh
python run.py selftest    # internal checks with synthetic values
python run.py demo        # synthetic findings across all surfaces
python run.py scan examples/ --no-store
```

Do not test with live credentials, even your own.