# Remediation

Detection is only half the flow. Every finding can be triaged and then acted on through one of four actions, available identically from the dashboard, the CLI (`python run.py remediate ID --action ...`), and the API (`POST /api/remediate`). Each executed action is recorded in the `remediations` table and advances the finding's status.

**Rule of thumb: redaction removes the exposure, but only rotation neutralizes the credential.** Always rotate after any exposure outside a purely local, never-shared file.

## The four actions

| Action | What it does | Resulting status | Output |
| --- | --- | --- | --- |
| `rotate-guide` | Writes a family-specific markdown playbook for the finding | `triaged` | `data/remediation/<id>.md` |
| `redact` | Replaces the matched secret in-place with `<REDACTED:detector_id>` on the recorded line | `remediated` | Modified source file |
| `quarantine` | Moves the whole source file out of the tree | `remediated` | `data/quarantine/<id>-<filename>` |
| `ticket` | Creates a Jira security task when configured; otherwise writes a ticket draft | `triaged` | Jira issue, or `data/outbox/ticket-<id>.json` |

Behavior details:

- **rotate-guide** selects the playbook from the detector's `remediation` key (see below); unknown keys fall back to the generic rotation guide. The guide includes finding id, severity, surface, and location.
- **redact** re-applies the detector pattern to the recorded line. If the file is gone, the line no longer exists, or the pattern no longer matches, it reports that manual redaction and rotation are required instead of guessing.
- **quarantine** is the safe choice when a file is mostly secret material (key files, credential dumps) or the exposure cannot be surgically removed. The move is recorded with both source and destination paths.
- **ticket** uses `[surfaces.jira]` `base_url` + `SENTRIX_JIRA_TOKEN`; the ticket summary is `[SENTRIX] <title> in <path>`, priority follows severity, and the description carries the masked value and rotation guidance. Without Jira configuration, the draft lands in the outbox for manual filing — nothing is sent.

## Playbooks by family

Playbooks live in `sentrix/remediation/playbooks.py`. Summary of each:

| Playbook | Applies to | Core steps |
| --- | --- | --- |
| `rotate-aws` | AWS access key id / secret key | Deactivate the key in IAM; issue a replacement into a secrets manager; update all consumers (CI, Lambda env, local configs); review CloudTrail for the exposure window; purge git history with team consent |
| `rotate-gcp` | GCP API keys, service-account keys | Restrict/delete the exposed key; issue a least-privilege replacement; redeploy referencing workloads; audit Cloud Audit Logs |
| `rotate-azure` | Storage connection strings, AD client secrets | Regenerate the account key / rotate the client secret; move connection strings to Key Vault references; review sign-in and access logs |
| `rotate-github` | GitHub tokens | Revoke the token; issue a fine-grained replacement with minimal scopes; audit the audit log for exposure-window use |
| `rotate-gitlab` | GitLab personal access tokens | Revoke and replace with a scoped token; check audit events for anomalous API activity |
| `rotate-slack` | Slack tokens and webhooks | Revoke/regenerate in the app config; delete the exposing message and notify the channel owner; review app access logs |
| `rotate-stripe` | Stripe secret/restricted keys | Roll the key in the dashboard; update server-side consumers only (never ship secret keys to clients); review logs for unauthorized calls |
| `rotate-openai` | OpenAI API keys | Revoke and replace with spend limits; review usage dashboards for unexpected consumption |
| `rotate-db` | Database URIs with passwords | Rotate the password, update the secrets manager, restart dependent services, audit DB access logs |
| `rotate-keypair` | PEM private keys, OpenSSH key bodies | Generate a new keypair; revoke trust in the exposed public key; update `authorized_keys` / KMS / deployment targets; audit authentication logs |
| `rotate` (generic) | Everything else (SendGrid, Twilio, npm, PyPI, Mailchimp, JWTs, generic assignments, env secrets) | Revoke/rotate at the provider; store the replacement in a secrets manager, not code; remove the exposure from history, docs, and chat; verify with a fresh scan |

Detectors without a dedicated playbook (e.g. `sendgrid-key`, `twilio-key`, `npm-token`, `pypi-token`, `mailchimp-key`, `jwt`, `basic-auth-url`, generic detectors) use the generic `rotate` guide. JWTs deserve extra care: revoke the signing key or session if the token grants access, and check expiry.

## Status lifecycle

```text
open ── triage / rotate-guide / ticket ──> triaged ── redact / quarantine ──> remediated
  │                                          │
  └──── allowlist fingerprint ───────────────┴──────> false_positive
```

| Status | Meaning | How it is set |
| --- | --- | --- |
| `open` | New, unhandled finding | Default on first ingest |
| `triaged` | Reviewed; guidance or ticket issued, credential not yet neutralized | `triage` follow-up, `rotate-guide`, `ticket`, or manual status update |
| `remediated` | Exposure removed from the source | `redact`, `quarantine`, or manual update after rotation |
| `false_positive` | Confirmed non-secret; suppressed everywhere by fingerprint | Allowlist add (CLI, dashboard, or API) |

Notes:

- Re-detecting a known finding refreshes `updated_at` but never resets its status.
- Allowlisting marks all stored findings with that fingerprint `false_positive` and suppresses future detections on every layer.
- Status can also be set directly (`POST /api/findings/{id}/status`) to record out-of-band work, e.g. marking `remediated` after rotating at the provider.
- Recommended sequence for true positives: **triage → rotate at the provider → rotate-guide/ticket for tracking → redact or quarantine the source → verify with a fresh scan**.