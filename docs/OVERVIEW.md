# SENTRIX Overview

**Secret Exposure & Network Threat Response Intelligence eXchange**
One Intelligence. Every Exposure. Total Control.

SENTRIX is an enterprise security intelligence platform that finds exposed credentials wherever they appear, explains how they got there, prioritizes them with an explainable risk engine, and drives them through a complete response lifecycle to verified closure. It is a single Python 3.11+ application with zero required dependencies: one process serves the Command Center console, the JSON API, the detection engine, the alert router, the job scheduler and the SQLite store.

## Who it is for

- **Security / AppSec teams** that need one prioritized queue of credential exposure across code, cloud and collaboration tools.
- **DevSecOps / platform teams** that want blocking gates in git and CI plus scheduled and on-demand scanning.
- **SOC / incident responders** that need alert routing, escalation, investigation notes and remediation playbooks.
- **Compliance / audit functions** that need an audit trail, structured logs, reports and control-to-evidence mapping.

## The seven logical layers

Every capability belongs to exactly one logical layer. Layers communicate through the shared models in `sentrix/core/models.py` (`Finding`, `Event`, `Alert`, `Remediation`) and the pipeline, never through private shortcuts.

| # | Layer | Responsibility | Implementation |
| --- | --- | --- | --- |
| 1 | **Collection** | Capture text where secrets appear: editor saves, git diffs, CI ranges, filesystem trees, cloud function artifacts, SaaS exports and live polls | `sentrix/surfaces/*`, `sentrix/watch.py`, `hooks/`, `ci/`, `editors/vscode/` |
| 2 | **Ingestion** | Normalize everything into one flow: allowlist re-check, provenance stamping, risk scoring, dedupe upsert, event recording | `sentrix/core/pipeline.py` |
| 3 | **Intelligence Core** | Decide what is a secret and how much it matters: detector registry, entropy, validation heuristics, environment classification, fingerprinting, risk scoring, triage | `sentrix/detectors/*`, `sentrix/core/engine.py`, `entropy.py`, `risk.py`, `allowlist.py`, `sentrix/ai/*` |
| 4 | **Security Management** | Run the finding lifecycle: statuses, notes, tags, assignment, severity overrides, pin/mute, checklists, history, bulk actions, saved filters, exceptions | `sentrix/core/extensions.py`, finding endpoints in `sentrix/server.py` |
| 5 | **Response** | Notify and remediate: channel routing with rules/quiet hours/dedupe/retries, escalation, rotation playbooks, redact/quarantine/ticket/verify, SLA tracking | `sentrix/alerting/router.py`, `sentrix/remediation/playbooks.py` |
| 6 | **Control Plane** | Operate the platform: auth/RBAC, API, console, jobs, schedules, reports, integrations hub, logs/audit, backup/restore/purge, metrics | `sentrix/server.py`, `auth.py`, `cli.py`, `core/jobs.py`, `core/reports.py`, `core/integrations.py`, `dashboard/` |
| 7 | **Storage** | Persist everything in one SQLite file with thread-local connections and a global write lock; schema migrations and legacy compatibility | `sentrix/core/storage.py`, `sentrix/core/extensions.py` |

## Module map

| Module | Sub-brand | Responsibilities |
| --- | --- | --- |
| `sentrix/server.py` | Command Center | Stdlib `ThreadingHTTPServer`; authenticated JSON API; static console; request authorization (session or Bearer), role gates, origin check; aggregates posture/intelligence/compliance views from live storage |
| `sentrix/dashboard/` | Command Center | Hash-routed SPA: 27 views in six groups, finding drawer, bulk bar, command palette, help popovers, dark/light themes |
| `sentrix/auth.py` | Command Center | PBKDF2 passwords, sessions, remember-me, login rate limiting, eight-role RBAC, hashed API tokens, audit helper, demo roster (local-only) |
| `sentrix/core/engine.py` | Intelligence Core | One scan path for text/file/tree; keyword prefilter, regex match, extraction, validation, allowlist, masking, fingerprint, entropy, confidence, environment |
| `sentrix/detectors/` | Intelligence Core | 26 registered detectors in cloud, crypto, saas, ai and generic families; custom family for user rules |
| `sentrix/core/risk.py` | Intelligence Core | Explainable 0-100 score: severity, category, surface exposure, confidence, validation, environment, age, repetition |
| `sentrix/ai/` | Intelligence Core | Deterministic heuristic triage; optional GPT-compatible triage carrying masked values only |
| `sentrix/core/pipeline.py` | Intelligence Core | Ingest: allowlist, provenance, risk, upsert/dedupe, event record, SaaS confirm/ignore branch, alert trigger, auto-ticket |
| `sentrix/surfaces/` | Connect | Adapters: ide, git (diff-only), filesystem, cloud (local artifacts or live AWS), slack/confluence/jira (export + live REST), postman (export) |
| `sentrix/core/integrations.py` | Connect | Nine-provider registry with honest `connected`/`demo`/`disconnected` states, permissions, rate limits, related findings |
| `sentrix/core/extensions.py` | Exposure Center | Management tables and operations: finding extras, history, notes, checklists, filters, jobs, schedules, rules, reports, custom rules, migrations, backup/purge |
| `sentrix/alerting/router.py` | Response | Channels (console, outbox, slack, webhook), per-channel severity rules, quiet hours, dedupe window, mute, retry backoff, Slack owner mention |
| `sentrix/remediation/playbooks.py` | Response | Eleven rotation playbooks; rotate-guide, preview-redact, redact, quarantine, restore, ticket, verify; auto-ticket |
| `sentrix/core/jobs.py` | Response / Control Plane | Background scans with incremental cache, two-slot semaphore, cooperative cancel; scheduler loop (schedules, escalation, triage sweep) |
| `sentrix/core/reports.py` | Command Center | Eleven report types, CSV/JSON generation from live storage, persisted report history |
| `sentrix/core/storage.py` | Storage | Core tables, thread-local SQLite connections, write lock, dedupe upsert, stats |
| `sentrix/cli.py`, `config.py`, `demo.py`, `watch.py` | Control Plane | CLI for every layer; layered config; synthetic seeding; polling watcher |

## Event lifecycle

```text
surface event (save / hook / CI diff / schedule / export / poll / API)
        |
        v
Collection adapter extracts text or diff lines
        |
        v
Intelligence Core: engine.scan_text / scan_file / scan_tree
  detectors -> entropy -> validation -> allowlist -> mask + fingerprint
        |
        v
Pipeline.ingest: provenance + risk score -> dedupe upsert
  new finding  -> Event recorded -> SaaS confirm/ignore branch -> AlertRouter
  known finding-> occurrence counter + last_seen bumped (no alert storm)
        |
        v
AlertRouter: rules -> quiet hours -> dedupe window -> channel delivery
  (console / outbox / slack / webhook; auto-ticket at critical when enabled)
        |
        v
Security Management: triage -> assign -> investigate -> checklist
        |
        v
Response: rotate-guide / redact / quarantine / ticket -> verify rescan
        |
        v
Closure: remediated -> verified -> closed (human-confirmed, never automatic)
```

Every stage writes a `system_log` entry; security-relevant actions additionally write the `audit` table. Both are visible live in the console Logs view and exportable.

## Design principles

1. **One intelligence, many surfaces.** Detection logic lives only in the engine and detector registry. Surfaces extract text; they never decide what a secret is.
2. **Raw secrets never persist.** Storage, logs, alerts, exports and AI prompts carry masked previews and SHA-256 fingerprints only.
3. **Honest states.** Integrations report `demo` when no credentials exist; risk scores never claim provider-confirmed validity; compliance mapping is evidence, not certification.
4. **Explainability.** Every risk score lists its factors; every finding carries provenance ("how did that get there?"); every status change records actor and time.
5. **Offline-first, stdlib-only.** Everything works with no network and no dependencies. Live connectors and GPT triage are opt-in enhancements that degrade gracefully.
6. **Never auto-close on disappearance.** A secret vanishing from a file is not proof of rotation. Verification is an explicit rescan action; `verified` and `closed` are human decisions.
7. **Safe defaults.** Loopback binding, demo credentials confined to loopback + demo mode, dry-run webhooks when unconfigured, hooks fail open when the installation is missing.

## Current capability honesty

What is live, what is export-based, and what is optional — stated plainly:

| Capability | Status |
| --- | --- |
| Detection engine, dedupe, allowlist, risk scoring, lifecycle, jobs, schedules, alerting, reports, logs/audit, backup/restore | **Live** in every installation, fully offline |
| Console, JSON API, auth/RBAC, tokens | **Live** (stdlib HTTP server) |
| Slack, Jira, Confluence scanning | **Live-capable**: REST polling when base URL/token are configured; otherwise **export-based** (JSON exports scanned locally) |
| Jira ticket creation | **Live-capable** with credentials; otherwise an outbox draft file |
| AWS Lambda scanning | **Optional live** mode requires `surfaces.cloud.provider = "aws"`, installed `boto3` and ambient AWS credentials; default is **export-based** local artifacts (`examples/lambda` layout) |
| Postman scanning | **Export-based** only (collection/environment JSON); no live API connector |
| GitHub, GitLab, Bitbucket, Jenkins | **No live connector**: coverage through git hooks, CI diff gates and repository exports; the hub shows them honestly as `demo`/`disconnected` |
| Integration "Sync" button | Records a sync event and structured log entry (`sync-recorded`); it does not itself fetch provider data — ingestion runs through `sentrix ingest`, hooks, CI or schedules |
| GPT triage | **Optional** (`ai.enabled` + `SENTRIX_AI_KEY`); deterministic heuristic otherwise; masked values only |
| External credential validation | **Not performed**: SENTRIX never sends detected secrets to providers to test them; `format_validated` means provider-format checks, not live validity |
| PostgreSQL, OAuth connectors, MFA, PDF reports, distributed workers | **Not implemented** — see [ROADMAP.md](ROADMAP.md) |

## Where to go next

- Run it: [DEPLOYMENT.md](DEPLOYMENT.md)
- Use it: [USER_GUIDE.md](USER_GUIDE.md)
- Understand it: [ARCHITECTURE.md](ARCHITECTURE.md), [DATABASE.md](DATABASE.md), [DETECTION_ENGINE.md](DETECTION_ENGINE.md)
- Integrate it: [API.md](API.md), [INTEGRATIONS.md](INTEGRATIONS.md)
- Operate it: [OPERATIONS.md](OPERATIONS.md), [SECURITY.md](SECURITY.md), [TROUBLESHOOTING.md](TROUBLESHOOTING.md)