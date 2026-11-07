# Changelog

All notable changes to KeySentry are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-08

Initial release.

### Added

- Unified flow — event → scan → alert → remediation — shared by every layer.
- Detector registry with 26 detectors (regex + entropy + validators) covering cloud
  credentials, SaaS and developer-platform tokens, private key material, connection
  URIs, and generic/high-entropy assignments.
- Layers: local-only IDE on-save scanning, pre-commit/pre-push git hooks, CI diff
  gates (GitHub Actions, GitLab CI, Jenkins), cloud/Lambda code and environment
  scanning, SaaS monitoring (Slack, Confluence, Jira, Postman), and filesystem watch.
- Surface adapters with export/file mode for all SaaS sources and optional
  rate-limited live mode (Slack, Confluence, Jira, AWS via optional boto3).
- SQLite storage with dedupe by fingerprint + path + line; raw secrets never stored
  (masked previews and SHA-256 fingerprints only).
- Allowlist/false-positive registry: built-in safe values and patterns, configurable
  regex patterns, and per-fingerprint suppression across all layers.
- Alert channels: console, file outbox (`data/outbox`), Slack webhook, generic
  webhook; alert dedupe window and dry-run behavior when unconfigured.
- Remediation actions: rotate-guide (per-family markdown playbooks), redact
  (in-place replacement), quarantine (move to `data/quarantine`), ticket (Jira or
  outbox draft); status lifecycle open → triaged → false_positive/remediated.
- Optional GPT triage via any OpenAI-compatible endpoint (`[ai]`,
  `KEYSENTRY_AI_KEY`) with deterministic heuristic fallback; prompts carry masked
  values only.
- Stdlib dashboard at `http://127.0.0.1:8710` with dark and light themes and views
  for Overview, Findings, Playground, Activity, Allowlist, and Settings.
- JSON REST API for findings, events, alerts, allowlist, stats, config, scanning,
  demo seeding, triage, remediation, and status updates.
- CLI: serve, scan, gate, hooks, demo, selftest, report, watch, surfaces, allowlist,
  triage, remediate, ingest; one-click launchers `run.bat` (Windows) and `run.sh`
  (Linux/macOS); Make targets serve, scan, demo, test, selftest, hooks, report.
- Layered configuration: defaults < config.toml < config.local.toml < environment;
  zero required dependencies (Python 3.11+ standard library only).
- Documentation: architecture, flowcharts, install, detectors, surfaces, API,
  remediation, privacy, AI triage; contributing guide and security policy.