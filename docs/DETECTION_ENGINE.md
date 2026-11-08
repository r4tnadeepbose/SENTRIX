# SENTRIX Detection Engine

One intelligence core decides what is a secret, everywhere. The engine (`sentrix/core/engine.py`) applies the same detector registry, entropy scoring, validation heuristics and allowlist to editor saves, git diffs, CI ranges, filesystem trees, cloud artifacts and SaaS content. Surfaces extract text; the engine decides.

## Detector registry

Detectors are dataclasses registered in `sentrix/detectors/base.py::REGISTRY`:

| Field | Meaning |
| --- | --- |
| `id` | Unique kebab-case identifier (also the fingerprint salt) |
| `title` | Human-readable finding title |
| `severity` | Default severity: `critical`, `high`, `medium`, `low`, `info` |
| `pattern` | Compiled regular expression |
| `secret_group` | Capture group holding the secret (falls back to group 0) |
| `validator` | Optional callable `(secret) -> bool` rejecting false matches |
| `keywords` | Tuple of substrings; if none appear in the text the detector is skipped (fast prefilter) |
| `family` | `cloud`, `crypto`, `saas`, `ai`, `generic`, `custom` — drives confidence and risk weight |
| `remediation` | Playbook key (e.g. `rotate-aws`); defaults to `rotate` |

## The 26 built-in detectors

### Cloud (6) — `sentrix/detectors/cloud.py`

| ID | Title | Severity | Playbook |
| --- | --- | --- | --- |
| `aws-access-key-id` | AWS Access Key ID (AKIA/ASIA/ABIA/ACCA + 16) | high | rotate-aws |
| `aws-secret-access-key` | AWS Secret Access Key (40-char assignment) | critical | rotate-aws |
| `gcp-api-key` | Google Cloud API Key (`AIza` + 35) | high | rotate-gcp |
| `gcp-service-account` | GCP Service Account Private Key Material | critical | rotate-gcp |
| `azure-storage-connection` | Azure Storage Connection String | critical | rotate-azure |
| `azure-client-secret` | Azure AD Client Secret | critical | rotate (default) |

### Crypto (5) — `sentrix/detectors/crypto.py`

| ID | Title | Severity | Playbook |
| --- | --- | --- | --- |
| `private-key` | Private Key Block (RSA / EC / DSA / OPENSSH / PGP) | critical | rotate-keypair |
| `jwt` | JSON Web Token (`eyJ...` three segments) | medium | rotate |
| `basic-auth-url` | Credentials Embedded in URL (`scheme://user:pass@`) | high | rotate |
| `postgres-uri` | Database Connection URI with Password (postgres/mysql/mongodb/redis/amqp) | critical | rotate-db |
| `ssh-private-key-body` | OpenSSH Private Key Body (base64 header match) | critical | rotate-keypair |

### SaaS and developer platforms (10) — `sentrix/detectors/saas.py`

| ID | Title | Severity | Playbook |
| --- | --- | --- | --- |
| `github-token` | GitHub Personal / OAuth / App Token (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`) | critical | rotate-github |
| `gitlab-token` | GitLab Personal Access Token (`glpat-`) | critical | rotate-gitlab |
| `slack-token` | Slack Bot / User / Legacy Token (`xox[baprs]-`) | high | rotate-slack |
| `slack-webhook` | Slack Incoming Webhook URL | medium | rotate-slack |
| `stripe-key` | Stripe Secret / Restricted Key (`sk_live_`, `sk_test_`, `rk_live_`) | critical | rotate-stripe |
| `sendgrid-key` | SendGrid API Key (`SG.` two segments) | high | rotate |
| `twilio-key` | Twilio API Key (`SK` + 32 hex) | high | rotate |
| `npm-token` | npm Access Token (`npm_` + 36) | high | rotate |
| `pypi-token` | PyPI Upload Token (`pypi-AgEIcHlwaS5vcmc...`) | high | rotate |
| `mailchimp-key` | Mailchimp API Key (32 hex + `-usN`) | medium | rotate |

### AI providers (2) — `sentrix/detectors/saas.py`, family `ai`

| ID | Title | Severity | Playbook |
| --- | --- | --- | --- |
| `openai-key` | OpenAI API Key (`sk-`, `sk-proj-`) | critical | rotate-openai |
| `anthropic-key` | Anthropic API Key (`sk-ant-`) | critical | rotate |

### Generic (3) — `sentrix/detectors/generic.py`

| ID | Title | Severity | Notes |
| --- | --- | --- | --- |
| `generic-secret-assignment` | Hardcoded Secret Assignment (`password/secret/token/api_key/... = "..."`) | high | Quoted values, 8+ chars |
| `high-entropy-string` | High-Entropy String (possible secret) | medium | Validator: `looks_random` — length >= 16 and Shannon entropy >= 4.5 |
| `env-secret` | Secret in Environment File (`*SECRET/TOKEN/PASSWORD/APIKEY/PRIVATE_KEY* = value`) | high | Multiline, optional `export` |

Custom detectors (config or runtime rules) add a `custom` family on top of these 26.

## Scan flow

`engine.scan_text(text, path, surface, allowlist)` per detector:

1. Skip disabled detectors (tuning) and detectors whose `keywords` are absent.
2. Iterate regex matches; extract `secret_group`; skip empty results.
3. Run the `validator` when present; reject on False.
4. Compute the fingerprint; skip allowlisted values.
5. Compute the 1-based line number; dedupe within the scan by `(detector_id, fingerprint, path, line)`.
6. Emit a `Finding` with masked secret, entropy, severity (override-aware) and meta.

File hygiene (`scan_file` / `scan_tree`): files larger than `scan.max_file_bytes` (default 1,000,000) are skipped; a NUL byte in the first 1024 bytes marks binary and skips; text decodes as UTF-8 with replacement; `walk_files` prunes `scan.ignore_dirs` and `scan.ignore_files` (fnmatch).

## Entropy

`sentrix/core/entropy.py` computes Shannon entropy in bits per character: `-sum(p * log2(p))` over character frequencies, rounded to 2 decimals on the finding. `looks_random(value, threshold=4.5)` requires length >= 16 and entropy >= threshold; it gates the catch-all `high-entropy-string` detector. `scan.entropy_threshold` in config documents the same 4.5 default. Entropy ranks candidates; it never decides alone except in that one detector.

## Confidence and validation status

Each finding's meta carries two honest quality signals:

**Confidence** (family-based prior, not a probability of live validity):

| Family | Confidence |
| --- | --- |
| `crypto` | 0.95 |
| `cloud` | 0.90 |
| `saas` | 0.90 |
| `ai` | 0.90 |
| `custom` | 0.70 |
| `generic` | 0.55 |
| any other | 0.60 |

**Validation** — one of two values:

- `format_validated`: the detector has a validator, or its family is `cloud`, `saas` or `crypto` — the value matches the provider's published credential format (structure, prefix, length).
- `pattern_match`: regex-only detection (generic assignments, env files, AI-family keys without validators, custom rules).

**Neither value means the credential was tested against the provider.** SENTRIX performs no external credential validation by design (see [SECURITY.md](SECURITY.md)); the risk engine's `confirmed_validity` is always `false`.

## Environment heuristic

The finding's path (lowercased) classifies the environment:

- contains `prod` or `live` -> `production` (+10 risk points)
- contains `dev`, `staging` or `test` -> `non-production`
- otherwise -> `unknown`

This is a heuristic for prioritization, not an inventory fact; the Posture view aggregates it and analysts can override severity per finding.

## Masking and fingerprinting

- **Mask** (`core/util.py::mask_secret`): values of 8 characters or fewer keep the first 2 plus asterisks; longer values keep `first4 + ******** + last4`. This is the only representation ever stored, displayed, alerted, exported or sent to triage.
- **Fingerprint**: `SHA-256("<detector_id>|<stripped secret>")` hex. Stable across surfaces, so the same credential in git, Slack and a Lambda env dedupes to one allowlist entry and relates across locations.
- **Finding id**: first 12 hex of `SHA-256("<fingerprint>|<path>|<line>")`.

## Dedupe

Two levels:

1. **Within a scan** — identical `(detector_id, fingerprint, path, line)` matches emit once.
2. **Across scans** — `Storage.upsert_finding` looks up `fingerprint + path + line`. A hit updates `updated_at`, reuses the existing id and status, and bumps `finding_extra.occurrences` + `last_seen`; only genuinely new findings trigger alerts. `GET /api/findings/{id}/related` lists other locations sharing the fingerprint.

## Allowlist

`sentrix/core/allowlist.py`, checked in the engine and again at ingestion:

- **Fingerprint registry** (`allowlist` table): add via console, `POST /api/allowlist`, bulk action or CLI; matching stored findings become `false_positive`.
- **Built-in safe values**: documented example keys (`AKIAIOSFODNN7EXAMPLE`, the matching example secret), `changeme`, `placeholder`, `your_api_key`, `your-api-key`, `xxxxxxxx`.
- **Built-in safe patterns**: anything containing `EXAMPLE`; runs of 6+ `x`; prefixes `your-/my-/sample-/dummy-/fake-`; environment variable references (`${VAR}` / `$VAR`); angle-bracket placeholders (`<...>`).
- **Config patterns**: `scan.allowlist_patterns` — extra regexes applied to the candidate secret.

## Custom rules

Two paths, both producing family-`custom` detectors:

1. **Config** — `[[custom_detectors]]` blocks in `config.toml` / `config.local.toml` with `id`, `title`, `severity`, `pattern`, optional `secret_group`; registered by `engine.configure` at startup.
2. **Runtime** — `POST /api/detection-rules` validates the regex (invalid -> 400), registers the detector immediately and persists it in `custom_rules`. `GET /api/detection-rules` lists stored rules; `POST /api/detection-rules/{id}/delete` removes the row.

Honest restart semantics: runtime-created rules are persisted and listed, but the engine registry is rebuilt from config on startup — re-add a runtime rule after a restart (or promote it to `[[custom_detectors]]`) to make it permanent. Deleting a rule removes the stored row; the already-registered in-memory detector stays active until restart.

## Risk scoring

`sentrix/core/risk.py` stamps every ingested finding with an explainable 0-100 score:

| Factor | Points |
| --- | --- |
| Severity baseline | critical 40, high 30, medium 18, low 8, info 2 |
| Secret category | cloud 30, crypto 28, ai 24, saas 22, custom 18, generic 14 |
| Exposure surface | cloud 20, ci 18, git 16, slack 16, confluence 14, postman 14, jira 12, pre_push 10, filesystem 8, ide 6 |
| Detection confidence | `round(confidence * 10)` |
| Format validated | +6 |
| Production environment | +10 |
| Exposure duration | +1 per day, capped at 10 |
| Repeated exposure | `min(6, occurrences)` when > 1 |

Clamped to 0-100; bands: >= 80 critical, >= 60 high, >= 40 medium, >= 20 low, else info. The result includes the human-readable `factors` list, `explainable: true` and `confirmed_validity: false`. The Intelligence view ranks priorities by this score.

## Tuning

- **Disable / severity overrides** — `detectors.disabled` and `detectors.severity_overrides` in config, or `POST /api/detectors/tuning` at runtime (audited, immediate for new scans; runtime values do not persist across restarts unless written to config).
- **Registry listing** — `GET /api/detectors` shows id, title, effective severity, family and enabled state.
- **Scan hygiene** — `scan.max_file_bytes`, `ignore_dirs`, `ignore_files`, `allowlist_patterns`.
- **Gate threshold** — `scan.fail_on` (default `high`) decides which severities block hooks/CI with `--strict`/`gate`.