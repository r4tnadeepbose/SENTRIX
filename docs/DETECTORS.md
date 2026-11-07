# Detectors

All layers share one registry (`keysentry/detectors/`). Each detector combines a keyword pre-filter, a regex pattern, an optional validator, and a severity. Matches are masked, fingerprinted (SHA-256), and allowlist-checked before becoming findings. The registry currently holds **26 detectors**; `selftest` verifies at least 25 are registered.

## Registry

| ID | Severity | Family | What it matches |
| --- | --- | --- | --- |
| `aws-access-key-id` | high | cloud | Access key IDs: `AKIA`/`ASIA`/`ABIA`/`ACCA` followed by 16 uppercase alphanumerics |
| `aws-secret-access-key` | critical | cloud | 40-character secret assigned to `aws_secret_access_key`, `aws_secret`, or `secret_access_key` |
| `gcp-api-key` | high | cloud | Google Cloud API keys: `AIza` followed by 35 characters |
| `gcp-service-account` | critical | cloud | Service-account JSON containing a `"private_key"` PEM block |
| `azure-storage-connection` | critical | cloud | Storage connection strings with `DefaultEndpointsProtocol`, `AccountName`, and `AccountKey` |
| `azure-client-secret` | critical | cloud | `client_secret` / `azure_secret` assignments of 30+ characters |
| `github-token` | critical | saas | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` tokens and `github_pat_` fine-grained tokens |
| `gitlab-token` | critical | saas | GitLab personal access tokens: `glpat-` prefix |
| `slack-token` | high | saas | Slack bot/user/legacy tokens: `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` |
| `slack-webhook` | medium | saas | Incoming webhook URLs: `hooks.slack.com/services/T.../B.../...` |
| `stripe-key` | critical | saas | Stripe secret/restricted keys: `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_` |
| `sendgrid-key` | high | saas | SendGrid keys: `SG.` followed by two dot-separated segments |
| `twilio-key` | high | saas | Twilio API keys: `SK` followed by 32 hex characters |
| `openai-key` | critical | ai | OpenAI keys: `sk-` with optional `proj-` segment |
| `anthropic-key` | critical | ai | Anthropic keys: `sk-ant-` prefix |
| `npm-token` | high | saas | npm access tokens: `npm_` followed by 36+ alphanumerics |
| `pypi-token` | high | saas | PyPI upload tokens: `pypi-AgEIcHlwaS5vcmc...` macaroon prefix |
| `mailchimp-key` | medium | saas | Mailchimp keys: 32 hex characters plus `-us<dc>` suffix |
| `private-key` | critical | crypto | PEM headers: `BEGIN (RSA/EC/DSA/OPENSSH/PGP) PRIVATE KEY (BLOCK)` |
| `jwt` | medium | crypto | JSON Web Tokens: three base64url segments starting `eyJ` |
| `basic-auth-url` | high | crypto | Credentials embedded in URLs: `scheme://user:password@host` |
| `postgres-uri` | critical | crypto | Database URIs with passwords: `postgres`, `postgresql`, `mysql`, `mongodb(+srv)`, `redis`, `amqp` |
| `ssh-private-key-body` | critical | crypto | OpenSSH private key body (base64 marker `b3BlbnNzaC1rZXktdjE...`) |
| `generic-secret-assignment` | high | generic | Quoted assignments to `password`, `secret`, `token`, `api_key`, `apikey`, `access_key`, `auth_token`, `client_secret` (8+ char values) |
| `high-entropy-string` | medium | generic | Quoted 24–120 character strings that pass the randomness validator (Shannon entropy ≥ 4.5, length ≥ 16) |
| `env-secret` | high | generic | Environment-file lines whose variable name contains `SECRET`, `TOKEN`, `PASSWORD`, `APIKEY`, `API_KEY`, or `PRIVATE_KEY` |

Severity order for gating: `critical > high > medium > low > info`. The gate/`--strict` threshold is `scan.fail_on` (default `high`).

## Adding a detector

Detectors are plain dataclass registrations. Add one to an existing family module in `keysentry/detectors/` (or create a new module and import it from `keysentry/detectors/__init__.py` so registration runs at startup):

```python
# keysentry/detectors/saas.py (or a new module imported by __init__.py)
import re
from keysentry.detectors.base import Detector, register

register(Detector(
    id="acme-api-key",                 # unique, kebab-case
    title="Acme API Key",              # shown in findings and alerts
    severity="high",                   # critical | high | medium | low | info
    pattern=re.compile(r"\b(acme_[A-Za-z0-9]{32})\b"),
    secret_group=1,                    # capture group holding the raw secret
    keywords=("acme_",),               # cheap pre-filter; empty = always run
    validator=None,                    # optional callable(str) -> bool
    family="saas",                     # grouping for triage/playbooks
    remediation="rotate",              # playbook key in remediation/playbooks.py
))
```

Field notes:

- `secret_group` selects the capture group that is masked, fingerprinted, and entropy-scored; the full match is used for line context.
- `keywords` short-circuit the regex when none appear in the text — keep them distinctive.
- `validator` runs on the extracted value; use it for entropy or format checks (see `high-entropy-string`).
- `remediation` maps to a playbook in `keysentry/remediation/playbooks.py`; unknown keys fall back to the generic `rotate` guide. Add a family-specific playbook there when useful.

After adding: run `python run.py selftest`, scan a synthetic fixture (`python run.py scan examples/ --no-store`), and confirm the finding appears with the right severity. Never test with real credentials.

## Tuning entropy

The catch-all `high-entropy-string` detector validates candidates with `looks_random(value, 4.5)` in `keysentry/detectors/generic.py`: minimum length 16 and Shannon entropy ≥ 4.5 bits/character. To tune:

- **Fewer false positives:** raise the threshold in that validator (e.g. 4.8) or raise the minimum length.
- **More coverage:** lower the threshold (e.g. 4.2), expecting more review noise.
- `scan.entropy_threshold` in `config.toml` documents the intended baseline (4.5); the per-detector validator is the enforcement point.

Entropy for every finding is computed regardless (`core/entropy.py`) and stored on the finding to support triage ranking.

## Allowlist and false positives

Three mechanisms, applied in the engine and again at ingest:

1. **Built-in safe values/patterns** (`core/allowlist.py`): documented example keys, `changeme`, `placeholder`, `your_api_key`, runs of `x`, `EXAMPLE` markers, `your-/my-/sample-/dummy-/fake-` prefixes, `${VAR}` references, and `<placeholder>` tokens.
2. **Config patterns:** add regexes matched against the secret value:

   ```toml
   [scan]
   allowlist_patterns = ["^test_", "CI_ONLY"]
   ```

3. **Fingerprint registry:** suppress a specific confirmed false positive everywhere:

   ```sh
   python run.py allowlist add <fingerprint> --reason "Synthetic fixture in docs"
   python run.py allowlist list
   ```

   The dashboard Allowlist view and `POST /api/allowlist` do the same and mark matching stored findings `false_positive`. Fingerprints are stable across surfaces, so one entry suppresses the same value in IDE, CI, chat, and cloud scans alike.

## Detector tuning (v1.1)

Every detector — built-in or custom — can be disabled or re-severitized without code changes. Tuning applies to all layers at once because the engine is shared.

### Via config (durable)

```toml
[detectors]
disabled = ["high-entropy-string"]
severity_overrides = { "jwt" = "low", "generic-secret-assignment" = "medium" }
```

- `disabled` is a list of detector ids to skip entirely during scans.
- `severity_overrides` maps detector id → severity (`critical`, `high`, `medium`, `low`, `info`). The override replaces the registry default for new findings and for gating (`scan.fail_on`); existing stored findings keep their recorded severity unless you set a per-finding override in the dashboard.
- Put durable tuning in `config.local.toml` (gitignored) or `config.toml`; it is applied at startup by `engine.configure`.

### Via API / dashboard (runtime)

- `GET /api/detectors` lists every registered detector with its effective severity, family, and enabled flag.
- `POST /api/detectors/tuning` applies changes immediately to the running engine:

  ```json
  {"disabled": ["high-entropy-string"], "severity_overrides": {"jwt": "low"}}
  ```

  The change is audited (`detectors.tuning`) but lives only for the current process — it is not written back to `config.toml`. Mirror it in config for durability. The Settings view exposes the same controls.

Disabling a detector stops new detections only; stored findings, allowlist entries, and history are untouched.

## Custom detectors from config (v1.1)

Add organization-specific patterns without editing Python. Each `[[custom_detectors]]` entry is registered at startup (and on runtime re-tuning) with family `custom`:

```toml
[[custom_detectors]]
id = "internal-api-key"
title = "Internal API Key"
severity = "high"
pattern = "internal_[A-Za-z0-9]{24,}"

[[custom_detectors]]
id = "build-secret"
title = "Build Pipeline Secret"
severity = "critical"
pattern = "bldsec_([A-Fa-f0-9]{40})"
secret_group = 1
```

| Field | Required | Default | Notes |
| --- | --- | --- | --- |
| `id` | yes | — | Unique kebab-case id; a custom id matching a built-in replaces it in the registry |
| `title` | no | the id | Shown in findings and alerts |
| `severity` | no | `medium` | `critical` \| `high` \| `medium` \| `low` \| `info` |
| `pattern` | yes | — | Python regex; the match locates the finding |
| `secret_group` | no | `0` | Capture group holding the raw secret (0 = whole match); this group is masked, fingerprinted, and entropy-scored |

Behavior notes:

- Config-defined detectors are regex-only: no keyword pre-filter or validator. For those, register a full `Detector` in code (see [Adding a detector](#adding-a-detector)).
- Custom detectors participate in everything: allowlist, dedupe, tuning (`disabled` / `severity_overrides` accept custom ids), jobs, gates, and all surfaces. Remediation falls back to the generic `rotate` guide.
- Patterns are compiled at registration; an invalid regex fails startup, so test with `python run.py selftest` and a synthetic fixture (`python run.py scan examples/ --no-store`) after changes. Never use real credentials in patterns or fixtures.