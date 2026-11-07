# AI Triage

Triage ranks a finding as likely true positive, likely false positive, or needs review, with reasons and a recommendation. KeySentry offers two engines behind one interface: an optional GPT call to **any OpenAI-compatible endpoint**, and a **deterministic heuristic fallback** that always works offline. Triage is advisory — it never rotates, redacts, or allowlists anything by itself.

Run it from the dashboard, the CLI, or the API:

```sh
python run.py triage <finding-id>
```

```sh
curl -X POST http://127.0.0.1:8710/api/triage -d '{"id": "<finding-id>"}'
```

The result is stored in `finding.meta.triage` and returned by `GET /api/findings/{id}`.

## Enabling GPT triage

1. Set the API key in the environment (never in config files):

   ```sh
   export KEYSENTRY_AI_KEY="sk-..."        # Linux/macOS
   set KEYSENTRY_AI_KEY=sk-...             # Windows (current session)
   ```

2. Enable in `config.local.toml` (gitignored):

   ```toml
   [ai]
   enabled = true
   base_url = "https://api.openai.com/v1"   # any OpenAI-compatible endpoint
   model = "gpt-4o-mini"
   api_key_env = "KEYSENTRY_AI_KEY"
   ```

Defaults: `enabled = false`, `base_url = "https://api.openai.com/v1"`, `model = "gpt-4o-mini"`, `api_key_env = "KEYSENTRY_AI_KEY"`.

### OpenAI-compatible endpoints

The client (`keysentry/ai/gpt.py`) is a minimal stdlib chat client: it POSTs to `{base_url}/chat/completions` with `Authorization: Bearer <key>`, `temperature = 0.1`, and a 30-second timeout. Any service implementing that contract works — hosted providers, self-hosted inference servers, or local gateways. Point `base_url` at your endpoint and set `model` accordingly:

```toml
[ai]
enabled = true
base_url = "http://127.0.0.1:8000/v1"   # example: local inference server
model = "your-local-model"
```

A local endpoint keeps even masked metadata on your machine.

## Prompt privacy

The prompt (`keysentry/ai/prompts.py`) is built exclusively from the stored finding — which never contains a raw secret. Exactly these fields are sent:

- `detector` (detector id), `title`, `severity`, `surface`
- `path`, `line`
- `masked_secret` (masked preview only)
- `entropy`

The system prompt instructs the model to act as a security analyst and respond with strict JSON. **Raw secrets are never sent**, because they are never stored in the first place. Paths and line numbers are included as context; if your file naming is itself sensitive, prefer a local endpoint or the heuristic. See [PRIVACY.md](PRIVACY.md).

## Result shape

```json
{
  "source": "gpt",
  "verdict": "likely_true_positive",
  "confidence": 0.9,
  "reasons": ["Matches a known credential format with high entropy."],
  "recommendation": "Rotate the credential and remove the exposure; follow the rotation guide."
}
```

- `source`: `gpt` or `heuristic`
- `verdict`: `likely_true_positive`, `likely_false_positive`, or `needs_review`
- `confidence`: 0.0–1.0
- `reasons`: list of short justifications
- `recommendation`: next step for the operator

## Heuristic fallback

The fallback (`keysentry/ai/triage.py`) runs when AI is disabled, the key is missing, or the GPT call fails for any reason (network, timeout, malformed response). It is deterministic and fully offline:

| Signal | Effect on score (base 0.5) |
| --- | --- |
| Path contains `test`, `example`, `fixture`, `sample`, `mock`, or `docs/` | −0.25 |
| Masked value resembles a placeholder (`EXAMPLE`, `your...`) | −0.30 |
| Entropy ≥ 4.5 | +0.20 |
| Severity `critical` or `high` | +0.15 |
| Surface `slack`, `confluence`, or `jira` | +0.10 |

The score is clamped to 0.05–0.95. Verdict thresholds: ≥ 0.65 → `likely_true_positive`; ≤ 0.35 → `likely_false_positive`; otherwise `needs_review`. Each applied signal is listed in `reasons`, so the verdict is always explainable.

## Operational notes

- Triage never changes finding status automatically; use the result to decide between rotation, remediation, and allowlisting.
- GPT failures degrade silently to the heuristic — check `source` in the result to know which engine answered.
- For high-volume workflows, triage selectively (critical/high first) rather than every medium-entropy candidate.