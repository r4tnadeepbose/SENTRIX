# Contributing to Wintermute

Thanks for helping improve Wintermute. This project is stdlib-only Python 3.11+; please keep it that way.

## Ground rules

- **No required third-party dependencies.** The standard library is the platform. `boto3` remains the only optional extra (live AWS).
- **Never commit real secrets.** All fixtures, demos, and tests must use synthetic values. The allowlist recognizes common placeholder forms, but do not rely on it — keep test material obviously fake.
- **One pattern set, many layers.** Detection logic belongs in `wintermute/detectors/`, not in surface adapters. Surfaces extract text; the engine decides.
- **Privacy invariants are non-negotiable:** raw secrets are never stored, logged, alerted, or sent to AI endpoints. Only masked previews and SHA-256 fingerprints leave the scanner.

## Development setup

```sh
git clone <your-fork-url>
cd Wintermute
python3 --version          # 3.11+
python3 run.py selftest    # sanity checks
python3 run.py demo        # synthetic data for the dashboard
python3 run.py serve       # http://127.0.0.1:8710
```

Optional editable install: `python -m pip install -e .` (adds the `wintermute` console command). Run the unit suite with `make test` (`python3 -m unittest discover -s tests -v`).

## Where things live

| Change | Location |
| --- | --- |
| New/updated detector | `wintermute/detectors/` (see [docs/DETECTORS.md](docs/DETECTORS.md)) |
| New surface adapter | `wintermute/surfaces/` + register in `SURFACE_MODULES` + CLI `ingest` branch |
| Alert channel | `wintermute/alerting/router.py` |
| Remediation playbook/action | `wintermute/remediation/playbooks.py` |
| API endpoint | `wintermute/server.py` + document in `docs/API.md` |
| Dashboard view | `wintermute/dashboard/` |

## Adding a detector: checklist

1. Register a `Detector` with a unique kebab-case id, accurate severity, distinctive `keywords`, and the correct `secret_group`.
2. Add a validator if the pattern alone is noisy (entropy, length, checksum).
3. Map `remediation` to an existing playbook or add one.
4. Add a synthetic fixture under `examples/` and verify with `python run.py scan <fixture> --no-store`.
5. Run `selftest` and the unit suite; confirm no real-looking values were introduced.

## Style

- Match the existing code: small modules, docstrings on public functions, type hints, `from __future__ import annotations`.
- Keep functions short and side-effect-free where possible; surfaces return findings, the pipeline owns storage and alerting.
- Documentation: clear, professional, concise; tables where useful; no marketing language. Update the relevant `docs/` page with any behavior change.
- Config changes must keep safe offline defaults and remain overridable via `config.local.toml`.

## Pull requests

1. Branch from the default branch; keep changes focused.
2. Include: what changed, why, and how you verified it (`selftest`, unit tests, manual scan output).
3. Ensure `python run.py selftest` and `make test` pass.
4. Do not include runtime state (`data/`, logs), virtual environments, or `config.local.toml` — they are gitignored; keep it that way.
5. Security-sensitive changes: follow [SECURITY.md](SECURITY.md) and avoid public details until coordinated.

## Reporting bugs

Open an issue with: command run, expected vs actual behavior, Python version and OS, and a **synthetic** reproducer. Never paste real credentials into issues — use masked or fake values.