# Installation

KeySentry requires **Python 3.11 or newer** and has **zero required dependencies**. Everything below is optional beyond the Python runtime itself.

## Windows 10 / 11

1. Install Python 3.11+ from [python.org](https://www.python.org/downloads/). During setup, enable **"Add python.exe to PATH"**.
2. Verify:

   ```bat
   python --version
   ```

3. From the KeySentry folder, double-click `run.bat` or run:

   ```bat
   run.bat
   ```

   The dashboard opens at `http://127.0.0.1:8710`. Any arguments are forwarded, e.g. `run.bat scan .`.

4. Optional: protect a repository with git hooks (requires Git for Windows):

   ```bat
   cd C:\path\to\your\repo
   python C:\path\to\KeySentry\run.py hooks install
   ```

   The hooks locate KeySentry via `KEYSENTRY_HOME` (see below) or a sibling `..\KeySentry` folder.

## Kali / Debian / Ubuntu

```sh
sudo apt update
sudo apt install -y python3 git
python3 --version    # must be 3.11+
```

If your distribution ships an older Python, install a newer release from your vendor's backports or build from source; KeySentry uses `tomllib`, which requires 3.11.

Run from the KeySentry folder:

```sh
chmod +x run.sh      # once, if needed
./run.sh
```

Or `python3 run.py`. Install hooks into a repository with:

```sh
cd /path/to/your/repo
python3 /path/to/KeySentry/run.py hooks install
```

## macOS

```sh
# Homebrew (recommended)
brew install python@3.12 git
python3 --version
```

Or install the official package from [python.org](https://www.python.org/downloads/). Then:

```sh
./run.sh
```

## Optional: editable install

To get a `keysentry` console command and importable package:

```sh
python -m pip install -e .
keysentry --version
```

This uses only the standard library at runtime; `setuptools` is needed at build time.

## Optional: live AWS scanning

Live Lambda scanning needs `boto3` plus normal AWS credentials (environment, shared config, or role):

```sh
python -m pip install -e ".[aws]"
# or: python -m pip install boto3
```

Then set in `config.local.toml`:

```toml
[surfaces.cloud]
provider = "aws"
```

Without `boto3` or credentials, `ingest --surface cloud` falls back to scanning the local `lambda_dir` (default `examples/lambda`). Nothing else in KeySentry requires third-party packages.

## Environment variables

Secrets are read from the environment, never from config files. Each variable name is itself configurable via the matching `*_env` key in `config.toml`.

| Variable | Used by | Purpose |
| --- | --- | --- |
| `KEYSENTRY_AI_KEY` | `[ai].api_key_env` | API key for optional GPT triage (any OpenAI-compatible endpoint) |
| `KEYSENTRY_SLACK_TOKEN` | `[surfaces.slack].token_env` | Slack live scanning (`conversations.history`) |
| `KEYSENTRY_CONFLUENCE_TOKEN` | `[surfaces.confluence].token_env` | Confluence live REST scanning (with `base_url`) |
| `KEYSENTRY_JIRA_TOKEN` | `[surfaces.jira].token_env` | Jira live scanning and security ticket creation (with `base_url`) |
| `KEYSENTRY_POSTMAN_KEY` | `[surfaces.postman].api_key_env` | Postman API key; reserved for workspace sync (1.0.0 scans exported files) |
| `KEYSENTRY_HOME` | git hooks | Absolute path to the KeySentry folder so hooks can find `run.py`; defaults to a sibling `../KeySentry` directory |

Setting variables:

```sh
# Linux / macOS (current shell)
export KEYSENTRY_AI_KEY="sk-..."
```

```bat
rem Windows (current session)
set KEYSENTRY_AI_KEY=sk-...
```

For persistence, use your shell profile or the Windows environment settings UI. Do not commit keys to the repository; `config.local.toml` and `.env*` files are gitignored.

## Verify the installation

```sh
python run.py selftest    # registry, detection, allowlist, dedupe checks
python run.py demo        # seed synthetic findings
python run.py serve       # open http://127.0.0.1:8710
```

## Uninstalling hooks

```sh
python run.py hooks uninstall --repo /path/to/repo
```

Only KeySentry-authored hooks are removed; other hooks are left untouched.