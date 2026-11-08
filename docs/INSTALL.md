# Installation

SENTRIX requires **Python 3.11 or newer** and has **zero required dependencies**. Everything below is optional beyond the Python runtime itself.

## Windows 10 / 11

1. Install Python 3.11+ from [python.org](https://www.python.org/downloads/). During setup, enable **"Add python.exe to PATH"**.
2. Verify:

   ```bat
   python --version
   ```

3. From the SENTRIX folder, double-click `run.bat` or run:

   ```bat
   run.bat
   ```

   The dashboard opens at `http://127.0.0.1:8710`. Any arguments are forwarded, e.g. `run.bat scan .`.

4. Optional: protect a repository with git hooks (requires Git for Windows):

   ```bat
   cd C:\path\to\your\repo
   python C:\path\to\SENTRIX\run.py hooks install
   ```

   The hooks locate SENTRIX via `SENTRIX_HOME` (see below) or a sibling `..\SENTRIX` folder.

## Kali / Debian / Ubuntu

```sh
sudo apt update
sudo apt install -y python3 git
python3 --version    # must be 3.11+
```

If your distribution ships an older Python, install a newer release from your vendor's backports or build from source; SENTRIX uses `tomllib`, which requires 3.11.

Run from the SENTRIX folder:

```sh
chmod +x run.sh      # once, if needed
./run.sh
```

Or `python3 run.py`. Install hooks into a repository with:

```sh
cd /path/to/your/repo
python3 /path/to/SENTRIX/run.py hooks install
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

## First run: login and initial password

Since v1.1 the dashboard and API require sign-in. On the very first start (when no users exist yet), SENTRIX creates an `admin` account:

1. **Password source.** If the `SENTRIX_ADMIN_PASSWORD` environment variable is set, it becomes the initial admin password. Otherwise SENTRIX generates a random one.
2. **Password file.** Either way, the credentials are written to `data/INITIAL_ADMIN_PASSWORD.txt` (username `admin` plus the password). The server also prints a reminder at startup.
3. **Sign in.** Open `http://127.0.0.1:8710`, enter the credentials on the login page, and you land in the graphite dashboard.
4. **Change the password.** Use the user menu → Settings → change password (the current password is required; the new one must be at least 10 characters). Then delete `data/INITIAL_ADMIN_PASSWORD.txt` or store it somewhere safe — it is plaintext.

Setting the initial password ahead of time (recommended for scripted installs):

```sh
# Linux / macOS
export SENTRIX_ADMIN_PASSWORD="a-strong-passphrase"
python3 run.py serve
```

```bat
rem Windows
set SENTRIX_ADMIN_PASSWORD=a-strong-passphrase
run.bat
```

Notes:

- The file is only written when the user table is empty; later restarts never overwrite existing accounts or passwords.
- Login attempts are rate-limited per IP (default 5 per rolling minute, `auth.login_rate_limit`); sessions last 12 hours by default (`auth.session_hours`). Both live under `[auth]` in `config.toml` / `config.local.toml`.
- Add teammates with `python run.py users add NAME --password P --role analyst` (roles: `admin`, `analyst`, `viewer`), or in Settings as an admin. Create CI tokens with `python run.py tokens create --name ci --role analyst`.
- Lost the admin password? Stop the server, move `data/sentrix.db` aside (or delete just the `users` rows with a SQLite tool), and start again to re-bootstrap. Treat the database as sensitive — it contains finding metadata and password hashes.

## Optional: editable install

To get a `sentrix` console command and importable package:

```sh
python -m pip install -e .
sentrix --version
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

Without `boto3` or credentials, `ingest --surface cloud` falls back to scanning the local `lambda_dir` (default `examples/lambda`). Nothing else in SENTRIX requires third-party packages.

## Environment variables

Secrets are read from the environment, never from config files. Each variable name is itself configurable via the matching `*_env` key in `config.toml`.

| Variable | Used by | Purpose |
| --- | --- | --- |
| `SENTRIX_ADMIN_PASSWORD` | `auth.ensure_admin` | Initial admin password on first run; when unset, a random password is generated and written to `data/INITIAL_ADMIN_PASSWORD.txt` |
| `SENTRIX_AI_KEY` | `[ai].api_key_env` | API key for optional GPT triage (any GPT-compatible chat endpoint) |
| `SENTRIX_SLACK_TOKEN` | `[surfaces.slack].token_env` | Slack live scanning (`conversations.history`) |
| `SENTRIX_CONFLUENCE_TOKEN` | `[surfaces.confluence].token_env` | Confluence live REST scanning (with `base_url`) |
| `SENTRIX_JIRA_TOKEN` | `[surfaces.jira].token_env` | Jira live scanning and security ticket creation (with `base_url`) |
| `SENTRIX_POSTMAN_KEY` | `[surfaces.postman].api_key_env` | Postman API key; reserved for workspace sync (1.0.0 scans exported files) |
| `SENTRIX_HOME` | git hooks | Absolute path to the SENTRIX folder so hooks can find `run.py`; defaults to a sibling `../SENTRIX` directory |

Setting variables:

```sh
# Linux / macOS (current shell)
export SENTRIX_AI_KEY="sk-..."
```

```bat
rem Windows (current session)
set SENTRIX_AI_KEY=sk-...
```

For persistence, use your shell profile or the Windows environment settings UI. Do not commit keys to the repository; `config.local.toml` and `.env*` files are gitignored.

## Verify the installation

```sh
python run.py selftest    # registry, detection, allowlist, dedupe checks
python run.py demo        # seed synthetic findings
python run.py serve       # open http://127.0.0.1:8710 and sign in as admin
```

Use the initial password from `data/INITIAL_ADMIN_PASSWORD.txt` (see [First run](#first-run-login-and-initial-password)), then change it in Settings.

## Uninstalling hooks

```sh
python run.py hooks uninstall --repo /path/to/repo
```

Only SENTRIX-authored hooks are removed; other hooks are left untouched.