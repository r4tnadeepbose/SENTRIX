# SENTRIX Deployment

SENTRIX requires **Python 3.11 or newer** (it uses `tomllib`) and has **zero required dependencies**. Everything below beyond the Python runtime is optional. The platform runs fully offline; live connectors are opt-in.

## Windows 10 / 11

1. Install Python 3.11+ from python.org with **"Add python.exe to PATH"** enabled. Verify: `python --version`.
2. From the SENTRIX folder, double-click `run.bat` or run:

   ```bat
   run.bat
   ```

   Arguments are forwarded, e.g. `run.bat scan .` or `run.bat serve --port 8720`.
3. Optional git hooks for a repository (requires Git for Windows):

   ```bat
   cd C:\path\to\your\repo
   python C:\path\to\SENTRIX\run.py hooks install
   ```

   Or use `scripts\install-hooks.ps1 -Repo C:\path\to\your\repo`. Hooks locate SENTRIX via `SENTRIX_HOME` or a sibling `..\SENTRIX` folder.

## Kali / Debian / Ubuntu

```sh
sudo apt update && sudo apt install -y python3 git
python3 --version    # must be 3.11+
chmod +x run.sh      # once, if needed
./run.sh
```

`scripts/setup-kali.sh` performs the package install and launcher chmod in one step. If your distribution ships Python < 3.11, install a newer release from backports or build from source. Hook install:

```sh
cd /path/to/your/repo
python3 /path/to/SENTRIX/run.py hooks install
```

## macOS

```sh
brew install python@3.12 git    # or the python.org installer
python3 --version
./run.sh
```

## First run: seeding and login

On the very first start:

1. **Admin account.** If no users exist, `admin` (role `super_admin`) is created. Password source: `SENTRIX_ADMIN_PASSWORD` environment variable when set; otherwise the demo password (`sentrix-demo`) in demo mode, or a random value. When the password was generated (env var unset), it is written to `data/INITIAL_ADMIN_PASSWORD.txt`; the server prints a reminder at startup.
2. **Demo roster.** With `auth.demo_mode = true`, five team accounts are seeded (see [SECURITY.md](SECURITY.md)); the login page lists them with one-click sign-in while their passwords are unchanged and the server is on loopback.
3. **Demo findings.** If the findings store is empty, synthetic findings are seeded across all ten surfaces so every view is populated.
4. **Sign in.** Open `http://127.0.0.1:8710`, sign in, then change the admin password (user menu -> Settings/Profile). Delete or protect `data/INITIAL_ADMIN_PASSWORD.txt` afterwards — it is plaintext.

Scripted installs should set the password ahead of time:

```sh
export SENTRIX_ADMIN_PASSWORD="a-strong-passphrase"   # Linux/macOS
python3 run.py serve
```

```bat
set SENTRIX_ADMIN_PASSWORD=a-strong-passphrase
run.bat
```

Optional editable install (adds the `sentrix` console command): `python -m pip install -e .`

## Production mode

Set in `config.local.toml` (gitignored):

```toml
[auth]
demo_mode = false

[server]
host = "127.0.0.1"   # keep loopback unless fronted by a TLS reverse proxy
```

Effects of `demo_mode = false`:

- No demo team accounts are seeded; the login-page roster and `GET /api/auth/demo-info` credential listing disappear (`enabled: false`).
- Integrations without configured credentials report `disconnected` instead of `demo`.
- The first-run admin password is random unless `SENTRIX_ADMIN_PASSWORD` is set.

Existing demo accounts created earlier remain in the database — disable or re-password them when switching an existing installation to production. Also review the hardening checklist in [SECURITY.md](SECURITY.md).

## Configuration reference

Layering: built-in defaults < `config.toml` < `config.local.toml`. Secrets and the initial admin password come from environment variables, never from committed config. `--config ROOT` points the CLI at another project root containing `config.toml`.

| Section / key | Default | Meaning |
| --- | --- | --- |
| `server.host` | `"127.0.0.1"` | Bind address |
| `server.port` | `8710` | HTTP port (`serve --port` overrides) |
| `auth.session_hours` | `12` | Session lifetime; cookie Max-Age |
| `auth.login_rate_limit` | `5` | Failed logins per IP per rolling 60 s |
| `auth.demo_mode` | `true` | Demo roster + demo integration states; set false for production |
| `auth.demo_password` | `"sentrix-demo"` | Initial admin password in demo mode |
| `scan.max_file_bytes` | `1000000` | Skip larger files |
| `scan.entropy_threshold` | `4.5` | Documented entropy threshold (catch-all validator uses 4.5) |
| `scan.fail_on` | `"high"` | Gate/`--strict` blocking threshold |
| `scan.ignore_dirs` | `.git`, `node_modules`, `__pycache__`, `.venv`, `venv`, `dist`, `build`, `data`, `logs`, `.mypy_cache`, `.pytest_cache`, `examples`, `tests`, `docs`, `assets`, `sentrix` | Pruned directories |
| `scan.ignore_files` | `*.png,*.jpg,*.jpeg,*.gif,*.pdf,*.ico,*.lock` | Skipped file patterns |
| `scan.allowlist_patterns` | `[]` | Extra regexes applied to candidate secrets |
| `storage.path` | `"data/sentrix.db"` | SQLite file (relative to SENTRIX root) |
| `alerting.channels` | `["console","outbox"]` | Delivery channels; add `"slack"`, `"webhook"` explicitly |
| `alerting.slack_webhook` / `webhook_url` | `""` | Unset = dry-run alerts |
| `alerting.dedupe_window_seconds` | `3600` | Per-finding alert dedupe |
| `alerting.escalate_after_hours` | `24` | Re-alert stale open findings |
| `alerting.quiet_hours.start/end` | unset | UTC window deferring network channels (wrap-around supported) |
| `alerting.auto_ticket` | `true` | Ticket critical findings from the store |
| `alerting.auto_ticket_min_severity` | `"critical"` | Auto-ticket threshold |
| `detectors.disabled` | `[]` | Detector ids to skip |
| `detectors.severity_overrides` | `{}` | Per-detector severity |
| `[[custom_detectors]]` | none | `id`, `title`, `severity`, `pattern`, optional `secret_group` |
| `ai.enabled` | `false` | GPT triage on/off (heuristic otherwise) |
| `ai.base_url` / `ai.model` | OpenAI-compatible chat endpoint / `gpt-4o-mini` | Any compatible endpoint works |
| `ai.api_key_env` | `"SENTRIX_AI_KEY"` | Env var holding the key |
| `surfaces.slack.token_env` / `channels` / `poll_seconds` | `SENTRIX_SLACK_TOKEN` / `[]` / `300` | Live Slack polling |
| `surfaces.confluence.base_url` / `token_env` | `""` / `SENTRIX_CONFLUENCE_TOKEN` | Live Confluence |
| `surfaces.jira.base_url` / `token_env` / `project` | `""` / `SENTRIX_JIRA_TOKEN` / `"SEC"` | Live Jira + ticketing |
| `surfaces.postman.api_key_env` / `workspaces` | `SENTRIX_POSTMAN_KEY` / `[]` | Declared for Postman (export-based today) |
| `surfaces.cloud.provider` / `lambda_dir` | `"local"` / `"examples/lambda"` | `"aws"` enables live mode when boto3 + credentials exist |

Environment variables: `SENTRIX_ADMIN_PASSWORD`, `SENTRIX_SLACK_TOKEN`, `SENTRIX_JIRA_TOKEN`, `SENTRIX_CONFLUENCE_TOKEN`, `SENTRIX_POSTMAN_KEY`, `SENTRIX_AI_KEY`, `SENTRIX_HOME` (hook resolution).

## Port conflicts

If startup prints `Cannot start: 127.0.0.1:8710 is already held by another process`, an older console instance is usually still running (for example a window left open from a previous installation folder). Close that window and relaunch, or change the port:

```toml
[server]
port = 8720
```

or `python run.py serve --port 8720`. Only one process should own a given `storage.path`; running two servers against the same database file is unsupported. See [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Optional boto3 (live AWS)

```sh
python -m pip install boto3        # or: pip install -e ".[aws]"
```

Then set `surfaces.cloud.provider = "aws"` and provide ambient AWS credentials (profile/env/role) with `lambda:ListFunctions` and `lambda:GetFunctionConfiguration`. Without boto3 or credentials, live scan returns nothing and the local artifact mode keeps working — nothing blocks. Verify with `python run.py ingest --surface cloud`.

## Running as a service

SENTRIX is a single foreground process; use your platform's supervisor. Examples:

**systemd (Linux):**

```ini
[Unit]
Description=SENTRIX security intelligence console
After=network.target

[Service]
Type=simple
User=sentrix
WorkingDirectory=/opt/SENTRIX
Environment=SENTRIX_ADMIN_PASSWORD=change-me
ExecStart=/usr/bin/python3 /opt/SENTRIX/run.py serve
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

**Windows:** run `run.bat serve` under Task Scheduler (at startup, whether user is logged on or not) or wrap with a service manager such as NSSM. **macOS:** a launchd plist invoking `python3 /path/SENTRIX/run.py serve`.

Service guidance: dedicated low-privilege user; read/write only to the SENTRIX folder and scan targets; keep `data/` permissions tight; set production mode; front with a TLS reverse proxy if accessed beyond loopback; monitor `GET /api/health`.

## Backup and restore

```sh
python run.py backup --dest data/backups/manual.db   # online SQLite backup
```

Or from the console/API: `POST /api/ops/backup` (write role), `POST /api/ops/restore {"path": "..."}` (admin; replaces the live store — back up first). Logical export/import: `GET /api/ops/dump` / `POST /api/ops/import` (10 tables; identity and audit tables are only captured by the full SQLite backup). Schedule backups alongside retention purge + vacuum; details in [DATABASE.md](DATABASE.md) and [OPERATIONS.md](OPERATIONS.md).

## Upgrading

1. Stop the running console. 2. Back up `data/sentrix.db`. 3. Replace the application folder (keep `data/` and `config.local.toml`). 4. Start — migrations apply automatically (legacy `wintermute.db`/`keysentry.db` are renamed on first open, roles and schema upgraded idempotently). 5. Run `python run.py selftest` and `python -m unittest discover -s tests`. See [CHANGELOG.md](CHANGELOG.md) for the 2.0.0 transformation notes.