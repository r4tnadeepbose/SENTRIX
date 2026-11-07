# Surfaces

Every surface adapter feeds the same engine and pipeline. List them with `python run.py surfaces`. Two ingestion modes exist: **export/file mode** (offline, no credentials) and **live mode** (optional, token-based, rate-limited). All examples below use synthetic fixtures under `examples/`.

## IDE (local-only)

Scan a file exactly as an editor on-save hook would. Nothing leaves the machine.

```sh
python run.py ingest --surface ide --file src/settings.py
```

Wire it to your editor's "run on save" feature, or use the watcher below for editor-agnostic coverage. Findings carry surface `ide`.

## Filesystem and watch (local-only)

On-demand tree scan:

```sh
python run.py scan . --surface filesystem
python run.py scan ./infra --json --no-store
```

Continuous scan-on-change (polls mtimes, default every 2 seconds):

```sh
python run.py watch ./src --interval 2
```

Changed files are scanned with surface `ide` and ingested as `watch.changed` events. Ignored directories/files come from `scan.ignore_dirs` and `scan.ignore_files`; files over `scan.max_file_bytes` (default 1 MB) and binary files are skipped.

## Git: hooks and CI gates (diff-only)

Only **added lines** in diffs are scanned, mapped back to real file/line positions.

```sh
python run.py hooks install                 # into the current repo
python run.py gate --staged                 # what pre-commit runs
python run.py gate --range origin/main..HEAD  # what pre-push/CI runs
python run.py gate --base origin/main --head HEAD --repo /path/to/repo
```

Exit codes: `0` clean, `1` findings at/above `scan.fail_on` (default `high`), `2` not a git repository. Hooks locate Wintermute via `WINTERMUTE_HOME` or a sibling `../Wintermute` folder; if not found they warn and allow the operation (fail-open by design, so a missing install never blocks work).

CI usage (GitHub Actions, GitLab CI, Jenkins): checkout with the base branch available, then run `gate --base <base> --head HEAD` and let the non-zero exit fail the job. Gate results are recorded as `gate.blocked` / `gate.passed` events.

## Slack

**Export mode** — scan a JSON export (a list of messages, or `{"messages": [...]}` with `channel`, `ts`, `text`, `user` fields):

```sh
python run.py ingest --surface slack --file examples/slack/export.json
```

Finding paths look like `slack:#channel/ts`; the message author becomes the finding owner.

**Live mode** — set the token and list channels explicitly:

```sh
export WINTERMUTE_SLACK_TOKEN="xoxb-..."
```

```toml
[surfaces.slack]
channels = ["C0123456789"]   # channel IDs to read
poll_seconds = 300
```

```sh
python run.py ingest --surface slack
```

Live mode pages through `conversations.history` (200 messages per page, cursor pagination). Only channels you list are read. For private channels, obtain consent from the channel owner/workspace admin before enabling live reads; see [PRIVACY.md](PRIVACY.md).

## Confluence

**Export mode** — JSON with `pages` (or `results`): each page has `title`, `body` (HTML is stripped), optional `url` and `owner`:

```sh
python run.py ingest --surface confluence --file examples/confluence/pages.json
```

**Live mode**:

```sh
export WINTERMUTE_CONFLUENCE_TOKEN="..."
```

```toml
[surfaces.confluence]
base_url = "https://your-domain.atlassian.net/wiki"
```

```sh
python run.py ingest --surface confluence
```

Pages are fetched via `/rest/api/content` with `body.storage` expansion, 50 per page. The last editor is recorded as owner.

## Jira

**Export mode** — JSON with `issues`: each issue has `key` and `fields` (`summary`, `description`, `reporter`):

```sh
python run.py ingest --surface jira --file examples/jira/issues.json
```

**Live mode** — searches issues updated in the last day (`updated>=-1d`), 50 per page:

```sh
export WINTERMUTE_JIRA_TOKEN="..."
```

```toml
[surfaces.jira]
base_url = "https://your-domain.atlassian.net"
project = "SEC"    # project for remediation tickets
```

```sh
python run.py ingest --surface jira
```

The same configuration drives the `ticket` remediation action: with `base_url` + token, a security task is created via the REST API; without them, a draft is written to `data/outbox/ticket-<id>.json`.

## Postman

Postman scanning is file-based in 1.0.0: export collections and environments from the Postman app, then scan them.

**Collection** — every string in the collection JSON is scanned; findings record the JSON path in `meta.json_path`:

```sh
python run.py ingest --surface postman --file examples/postman/collection.json
```

**Environment** — each `values[]` entry is scanned as `key = "value"`; findings record `meta.env_key`:

```sh
python run.py ingest --surface postman-env --file examples/postman/environment.json
```

`WINTERMUTE_POSTMAN_KEY` (`[surfaces.postman].api_key_env`) is reserved for future live workspace sync; it is not required for export scanning.

## Cloud / Lambda

**Local mode (default)** — scans exported function artifacts under `surfaces.cloud.lambda_dir` (default `examples/lambda`): each function's `config.json` (`FunctionName`, `Environment.Variables`) plus all `.py` and `.js` code files:

```sh
python run.py ingest --surface cloud
# or point at your own export directory:
```

```toml
[surfaces.cloud]
provider = "local"
lambda_dir = "examples/lambda"
```

Env-var findings carry paths like `lambda:<function>/env` and `meta.env_key`.

**Live AWS mode (optional)** — requires `boto3` and normal AWS credentials:

```sh
python -m pip install -e ".[aws]"
```

```toml
[surfaces.cloud]
provider = "aws"
```

```sh
python run.py ingest --surface cloud
```

Lists all Lambda functions and scans their environment variables. If `boto3` or credentials are missing, Wintermute falls back to local mode. Live scanning is read-only and never blocks deployments.

## Rate limiting and network behavior

- Paginated live scans sleep **0.25 s between pages** (`surfaces/common.py: rate_limit`) to stay well inside provider limits; REST reads time out after 15 s.
- Slack history pages are capped at 200 messages; Confluence/Jira pages at 50.
- Alert webhook posts time out after 10 s; GPT triage calls after 30 s.
- Unconfigured live sources return no findings instead of erroring; unconfigured alert channels record `dry-run`.
- To reduce frequency, schedule `ingest` externally (cron, Task Scheduler, CI schedule) rather than tight-looping; `surfaces.slack.poll_seconds` documents the intended cadence (default 300 s).