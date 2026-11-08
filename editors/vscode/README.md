<!-- SYNTHETIC FIXTURE - fake values for scanner testing only, not real credentials. -->
# SENTRIX editor extension

Scans the current file with the SENTRIX CLI on every save and on demand, then
publishes the findings as editor diagnostics (Problems panel) with an output
channel named `SENTRIX` for the raw CLI log.

## Install

Option 1 - package and install:

```sh
npm install -g @vsce/vsce   # if the packaging tool is not installed yet
cd editors/vscode
vsce package
code --install-extension sentrix-0.1.0.vsix
```

Option 2 - run from source:

1. Open the `editors/vscode` folder as the workspace.
2. Press `F5` to launch an Extension Development Host with the extension loaded.

## Usage

- Save any file: it is scanned automatically.
- Command palette: `SENTRIX: Scan File` scans the active editor's file.
- Findings appear as diagnostics: critical/high = Error, medium = Warning,
  low = Information, anything else = Hint.

The extension runs: `python <home>/run.py scan --json --no-store <file>` and
parses the JSON array printed to stdout. Nothing is stored by the scan.

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `sentrix.home` | `""` (empty) | SENTRIX project root (the folder containing `run.py`). When empty, resolves to two levels up from the workspace folder (the `editors/vscode` layout), falling back to the workspace folder itself if it contains `run.py`. |
| `sentrix.python` | `"python"` | Python executable used to run the CLI. Use `python3` or a full path if needed. |

## Requirements

- Python 3.11+ on PATH (or set `sentrix.python`).
- A SENTRIX checkout reachable via `sentrix.home`.