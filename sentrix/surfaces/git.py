"""Git surface: diff-only scanning for pre-push gates and CI checks."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from sentrix.core.engine import scan_text
from sentrix.core.models import Finding

HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def repo_root(path: str | Path = ".") -> Path | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], cwd=str(path),
            capture_output=True, text=True, check=True)
        return Path(out.stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _git_diff(args: list[str], repo: Path) -> str:
    out = subprocess.run(
        ["git", "diff", "--unified=0", "--no-color", *args], cwd=str(repo),
        capture_output=True, text=True, check=True)
    return out.stdout


def parse_added_lines(diff_text: str):
    """Yield (file_path, line_number, added_line) from a unified diff."""
    current_file = ""
    line_no = 0
    for raw in diff_text.split("\n"):
        if raw.startswith("+++ b/"):
            current_file = raw[6:]
        elif raw.startswith("+++ "):
            current_file = raw[4:]
        elif raw.startswith("@@"):
            match = HUNK_HEADER.match(raw)
            if match:
                line_no = int(match.group(1))
        elif raw.startswith("+") and not raw.startswith("+++"):
            yield current_file, line_no, raw[1:]
            line_no += 1
        elif not raw.startswith("-"):
            line_no += 1


def scan_diff(diff_text: str, surface: str, allowlist=None) -> list[Finding]:
    findings: list[Finding] = []
    for path, line_no, content in parse_added_lines(diff_text):
        for finding in scan_text(content, path, surface, allowlist):
            finding.line = line_no
            findings.append(finding)
    return findings


def commit_author(repo: Path, ref: str = "HEAD") -> str:
    try:
        out = subprocess.run(
            ["git", "log", "-1", "--format=%ae", ref], cwd=str(repo),
            capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def staged_findings(repo: Path, cfg: dict, allowlist=None) -> list[Finding]:
    findings = scan_diff(_git_diff(["--cached"], repo), "pre_push", allowlist)
    author = commit_author(repo)
    for finding in findings:
        finding.owner = finding.owner or author
        finding.meta.setdefault("origin", {}).update(
            {"commit": "staged", "author": author})
    return findings


def range_findings(repo: Path, base: str, head: str, cfg: dict, allowlist=None,
                   surface: str = "ci") -> list[Finding]:
    findings = scan_diff(_git_diff([base, head], repo), surface, allowlist)
    author = commit_author(repo, head)
    for finding in findings:
        finding.owner = finding.owner or author
        finding.meta.setdefault("origin", {}).update(
            {"range": f"{base}..{head}", "author": author})
    return findings