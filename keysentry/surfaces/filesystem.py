"""Filesystem surface: on-demand and scheduled tree scans."""
from __future__ import annotations

from pathlib import Path

from keysentry.core.engine import scan_file, scan_tree
from keysentry.core.models import Finding


def scan(path: str | Path, cfg: dict, allowlist=None) -> tuple[list[Finding], int]:
    return scan_tree(Path(path), "filesystem", cfg, allowlist)


def scan_one(path: str | Path, cfg: dict, allowlist=None) -> list[Finding]:
    return scan_file(Path(path), "filesystem", cfg, allowlist)