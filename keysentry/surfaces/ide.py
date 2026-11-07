"""IDE surface: local-only on-save scanning; nothing leaves the machine."""
from __future__ import annotations

from pathlib import Path

from keysentry.core.engine import scan_file
from keysentry.core.models import Finding


def scan_saved_file(path: str | Path, cfg: dict, allowlist=None) -> list[Finding]:
    return scan_file(Path(path), "ide", cfg, allowlist)