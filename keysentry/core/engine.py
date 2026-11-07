"""The scanning engine: one pattern set applied to any text, file or tree."""
from __future__ import annotations

import fnmatch
import os
from pathlib import Path

from keysentry.core.allowlist import Allowlist
from keysentry.core.entropy import shannon
from keysentry.core.models import Finding
from keysentry.core.util import fingerprint, mask_secret
from keysentry.detectors import all_detectors


def scan_text(text: str, path: str, surface: str, allowlist: Allowlist | None = None) -> list[Finding]:
    allowlist = allowlist or Allowlist()
    findings: list[Finding] = []
    seen: set[tuple] = set()
    for detector in all_detectors():
        if detector.keywords and not any(k in text for k in detector.keywords):
            continue
        for match in detector.pattern.finditer(text):
            secret = detector.extract(match)
            if not secret:
                continue
            if detector.validator and not detector.validator(secret):
                continue
            fp = fingerprint(detector.id, secret)
            if allowlist.is_allowed(fp, secret, path):
                continue
            line = text.count("\n", 0, match.start()) + 1
            key = (detector.id, fp, path, line)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                detector_id=detector.id,
                title=detector.title,
                severity=detector.severity,
                surface=surface,
                path=path,
                line=line,
                secret_masked=mask_secret(secret),
                entropy=round(shannon(secret), 2),
                fingerprint=fp,
                meta={"family": detector.family, "remediation": detector.remediation},
            ))
    return findings


def _is_binary(head: bytes) -> bool:
    return b"\0" in head


def scan_file(path: Path, surface: str, cfg: dict, allowlist: Allowlist | None = None) -> list[Finding]:
    max_bytes = cfg.get("scan", {}).get("max_file_bytes", 1_000_000)
    try:
        if path.stat().st_size > max_bytes:
            return []
        with open(path, "rb") as fh:
            head = fh.read(1024)
            if _is_binary(head):
                return []
            fh.seek(0)
            text = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    return scan_text(text, str(path), surface, allowlist)


def walk_files(root: Path, cfg: dict):
    scan_cfg = cfg.get("scan", {})
    ignore_dirs = set(scan_cfg.get("ignore_dirs", []))
    ignore_files = scan_cfg.get("ignore_files", [])
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ignore_dirs]
        for name in sorted(filenames):
            if any(fnmatch.fnmatch(name, pat) for pat in ignore_files):
                continue
            yield Path(dirpath) / name


def scan_tree(root: Path, surface: str, cfg: dict, allowlist: Allowlist | None = None) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    count = 0
    if root.is_file():
        return scan_file(root, surface, cfg, allowlist), 1
    for path in walk_files(root, cfg):
        count += 1
        findings.extend(scan_file(path, surface, cfg, allowlist))
    return findings, count