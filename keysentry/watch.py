"""Polling filesystem watcher: scan-on-save for any editor or drop folder."""
from __future__ import annotations

import time
from pathlib import Path

from keysentry.core.engine import scan_file, walk_files
from keysentry.core.pipeline import Pipeline


def watch_tree(root: Path, cfg: dict, pipeline: Pipeline, interval: float = 2.0):
    print(f"Watching {root} (interval {interval}s). Ctrl+C to stop.")
    mtimes: dict[Path, float] = {}
    for path in walk_files(root, cfg):
        try:
            mtimes[path] = path.stat().st_mtime
        except OSError:
            continue
    try:
        while True:
            time.sleep(interval)
            current: dict[Path, float] = {}
            for path in walk_files(root, cfg):
                try:
                    current[path] = path.stat().st_mtime
                except OSError:
                    continue
            changed = [p for p, m in current.items() if mtimes.get(p) != m]
            for path in changed:
                findings = scan_file(path, "ide", cfg, pipeline.allowlist)
                if findings:
                    pipeline.ingest(findings, kind="watch.changed")
                    print(f"{path}: {len(findings)} finding(s)")
            mtimes = current
    except KeyboardInterrupt:
        print("\nWatcher stopped.")