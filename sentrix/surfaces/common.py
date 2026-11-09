"""Shared helpers for SaaS surfaces: REST calls, pagination, export loading."""
from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path
from sentrix.core.net import assert_safe_outbound_url


def rest_json(url: str, headers: dict | None = None, timeout: int = 15):
    assert_safe_outbound_url(url)
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def load_export(path: str | Path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def rate_limit(seconds: float = 0.25):
    time.sleep(seconds)


def walk_strings(node, trail=""):
    """Yield (key_path, string_value) pairs from nested JSON structures."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield from walk_strings(value, f"{trail}.{key}" if trail else key)
    elif isinstance(node, list):
        for idx, value in enumerate(node):
            yield from walk_strings(value, f"{trail}[{idx}]")
    elif isinstance(node, str):
        yield trail, node