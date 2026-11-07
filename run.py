#!/usr/bin/env python3
"""Wintermute one-click entry point. No arguments starts the dashboard."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wintermute.cli import main

if __name__ == "__main__":
    raise SystemExit(main())