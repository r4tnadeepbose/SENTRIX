#!/bin/sh
# SENTRIX one-click launcher for Linux/macOS.
cd "$(dirname "$0")" || exit 1
exec python3 run.py "$@"