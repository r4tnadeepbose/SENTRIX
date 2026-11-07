#!/usr/bin/env bash
# SYNTHETIC FIXTURE - fake values for scanner testing only, not real credentials.
# Scan a path (default: the whole KeySentry tree) with the filesystem surface.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 run.py scan "${1:-.}"