#!/usr/bin/env bash
# SYNTHETIC FIXTURE - fake values for scanner testing only, not real credentials.
# Seed synthetic demo findings, then open the dashboard.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 run.py demo && python3 run.py serve