#!/usr/bin/env bash
# SYNTHETIC FIXTURE - fake values for scanner testing only, not real credentials.
# One-time setup for a Kali-style workstation: install Python and git, make the
# launcher executable.
set -euo pipefail
cd "$(dirname "$0")/.."

sudo apt-get update && sudo apt-get install -y python3 git
chmod +x run.sh
echo "done"