#!/usr/bin/env bash
# Narrow pre-deploy checks; the full gate runs after live acceptance.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 scripts/fast-check.py "$@"
