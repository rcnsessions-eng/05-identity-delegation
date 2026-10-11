#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
bash ../../04-mcp-constrained-tools/code/scripts/check.sh
python3 scripts/setup_env.py
docker compose config --quiet
docker compose --profile tools build checks gateway
docker compose --profile tools run --rm --no-deps checks
docker compose up -d --wait gateway
docker compose --profile tools run --rm --no-deps smoke