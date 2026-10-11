#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/setup_env.py
docker compose up -d --build --wait gateway
printf 'Gateway: http://127.0.0.1:%s/docs\nKeycloak: http://localhost:%s\n' "${LEARNING_PORT:-8225}" "${LEARNING_IDP_PORT:-8425}"