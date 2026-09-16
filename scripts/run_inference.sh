#!/usr/bin/env bash
set -euo pipefail

host="${DDOS_HOST:-127.0.0.1}"
port="${DDOS_PORT:-8000}"

exec uv run uvicorn sdn_ddos.detection.api:app --host "$host" --port "$port"
