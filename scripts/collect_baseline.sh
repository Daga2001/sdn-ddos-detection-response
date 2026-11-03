#!/usr/bin/env bash
# Cron-friendly orchestrator: starts the detection stack + a bounded baseline
# (no-attack) traffic session, lets real metrics flow into the configured
# database, then tears everything down cleanly.
#
# Meant to be invoked by cron every few minutes for unattended "normal
# traffic" dataset collection. The attack protocol in docs/experiments.md
# stays manual/deliberate and is NOT run from here.
#
# Env overrides:
#   BASELINE_DURATION_SECONDS  seconds of active traffic per run (default 60)
#   SDN_DETECTION_MODE         llm | entropy | off (default llm)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DURATION_SECONDS="${BASELINE_DURATION_SECONDS:-60}"
LOCK_FILE="/tmp/sdn-ddos-collect-baseline.lock"
LOG_DIR="$REPO_ROOT/logs"
mkdir -p "$LOG_DIR"

# Prevent overlapping runs if a previous invocation is still finishing up
# (e.g. a slow Neon cold-start) when the next cron tick fires.
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
  echo "$(date -Is) skip: previous run still in progress" >> "$LOG_DIR/cron.log"
  exit 0
fi

MODE_OVERRIDE="${SDN_DETECTION_MODE:-}"
set -a
. .env
set +a
MODE="${MODE_OVERRIDE:-${SDN_DETECTION_MODE:-llm}}"

. "$REPO_ROOT/scripts/lib_stack.sh"

echo "$(date -Is) start (mode=${MODE} duration=${DURATION_SECONDS}s)" >> "$LOG_DIR/cron.log"

trap stop_stack EXIT
start_stack "$MODE"

sudo -E env "PYTHONPATH=$REPO_ROOT/src" "$REPO_ROOT/.venv/bin/python" \
  "$REPO_ROOT/scripts/collect_baseline.py" --duration "$DURATION_SECONDS" \
  >> "$LOG_DIR/topology.log" 2>&1

echo "$(date -Is) end" >> "$LOG_DIR/cron.log"
