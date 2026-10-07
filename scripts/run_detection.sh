#!/usr/bin/env bash
# Manual mode: start the stack for the detector you choose and keep it running
# until Ctrl+C. Open the topology in another terminal:
#   ./scripts/start_topology.sh   (or: sudo -E .venv/bin/python scripts/run_experiment.py ...)
#
# Usage: scripts/run_detection.sh llm|entropy|off
set -euo pipefail

MODE="${1:-}"
[ -n "$MODE" ] || { echo "usage: $0 llm|entropy|off" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG_DIR="$REPO_ROOT/logs"
mkdir -p "$LOG_DIR"

set -a
. .env
set +a
. "$REPO_ROOT/scripts/lib_stack.sh"

trap 'stop_stack; exit 0' INT TERM
trap stop_stack EXIT
start_stack "$MODE"
echo "stack up (mode=$MODE). Controller log: $LOG_DIR/controller.log -- Ctrl+C to stop."
tail -f "$LOG_DIR/controller.log"
