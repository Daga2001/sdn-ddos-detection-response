#!/usr/bin/env bash
# One full experiment with the detector of your choice.
#   scripts/run_experiment.sh llm|entropy|off [run_experiment.py options...]
# Example: scripts/run_experiment.sh entropy --attack-rate 800 --attack-seconds 40
#
# Isolated-lab only: the attack goes from one Mininet host to another through
# the repo's bounded launcher (rate <= 1000 pkt/s, duration <= 300 s).
set -euo pipefail

MODE="${1:-}"
[ -n "$MODE" ] || { echo "usage: $0 llm|entropy|off [options]" >&2; exit 1; }
shift

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG_DIR="$REPO_ROOT/logs"
mkdir -p "$LOG_DIR"

set -a
. .env
set +a
. "$REPO_ROOT/scripts/lib_stack.sh"

trap stop_stack EXIT
start_stack "$MODE"

sudo -E env "PYTHONPATH=$REPO_ROOT/src" "$REPO_ROOT/.venv/bin/python" \
  "$REPO_ROOT/scripts/run_experiment.py" --mode "$MODE" --out-dir "$LOG_DIR" "$@" \
  2>&1 | tee "$LOG_DIR/experiment_${MODE}.log"
