#!/usr/bin/env bash
# Repetition matrix for the response conditions, run on the VM after
# scripts/lab_detector.sh up. Conditions are interleaved (rep 1 of every condition,
# then rep 2, ...) so drift over time does not favour one of them.
#
#   bash scripts/run_matrix.sh [REPS] [CONDITIONS...]
#   bash scripts/run_matrix.sh 5 none rate_limit block
#
# none        mitigation off (the detector still runs, nothing is enforced)
# rate_limit  / block / escalate   response policy with mitigation on
#
# Same bounded attack in every run (SYN, 1000 pkt/s, h1a -> h1b). Results go to
# /tmp/matrix.log; summarize them with scripts/summarize_runs.py.
set -uo pipefail
cd "$(dirname "$0")/.."
REPS="${1:-5}"
shift || true
CONDITIONS=("$@")
[[ ${#CONDITIONS[@]} -gt 0 ]] || CONDITIONS=(none rate_limit block)
[[ "$REPS" =~ ^[0-9]+$ && "$REPS" -ge 1 && "$REPS" -le 20 ]] || { echo "REPS must be 1-20"; exit 2; }
LOG="${MATRIX_LOG:-/tmp/matrix.log}"
: > "$LOG"
echo "# matrix reps=$REPS conditions=${CONDITIONS[*]} started=$(date -u +%FT%TZ)" >> "$LOG"

run_one() { # CONDITION
  local cond="$1" policy="block" flags=()
  case "$cond" in
    none) policy="block" ;;
    rate_limit|block|escalate) policy="$cond"; flags=(--mitigation) ;;
    *) echo "unknown condition: $cond"; return 2 ;;
  esac
  bash scripts/detector.sh set --mode llm --prompt lab --response "$policy" --dry-run false \
    </dev/null >/dev/null || return 1
  sleep 3
  local out
  for attempt in 1 2; do
    out=$(python3 scripts/lab_runs.py --rate 1000 --kind syn --baseline 30 --duration 40 \
      --recovery 20 "${flags[@]}" --tag "$cond" 2>&1 | grep '^RUN ' | tail -1)
    if [[ "$out" == *"final=completed"* ]]; then
      echo "$out" >> "$LOG"
      return 0
    fi
    echo "# retry $cond (attempt $attempt): ${out:-no output}" >> "$LOG"
    sleep 10
  done
  return 1
}

for rep in $(seq 1 "$REPS"); do
  for cond in "${CONDITIONS[@]}"; do
    echo "# rep $rep $cond $(date -u +%T)" >> "$LOG"
    run_one "$cond" || echo "# FAILED $cond rep $rep" >> "$LOG"
  done
done
echo "# FIN $(date -u +%FT%TZ)" >> "$LOG"
