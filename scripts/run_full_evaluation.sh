#!/usr/bin/env bash
# Evidence for the four result reports, run unattended on the VM after the lab is up:
#   1. offline comparison of the five LLMs on the same labeled lab flows, both prompts
#   2. live runs with the other LLMs (no mitigation, same attack as the matrix)
#   3. entropy detection sweep over SDN_ENTROPY_K (detection only, no mitigation)
#   4. repetitions of the `escalate` response policy
# Each stage is independent: a failure is logged and the next stage still runs.
#
#   bash scripts/run_full_evaluation.sh [--wait-for /tmp/diverse.log]
# Progress: /tmp/full_eval.log. Raw runs: /tmp/live_llm.log, /tmp/entropy_sweep.log,
# /tmp/matrix_escalate.log; offline results: logs/lab_cmp5_<prompt>.json
set -uo pipefail
cd "$(dirname "$0")/.."
LOG=/tmp/full_eval.log
say() { echo "# $(date -u +%T) $*" | tee -a "$LOG"; }
: > "$LOG"

if [[ "${1:-}" == "--wait-for" && -n "${2:-}" ]]; then
  say "waiting for $2 to finish"
  until grep -q '^# FIN' "$2" 2>/dev/null; do sleep 15; done
fi

MODELS="llama3.2:3b,gemma2:2b,qwen2.5:3b,phi3.5,llama3.2:1b"

say "stage 1: offline comparison (both prompts)"
for prompt in lab insdn; do
  PYTHONPATH=src .venv/bin/python scripts/compare_llms.py --models "$MODELS" \
    --samples logs/lab_eval_small.csv --repeats 1 --timeout 90 --prompt "$prompt" \
    --out "logs/lab_cmp5_${prompt}.json" > "/tmp/cmp5_${prompt}.log" 2>&1 \
    || say "stage 1 ($prompt) failed"
done

say "stage 2: live runs with the other LLMs"
: > /tmp/live_llm.log
for model in gemma2:2b qwen2.5:3b; do
  bash scripts/detector.sh set --mode llm --model "$model" --prompt lab \
    --response block --dry-run true </dev/null >/dev/null || { say "cannot select $model"; continue; }
  sleep 25
  for rep in 1 2 3 4 5; do
    out=$(python3 scripts/lab_runs.py --rate 1000 --kind syn --baseline 30 --duration 40 \
      --recovery 20 --tag "llm_${model}" 2>&1 | grep '^RUN ' | tail -1)
    if [[ "$out" == *"final=completed"* ]]; then echo "$out" >> /tmp/live_llm.log
    else say "run failed: $model rep $rep: ${out:-no output}"; fi
  done
done
bash scripts/detector.sh set --model llama3.2:3b </dev/null >/dev/null || true

say "stage 3: entropy sweep"
: > /tmp/entropy_sweep.log
for k in 1.0 2.0 3.0; do
  say "entropy k=$k (recreating the detector)"
  SDN_ENTROPY_K="$k" timeout 600 docker compose up -d --build > /tmp/entropy_up.log 2>&1 \
    || { say "lab up failed for k=$k"; continue; }
  sleep 15
  bash scripts/detector.sh set --mode entropy --response block --dry-run true \
    </dev/null >/dev/null || { say "cannot select entropy"; continue; }
  for rep in 1 2 3; do
    out=$(python3 scripts/lab_runs.py --rate 1000 --kind syn --baseline 180 --duration 60 \
      --recovery 20 --tag "entropy_k${k}" 2>&1 | grep '^RUN ' | tail -1)
    if [[ "$out" == *"final=completed"* ]]; then echo "$out" >> /tmp/entropy_sweep.log
    else say "run failed: entropy k=$k rep $rep: ${out:-no output}"; fi
  done
done
say "restoring default detector settings"
timeout 600 docker compose up -d --build > /tmp/entropy_up.log 2>&1 || say "restore failed"
sleep 15
bash scripts/detector.sh set --mode llm --model llama3.2:3b --prompt lab --response block \
  --dry-run true </dev/null >/dev/null || say "cannot restore llm"

say "stage 4: escalate repetitions"
MATRIX_LOG=/tmp/matrix_escalate.log bash scripts/run_matrix.sh 5 escalate || say "stage 4 failed"

say "FIN"
echo "# FIN" >> "$LOG"
