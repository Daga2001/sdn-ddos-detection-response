#!/usr/bin/env bash
# Inspect/choose the detection service's active mode and LLM. Run on the VM after
# scripts/lab_detector.sh up. Changes apply to the NEXT lab run (Observe/Start):
# the controller reads the mode when it starts.
#
#   bash scripts/detector.sh status
#   bash scripts/detector.sh models
#   bash scripts/detector.sh set --mode llm --model qwen2.5:3b
#   bash scripts/detector.sh set --mode entropy
#   bash scripts/detector.sh set --prompt lab      # prompt calibration: insdn | lab
#   bash scripts/detector.sh set --response escalate --dry-run false   # response policy
set -euo pipefail
cd "$(dirname "$0")/.."
compose=(docker compose --env-file .env --env-file .lab/env -f compose.lab.yaml -f compose.detector.yaml)

call() { # METHOD PATH [JSON]; the API key never leaves the container
  "${compose[@]}" exec -T detector /app/.venv/bin/python -c '
import json, os, sys, urllib.error, urllib.request
method, path = sys.argv[1], sys.argv[2]
body = sys.argv[3].encode() if len(sys.argv) > 3 else None
request = urllib.request.Request(
    "http://127.0.0.1:8000" + path, data=body, method=method,
    headers={"X-Api-Key": os.environ["DDOS_API_KEY"], "Content-Type": "application/json"})
try:
    print(json.dumps(json.load(urllib.request.urlopen(request, timeout=15)), indent=2))
except urllib.error.HTTPError as error:
    print(error.code, error.read().decode()); sys.exit(1)
' "$@"
}

case "${1:-help}" in
  status) call GET /health; call GET /config ;;
  models) call GET /models ;;
  set)
    shift
    mode=""; model=""; prompt=""; response=""; dry=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --mode) mode="${2:?--mode needs a value}"; shift 2 ;;
        --model) model="${2:?--model needs a value}"; shift 2 ;;
        --prompt) prompt="${2:?--prompt needs a value}"; shift 2 ;;
        --response) response="${2:?--response needs a value}"; shift 2 ;;
        --dry-run) dry="${2:?--dry-run needs true or false}"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 2 ;;
      esac
    done
    [[ -n "$mode$model$prompt$response$dry" ]] || { echo 'Give at least one option'; exit 2; }
    [[ -z "$response" || "$response" =~ ^(block|rate_limit|escalate)$ ]] || { echo 'response must be block, rate_limit or escalate'; exit 2; }
    [[ -z "$dry" || "$dry" =~ ^(true|false)$ ]] || { echo '--dry-run must be true or false'; exit 2; }
    [[ -z "$mode" || "$mode" =~ ^(llm|entropy|off)$ ]] || { echo 'mode must be llm, entropy or off'; exit 2; }
    [[ -z "$model" || "$model" =~ ^[A-Za-z0-9_.:/-]+$ ]] || { echo 'invalid model name'; exit 2; }
    [[ -z "$prompt" || "$prompt" =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'invalid prompt name'; exit 2; }
    parts=()
    [[ -z "$mode" ]] || parts+=("\"mode\": \"$mode\"")
    [[ -z "$model" ]] || parts+=("\"model\": \"$model\"")
    [[ -z "$prompt" ]] || parts+=("\"prompt\": \"$prompt\"")
    [[ -z "$response" ]] || parts+=("\"response\": \"$response\"")
    [[ -z "$dry" ]] || parts+=("\"dry_run\": $dry")
    payload="{$(IFS=,; echo "${parts[*]}")}"
    call PUT /config "$payload"
    ;;
  *) echo 'Usage: bash scripts/detector.sh {status|models|set [--mode llm|entropy|off] [--model NAME] [--prompt NAME] [--response block|rate_limit|escalate] [--dry-run true|false]}'; exit 2 ;;
esac
