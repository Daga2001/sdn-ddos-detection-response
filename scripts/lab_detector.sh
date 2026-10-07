#!/usr/bin/env bash
# Graphical lab + our detection service (LLM / entropy). Native Linux only.
# Reuses the tutor's scripts/lab.sh for setup/doctor and adds compose.detector.yaml.
set -euo pipefail
cd "$(dirname "$0")/.."
compose=(docker compose --env-file .env --env-file .lab/env -f compose.lab.yaml -f compose.detector.yaml)
case "${1:-help}" in
  setup|doctor)
    bash scripts/lab.sh "$1"
    ;;
  up)
    [[ -f .env && -f .lab/env ]] || { echo 'Provide .env and run: bash scripts/lab_detector.sh setup'; exit 1; }
    bash scripts/lab.sh doctor
    chmod +x containers/ryu-modes.sh
    "${compose[@]}" up --build -d
    echo 'Workspace: http://localhost:8080 — token in .lab/env (SDN_LAB_TOKEN).'
    echo 'Pick the detector with: bash scripts/detector.sh status | set --mode llm|entropy|off [--model NAME]'
    ;;
  down)
    "${compose[@]}" down --timeout 45
    ;;
  logs)
    "${compose[@]}" logs --tail 100 "${@:2}"
    ;;
  ps)
    "${compose[@]}" ps
    ;;
  *) echo 'Usage: bash scripts/lab_detector.sh {setup|doctor|up|down|logs [service]|ps}'; exit 2 ;;
esac
