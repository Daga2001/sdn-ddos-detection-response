#!/usr/bin/env bash
# Shared helpers (source, don't execute) to start/stop the detection stack for
# a chosen mode: llm | entropy | off. Expects REPO_ROOT and LOG_DIR to be set
# and .env to be already exported (set -a; . .env; set +a).

start_stack() {
  local mode="$1"
  case "$mode" in
    llm|entropy|off) ;;
    *) echo "invalid detection mode: $mode (use llm|entropy|off)" >&2; return 1 ;;
  esac
  export SDN_DETECTION_MODE="$mode"
  export PGSERVICEFILE="$REPO_ROOT/config/pg_service.conf" PGSERVICE=sdn
  LLM_API_PID=""
  CONTROLLER_PID=""

  sudo -n mn -c > /dev/null 2>&1 || true

  if [ "$mode" = "llm" ]; then
    local api_host="${SDN_LLM_SERVICE_HOST:-127.0.0.1}" api_port="${SDN_LLM_SERVICE_PORT:-8001}"
    "$REPO_ROOT/.venv/bin/uvicorn" sdn_ddos.detection.llm_api:app \
      --host "$api_host" --port "$api_port" --app-dir "$REPO_ROOT/src" \
      > "$LOG_DIR/llm_api.log" 2>&1 &
    LLM_API_PID=$!
    for _ in $(seq 1 20); do
      curl -s -m 2 "http://$api_host:$api_port/health" | grep -q '"ready"' && break
      sleep 1
    done
    # Load the model into memory now so the first samples do not time out.
    curl -s -m 90 "${SDN_LLM_OLLAMA_URL:-http://192.168.83.1:11434}/api/generate" \
      -d "{\"model\": \"${SDN_LLM_MODEL:-llama3.2:3b}\", \"prompt\": \"ok\", \"stream\": false}" \
      > /dev/null || echo "warning: could not warm up the LLM" >&2
  fi

  PYTHONPATH="$REPO_ROOT/src" "$REPO_ROOT/.venv-ryu/bin/ryu-manager" --verbose \
    "$REPO_ROOT/src/sdn_ddos/controller/app_modes.py" > "$LOG_DIR/controller.log" 2>&1 &
  CONTROLLER_PID=$!
  sleep 4   # let the controller bind :6653 before Mininet connects
}

stop_stack() {
  for pid in "${CONTROLLER_PID:-}" "${LLM_API_PID:-}"; do
    [ -n "$pid" ] && kill "$pid" > /dev/null 2>&1 || true
  done
  for pid in "${CONTROLLER_PID:-}" "${LLM_API_PID:-}"; do
    [ -n "$pid" ] && wait "$pid" 2> /dev/null || true
  done
}
