#!/usr/bin/env bash
# Starts the LLM-backed inference service (Llama 3.2 3B via Ollama on the
# Windows host) instead of the Random Forest one. Point
# SDN_DDOS_SERVICE_URL at this service's host:port in .env so the
# controller uses the LLM's verdict as the final DDoS decision.
set -euo pipefail

host="${SDN_LLM_SERVICE_HOST:-127.0.0.1}"
port="${SDN_LLM_SERVICE_PORT:-8001}"

exec uv run uvicorn sdn_ddos.detection.llm_api:app --host "$host" --port "$port"
