#!/usr/bin/env bash
set -euo pipefail

if ! command -v ryu-manager >/dev/null 2>&1; then
  echo "ryu-manager is unavailable; follow docs/setup.md for the isolated Ryu environment" >&2
  exit 1
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="${repository_root}/src${PYTHONPATH:+:${PYTHONPATH}}"
case "${SDN_MATCH_L4_PORTS:-}" in
  true|false) ;;
  *)
    echo "Choose the forwarding rules: set SDN_MATCH_L4_PORTS to true (per-port, Experiment A) or false (port-free, Experiment B)." >&2
    exit 1
    ;;
esac

exec ryu-manager --verbose "${repository_root}/src/sdn_ddos/controller/app.py"
