#!/usr/bin/env bash
# Native Linux only. This helper never changes the existing database container.
set -euo pipefail
cd "$(dirname "$0")/.."
case "${1:-help}" in
  setup)
    umask 077
    mkdir -p .lab
    if [[ -e .lab/env ]]; then
      echo 'Keeping existing .lab/env credentials.'
    else
      # Atomic exclusive creation; credentials are not printed or committed.
      (set -o noclobber
       printf 'SDN_LAB_TOKEN=%s\nSDN_RUNNER_TOKEN=%s\nSDN_LAB_INFERENCE_KEY=%s\n' \
         "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" > .lab/env)
      echo 'Created private credentials in .lab/env. Use SDN_LAB_TOKEN to sign in.'
    fi
    ;;
  doctor)
    [[ "$(uname -s)" == Linux ]] || { echo 'Native Linux is required.'; exit 1; }
    docker info --format '{{.OperatingSystem}} | {{.Architecture}} | {{json .SecurityOptions}}'
    docker compose version
    lab_endpoint=$(docker context inspect --format '{{.Endpoints.docker.Host}}')
    if [[ "$lab_endpoint" != unix://* || -n "${DOCKER_HOST:-}" ]]; then
      echo 'Use a local native Linux Docker context, without DOCKER_HOST overrides.'; exit 1
    fi
    if docker info --format '{{.OperatingSystem}}' | grep -qi 'docker desktop'; then
      echo 'Docker Desktop is not supported by this native Linux runner.'; exit 1
    fi
    if docker info --format '{{json .SecurityOptions}}' | grep -q rootless; then
      echo 'Rootless Docker cannot run this Mininet runner.'; exit 1
    fi
    if [[ ! -d /sys/module/openvswitch ]]; then
      echo 'Open vSwitch is not loaded. On the intended isolated Linux host, run: sudo modprobe openvswitch'
      echo 'No host changes were made.'; exit 1
    fi
    echo 'Kernel OVS is loaded. Check .env, the external DB network, and apply database/migrations/002_lab.sql before starting.'
    ;;
  up|down|logs)
    echo 'This lifecycle command is retired. Use docker compose up, down, or logs from the repository root.' >&2
    exit 2
    ;;
  *) echo 'Usage: bash scripts/lab.sh {setup|doctor}'; exit 2 ;;
esac
