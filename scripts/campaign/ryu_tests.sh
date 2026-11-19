#!/usr/bin/env bash
# Controller tests need Ryu, which only the runner container has (Python 3.9). pytest is installed
# into /tmp/pt there on first use (pip install --target /tmp/pt pytest).
#
# The container is found, in this order, from SDN_RUNNER_CONTAINER, the historical name
# sdn-lab-runner-1, or the only running container whose name ends in -runner-1 (the Compose
# project name decides the prefix, e.g. sdn-ddos-detection-response-runner-1). Set DOCKER="sudo docker"
# when the Docker socket needs it.
set -euo pipefail
cd "$(dirname "$0")/../.."
DOCKER="${DOCKER:-docker}"

running="$($DOCKER ps --format '{{.Names}}')"
runner="${SDN_RUNNER_CONTAINER:-${SDN_LAB_RUNNER_CONTAINER:-}}"
if [ -z "$runner" ]; then
  if printf '%s\n' "$running" | grep -qx 'sdn-lab-runner-1'; then
    runner="sdn-lab-runner-1"
  else
    matches="$(printf '%s\n' "$running" | grep -E -- '-runner-1$' || true)"
    if [ "$(printf '%s\n' "$matches" | grep -c .)" -ne 1 ]; then
      echo "ryu_tests: cannot tell which container is the runner; set SDN_RUNNER_CONTAINER" >&2
      exit 2
    fi
    runner="$matches"
  fi
fi
echo "ryu_tests: using container $runner"

$DOCKER exec "$runner" sh -c "rm -rf /tmp/t; mkdir -p /tmp/t; [ -d /tmp/pt ] || /opt/ryu/bin/pip install -q --target /tmp/pt pytest >/dev/null 2>&1"
$DOCKER cp src "$runner:/tmp/t/src"
$DOCKER cp tests "$runner:/tmp/t/tests"
$DOCKER exec "$runner" sh -c 'cd /tmp/t && PYTHONPATH=/tmp/t/src:/tmp/pt /opt/ryu/bin/python -W ignore -m pytest -q -p no:cacheprovider -o addopts="" tests/test_llm_async.py tests/test_llm_cache.py tests/test_app_modes_stats.py tests/test_controller_core.py tests/test_response.py tests/test_protected_names.py 2>&1 | tail -15'
