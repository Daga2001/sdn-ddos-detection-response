#!/usr/bin/env bash
# Controller tests need Ryu, which only the runner container has (Python 3.9). pytest is installed
# into /tmp/pt there on first use (pip install --target /tmp/pt pytest).
cd "$(dirname "$0")/../.."
R=${SDN_LAB_RUNNER_CONTAINER:-sdn-ddos-detection-response-runner-1}
docker exec "$R" sh -c "rm -rf /tmp/t; mkdir -p /tmp/t; [ -d /tmp/pt ] || /opt/ryu/bin/pip install -q --target /tmp/pt pytest >/dev/null 2>&1"
docker cp src "$R":/tmp/t/src
docker cp tests "$R":/tmp/t/tests
docker exec "$R" sh -c 'cd /tmp/t && PYTHONPATH=/tmp/t/src:/tmp/pt /opt/ryu/bin/python -W ignore -m pytest -q -p no:cacheprovider -o addopts="" tests/test_llm_async.py tests/test_llm_cache.py tests/test_app_modes_stats.py tests/test_controller_core.py tests/test_response.py 2>&1 | tail -15'
