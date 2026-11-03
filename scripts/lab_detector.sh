#!/usr/bin/env bash
# Retired: there is only one supported Compose entry point.
set -euo pipefail
echo 'This wrapper is retired. Use docker compose up, down, logs, or ps from the repository root.' >&2
exit 2
