#!/usr/bin/env bash
# Abort a running campaign: kill the driver and stop the lab run it started.
cd "$(dirname "$0")/../.." || exit 1
pkill -f lab_campaign.py && echo "campaign driver stopped"
set -a; . ./.env; set +a
PYTHONPATH=src python3 - <<'PY'
import sys
sys.path.insert(0, "scripts")
from lab_runs import Lab, wait_idle
lab = Lab(); lab.login()
lab.call("POST", "/api/stop")
print("lab:", wait_idle(lab, 120).get("state"))
PY
