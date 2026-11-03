#!/usr/bin/env bash
# Start the campaign in the background on the VM, immune to the SSH session closing.
#   bash scripts/campaign/start.sh NAME SCENARIO_IDS...     e.g.  bash scripts/campaign/start.sh night1 M1 L1 E1
#   bash scripts/campaign/start.sh NAME --group R
# Output: ~/campaign/NAME.log (human summary) and ~/campaign/results.jsonl (one JSON per scenario).
cd "$(dirname "$0")/../.." || exit 1
name="${1:?usage: start.sh NAME ids...}"; shift
mkdir -p ~/campaign
set -a; . ./.env; set +a
export PYTHONPATH=src
nohup python3 scripts/campaign/lab_campaign.py "$@" --out ~/campaign/results.jsonl > ~/campaign/"$name".log 2>&1 < /dev/null &
echo "started $name (pid $!)"
