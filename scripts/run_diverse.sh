#!/usr/bin/env bash
# Varied, held-out detection runs for the LLM (no mitigation, so the response never
# changes what the detector sees). Different topologies, attacker/victim positions,
# protocols, attacker counts and rates, with extra weight on the low rates where the
# prompt's thresholds (10 and 50 pkt/s) are expected to matter.
#
#   bash scripts/run_diverse.sh            # ~27 min, writes /tmp/diverse.log
#   python3 scripts/evaluate_live_detection.py --log /tmp/diverse.log --out logs/diverse
#
# Each line: tag | preset | attackers | victims | kind | rate (pkt/s per attacker, per victim)
set -uo pipefail
cd "$(dirname "$0")/.."
LOG="${DIVERSE_LOG:-/tmp/diverse.log}"
: > "$LOG"
echo "# diverse started=$(date -u +%FT%TZ)" >> "$LOG"

PLAN=(
  "ce_syn_20_1att|Connected enterprise|h1a|h1b|syn|20"
  "ce_udp_300_1att|Connected enterprise|h3a|h2c|udp|300"
  "ln_syn_50_1att|Linear network|h1|h6|syn|50"
  "ce_syn_100_1att|Connected enterprise|h2a|h3b|syn|100"
  "ce_udp_50_1att|Connected enterprise|h1a|h1b|udp|50"
  "sm_syn_100_1att|Small teaching network|h1|h2|syn|100"
  "ce_syn_1000_2att|Connected enterprise|h3a,h2a|h1c|syn|1000"
  "ce_udp_20_1att|Connected enterprise|h2b|h1a|udp|20"
  "ln_udp_100_1att|Linear network|h6|h1|udp|100"
  "ce_syn_50_1att|Connected enterprise|h1c|h3c|syn|50"
  "ce_udp_100_3att|Connected enterprise|h1a,h2a,h3a|h2b|udp|100"
  "ce_syn_80_1att|Connected enterprise|h2a|h1b|syn|80"
  "sm_udp_300_1att|Small teaching network|h2|h3|udp|300"
  "ln_syn_300_1att|Linear network|h3|h4|syn|300"
  "ce_syn_300_3att|Connected enterprise|h1a,h3a,h3b|h2c|syn|300"
  "ce_udp_1000_1att|Connected enterprise|h2c|h1b|udp|1000"
)

bash scripts/detector.sh set --mode llm --prompt lab --response block --dry-run true \
  </dev/null >/dev/null || { echo "# FAILED to configure the detector" >> "$LOG"; exit 1; }
sleep 5

for entry in "${PLAN[@]}"; do
  IFS='|' read -r tag preset attackers victims kind rate <<< "$entry"
  echo "# $tag $(date -u +%T)" >> "$LOG"
  for attempt in 1 2; do
    out=$(python3 scripts/lab_runs.py --preset "$preset" --attackers "$attackers" \
      --victims "$victims" --kind "$kind" --rate "$rate" --baseline 30 --duration 40 \
      --recovery 15 --tag "$tag" 2>&1 | grep '^RUN ' | tail -1)
    if [[ "$out" == *"final=completed"* ]]; then
      echo "$out" >> "$LOG"
      break
    fi
    echo "# retry $tag (attempt $attempt): ${out:-no output}" >> "$LOG"
    sleep 10
  done
done
echo "# FIN $(date -u +%FT%TZ)" >> "$LOG"
