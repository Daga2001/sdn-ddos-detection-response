#!/usr/bin/env bash
# Show the LLM detector's most recent verdicts from the lab database.
#
#   bash scripts/llm_decisions.sh              last 20 verdicts
#   bash scripts/llm_decisions.sh 50           last 50
#   bash scripts/llm_decisions.sh 50 attacks   only the ones judged an attack
#   bash scripts/llm_decisions.sh follow       refresh every 2 s (Ctrl+C to stop)
#
# One row per flow the model judged: time, verdict, probability the model gave, the
# packet rate (pkt/s) it was shown, and whether the verdict came from the cache (the
# model is deterministic, so a flow it already judged is not sent again).
set -euo pipefail
cd "$(dirname "$0")/.."

CONTAINER="${SDN_POSTGRES_CONTAINER:-sdn-ddos-detection-response-postgres-1}"
if [[ "${1:-}" == "follow" ]]; then
  while true; do
    clear
    bash "$0" 15
    sleep 2
  done
fi
LIMIT="${1:-20}"
[[ "$LIMIT" =~ ^[0-9]+$ ]] || { echo "usage: $0 [N|follow] [attacks]"; exit 2; }
FILTER=""
[[ "${2:-}" == "attacks" ]] && FILTER="AND verdict"

docker exec -i "$CONTAINER" psql -U "${SDN_PG_USER:-sdn_user}" -d "${SDN_PG_DB:-sdn_monitor}" <<SQL
SELECT to_char(ts, 'HH24:MI:SS') AS hora,
       CASE WHEN verdict THEN 'ATAQUE' ELSE 'normal' END AS veredicto,
       round(score::numeric, 2) AS probabilidad,
       details->'sample'->>'pktrate' AS pkt_s,
       CASE WHEN (details->>'cached')::boolean THEN 'cache' ELSE 'modelo' END AS origen
FROM detection_decisions
WHERE detector = 'llm' ${FILTER}
ORDER BY ts DESC
LIMIT ${LIMIT};
SQL
