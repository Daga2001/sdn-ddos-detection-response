#!/usr/bin/env bash
# Summary of the latest (or a given) lab run: phases, who the detector flagged,
# and how many decisions were true/false per phase. Run on the VM:
#   bash scripts/last_run_report.sh [run_id]
set -euo pipefail
cd "$(dirname "$0")/.."
psql_lab() { docker exec -i sdn-ddos-detection-response-postgres-1 psql -U sdn_user -d sdn_monitor "$@"; }
RUN="${1:-}"
if [[ -z "$RUN" ]]; then
  RUN=$(psql_lab -t -A -c "select id from lab_runs order by started_at desc limit 1")
fi
[[ "$RUN" =~ ^[0-9a-f-]{36}$ ]] || { echo "invalid run id"; exit 2; }
psql_lab -v run="$RUN" <<'SQL'
\echo === corrida
select id, status, started_at, round(extract(epoch from coalesce(ended_at, now()) - started_at)) as segundos
from lab_runs where id = :'run';
\echo === fases (segundos desde el inicio)
select round(extract(epoch from e.ts - r.started_at)) as seg, e.kind, e.data->>'phase' as fase
from lab_events e join lab_runs r on r.id = e.run_id
where e.run_id = :'run' and e.kind in ('phase', 'attack_started', 'attack_stopped') order by e.ts;
\echo === a quien marco el detector como ataque (eventos Detection events de la GUI)
select e.data->>'ipv4_src' as origen, e.data->>'ipv4_dst' as destino, count(*) as veces,
       min(round(extract(epoch from e.ts - r.started_at))) as primer_seg
from lab_events e join lab_runs r on r.id = e.run_id
where e.run_id = :'run' and e.kind = 'detection' group by 1, 2 order by veces desc;
\echo === decisiones guardadas por detector y veredicto
select d.detector, d.verdict, count(*) as n
from detection_decisions d join lab_runs r on r.id = :'run'
where d.ts between r.started_at and coalesce(r.ended_at, now()) group by 1, 2 order by 1, 2;
SQL
