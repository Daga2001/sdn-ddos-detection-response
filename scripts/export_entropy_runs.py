#!/usr/bin/env python3
# ruff: noqa: E501
"""Write the runs.json that scripts/replay_entropy.py needs, from the lab database.

For every run that has `entropy_window` events (or the ones named on the command line) it
reads when the attack really started and stopped and describes the experiment, so a replay
can tell attack windows from normal ones. On the VM:

    set -a; . ./.env; set +a
    PYTHONPATH=src python3 scripts/export_entropy_runs.py --since 2026-10-19 > runs.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from sdn_ddos.config import DatabaseSettings

QUERY = """
SELECT r.id::text, r.settings,
       (SELECT min(ts) FROM lab_events WHERE run_id = r.id AND kind = 'attack_started'),
       (SELECT max(ts) FROM lab_events WHERE run_id = r.id AND kind = 'attack_stopped')
FROM lab_runs r
WHERE r.started_at >= %(since)s
  AND EXISTS (SELECT 1 FROM lab_events e WHERE e.run_id = r.id AND e.kind = 'entropy_window')
ORDER BY r.started_at
"""


def describe(settings: Dict[str, Any]) -> str:
    kind = "+".join(settings.get("traffic", ["?"]))
    return (
        f"{len(settings.get('attackers', []))} atk {kind} {settings.get('rate')} pkt/s"
        f" -> {len(settings.get('victims', []))} victim(s), {settings.get('duration')} s"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--since", default="2026-01-01", help="only runs started after this date"
    )
    parser.add_argument(
        "--benign-rate",
        type=float,
        default=2.0,
        help="runs sending at most this many pkt/s per attacker are not attacks",
    )
    parser.add_argument(
        "--topology",
        type=Path,
        help="the project's topology JSON (hosts with their IPs): adds the attackers' "
        "and victims' addresses so scripts/replay_entropy.py can score who was named",
    )
    args = parser.parse_args()
    addresses: Dict[str, str] = {}
    if args.topology is not None:
        hosts = json.loads(args.topology.read_text(encoding="utf-8"))["hosts"]
        addresses = {host["name"]: host["ip"].split("/")[0] for host in hosts}
    import psycopg2  # imported late: the database driver is only needed here

    database = DatabaseSettings.from_env()
    connection = psycopg2.connect(
        host=database.host,
        port=database.port,
        dbname=database.database,
        user=database.user,
        password=database.password,
    )
    runs: List[Optional[Dict[str, Any]]] = []
    with connection, connection.cursor() as cursor:
        cursor.execute(QUERY, {"since": args.since})
        for run_id, settings, started, stopped in cursor.fetchall():
            if started is None or stopped is None:
                continue
            settings = settings or {}
            runs.append(
                {
                    "run": run_id,
                    "label": describe(settings),
                    "a0": started.isoformat(),
                    "a1": stopped.isoformat(),
                    "benign": float(settings.get("rate") or 0) <= args.benign_rate,
                    "settings": settings.get("detection", {}).get("entropy", {}),
                    "attackers": [
                        addresses[n]
                        for n in settings.get("attackers", [])
                        if n in addresses
                    ],
                    "victims": [
                        addresses[n]
                        for n in settings.get("victims", [])
                        if n in addresses
                    ],
                }
            )
    json.dump(runs, sys.stdout, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
