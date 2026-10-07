#!/usr/bin/env python3
# ruff: noqa: E501  (CLI help and messages)
"""Export labeled flow samples from graphical-lab runs (flow_stats + lab_events).

Ground truth comes from how the experiment was built, never from a model:
  label 1: attacker -> victim flow while the attack is active
           (between `attack_started` and `attack_stopped` of the run)
  label 0: any flow that does not involve an attacker as source: legitimate
           client probes (inside or outside the attack window) and baseline
Skipped as ambiguous: the first SETTLE seconds, rows without a rate (first
observation of a flow), the victim's replies to attackers during the attack,
and the attacker flow right after the attack stops (rate decays over a poll).

Usage (on the VM):  python3 scripts/export_gui_samples.py RUN_ID [RUN_ID ...] --out logs/gui_samples.csv
Needs DB access (SDN_PG_* from .env). Output columns: six features + label + run_id.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, List, Set

import psycopg2

from sdn_ddos.config import DatabaseSettings

FEATURES = (
    "packet_count",
    "byte_count",
    "pktrate",
    "byterate",
    "ip_proto",
    "l4_dst_port",
)
SETTLE_SECONDS = 15
DECAY_SECONDS = 10


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runs", nargs="+")
    parser.add_argument("--out", type=Path, default=Path("logs/gui_samples.csv"))
    args = parser.parse_args()

    settings = DatabaseSettings.from_env()
    connection = psycopg2.connect(
        host=settings.host,
        port=settings.port,
        dbname=settings.database,
        user=settings.user,
        password=settings.password,
        connect_timeout=settings.connect_timeout_seconds,
    )
    rows_out: List[list] = []
    with connection, connection.cursor() as cursor:
        for run_id in args.runs:
            cursor.execute(
                "SELECT started_at, topology FROM lab_runs WHERE id = %s", (run_id,)
            )
            found = cursor.fetchone()
            if found is None:
                raise SystemExit(f"run {run_id} not found")
            started_at, topology = found
            topology = topology if isinstance(topology, dict) else json.loads(topology)
            ip_of: Dict[str, str] = {
                h["name"]: h["ip"].split("/")[0] for h in topology["hosts"]
            }
            cursor.execute(
                "SELECT kind, ts, data FROM lab_events WHERE run_id = %s "
                "AND kind IN ('attack_started', 'attack_stopped') ORDER BY ts",
                (run_id,),
            )
            events = {kind: (ts, data) for kind, ts, data in cursor.fetchall()}
            if "attack_started" not in events or "attack_stopped" not in events:
                print(f"skip {run_id}: no complete attack window")
                continue
            attack_start, start_data = events["attack_started"]
            attack_end = events["attack_stopped"][0]
            attackers: Set[str] = {ip_of[h] for h in start_data["attackers"]}
            victims: Set[str] = {ip_of[h] for h in start_data["victims"]}
            cursor.execute(
                "SELECT ts, host(ipv4_src), host(ipv4_dst), ip_proto, l4_dst_port, "
                "packet_count, byte_count, pktrate, byterate FROM flow_stats "
                "WHERE run_id = %s AND pktrate IS NOT NULL AND ip_proto IS NOT NULL "
                "AND l4_dst_port IS NOT NULL AND ipv4_src IS NOT NULL "
                "AND ts >= %s + make_interval(secs => %s)",
                (run_id, started_at, SETTLE_SECONDS),
            )
            kept = 0
            for (
                ts,
                src,
                dst,
                proto,
                port,
                pkts,
                byts,
                prate,
                brate,
            ) in cursor.fetchall():
                active = attack_start <= ts <= attack_end
                if src in attackers and dst in victims:
                    if not active:
                        continue
                    label = 1
                elif (src in victims and dst in attackers) or src in attackers:
                    continue
                else:
                    label = 0
                rows_out.append([pkts, byts, prate, brate, proto, port, label, run_id])
                kept += 1
            print(f"{run_id}: {kept} samples")
    connection.close()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow([*FEATURES, "label", "run_id"])
        writer.writerows(rows_out)
    positives = sum(1 for row in rows_out if row[6] == 1)
    print(
        f"{len(rows_out)} samples ({positives} attack, {len(rows_out) - positives} legitimate) -> {args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
