#!/usr/bin/env python3
# ruff: noqa: E501  (CLI help and messages)
"""Export labeled flow samples from lab experiments (flow_stats + phase logs).

Ground truth comes from how the experiment was built, not from a model:
  label 1: flows attacker -> victim on the attack port during the attack window
  label 0: legitimate iperf3 flows (port 5201) outside/inside the attack window,
           and any flow before the attack starts (after a 30 s settling time)
Reverse RST replies and other flows inside the attack window are skipped
(their label is ambiguous). Output: CSV with the six model features + label,
ready for scripts/compare_llms.py --samples.

Usage: export_lab_samples.py logs/experiment_*_2*.json --out logs/lab_samples.csv
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timedelta
from pathlib import Path

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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiments", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, default=Path("logs/lab_samples.csv"))
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
    rows_out = []
    with connection, connection.cursor() as cursor:
        for path in args.experiments:
            record = json.loads(path.read_text())
            phases = {k: datetime.fromisoformat(v) for k, v in record["phases"].items()}
            cfg = record["args"]
            cursor.execute(
                "SELECT ts, host(ipv4_src), host(ipv4_dst), ip_proto, l4_dst_port, "
                "packet_count, byte_count, pktrate, byterate FROM flow_stats "
                "WHERE ts BETWEEN %s AND %s AND pktrate IS NOT NULL AND ip_proto IS NOT NULL "
                "AND l4_dst_port IS NOT NULL AND ipv4_src IS NOT NULL",
                (
                    phases["baseline_start"] + timedelta(seconds=30),
                    phases["recovery_end"],
                ),
            )
            attacker_hosts = cfg["attackers"].split(",")
            # attacker/victim IPs follow the topology spec: h2b -> 10.0.2.2, ...
            ip_of = {
                f"h{s}{c}": f"10.0.{s}.{i}"
                for s in (1, 2, 3)
                for i, c in enumerate("abc", 1)
            }
            attackers = {ip_of[h] for h in attacker_hosts}
            victim = ip_of[cfg["victim"]]
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
                in_attack = phases["attack_start"] <= ts <= phases["attack_end"]
                attack_flow = (
                    src in attackers and dst == victim and port == cfg["attack_port"]
                )
                if in_attack and attack_flow:
                    label = 1
                elif port == 5201 or ts < phases["attack_start"]:
                    label = 0
                else:
                    continue
                rows_out.append([pkts, byts, prate, brate, proto, port, label])
    connection.close()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow([*FEATURES, "label"])
        writer.writerows(rows_out)
    positives = sum(1 for row in rows_out if row[-1] == 1)
    print(
        f"{len(rows_out)} samples ({positives} attack, {len(rows_out) - positives} legitimate) -> {args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
