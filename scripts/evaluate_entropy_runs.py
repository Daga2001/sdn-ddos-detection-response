#!/usr/bin/env python3
# ruff: noqa: E501  (CLI messages)
"""Evaluate the entropy detector run by run against the experiment's ground truth.

Uses the entropy decisions the controller stored (one per 10 s window) and the
attack window recorded as lab events:

  false alarm   a confirmed alarm in a window that ends before the attack starts
  detection     a confirmed alarm during the attack whose candidates include an
                attacker; delay = seconds from the attack start
  collateral    legitimate hosts named as candidates during the run (a response
                would have acted on them)

Input is the log written by lab_runs.py (tag = condition, e.g. entropy_k1.0).
Usage: evaluate_entropy_runs.py --log /tmp/entropy_sweep.log --out logs/entropy
"""

from __future__ import annotations

import argparse
import csv
import math
import re
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psycopg2

from sdn_ddos.config import DatabaseSettings

RUN_LINE = re.compile(
    r"^RUN (?P<id>[0-9a-f-]{36}) .*?final=(?P<final>\S+)(?: tag=(?P<tag>\S*))?"
)


def parse_log(path: Path) -> List[Tuple[str, str]]:
    runs = []
    for line in path.read_text().splitlines():
        found = RUN_LINE.match(line)
        if found and found["final"] == "completed":
            runs.append((found["id"], found["tag"] or "sin-etiqueta"))
    return runs


def wilson(hits: int, total: int) -> Tuple[float, float]:
    if total == 0:
        return (math.nan, math.nan)
    z = 1.96
    p = hits / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = (
        z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    )
    return (max(0.0, center - margin), min(1.0, center + margin))


def evaluate_run(cursor: Any, run_id: str, tag: str) -> Optional[Dict[str, Any]]:
    cursor.execute(
        "SELECT started_at, ended_at, topology FROM lab_runs WHERE id = %s", (run_id,)
    )
    found = cursor.fetchone()
    if found is None:
        return None
    started_at, ended_at, topology = found
    ip_of = {h["name"]: h["ip"].split("/")[0] for h in topology["hosts"]}
    cursor.execute(
        "SELECT kind, ts, data FROM lab_events WHERE run_id = %s "
        "AND kind IN ('attack_started', 'attack_stopped') ORDER BY ts",
        (run_id,),
    )
    events = {kind: (ts, data) for kind, ts, data in cursor.fetchall()}
    if "attack_started" not in events or "attack_stopped" not in events:
        return None
    a0, config = events["attack_started"]
    a1 = events["attack_stopped"][0]
    attackers = {ip_of[h] for h in config["attackers"]}
    victims = {ip_of[h] for h in config["victims"]}

    cursor.execute(
        "SELECT ts, verdict, details FROM detection_decisions WHERE detector = 'entropy' "
        "AND ts BETWEEN %s AND %s ORDER BY ts",
        (started_at, ended_at),
    )
    windows = cursor.fetchall()
    evaluated = [(ts, v, d) for ts, v, d in windows if d.get("reason") == "evaluated"]
    baseline = [w for w in evaluated if w[0] < a0]
    attack = [w for w in evaluated if a0 <= w[0] <= a1]
    false_alarms = sum(1 for _, verdict, _ in baseline if verdict)
    suspicious_baseline = sum(1 for _, _, d in baseline if d.get("suspicious"))
    delays = [
        (ts - a0).total_seconds()
        for ts, verdict, d in attack
        if verdict and attackers & set(d.get("candidates") or [])
    ]
    legit_candidates = set()
    for _, verdict, d in evaluated:
        if verdict:
            legit_candidates |= set(d.get("candidates") or []) - attackers - victims
    victim_named = any(
        set(d.get("candidates") or []) & victims
        for _, verdict, d in evaluated
        if verdict
    )
    return {
        "tag": tag,
        "windows_evaluated": len(evaluated),
        "baseline_windows": len(baseline),
        "baseline_suspicious": suspicious_baseline,
        "baseline_false_alarms": false_alarms,
        "attack_windows": len(attack),
        "attacker_detected": 1 if delays else 0,
        "detect_delay_s": min(delays) if delays else None,
        "legit_candidates": len(legit_candidates),
        "victim_named_as_candidate": int(victim_named),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=Path("logs/entropy"))
    args = parser.parse_args()
    runs = parse_log(args.log)
    if not runs:
        raise SystemExit("no completed runs in the log")

    settings = DatabaseSettings.from_env()
    connection = psycopg2.connect(
        host=settings.host,
        port=settings.port,
        dbname=settings.database,
        user=settings.user,
        password=settings.password,
        connect_timeout=settings.connect_timeout_seconds,
    )
    results: List[Dict[str, Any]] = []
    with connection, connection.cursor() as cursor:
        for run_id, tag in runs:
            outcome = evaluate_run(cursor, run_id, tag)
            if outcome is not None:
                results.append({"run_id": run_id, **outcome})
    connection.close()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(f"{args.out}_runs.csv", "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(results[0]))
        writer.writeheader()
        writer.writerows(results)

    print(
        f"{'condicion':<16}{'ventanas base':>14}{'sospechosas':>12}{'falsas alarmas':>15}"
        f"{'detectado':>10}{'retraso':>9}{'legit candidatos':>17}{'victima nombrada':>17}"
    )
    for r in results:
        delay = "-" if r["detect_delay_s"] is None else f"{r['detect_delay_s']:.0f}s"
        print(
            f"{r['tag']:<16}{r['baseline_windows']:>14}{r['baseline_suspicious']:>12}"
            f"{r['baseline_false_alarms']:>15}{('SI' if r['attacker_detected'] else 'NO'):>10}"
            f"{delay:>9}{r['legit_candidates']:>17}{r['victim_named_as_candidate']:>17}"
        )
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in results:
        groups[r["tag"]].append(r)
    print("\n== por condicion ==")
    for tag in sorted(groups):
        items = groups[tag]
        hits = sum(r["attacker_detected"] for r in items)
        low, high = wilson(hits, len(items))
        delays = [r["detect_delay_s"] for r in items if r["detect_delay_s"] is not None]
        spread = f"{statistics.fmean(delays):.0f}s" if delays else "-"
        windows = sum(r["baseline_windows"] for r in items)
        false_alarms = sum(r["baseline_false_alarms"] for r in items)
        print(
            f"  {tag}: atacante detectado {hits}/{len(items)} (IC95 {100 * low:.0f}-{100 * high:.0f}%), "
            f"retraso medio {spread}, falsas alarmas en linea base {false_alarms}/{windows} ventanas, "
            f"legitimos nombrados candidatos {sum(r['legit_candidates'] for r in items)}"
        )
    print(f"\nper-run: {args.out}_runs.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
