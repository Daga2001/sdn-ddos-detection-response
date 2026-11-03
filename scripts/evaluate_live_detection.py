#!/usr/bin/env python3
"""Evaluate the live detector run by run against the experiment's own ground truth.

Ground truth comes from how each run was built (attackers, victims and the
attack window recorded as lab events), never from a model:

  attack row   a flow_stats row attacker -> victim inside the attack window
  legit row    any other row, except the victim's replies to an attacker
               (their label is ambiguous)

Only rows the detector actually judged (prob_ddos not null) count as hits or
misses; `coverage` is the share of attack rows that got a verdict. Row-level
numbers are NOT independent samples (a flow is read at every poll), so the
headline unit is the run: was the attacker flagged, and how fast.

Usage: evaluate_live_detection.py --log /tmp/diverse.log --out logs/diverse
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
    """95 % Wilson interval for a proportion (small samples)."""

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
    cursor.execute("SELECT started_at, topology FROM lab_runs WHERE id = %s", (run_id,))
    found = cursor.fetchone()
    if found is None:
        return None
    _, topology = found
    ip_of = {h["name"]: h["ip"].split("/")[0] for h in topology["hosts"]}
    cursor.execute(
        "SELECT kind, ts, data FROM lab_events WHERE run_id = %s "
        "AND kind IN ('attack_started', 'attack_stopped', 'detection') ORDER BY ts",
        (run_id,),
    )
    events = cursor.fetchall()
    starts = [(ts, d) for kind, ts, d in events if kind == "attack_started"]
    stops = [ts for kind, ts, _ in events if kind == "attack_stopped"]
    if not starts or not stops:
        return None
    a0, config = starts[0]
    a1 = stops[0]
    attackers = {ip_of[h] for h in config["attackers"]}
    victims = {ip_of[h] for h in config["victims"]}

    cursor.execute(
        "SELECT ts, host(ipv4_src), host(ipv4_dst), pktrate, prob_ddos, label "
        "FROM flow_stats WHERE run_id = %s AND ipv4_src IS NOT NULL "
        "AND pktrate IS NOT NULL",
        (run_id,),
    )
    attack_all = attack_eval = attack_flag = 0
    legit_eval = legit_flag = 0
    legit_sources = set()
    attack_rates: List[float] = []
    for ts, src, dst, pktrate, prob, label in cursor.fetchall():
        is_attack = src in attackers and dst in victims and a0 <= ts <= a1
        if is_attack:
            attack_all += 1
            attack_rates.append(float(pktrate))
            if prob is not None:
                attack_eval += 1
                attack_flag += int(label == 1)
        elif src in attackers or (src in victims and dst in attackers):
            continue
        elif prob is not None:
            legit_eval += 1
            if label == 1:
                legit_flag += 1
                legit_sources.add(src)
    delays = [
        (ts - a0).total_seconds()
        for kind, ts, d in events
        if kind == "detection" and d.get("ipv4_src") in attackers and ts >= a0
    ]
    return {
        "tag": tag,
        "kind": config["traffic"][0],
        "rate": config["rate"],
        "attackers": len(attackers),
        "measured_pktrate_median": statistics.median(attack_rates)
        if attack_rates
        else None,
        "attack_rows": attack_all,
        "attack_rows_judged": attack_eval,
        "attack_rows_flagged": attack_flag,
        "attacker_detected": 1 if delays else 0,
        "detect_delay_s": min(delays) if delays else None,
        "legit_rows_judged": legit_eval,
        "legit_rows_flagged": legit_flag,
        "legit_sources_flagged": len(legit_sources),
    }


def pct(hits: int, total: int) -> str:
    return "-" if total == 0 else f"{100 * hits / total:.0f}%"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=Path("logs/diverse"))
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
        f"{'run':<20}{'rate':>5}{'kind':>5}{'att':>4}{'pkt/s medido':>13}"
        f"{'filas ataque (juzgadas/total)':>31}{'acierto filas':>14}{'detectado':>10}"
        f"{'retraso':>8}{'legit marcadas':>16}{'fuentes legit':>14}"
    )
    for r in results:
        rate = r["measured_pktrate_median"]
        measured = "-" if rate is None else f"{rate:.0f}"
        delay = "-" if r["detect_delay_s"] is None else f"{r['detect_delay_s']:.0f}s"
        detected = "SI" if r["attacker_detected"] else "NO"
        hit_rate = pct(r["attack_rows_flagged"], r["attack_rows_judged"])
        print(
            f"{r['tag']:<20}{r['rate']:>5}{r['kind']:>5}{r['attackers']:>4}"
            f"{measured:>13}"
            f"{r['attack_rows_judged']:>14}/{r['attack_rows']:<16}"
            f"{hit_rate:>14}{detected:>10}{delay:>8}"
            f"{r['legit_rows_flagged']:>10}/{r['legit_rows_judged']:<5}"
            f"{r['legit_sources_flagged']:>14}"
        )

    print("\n== por tasa nominal por atacante (unidad: corrida) ==")
    by_rate: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for r in results:
        by_rate[r["rate"]].append(r)
    for rate in sorted(by_rate):
        items = by_rate[rate]
        hits = sum(r["attacker_detected"] for r in items)
        low, high = wilson(hits, len(items))
        flagged = sum(r["attack_rows_flagged"] for r in items)
        judged = sum(r["attack_rows_judged"] for r in items)
        print(
            f"  {rate:>5} pkt/s: atacante detectado en {hits}/{len(items)} corridas "
            f"(IC95 {100 * low:.0f}-{100 * high:.0f}%), "
            f"filas acertadas {pct(flagged, judged)} ({flagged}/{judged})"
        )
    legit_flag = sum(r["legit_rows_flagged"] for r in results)
    legit_judged = sum(r["legit_rows_judged"] for r in results)
    sources = [r["legit_sources_flagged"] for r in results]
    print(
        f"\n== falsas alarmas ==\n"
        f"  filas legitimas marcadas: {legit_flag}/{legit_judged} "
        f"({pct(legit_flag, legit_judged)}); clientes legitimos marcados por corrida: "
        f"media {statistics.fmean(sources):.1f}, maximo {max(sources)}"
    )
    print(f"\nper-run: {args.out}_runs.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
