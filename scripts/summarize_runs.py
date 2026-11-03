#!/usr/bin/env python3
"""Summarize graphical-lab runs per condition (mean and sample sd) from the database.

Input is the log written by `lab_runs.py` (`RUN <id> ... final=<state> tag=<cond>`)
or explicit `--run ID:TAG` pairs. Only completed runs with an attack window count.
Every number comes from recorded events, never from a model:

  availability   success rate and mean latency of the legitimate HTTP probes in
                 each phase (baseline / attack / recovery)
  load           mean traffic from the switch to the victim during the attack
  detection      whether and when an event flagged an attacker, and how many
                 legitimate sources were flagged
  response       whether and when the attacker was limited/blocked, and how many
                 legitimate sources were limited/blocked (dry-run actions apart)

Usage (on the VM, DB settings from .env):
  summarize_runs.py --log /tmp/matrix.log --out logs/matrix
"""

from __future__ import annotations

import argparse
import csv
import re
import statistics
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psycopg2

from sdn_ddos.config import DatabaseSettings

RUN_LINE = re.compile(
    r"^RUN (?P<id>[0-9a-f-]{36}) .*?final=(?P<final>\S+)(?: tag=(?P<tag>\S*))?"
)
METRICS = (
    "probes_attack",
    "succ_baseline",
    "succ_attack",
    "succ_recovery",
    "lat_baseline_ms",
    "lat_attack_ms",
    "lat_recovery_ms",
    "victim_kbps_attack",
    "attacker_detected",
    "detect_delay_s",
    "fp_sources_detected",
    "attacker_responded",
    "response_delay_s",
    "attacker_blocked",
    "collateral_limited",
    "collateral_blocked",
    "dry_run_actions",
)
SHOWN = (
    "succ_attack",
    "succ_recovery",
    "lat_attack_ms",
    "victim_kbps_attack",
    "detect_delay_s",
    "response_delay_s",
    "collateral_limited",
    "collateral_blocked",
    "fp_sources_detected",
)


def parse_log(path: Path) -> List[Tuple[str, str]]:
    runs = []
    for line in path.read_text().splitlines():
        found = RUN_LINE.match(line)
        if found and found["final"] == "completed":
            runs.append((found["id"], found["tag"] or "sin-etiqueta"))
    return runs


def _mean(values: List[float]) -> Optional[float]:
    return statistics.fmean(values) if values else None


def _percent(flags: List[bool]) -> Optional[float]:
    return 100.0 * sum(flags) / len(flags) if flags else None


def run_metrics(cursor: Any, run_id: str) -> Optional[Dict[str, Optional[float]]]:
    cursor.execute(
        "SELECT started_at, ended_at, topology FROM lab_runs WHERE id = %s", (run_id,)
    )
    found = cursor.fetchone()
    if found is None:
        return None
    started_at, ended_at, topology = found
    ip_of = {h["name"]: h["ip"].split("/")[0] for h in topology["hosts"]}
    cursor.execute(
        "SELECT kind, ts, data FROM lab_events WHERE run_id = %s AND kind IN "
        "('attack_started', 'attack_stopped', 'service', 'detection', 'links') "
        "ORDER BY ts",
        (run_id,),
    )
    events = cursor.fetchall()
    starts = [(ts, data) for kind, ts, data in events if kind == "attack_started"]
    stops = [ts for kind, ts, _ in events if kind == "attack_stopped"]
    if not starts or not stops:
        return None
    a0, start_data = starts[0]
    a1 = stops[0]
    attackers = {ip_of[h] for h in start_data["attackers"]}
    victim = start_data["victims"][0]

    def seconds(moment: datetime, since: datetime) -> float:
        return (moment - since).total_seconds()

    out: Dict[str, Optional[float]] = {name: None for name in METRICS}
    phases: Dict[str, List[Tuple[bool, Optional[float]]]] = defaultdict(list)
    kbps: List[float] = []
    detected: List[float] = []
    flagged_legit = set()
    for kind, ts, data in events:
        if kind == "service":
            phase = "baseline" if ts < a0 else ("attack" if ts <= a1 else "recovery")
            phases[phase].append((bool(data["success"]), data.get("latency_ms")))
        elif kind == "links" and a0 <= ts <= a1 and seconds(ts, a0) >= 10:
            # skip the first 10 s so the average describes the sustained attack
            for link in data["links"]:
                if link["link_id"] == f"link-{victim}":
                    kbps.append(link["rates"]["tx_bps"] / 1000.0)
        elif kind == "detection":
            source = data.get("ipv4_src")
            if source in attackers:
                detected.append(seconds(ts, a0))
            elif source:
                flagged_legit.add(source)
    for phase in ("baseline", "attack", "recovery"):
        probes = phases[phase]
        out[f"succ_{phase}"] = _percent([ok for ok, _ in probes])
        out[f"lat_{phase}_ms"] = _mean(
            [float(ms) for ok, ms in probes if ok and ms is not None]
        )
    out["probes_attack"] = float(len(phases["attack"]))
    out["victim_kbps_attack"] = _mean(kbps)
    out["attacker_detected"] = 1.0 if detected else 0.0
    out["detect_delay_s"] = min(detected) if detected else None
    out["fp_sources_detected"] = float(len(flagged_legit))

    cursor.execute(
        "SELECT ts, host(ipv4_src), action FROM mitigation_events "
        "WHERE ts BETWEEN %s AND %s ORDER BY ts",
        (started_at, ended_at),
    )
    actions = cursor.fetchall()
    on_attacker = [(ts, a) for ts, src, a in actions if src in attackers]
    real = [(ts, a) for ts, a in on_attacker if not a.startswith("dry_run_")]
    out["attacker_responded"] = 1.0 if real else 0.0
    out["response_delay_s"] = seconds(real[0][0], a0) if real else None
    out["attacker_blocked"] = (
        1.0 if any(a == "temporary_drop" for _, a in real) else 0.0
    )
    others = [(src, a) for _, src, a in actions if src not in attackers]
    out["collateral_limited"] = float(
        len({s for s, a in others if a.startswith("rate_limit")})
    )
    out["collateral_blocked"] = float(
        len({s for s, a in others if a == "temporary_drop"})
    )
    out["dry_run_actions"] = float(
        sum(1 for _, _, a in actions if a.startswith("dry_run_"))
    )
    return out


def aggregate(
    values: List[Optional[float]],
) -> Tuple[Optional[float], Optional[float], int]:
    defined = [v for v in values if v is not None]
    if not defined:
        return None, None, 0
    sd = statistics.stdev(defined) if len(defined) > 1 else None
    return statistics.fmean(defined), sd, len(defined)


def cell(values: List[Optional[float]], total: int) -> str:
    mean, sd, n = aggregate(values)
    if mean is None:
        return "-"
    text = f"{mean:.1f}" if sd is None else f"{mean:.1f}±{sd:.1f}"
    return text if n == total else f"{text} ({n}/{total})"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, help="lab_runs.py output")
    parser.add_argument("--run", action="append", default=[], help="RUN_ID:TAG")
    parser.add_argument("--out", type=Path, default=Path("logs/matrix"))
    args = parser.parse_args()

    runs = parse_log(args.log) if args.log else []
    runs += [tuple(item.split(":", 1)) for item in args.run]  # type: ignore[misc]
    if not runs:
        raise SystemExit("no completed runs to summarize")

    settings = DatabaseSettings.from_env()
    connection = psycopg2.connect(
        host=settings.host,
        port=settings.port,
        dbname=settings.database,
        user=settings.user,
        password=settings.password,
        connect_timeout=settings.connect_timeout_seconds,
    )
    per_tag: Dict[str, List[Dict[str, Optional[float]]]] = defaultdict(list)
    rows: List[Dict[str, Any]] = []
    with connection, connection.cursor() as cursor:
        for run_id, tag in runs:
            metrics = run_metrics(cursor, run_id)
            if metrics is None:
                print(f"skip {run_id}: no complete attack window")
                continue
            per_tag[tag].append(metrics)
            rows.append({"run_id": run_id, "tag": tag, **metrics})
    connection.close()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(f"{args.out}_runs.csv", "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["run_id", "tag", *METRICS])
        writer.writeheader()
        writer.writerows(rows)
    with open(f"{args.out}_summary.csv", "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["tag", "metric", "n_runs", "n_defined", "mean", "sd"])
        for tag, items in per_tag.items():
            for name in METRICS:
                mean, sd, n = aggregate([m[name] for m in items])
                writer.writerow([tag, name, len(items), n, mean, sd])

    print(f"{'condition':<16}{'n':>3}  " + "  ".join(f"{m:>22}" for m in SHOWN))
    for tag, items in sorted(per_tag.items()):
        cells = [cell([m[name] for m in items], len(items)) for name in SHOWN]
        print(f"{tag:<16}{len(items):>3}  " + "  ".join(f"{c:>22}" for c in cells))
    print(f"\nper-run: {args.out}_runs.csv   per-condition: {args.out}_summary.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
