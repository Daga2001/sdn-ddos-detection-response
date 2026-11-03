#!/usr/bin/env python3
"""Detection metrics of one experiment, from `detection_decisions` + phase log.

Both detectors are compared at the same granularity: time buckets (default
10 s). A bucket is "positive" when the detector raised at least one positive
verdict inside it. Ground truth comes from the experiment JSON written by
run_experiment.py (baseline / attack / recovery phases; the attack window is
also stored in `attack_windows`).

    Detection Rate (DR)        = TP / (TP + FN)    attack buckets flagged
    False Alarm Rate (FAR)     = FP / (FP + TN)    non-attack buckets flagged
    Average detection time     = first positive verdict after attack start

Usage: report_experiment.py logs/experiment_entropy_<ts>.json [--bucket 10]
"""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import psycopg2

from sdn_ddos.config import DatabaseSettings


def parse(moment: str) -> datetime:
    return datetime.fromisoformat(moment)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiment", type=Path)
    parser.add_argument(
        "--bucket", type=float, default=10.0, help="bucket size in seconds"
    )
    args = parser.parse_args()

    record = json.loads(args.experiment.read_text())
    detector = record["mode"]
    if detector not in ("llm", "entropy"):
        raise SystemExit(f"experiment mode {detector!r} has no detector to evaluate")
    phases = {name: parse(value) for name, value in record["phases"].items()}
    start, end = phases["baseline_start"], phases["recovery_end"]
    attack_start, attack_end = phases["attack_start"], phases["attack_end"]

    settings = DatabaseSettings.from_env()
    connection = psycopg2.connect(
        host=settings.host,
        port=settings.port,
        dbname=settings.database,
        user=settings.user,
        password=settings.password,
        connect_timeout=settings.connect_timeout_seconds,
    )
    with connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT ts, verdict, latency_ms FROM detection_decisions "
            "WHERE detector = %s AND ts BETWEEN %s AND %s ORDER BY ts",
            (detector, start, end),
        )
        rows = cursor.fetchall()
    connection.close()

    buckets: Dict[int, List[bool]] = defaultdict(list)
    latencies: List[float] = []
    first_positive = None
    for ts, verdict, latency in rows:
        buckets[int((ts - start).total_seconds() // args.bucket)].append(bool(verdict))
        if latency is not None:
            latencies.append(latency)
        if verdict and ts >= attack_start and first_positive is None:
            first_positive = ts

    tp = fn = fp = tn = 0
    for index, verdicts in buckets.items():
        bucket_start = start.timestamp() + index * args.bucket
        in_attack = attack_start.timestamp() <= bucket_start <= attack_end.timestamp()
        positive = any(verdicts)
        if in_attack:
            tp += positive
            fn += not positive
        else:
            fp += positive
            tn += not positive

    def ratio(numerator: float, denominator: float) -> Any:
        return round(numerator / denominator, 3) if denominator else None

    report = {
        "detector": detector,
        "decisions": len(rows),
        "buckets": {"TP": tp, "FN": fn, "FP": fp, "TN": tn},
        "DR": ratio(tp, tp + fn),
        "FAR": ratio(fp, fp + tn),
        "precision": ratio(tp, tp + fp),
        "detection_time_s": (
            round((first_positive - attack_start).total_seconds(), 1)
            if first_positive
            else None
        ),
        "mean_decision_latency_ms": round(sum(latencies) / len(latencies), 1)
        if latencies
        else None,
        "attack_window_s": round((attack_end - attack_start).total_seconds(), 1),
        "bucket_s": args.bucket,
    }
    print(json.dumps(report, indent=2))
    out = args.experiment.with_name(args.experiment.stem + "_report.json")
    out.write_text(json.dumps(report, indent=2))
    print(f"saved: {out}")
    return 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    raise SystemExit(main())
