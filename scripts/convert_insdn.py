#!/usr/bin/env python3
# ruff: noqa: E501  (CLI help and messages)
"""Convert InSDN CICFlowMeter CSVs to the six-feature + label format used by
scripts/compare_llms.py --samples.

InSDN (Elsawy et al.) labels several attack families beyond DDoS (Probe, DoS,
BFA, U2R, Web-Attack, BOTNET). Only rows labeled exactly "DDoS" (label=1) and
"Normal" (label=0) are kept -- the others are not floods, and our detectors
(entropy/LLM) are rate-based, so labeling them either way would misrepresent
what is being measured. Use --include-dos to also treat "DoS" (single-source
flood) rows as positive.

Column mapping (InSDN -> our 6 features):
    packet_count = Tot Fwd Pkts + Tot Bwd Pkts
    byte_count   = TotLen Fwd Pkts + TotLen Bwd Pkts
    pktrate      = Flow Pkts/s
    byterate     = Flow Byts/s
    ip_proto     = Protocol
    l4_dst_port  = Dst Port

Usage:
    convert_insdn.py Normal_data.csv OVS.csv metasploitable-2.csv \
        --out logs/insdn_samples.csv --per-class 300
"""

from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path
from typing import List, Tuple

FEATURES = (
    "packet_count",
    "byte_count",
    "pktrate",
    "byterate",
    "ip_proto",
    "l4_dst_port",
)
Row = Tuple[int, int, float, float, int, int, int]  # 6 features + label


def convert_file(path: Path, include_dos: bool) -> Tuple[List[Row], List[Row]]:
    positives: List[Row] = []
    negatives: List[Row] = []
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        for record in csv.DictReader(handle):
            label = record["Label"].strip()
            if label == "Normal":
                target = negatives
            elif label == "DDoS" or (include_dos and label == "DoS"):
                target = positives
            else:
                continue
            try:
                row: Row = (
                    int(float(record["Tot Fwd Pkts"]) + float(record["Tot Bwd Pkts"])),
                    int(
                        float(record["TotLen Fwd Pkts"])
                        + float(record["TotLen Bwd Pkts"])
                    ),
                    float(record["Flow Pkts/s"]),
                    float(record["Flow Byts/s"]),
                    int(float(record["Protocol"])),
                    int(float(record["Dst Port"])),
                    1 if target is positives else 0,
                )
            except (ValueError, KeyError):
                continue
            if (
                row[2] < 0
                or row[3] < 0
                or not (0 <= row[5] <= 65535)
                or not (0 <= row[4] <= 255)
            ):
                continue  # a handful of malformed CICFlowMeter rows
            target.append(row)
    return positives, negatives


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("csvs", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, default=Path("logs/insdn_samples.csv"))
    parser.add_argument(
        "--per-class",
        type=int,
        default=300,
        help="rows kept per class, after shuffling (0 = all)",
    )
    parser.add_argument(
        "--include-dos",
        action="store_true",
        help="treat single-source DoS rows as positive too",
    )
    parser.add_argument("--seed", type=int, default=13)
    args = parser.parse_args()

    all_positives: List[Row] = []
    all_negatives: List[Row] = []
    for path in args.csvs:
        positives, negatives = convert_file(path, args.include_dos)
        print(
            f"{path.name}: {len(positives)} attack rows, {len(negatives)} normal rows"
        )
        all_positives += positives
        all_negatives += negatives

    rng = random.Random(args.seed)
    rng.shuffle(all_positives)
    rng.shuffle(all_negatives)
    if args.per_class:
        all_positives = all_positives[: args.per_class]
        all_negatives = all_negatives[: args.per_class]
    rows = all_positives + all_negatives
    rng.shuffle(rows)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow([*FEATURES, "label"])
        writer.writerows(rows)
    print(
        f"kept: {len(all_positives)} attack + {len(all_negatives)} normal = {len(rows)} -> {args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
