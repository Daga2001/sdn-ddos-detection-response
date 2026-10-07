#!/usr/bin/env python3
# ruff: noqa: E501  (CLI help and messages)
"""Pick real few-shot examples from a labeled sample CSV and remove them from
the evaluation set (no leakage between the prompt's examples and the test).

Picks, per class, the rows at the 10th/50th/90th percentile of `pktrate` --
gives the model the range it actually needs to separate, using real numbers
instead of invented ones (per the thesis proposal's own methodology).
Percentiles (not literal min/max) are used on purpose: InSDN has near-zero-
duration flows (e.g. a rejected connection, 2 packets) whose computed pktrate
is in the millions without carrying any real load, and in this dataset that
happens on BOTH classes -- a literal max would hand the model a normal and an
attack example with the identical value, which teaches nothing. All rows
(percentile picks and artifacts alike) stay available in the eval set; only
the picks below are excluded from it.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("samples", type=Path)
    parser.add_argument(
        "--fewshot-out", type=Path, default=Path("logs/insdn_fewshot.csv")
    )
    parser.add_argument("--eval-out", type=Path, default=Path("logs/insdn_eval.csv"))
    parser.add_argument(
        "--normal-fractions",
        default="0.10,0.50,0.90",
        help="pktrate percentiles to pick for class 0 (lab data is mostly idle: use e.g. 0.50,0.95,0.995)",
    )
    parser.add_argument("--attack-fractions", default="0.10,0.50,0.90")
    args = parser.parse_args()

    with args.samples.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)

    chosen_ids = set()
    fewshot = []
    fractions_by_label = {
        "0": [float(f) for f in args.normal_fractions.split(",")],
        "1": [float(f) for f in args.attack_fractions.split(",")],
    }
    for label in ("0", "1"):
        subset = sorted(
            (r for r in rows if r["label"] == label), key=lambda r: float(r["pktrate"])
        )
        n = len(subset)
        for fraction in fractions_by_label[label]:
            pick = subset[min(n - 1, int(fraction * n))]
            if id(pick) not in chosen_ids:
                chosen_ids.add(id(pick))
                fewshot.append(pick)

    remaining = [r for r in rows if id(r) not in chosen_ids]

    for path, data in ((args.fewshot_out, fewshot), (args.eval_out, remaining)):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)

    print(f"few-shot: {len(fewshot)} rows -> {args.fewshot_out}")
    print(f"eval (leakage-free): {len(remaining)} rows -> {args.eval_out}")
    for row in fewshot:
        print(f"  label={row['label']} pktrate={float(row['pktrate']):.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
