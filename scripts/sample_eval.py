#!/usr/bin/env python3
# ruff: noqa: E501  (CLI help and messages)
"""Draw a small, balanced evaluation set from a large labeled CSV (seeded).

Lab data is ~97 % idle legitimate flows, which would make any detector look
perfect. The negatives therefore include a share of the HARD ones (the highest
pktrate legitimate flows, the kind that produced false positives); the rest are
random. The positives are a random draw. Report that composition with results.

Usage: sample_eval.py logs/lab_eval_all.csv --pos 100 --neg 100 --hard-frac 0.5 --out logs/lab_eval_small.csv
"""

from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("samples", type=Path)
    parser.add_argument("--pos", type=int, default=100)
    parser.add_argument("--neg", type=int, default=100)
    parser.add_argument("--hard-frac", type=float, default=0.5)
    parser.add_argument("--hard-min-pktrate", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out", type=Path, default=Path("logs/lab_eval_small.csv"))
    args = parser.parse_args()

    with args.samples.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    rng = random.Random(args.seed)
    positives = [r for r in rows if r["label"] == "1"]
    negatives = [r for r in rows if r["label"] == "0"]
    hard = [r for r in negatives if float(r["pktrate"]) >= args.hard_min_pktrate]
    easy = [r for r in negatives if float(r["pktrate"]) < args.hard_min_pktrate]
    n_hard = min(len(hard), int(args.neg * args.hard_frac))
    chosen = (
        rng.sample(positives, min(args.pos, len(positives)))
        + rng.sample(hard, n_hard)
        + rng.sample(easy, min(len(easy), args.neg - n_hard))
    )
    rng.shuffle(chosen)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(chosen)
    print(
        f"{len(chosen)} samples: {min(args.pos, len(positives))} attack, "
        f"{n_hard} hard legitimate (pktrate >= {args.hard_min_pktrate}), "
        f"{len(chosen) - min(args.pos, len(positives)) - n_hard} random legitimate "
        f"({len(hard)} hard available) -> {args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
