#!/usr/bin/env python3
# ruff: noqa: E501
"""Calibrate the entropy detector by replaying recorded windows over a fixed grid.

The grid is written down here, before any result is looked at, and `--list` prints it. Every
configuration is replayed through the real `EntropyDetector` over the same dumped windows
(`scripts/replay_entropy.py`), and scored with one rule fixed in advance:

  1. no legitimate host is named, in any phase of any run (baseline, attack, recovery);
  2. among those, the most attackers named in total;
  3. then the shortest mean time to the first alarm that names an attacker;
  4. then the fewest confirmed alarms before the attack.

Many configurations tie on those four (campaign R0/R1: 61 of 6000). `--analyze` breaks the tie
with rules written down before looking at it: the share of one-step neighbours (see
`neighbours`) that still name every attacker and no legitimate host, then the fewest changes
from the original "Destination entropy" preset, then a robust centre (median + MAD) over the
mean, then the name.

    python3 scripts/calibrate_entropy.py windows_R0.jsonl windows_R1.jsonl runs.json \\
        --variant primary --out primary.jsonl
    python3 scripts/calibrate_entropy.py windows.jsonl runs.json --variant secondary
    python3 scripts/calibrate_entropy.py --analyze primary.jsonl

runs.json: [{"run", "label", "a0", "a1", "benign", "attackers": [IP], "victims": [IP]}]. A run
marked `benign` has no attack: any host named in it is a false accusation, whoever it is.
The windows files may be several (their runs are merged). Use calibration runs only; the
held-out runs are scored once, with the chosen configuration, by `replay_entropy.py`.
"""

from __future__ import annotations

import argparse
import itertools
import json
import multiprocessing
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import replay_entropy as replay

MEASURES: Dict[str, Dict[str, Any]] = {
    "norm": {"measure": "norm"},
    "shannon": {"measure": "shannon"},
    "renyi2": {"measure": "renyi", "order": 2.0},
    "tsallis2": {"measure": "tsallis", "order": 2.0},
    "min": {"measure": "min"},
}
MARGINS = (0.01, 0.05, 0.1, 0.2, 0.3)
EWMA_K = (2.5, 4.0, 6.0, 10.0)
ROBUST_K = (3.0, 5.0, 8.0)
CONTEXTS = ("normal", "all")
WARMUP = (16, 30)
CONSECUTIVE = (1, 2, 3)
CANDIDATE_MIN_RATE = (20.0, 50.0, 100.0, 200.0)
CANDIDATE_SHARE = (0.1, 0.3)
# Only the secondary variant lets the minimum window rate move (the preset's value is 2).
MIN_TOTAL_RATE_PRIMARY = (2.0,)
MIN_TOTAL_RATE_SECONDARY = (2.0, 20.0, 100.0, 500.0)
FIXED = {"features": ("src", "dst"), "decide": ("dst",), "history": 0}


def models() -> List[Tuple[str, Dict[str, Any]]]:
    """Measure x threshold model: the part of the grid that decides alarms."""

    out: List[Tuple[str, Dict[str, Any]]] = []
    for name, measure in MEASURES.items():
        for margin in MARGINS:
            out.append(
                (
                    f"{name}/ewma_margin m={margin:g}",
                    {
                        **measure,
                        "center": "ewma_margin",
                        "alpha": 0.13,
                        "margin": margin,
                        "context": "normal",
                    },
                )
            )
        for context in CONTEXTS:
            for k in EWMA_K:
                out.append(
                    (
                        f"{name}/ewma k={k:g} {context}",
                        {**measure, "center": "ewma", "k": k, "context": context},
                    )
                )
            for k in ROBUST_K:
                out.append(
                    (
                        f"{name}/median+mad k={k:g} {context}",
                        {
                            **measure,
                            "center": "median",
                            "spread": "mad",
                            "k": k,
                            "context": context,
                        },
                    )
                )
                out.append(
                    (
                        f"{name}/mean+std k={k:g} {context}",
                        {
                            **measure,
                            "center": "mean",
                            "spread": "std",
                            "k": k,
                            "context": context,
                        },
                    )
                )
    return out


def grid(variant: str) -> List[Tuple[str, Dict[str, Any]]]:
    rates = (
        MIN_TOTAL_RATE_SECONDARY if variant == "secondary" else MIN_TOTAL_RATE_PRIMARY
    )
    out = []
    for (label, base), warmup, consecutive, mine, share, floor in itertools.product(
        models(),
        WARMUP,
        CONSECUTIVE,
        CANDIDATE_MIN_RATE,
        CANDIDATE_SHARE,
        rates,
    ):
        name = (
            f"{label} | warmup={warmup} consec={consecutive} "
            f"cand_rate={mine:g} cand_share={share:g} min_rate={floor:g}"
        )
        out.append(
            (
                name,
                {
                    **FIXED,
                    **base,
                    "warmup_windows": warmup,
                    "consecutive_windows": consecutive,
                    "candidate_min_rate": mine,
                    "candidate_share": share,
                    "min_total_rate": floor,
                },
            )
        )
    return out


WINDOWS: Dict[str, List[Dict[str, Any]]] = {}
RUNS: List[Dict[str, Any]] = []


def init(windows: Dict[str, List[Dict[str, Any]]], runs: List[Dict[str, Any]]) -> None:
    global WINDOWS, RUNS
    WINDOWS, RUNS = windows, runs


def evaluate(item: Tuple[str, Dict[str, Any]]) -> Dict[str, Any]:
    name, settings = item
    per_run = []
    for meta in RUNS:
        results = replay.replay_run(WINDOWS[meta["run"]], settings)
        a0 = replay.parse_time(meta["a0"])
        a1 = replay.parse_time(meta["a1"])
        attackers = set(meta.get("attackers", [])) if not meta.get("benign") else set()
        victims = set(meta.get("victims", []))
        named: set = set()
        first: Optional[float] = None
        before = 0
        for stamp, result in results:
            if not result.confirmed:
                continue
            if stamp <= a0:
                before += 1
            named.update(result.candidates)
            if (
                first is None
                and a0 < stamp <= a1 + replay.GRACE_SECONDS
                and attackers & set(result.candidates)
            ):
                first = stamp - a0
        per_run.append(
            {
                "run": meta["label"],
                "attackers_named": len(named & attackers),
                "attackers": len(attackers),
                "legit_named": len(named - attackers - victims),
                "victim_named": bool(named & victims),
                "first": None if first is None else round(first, 1),
                "base_alarms": before,
            }
        )
    attack_runs = [r for r in per_run if r["attackers"]]
    firsts = [r["first"] for r in attack_runs]
    return {
        "name": name,
        "legit": sum(r["legit_named"] for r in per_run),
        "attackers": sum(r["attackers_named"] for r in per_run),
        "victim": sum(1 for r in per_run if r["victim_named"]),
        "mean_first": (
            None
            if any(f is None for f in firsts) or not firsts
            else round(sum(firsts) / len(firsts), 2)
        ),
        "base_alarms": sum(r["base_alarms"] for r in per_run),
        "per_run": per_run,
        "settings": {
            k: (list(v) if isinstance(v, tuple) else v) for k, v in settings.items()
        },
    }


def rank_key(row: Dict[str, Any]) -> Tuple[Any, ...]:
    """The rule fixed in advance. A configuration with legitimate hosts named comes after
    every one without; among those, fewer legitimate hosts is better (the fallback)."""

    mean = row["mean_first"] if row["mean_first"] is not None else 1e9
    return (row["legit"], -row["attackers"], mean, row["base_alarms"])


AXES = {
    "margin": [0.01, 0.05, 0.1, 0.2, 0.3],
    "k_ewma": list(EWMA_K),
    "k_robust": list(ROBUST_K),
    "warmup_windows": list(WARMUP),
    "consecutive_windows": list(CONSECUTIVE),
    "candidate_min_rate": list(CANDIDATE_MIN_RATE),
    "candidate_share": list(CANDIDATE_SHARE),
    "min_total_rate": list(MIN_TOTAL_RATE_SECONDARY),
}
# The original "Destination entropy" preset, to count how far a configuration has moved.
PRESET = {
    "measure": "norm",
    "center": "ewma_margin",
    "context": "normal",
    "warmup_windows": 30,
    "consecutive_windows": 1,
    "candidate_min_rate": 20.0,
    "candidate_share": 0.3,
    "margin": 0.01,
    "min_total_rate": 2.0,
}


def ident(s: Dict[str, Any]) -> Tuple[Any, ...]:
    return (
        s["measure"],
        s.get("order"),
        s["center"],
        s.get("spread"),
        s["context"],
        s.get("margin") if s["center"] == "ewma_margin" else None,
        s["k"] if s["center"] != "ewma_margin" else None,
        s["warmup_windows"],
        s["consecutive_windows"],
        s["candidate_min_rate"],
        s["candidate_share"],
        s["min_total_rate"],
    )


def neighbours(s: Dict[str, Any], moves_min_rate: bool) -> List[Dict[str, Any]]:
    """One axis moved one step along its ordered values, or the learning context flipped.

    The measure and the kind of centre are categories, not neighbours of each other, and
    `ewma_margin` only learns normal windows, so its context is not flipped.
    """

    axes: List[Tuple[str, List[Any]]] = []
    if s["center"] == "ewma_margin":
        axes.append(("margin", AXES["margin"]))
    else:
        axes.append(("k", AXES["k_ewma" if s["center"] == "ewma" else "k_robust"]))
    for name in (
        "warmup_windows",
        "consecutive_windows",
        "candidate_min_rate",
        "candidate_share",
    ):
        axes.append((name, AXES[name]))
    if moves_min_rate:
        axes.append(("min_total_rate", AXES["min_total_rate"]))
    out = []
    for name, values in axes:
        position = values.index(s[name])
        for step in (position - 1, position + 1):
            if 0 <= step < len(values):
                out.append({**s, name: values[step]})
    if s["center"] != "ewma_margin":
        flipped = "all" if s["context"] == "normal" else "normal"
        out.append({**s, "context": flipped})
    return out


def analyze(rows: List[Dict[str, Any]], top: int = 10) -> str:
    """The configurations tied at the best rank, ordered by the declared tie-breaks."""

    index = {ident(r["settings"]): r for r in rows}
    moves = len({r["settings"]["min_total_rate"] for r in rows}) > 1

    def works(row: Dict[str, Any]) -> bool:
        return row["legit"] == 0 and row["attackers"] == max(
            r["attackers"] for r in rows
        )

    def stability(row: Dict[str, Any]) -> float:
        near = [index.get(ident(n)) for n in neighbours(row["settings"], moves)]
        return sum(1 for n in near if n is not None and works(n)) / max(1, len(near))

    def changes(row: Dict[str, Any]) -> int:
        return sum(1 for k, v in PRESET.items() if row["settings"].get(k) != v)

    best = min(rank_key(r) for r in rows)
    tied = [r for r in rows if rank_key(r) == best]
    tied.sort(
        key=lambda r: (
            -stability(r),
            changes(r),
            0 if r["settings"]["center"] == "median" else 1,
            r["name"],
        )
    )
    lines = [
        f"{len(rows)} configurations, {sum(1 for r in rows if r['legit'] == 0)} name no legitimate host, "
        f"{sum(1 for r in rows if works(r))} also name every attacker; best rank {best}, "
        f"{len(tied)} tied"
    ]
    for row in tied[:top]:
        lines.append(
            f"stability {stability(row):.2f}, {changes(row)} changes | {describe(row)}"
        )
    return chr(10).join(lines)


def load(paths: Sequence[Path]) -> Dict[str, List[Dict[str, Any]]]:
    windows: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for path in paths:
        for run, items in replay.load_windows(path).items():
            windows[run].extend(items)
    return windows


def describe(row: Dict[str, Any]) -> str:
    lines = [
        f"{row['name']}\n   legit {row['legit']}  attackers {row['attackers']}  victim runs {row['victim']}  "
        f"mean first detection {row['mean_first']}  baseline alarms {row['base_alarms']}"
    ]
    for r in row["per_run"]:
        lines.append(
            f"     {r['run']:34s} attackers {r['attackers_named']}/{r['attackers']}  legit {r['legit_named']}  "
            f"victim {'YES' if r['victim_named'] else 'no'}  first {r['first']}  baseline alarms {r['base_alarms']}"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "files", type=Path, nargs="*", help="windows dumps, then runs.json"
    )
    parser.add_argument(
        "--variant", choices=("primary", "secondary"), default="primary"
    )
    parser.add_argument(
        "--out", type=Path, help="write every configuration as JSON lines"
    )
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument(
        "--list", action="store_true", help="print the grid size and stop"
    )
    parser.add_argument(
        "--analyze",
        type=Path,
        help="the --out file of a sweep: print the tied best configurations and their stability",
    )
    args = parser.parse_args()
    if args.analyze is not None:
        saved = [
            json.loads(line)
            for line in args.analyze.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        print(analyze(saved, args.top))
        return 0
    configs = grid(args.variant)
    if args.list or not args.files:
        print(
            f"{args.variant}: {len(models())} models x warmup {WARMUP} x consecutive "
            f"{CONSECUTIVE} x candidate_min_rate {CANDIDATE_MIN_RATE} x candidate_share "
            f"{CANDIDATE_SHARE}"
            + (
                f" x min_total_rate {MIN_TOTAL_RATE_SECONDARY}"
                if args.variant == "secondary"
                else ""
            )
            + f" = {len(configs)} configurations"
        )
        return 0
    runs = json.loads(args.files[-1].read_text(encoding="utf-8"))
    windows = load(args.files[:-1])
    runs = [meta for meta in runs if meta["run"] in windows]
    with multiprocessing.Pool(
        args.workers, initializer=init, initargs=(windows, runs)
    ) as pool:
        rows = pool.map(evaluate, configs, chunksize=50)
    rows.sort(key=rank_key)
    if args.out:
        with args.out.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row) + "\n")
    print(
        f"{len(rows)} configurations; {sum(1 for r in rows if r['legit'] == 0)} with no legitimate host named"
    )
    for row in rows[: args.top]:
        print(describe(row))
    return 0


if __name__ == "__main__":
    sys.exit(main())
