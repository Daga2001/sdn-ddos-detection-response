#!/usr/bin/env python3
# ruff: noqa: E501
"""Replay recorded entropy windows through other detector settings, offline.

The controller can append every entropy window (the flows it saw and the port/protocol
histograms) to the file named by SDN_ENTROPY_DUMP. This tool feeds those windows to the
real `EntropyDetector` with another measure, threshold model, learning context or set of
watched features, and scores the result against when each attack really started and
stopped, so detector variants can be compared on identical traffic without running the lab.

    # runs.json: [{"run": "<run id>", "label": "T3 8 atk SYN 300", "a0": "<ISO time the attack
    # started>", "a1": "<ISO time it stopped>", "benign": false}, ...]
    python3 scripts/replay_entropy.py entropy_windows.jsonl runs.json            # the grid below
    python3 scripts/replay_entropy.py entropy_windows.jsonl runs.json --detail "center=median,spread=mad,context=all"

A detector is described as comma-separated `name=value` settings (any EntropyDetector field;
`features=src+dst+dport`). The lab defaults (k 2.5, 16 warm-up windows, 2 consecutive windows,
minimum rate 2 pkt/s) apply unless a setting overrides them.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from statistics import mean, median
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from sdn_ddos.detection.entropy import (
    EntropyDetector,
    EntropyResult,
    FlowObservation,
)

LAB_DEFAULTS: Dict[str, Any] = {
    "k": 2.5,
    "warmup_windows": 16,
    "consecutive_windows": 2,
    "min_total_rate": 2.0,
    "min_std": 0.05,
}
GRACE_SECONDS = 10.0  # after the attack ends the flood's tail is not a false alarm
INT_FIELDS = {"warmup_windows", "consecutive_windows", "update_hold", "history"}
STR_FIELDS = {"measure", "center", "spread", "context"}


def parse_time(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def parse_settings(text: str) -> Dict[str, Any]:
    settings: Dict[str, Any] = {}
    for item in filter(None, (part.strip() for part in text.split(","))):
        name, _, raw = item.partition("=")
        name = name.strip()
        if name in ("features", "decide"):
            settings[name] = tuple(raw.split("+"))
        elif name in STR_FIELDS:
            settings[name] = raw
        elif name in INT_FIELDS:
            settings[name] = int(raw)
        else:
            settings[name] = float(raw)
    return settings


def load_windows(path: Path) -> Dict[str, List[Dict[str, Any]]]:
    runs: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            record = json.loads(line)
            runs[record["run"]].append(record)
    return runs


def replay_run(
    windows: List[Dict[str, Any]], settings: Dict[str, Any]
) -> List[Tuple[float, EntropyResult]]:
    detector = EntropyDetector(**{**LAB_DEFAULTS, **settings})
    results = []
    for window in windows:
        flows = [
            FlowObservation(src, dst, weight) for src, dst, weight in window["flows"]
        ]
        extra = {
            name: [(float(weight), int(count)) for weight, count in histogram]
            for name, histogram in window.get("hist", {}).items()
        }
        results.append((parse_time(window["at"]), detector.observe(0, flows, extra)))
    return results


def score(
    results: List[Tuple[float, EntropyResult]], a0: float, a1: float, benign: bool
) -> Dict[str, Any]:
    in_attack = [(t, r) for t, r in results if a0 < t <= a1]
    alarms = [t for t, r in results if r.confirmed]
    first = next((t for t in alarms if a0 < t <= a1), None)
    before = sum(1 for t in alarms if t <= a0)
    after = sum(1 for t in alarms if t > a1 + GRACE_SECONDS)
    during = sum(1 for t in alarms if a0 < t <= a1 + GRACE_SECONDS) if benign else 0
    false_alarms = before + after + during
    judged = [r for _, r in in_attack if r.evaluated]
    return {
        "detected": first is not None and not benign,
        "delay": None if first is None or benign else round(first - a0, 1),
        "false_alarms": false_alarms,
        "before": before,
        "after": after,
        "attack_recall": (
            sum(r.suspicious for r in judged) / len(judged) if judged else 0.0
        ),
        "ready_before_attack": any(
            r.evaluated for t, r in results if t <= a0 + GRACE_SECONDS
        ),
    }


def compare(
    windows: Dict[str, List[Dict[str, Any]]],
    runs: List[Dict[str, Any]],
    settings: Dict[str, Any],
) -> Dict[str, Any]:
    scored = []
    for meta in runs:
        if meta["run"] not in windows:
            continue
        results = replay_run(windows[meta["run"]], settings)
        scored.append(
            (
                meta,
                score(
                    results,
                    parse_time(meta["a0"]),
                    parse_time(meta["a1"]),
                    bool(meta.get("benign")),
                ),
            )
        )
    attacks = [(m, s) for m, s in scored if not m.get("benign")]
    delays = [s["delay"] for _, s in attacks if s["delay"] is not None]
    # A false alarm is one raised before the attack, or any alarm of a run with no attack;
    # alarms that go on after the attack ended are its tail (the network is still disturbed).
    return {
        "per_run": scored,
        "detected": sum(1 for _, s in attacks if s["detected"]),
        "attacks": len(attacks),
        "median_delay": round(median(delays), 1) if delays else None,
        "false_alarms": sum(
            s["false_alarms"] if m.get("benign") else s["before"] for m, s in scored
        ),
        "tail_alarms": sum(s["after"] for m, s in scored if not m.get("benign")),
        "attack_recall": (
            round(mean(s["attack_recall"] for _, s in attacks), 2) if attacks else 0.0
        ),
    }


def grid() -> List[Tuple[str, Dict[str, Any]]]:
    """The variants worth comparing: the measure, the threshold model and the context."""

    out: List[Tuple[str, Dict[str, Any]]] = []
    for measure, order in (
        ("shannon", 2.0),
        ("norm", 2.0),
        ("renyi", 0.5),
        ("renyi", 2.0),
        ("renyi", 10.0),
        ("tsallis", 2.0),
        ("min", 2.0),
    ):
        name = (
            measure if measure in ("shannon", "norm", "min") else f"{measure}{order:g}"
        )
        out.append((f"measure {name}", {"measure": measure, "order": order}))
    models = (
        ("ewma / normal windows", {}),
        ("ewma / every window", {"context": "all"}),
        ("mean+std / every window", {"center": "mean", "context": "all"}),
        (
            "median+MAD / every window",
            {"center": "median", "spread": "mad", "context": "all"},
        ),
        ("median+MAD / normal windows", {"center": "median", "spread": "mad"}),
        ("improved EWMA (Yu) / every window", {"center": "yu", "context": "all"}),
    )
    for label, settings in models:
        out.append((f"threshold {label}", settings))
    for label, features in (
        ("src+dst+dport", ("src", "dst", "dport")),
        ("src+dst+proto", ("src", "dst", "proto")),
        ("src+dst+dport+proto", ("src", "dst", "dport", "proto")),
    ):
        out.append((f"features {label}", {"features": features}))
    return out


MEASURE_CHOICES: List[Tuple[str, Dict[str, Any]]] = [
    ("shannon", {"measure": "shannon"}),
    ("norm", {"measure": "norm"}),
    ("renyi0.5", {"measure": "renyi", "order": 0.5}),
    ("renyi2", {"measure": "renyi", "order": 2.0}),
    ("renyi10", {"measure": "renyi", "order": 10.0}),
    ("tsallis2", {"measure": "tsallis", "order": 2.0}),
    ("min", {"measure": "min"}),
]
THRESHOLD_CHOICES: List[Tuple[str, Dict[str, Any]]] = [
    ("ewma/normal", {}),
    ("ewma/all", {"context": "all"}),
    ("mean/all", {"center": "mean", "context": "all"}),
    ("median+mad/all", {"center": "median", "spread": "mad", "context": "all"}),
    ("median+mad/normal", {"center": "median", "spread": "mad"}),
    ("yu/all", {"center": "yu", "context": "all"}),
]
FEATURE_CHOICES: List[Tuple[str, Dict[str, Any]]] = [
    ("ip", {}),
    ("ip+dport", {"features": ("src", "dst", "dport")}),
    ("ip+dport+proto", {"features": ("src", "dst", "dport", "proto")}),
]


def full_grid() -> List[Tuple[str, Dict[str, Any]]]:
    """Every combination of measure, threshold model and watched features."""

    return [
        (f"{m_name} | {t_name} | {f_name}", {**m, **t, **f})
        for m_name, m in MEASURE_CHOICES
        for t_name, t in THRESHOLD_CHOICES
        for f_name, f in FEATURE_CHOICES
    ]


def rank_key(result: Dict[str, Any]) -> Tuple[Any, ...]:
    """The selection rule, fixed before the confirmation runs were looked at: most attacks
    detected, then fewest false alarms, then the shortest median delay, then the highest
    share of attack windows flagged, then the shortest tail of alarms after the attack."""

    delay = result["median_delay"] if result["median_delay"] is not None else 1e9
    return (
        -result["detected"],
        result["false_alarms"],
        delay,
        -result["attack_recall"],
        result["tail_alarms"],
    )


def print_table(rows: List[Tuple[str, Dict[str, Any]]]) -> None:
    width = max(len(name) for name, _ in rows)
    print(
        f"{'detector':{width}s}  detected  median delay  false alarms"
        "  tail alarms  attack-window recall"
    )
    for name, result in rows:
        delay = "-" if result["median_delay"] is None else f"{result['median_delay']} s"
        print(
            f"{name:{width}s}  {result['detected']:>3d}/{result['attacks']:<3d}  "
            f"{delay:>12s}  {result['false_alarms']:>12d}  {result['tail_alarms']:>11d}"
            f"  {result['attack_recall']:>20.2f}"
        )


def print_detail(result: Dict[str, Any]) -> None:
    for meta, s in result["per_run"]:
        delay = "-" if s["delay"] is None else f"+{s['delay']} s"
        verdict = (
            "benign"
            if meta.get("benign")
            else ("DETECTED" if s["detected"] else "missed")
        )
        print(
            f"{meta['label']:48s} {verdict:9s} {delay:>9s}  false alarms {s['false_alarms']}"
            f" (before {s['before']}, after {s['after']})"
            f"  recall {s['attack_recall']:.2f}  ready {s['ready_before_attack']}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("windows", type=Path, help="the SDN_ENTROPY_DUMP file")
    parser.add_argument(
        "runs", type=Path, help="JSON list: run, label, a0, a1 (and benign)"
    )
    parser.add_argument(
        "--detail", metavar="SETTINGS", help="per-run results of one detector"
    )
    parser.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="SETTINGS",
        help="also compare this detector (repeatable)",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="every measure x threshold model x features, ranked by the selection rule",
    )
    parser.add_argument("--top", type=int, default=25, help="rows shown with --full")
    parser.add_argument(
        "--only",
        metavar="TEXT",
        help="with --full, keep only combinations whose name contains TEXT",
    )
    parser.add_argument(
        "--pass", dest="pass_name", help="only the runs marked with this pass"
    )
    args = parser.parse_args()
    windows = load_windows(args.windows)
    runs: List[Optional[Dict[str, Any]]] = json.loads(
        args.runs.read_text(encoding="utf-8")
    )
    runs = [meta for meta in runs if meta]
    if args.pass_name is not None:
        runs = [meta for meta in runs if str(meta.get("pass")) == args.pass_name]
    if args.full:
        rows = [
            (n, compare(windows, runs, st))
            for n, st in full_grid()
            if not args.only or args.only in n
        ]
        rows.sort(key=lambda row: rank_key(row[1]))
        print_table(rows[: args.top])
        return 0
    if args.detail is not None:
        print_detail(compare(windows, runs, parse_settings(args.detail)))
        return 0
    rows = [(name, compare(windows, runs, settings)) for name, settings in grid()]
    rows += [
        (f"custom {text}", compare(windows, runs, parse_settings(text)))
        for text in args.set
    ]
    print_table(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
