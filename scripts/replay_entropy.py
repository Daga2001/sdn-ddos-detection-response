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

Naming (who the detector accused, not only whether it alarmed): give a run its `attackers`
and `victims` as IP lists in runs.json and every table row also says how many attackers were
named, how many legitimate hosts and whether a victim was. `--protect` applies the lab's rule
"a protected host is never named" to the replayed names (the victims), counting how many
names it dropped, so a detector can be scored with and without it on the same windows.

No dump (`--from-events`): the controller also stores every window as an `entropy_window`
event in `lab_events`, with the entropies of each distribution (`panel`) and the packet rate.
Export them as JSON lines and replay the *values* through the same bands, which re-scores the
alarm side (threshold, margin, k, warm-up, consecutive windows, learning context) of runs whose
flows were not dumped. It cannot name anybody (the flows are not in the event) and it can only
use a measure the panel holds (shannon, norm, renyi order 2 or 10, tsallis order 2, min).

    psql ... -At -c "select json_build_object('run', run_id, 'at', data->>'observed_at',
        'data', data) from lab_events where kind = 'entropy_window' and run_id in ('...')
        order by seq" > events.jsonl
    python3 scripts/replay_entropy.py --from-events events.jsonl runs.json --detail "..."
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from statistics import mean, median
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from sdn_ddos.detection.entropy import (
    PEAK_DECAY,
    SIDES,
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


def panel_key(measure: str, order: float) -> str:
    """Which entry of an event's `panel` holds this measure."""

    keys = {
        ("shannon", None): "shannon",
        ("norm", None): "norm",
        ("min", None): "min",
        ("renyi", 2.0): "renyi2",
        ("renyi", 10.0): "renyi10",
        ("tsallis", 2.0): "tsallis2",
    }
    key = keys.get((measure, order if measure in ("renyi", "tsallis") else None))
    if key is None:
        raise ValueError(
            f"--from-events cannot replay measure={measure} order={order:g}; the "
            "event's panel holds shannon, norm, min, renyi order 2 or 10, tsallis order 2"
        )
    return key


def replay_values(
    windows: List[Dict[str, Any]], settings: Dict[str, Any]
) -> List[Tuple[float, EntropyResult]]:
    """Replay `entropy_window` events: the recorded entropies go through the bands.

    The same learning and alarm rules as `EntropyDetector.observe` (warm-up, band side,
    learning context, update hold, consecutive windows), fed with the values the event
    already holds instead of recomputing them from flows. Windows whose rate is under the
    replayed minimum rate are idle. Nobody is named: the flows are not in the event.
    """

    detector = EntropyDetector(**{**LAB_DEFAULTS, **settings})
    key = panel_key(detector.measure, detector.order)
    state = detector._state(0)
    results: List[Tuple[float, EntropyResult]] = []
    for window in windows:
        data = window["data"]
        stamp = parse_time(window["at"])
        total = float(data.get("total_rate") or 0.0)
        panel = data.get("panel") or {}
        active = [name for name in detector.features if name in panel]
        if total < detector.min_total_rate or len(active) < len(detector.features):
            state.streak = 0
            state.recent_peak *= PEAK_DECAY
            results.append((stamp, EntropyResult(0, False, "idle", total_rate=total)))
            continue
        values = {name: float(panel[name][key]) for name in active}
        if not all(state.bands[name].ready for name in active):
            for name in active:
                state.bands[name].update(values[name], total)
            results.append((stamp, EntropyResult(0, False, "warmup", total_rate=total)))
            continue
        deciding = [n for n in active if not detector.decide or n in detector.decide]
        suspicious = any(
            detector._outside(state.bands[name], values[name], SIDES[name])
            for name in deciding
        )
        if detector.context == "all":
            state.streak = state.streak + 1 if suspicious else 0
            for name in active:
                state.bands[name].update(values[name], total)
        elif suspicious:
            state.streak += 1
            state.pending.clear()
        else:
            state.streak = 0
            state.pending.append(values)
            while len(state.pending) > detector.update_hold:
                old = state.pending.pop(0)
                for name in active:
                    if name in old:
                        state.bands[name].update(old[name], total)
        results.append(
            (
                stamp,
                EntropyResult(
                    0,
                    True,
                    "evaluated",
                    total_rate=total,
                    suspicious=suspicious,
                    confirmed=suspicious
                    and state.streak >= detector.consecutive_windows,
                    consecutive=state.streak,
                ),
            )
        )
    return results


def load_events(path: Path) -> Dict[str, List[Dict[str, Any]]]:
    """`entropy_window` events as JSON lines: {"run", "at", "data"} (see the docstring)."""

    runs: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            record = json.loads(line)
            runs[record["run"]].append(record)
    return runs


def replay_run(
    windows: List[Dict[str, Any]],
    settings: Dict[str, Any],
    from_events: bool = False,
) -> List[Tuple[float, EntropyResult]]:
    if from_events:
        return replay_values(windows, settings)
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


def naming(
    results: List[Tuple[float, EntropyResult]],
    attackers: Sequence[str],
    victims: Sequence[str],
    protect: bool = False,
) -> Dict[str, Any]:
    """Who the replayed detector accused over the whole run (confirmed alarms only).

    `protect` drops the victims from the names, as the controller does with protected
    hosts, and counts the names it dropped (`suppressed`). Without runs.json's `attackers`
    there is nothing to score and the result is empty.
    """

    if not attackers:
        return {}
    named: set = set()
    suppressed = 0
    for _, result in results:
        if not result.confirmed:
            continue
        for host in result.candidates:
            if protect and host in victims:
                suppressed += 1
            else:
                named.add(host)
    return {
        "attackers_named": len(named & set(attackers)),
        "attackers": len(set(attackers)),
        "legit_named": len(named - set(attackers) - set(victims)),
        "victim_named": bool(named & set(victims)),
        "suppressed": suppressed,
    }


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
    from_events: bool = False,
    protect: bool = False,
) -> Dict[str, Any]:
    scored = []
    for meta in runs:
        if meta["run"] not in windows:
            continue
        results = replay_run(windows[meta["run"]], settings, from_events)
        row = score(
            results,
            parse_time(meta["a0"]),
            parse_time(meta["a1"]),
            bool(meta.get("benign")),
        )
        if not from_events:
            row.update(
                naming(
                    results,
                    meta.get("attackers", []),
                    meta.get("victims", []),
                    protect,
                )
            )
        scored.append((meta, row))
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
        "attackers_named": sum(s.get("attackers_named", 0) for _, s in scored),
        "attackers_total": sum(s.get("attackers", 0) for _, s in scored),
        "legit_named": sum(s.get("legit_named", 0) for _, s in scored),
        "victim_runs": sum(1 for _, s in scored if s.get("victim_named")),
        "suppressed": sum(s.get("suppressed", 0) for _, s in scored),
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
            + (
                f"  named {s['attackers_named']}/{s['attackers']} attackers,"
                f" {s['legit_named']} legit, victim {'YES' if s['victim_named'] else 'no'}"
                f", {s['suppressed']} suppressed"
                if "attackers_named" in s
                else ""
            )
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "windows",
        type=Path,
        help="the SDN_ENTROPY_DUMP file (with --from-events: the events JSON lines)",
    )
    parser.add_argument(
        "--from-events",
        action="store_true",
        help="replay entropy_window events (values only, nobody is named)",
    )
    parser.add_argument(
        "--protect",
        action="store_true",
        help="drop the runs' victims from the replayed names, as the controller does",
    )
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
    windows = (
        load_events(args.windows) if args.from_events else load_windows(args.windows)
    )
    runs: List[Optional[Dict[str, Any]]] = json.loads(
        args.runs.read_text(encoding="utf-8")
    )
    runs = [meta for meta in runs if meta]
    if args.pass_name is not None:
        runs = [meta for meta in runs if str(meta.get("pass")) == args.pass_name]
    if args.full:
        rows = [
            (n, compare(windows, runs, st, args.from_events, args.protect))
            for n, st in full_grid()
            if not args.only or args.only in n
        ]
        rows.sort(key=lambda row: rank_key(row[1]))
        print_table(rows[: args.top])
        return 0
    if args.detail is not None:
        print_detail(
            compare(
                windows,
                runs,
                parse_settings(args.detail),
                args.from_events,
                args.protect,
            )
        )
        return 0
    rows = [
        (name, compare(windows, runs, settings, args.from_events, args.protect))
        for name, settings in grid()
    ]
    rows += [
        (
            f"custom {text}",
            compare(
                windows, runs, parse_settings(text), args.from_events, args.protect
            ),
        )
        for text in args.set
    ]
    print_table(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
