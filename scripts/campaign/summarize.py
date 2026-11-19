#!/usr/bin/env python3
# ruff: noqa: E501
"""Flatten campaign_results.jsonl into one CSV row per scenario and print group totals.

python3 scripts/campaign/summarize.py results.jsonl [out.csv]
"""

from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

COLUMNS = [
    "id", "group", "verdict", "title", "mode", "model", "prompt", "samples", "policy", "dry_run",
    "attackers", "victims", "traffic", "rate", "baseline_s", "attack_s", "recovery_s",
    "vp", "fn", "fp", "vn", "recall", "precision", "first_detection_s", "all_detected_s",
    "response_actions", "responded_attackers", "collateral", "response_first_s", "collateral_first_s",
    "svc_baseline_pct", "svc_attack_pct", "svc_recovery_pct", "svc_first_failure_s", "svc_first_recovery_s",
    "victim_kbps_baseline", "victim_kbps_mid", "victim_kbps_end", "drop_rules_max", "meters_max",
    "gap_events", "controller_cpu_max", "events", "wall_s", "run_id", "problems",
]  # fmt: skip


def row(result: dict[str, Any]) -> dict[str, Any]:
    request = result.get("request", {})
    detection = request.get("detection") or {}
    response = detection.get("response", {})
    m = result.get("metrics") or {}
    svc = m.get("service_pct", {})
    kbps = m.get("victim_kbps", {})
    rules = m.get("rules_seen", {})
    return {
        "id": result["id"], "group": result.get("group"), "verdict": result.get("verdict"), "title": result.get("title"),
        "mode": detection.get("mode", "(sin detection)"), "model": detection.get("model") if detection.get("mode") == "llm" else "",
        "prompt": detection.get("prompt") if detection.get("mode") == "llm" else "",
        "samples": detection.get("llm_max_samples") if detection.get("mode") == "llm" else "",
        "policy": response.get("policy", "") if request.get("mitigation") else "", "dry_run": response.get("dry_run", "") if request.get("mitigation") else "",
        "attackers": " ".join(request.get("attackers", [])), "victims": " ".join(request.get("victims", [])),
        "traffic": "+".join(request.get("traffic", [])), "rate": request.get("rate"),
        "baseline_s": request.get("baseline"), "attack_s": request.get("duration"), "recovery_s": request.get("recovery"),
        "vp": m.get("vp"), "fn": m.get("fn"), "fp": m.get("fp"), "vn": m.get("vn"), "recall": m.get("recall"), "precision": m.get("precision"),
        "first_detection_s": m.get("first_detection_s"), "all_detected_s": m.get("all_detected_s"),
        "response_actions": " ".join(m.get("response_actions", [])), "responded_attackers": len(m.get("responded_attackers", [])),
        "collateral": " ".join(m.get("collateral", [])), "response_first_s": m.get("response_first_s"),
        "collateral_first_s": m.get("collateral_first_s"),
        "svc_baseline_pct": svc.get("baseline"), "svc_attack_pct": svc.get("attack"), "svc_recovery_pct": svc.get("recovery"),
        "svc_first_failure_s": m.get("service_first_failure_s"), "svc_first_recovery_s": m.get("service_first_recovery_s"),
        "victim_kbps_baseline": kbps.get("baseline"), "victim_kbps_mid": kbps.get("mid"), "victim_kbps_end": kbps.get("end"),
        "drop_rules_max": rules.get("drops_max"), "meters_max": rules.get("meters_max"),
        "gap_events": m.get("gap_events"), "controller_cpu_max": m.get("controller_cpu_max"), "events": m.get("events"),
        "wall_s": result.get("wall_s"), "run_id": result.get("run_id", ""), "problems": " | ".join(result.get("problems", [])),
    }  # fmt: skip


def main() -> int:
    source = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else source.with_suffix(".csv")
    latest: dict[str, dict[str, Any]] = {}
    for line in source.read_text(encoding="utf-8").splitlines():
        if line.strip():
            result = json.loads(line)
            latest[result["id"]] = result  # the last execution of each scenario
    rows = [row(r) for r in latest.values()]
    with out.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    totals: dict[str, dict[str, int]] = defaultdict(lambda: {"PASS": 0, "FAIL": 0})
    for r in rows:
        totals[r["group"]][r["verdict"]] += 1
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    print(f"{len(rows)} scenarios -> {out}")
    for group, counts in sorted(totals.items()):
        print(f"  group {group}: {counts['PASS']} PASS, {counts['FAIL']} FAIL")
    return 0


if __name__ == "__main__":
    sys.exit(main())
