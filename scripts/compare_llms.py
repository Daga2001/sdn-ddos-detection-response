#!/usr/bin/env python3
# ruff: noqa: E501  (CLI help and messages)
"""Compare Ollama models as DDoS flow classifiers on the same labeled samples.

Uses the exact prompt, decoding settings (temperature 0, fixed seed) and
verdict parsing of the live service (sdn_ddos.detection.llm_api), so results
transfer to the controller. The verdict is `prob_ddos >= --threshold`, the same
rule the controller applies (SDN_DDOS_THRESHOLD, default 0.8).

Samples come from --samples (CSV with the six model features plus `label`
0/1) or, by default, a SYNTHETIC set that only checks that a model follows the
prompt's rule. Synthetic results are a sanity check, NOT a detection benchmark.

Examples:
  compare_llms.py --models llama3.2:3b,qwen2.5:3b
  compare_llms.py --models llama3.2:3b --samples dataset_samples.csv --repeats 3
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import statistics
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import requests

from sdn_ddos.detection.llm_api import (
    OllamaSettings,
    PredictSample,
    query_llm,
    to_prediction,
)

FEATURES = (
    "packet_count",
    "byte_count",
    "pktrate",
    "byterate",
    "ip_proto",
    "l4_dst_port",
)
LabeledSample = Tuple[PredictSample, int]


def synthetic_samples(count: int, seed: int) -> List[LabeledSample]:
    """Half clearly normal (<800 pkt/s), half clearly flood (>=12k pkt/s)."""

    rng = random.Random(seed)
    samples: List[LabeledSample] = []
    for index in range(count):
        attack = index % 2 == 1
        rate = 10 ** rng.uniform(4.1, 5.7) if attack else 10 ** rng.uniform(-0.3, 2.9)
        size = rng.choice([64, 74, 120, 512, 1400])
        seconds = rng.uniform(5, 600)
        packets = max(1, int(rate * seconds))
        samples.append(
            (
                PredictSample(
                    packet_count=packets,
                    byte_count=packets * size,
                    pktrate=round(rate, 2),
                    byterate=round(rate * size, 2),
                    ip_proto=rng.choice([6, 6, 17]),
                    l4_dst_port=rng.choice([22, 53, 80, 443, 5201, 8080]),
                ),
                int(attack),
            )
        )
    rng.shuffle(samples)
    return samples


def load_csv(path: Path, limit: int, seed: int) -> List[LabeledSample]:
    rows: List[LabeledSample] = []
    with path.open(newline="") as handle:
        for row in csv.DictReader(handle):
            rows.append(
                (
                    PredictSample(
                        packet_count=int(float(row["packet_count"])),
                        byte_count=int(float(row["byte_count"])),
                        pktrate=float(row["pktrate"]),
                        byterate=float(row["byterate"]),
                        ip_proto=int(float(row["ip_proto"])),
                        l4_dst_port=int(float(row["l4_dst_port"])),
                    ),
                    int(float(row["label"])),
                )
            )
    random.Random(seed).shuffle(rows)
    return rows[:limit] if limit else rows


def percentile(values: List[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(math.ceil(fraction * len(ordered))) - 1)]


def evaluate(
    model: str, samples: List[LabeledSample], args: argparse.Namespace
) -> Dict[str, Any]:
    settings = OllamaSettings(
        base_url=args.url,
        model=model,
        timeout_seconds=args.timeout,
        api_key="unused",
        prompt_profile=args.prompt,
    )
    http = requests.Session()
    started = time.monotonic()
    try:
        query_llm(samples[0][0], settings, http)  # loads the model; not timed below
    except Exception as exc:
        return {"model": model, "error": f"could not run model: {exc}"}
    load_seconds = time.monotonic() - started

    tp = tn = fp = fn = failures = calls = agreeing = evaluated = 0
    brier: List[float] = []
    latencies: List[float] = []
    for sample, label in samples:
        verdicts: List[bool] = []
        for _ in range(args.repeats):
            calls += 1
            begin = time.monotonic()
            try:
                is_ddos, confidence = query_llm(sample, settings, http)
            except Exception:
                failures += 1
                continue
            latencies.append((time.monotonic() - begin) * 1000.0)
            probability = to_prediction(is_ddos, confidence).prob_ddos
            verdicts.append(probability >= args.threshold)
            if len(verdicts) == 1:
                brier.append((probability - label) ** 2)
        if not verdicts:
            continue
        evaluated += 1
        agreeing += int(len(set(verdicts)) == 1)
        predicted = verdicts[0]
        if predicted and label:
            tp += 1
        elif predicted:
            fp += 1
        elif label:
            fn += 1
        else:
            tn += 1

    def ratio(numerator: float, denominator: float) -> float:
        return numerator / denominator if denominator else float("nan")

    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    return {
        "model": model,
        "samples": evaluated,
        "load_seconds": round(load_seconds, 1),
        "accuracy": ratio(tp + tn, evaluated),
        "precision": precision,
        "recall_DR": recall,
        "false_alarm_rate": ratio(fp, fp + tn),
        "f1": ratio(2 * precision * recall, precision + recall),
        "brier": statistics.fmean(brier) if brier else float("nan"),
        "consistency": ratio(agreeing, evaluated),
        "failure_rate": ratio(failures, calls),
        "latency_ms_mean": statistics.fmean(latencies) if latencies else float("nan"),
        "latency_ms_p95": percentile(latencies, 0.95) if latencies else float("nan"),
        "confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--models", required=True, help="comma separated Ollama model tags"
    )
    parser.add_argument("--url", default="http://192.168.83.1:11434")
    parser.add_argument(
        "--samples", type=Path, help="CSV with the six features + label"
    )
    parser.add_argument("--limit", type=int, default=0, help="max samples (0 = all)")
    parser.add_argument("--synthetic-count", type=int, default=40)
    parser.add_argument(
        "--repeats", type=int, default=2, help="calls per sample (consistency)"
    )
    parser.add_argument(
        "--prompt", default="insdn", help="prompt profile in llm_api.PROMPTS"
    )
    parser.add_argument("--threshold", type=float, default=0.8)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out", type=Path, default=Path("logs/llm_comparison.json"))
    args = parser.parse_args()

    if args.samples:
        samples = load_csv(args.samples, args.limit, args.seed)
        source = str(args.samples)
    else:
        samples = synthetic_samples(args.limit or args.synthetic_count, args.seed)
        source = "SYNTHETIC (sanity check only, not a detection benchmark)"
    print(
        f"samples: {len(samples)} from {source}; repeats={args.repeats}; threshold={args.threshold}"
    )

    results = [
        evaluate(model.strip(), samples, args) for model in args.models.split(",")
    ]
    header = f"{'model':<18}{'acc':>6}{'DR':>6}{'FAR':>6}{'F1':>6}{'brier':>7}{'consist':>8}{'fail':>6}{'ms(mean)':>10}{'ms(p95)':>9}"
    print(header)
    for r in results:
        if "error" in r:
            print(f"{r['model']:<18} ERROR: {r['error']}")
            continue
        print(
            f"{r['model']:<18}{r['accuracy']:>6.2f}{r['recall_DR']:>6.2f}"
            f"{r['false_alarm_rate']:>6.2f}{r['f1']:>6.2f}{r['brier']:>7.3f}"
            f"{r['consistency']:>8.2f}{r['failure_rate']:>6.2f}"
            f"{r['latency_ms_mean']:>10.0f}{r['latency_ms_p95']:>9.0f}"
        )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(
            {"source": source, "args": vars(args), "results": results},
            indent=2,
            default=str,
        )
    )
    print(f"saved: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
