"""Many-run comparison of detectors: the statistics of the evaluation protocol (§6).

Input is the one-row-per-run CSV of the Results tab (*Download results row*), several
files or one stacked file. Runs are grouped into **cells** (test case, forwarding,
detector, response, traffic, attackers, rate); a cell is one arm of one scenario.

* Only `held_out` runs are used by default, only valid ones, and a cell whose runs do
  not share one settings fingerprint is refused: they were not judged with the same
  frozen settings (Arp et al. 2022, data snooping).
* Proportions (detection rate, false alarm rate) are pooled over the runs of a cell
  and given a Wilson 95 % interval; per-run percentages of a handful of hosts are never
  averaged.
* Continuous metrics get the mean, a Student-t 95 % interval, the median and range.
* Arms of the same scenario are compared with a two-sided Mann-Whitney U test (exact
  without ties, normal approximation with tie correction otherwise) and the
  rank-biserial correlation as effect size.
* A cell with fewer than 10 runs is flagged (RFC 8456 §4.7).

Pure standard library, so it runs wherever the CSV is.
"""

from __future__ import annotations

import csv
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from itertools import combinations
from typing import Optional

MIN_RUNS = 10  # RFC 8456 §4.7: each test SHOULD be repeated at least 10 times
CELL_KEYS = (
    "scenario",
    "forwarding",
    "detector",
    "response",
    "traffic",
    "attackers",
    "rate_per_s",
)
CONTINUOUS = (
    "first_detection_s",
    "mean_detection_s",
    "early_detection_rate_pct",
    "time_per_decision_median_ms",
    "time_per_decision_p95_ms",
    "detector_cpu_per_decision_ms",
    "decisions_per_s_attack_per_s",
    "detector_ram_peak_mib",
    "ryu_cpu_attack_pct",
    "availability_attack_pct",
    "request_time_median_attack_ms",
    "ping_loss_attack_pct",
    "time_to_first_failure_s",
    "packet_in_handled_attack_per_s",
    "flow_rules_peak_attack",
    "response_time_s",
    "service_recovery_s",
    "controller_recovery_s",
)
COMPARED = (
    "availability_attack_pct",
    "mean_detection_s",
    "time_per_decision_median_ms",
    "detector_cpu_per_decision_ms",
    "service_recovery_s",
)
# Two-sided 0.975 quantiles of Student's t for 1..30 degrees of freedom.
_T975 = (
    12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
    2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086,
    2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042,
)  # fmt: skip
Z975 = 1.959964


def t975(df: int) -> float:
    if df < 1:
        raise ValueError("a confidence interval needs at least two runs")
    if df <= len(_T975):
        return _T975[df - 1]
    # Cornish-Fisher expansion: within 0.001 of the exact quantile for df > 30.
    z = Z975
    return z + (z**3 + z) / (4 * df) + (5 * z**5 + 16 * z**3 + 3 * z) / (96 * df**2)


@dataclass(frozen=True)
class Interval:
    estimate: float
    low: float
    high: float


def wilson(successes: int, total: int) -> Optional[Interval]:
    """Wilson score 95 % interval of a proportion (in percent)."""

    if total <= 0:
        return None
    if not 0 <= successes <= total:
        raise ValueError("successes must be between 0 and total")
    p = successes / total
    z2 = Z975**2
    centre = (p + z2 / (2 * total)) / (1 + z2 / total)
    half = (Z975 / (1 + z2 / total)) * math.sqrt(
        p * (1 - p) / total + z2 / (4 * total**2)
    )
    low = 0.0 if successes == 0 else max(0.0, centre - half)
    high = 1.0 if successes == total else min(1.0, centre + half)
    return Interval(100 * p, 100 * low, 100 * high)


@dataclass(frozen=True)
class Summary:
    n: int
    mean: float
    low: Optional[float]
    high: Optional[float]
    median: float
    minimum: float
    maximum: float


def summarize(values: Sequence[float]) -> Optional[Summary]:
    if not values:
        return None
    n = len(values)
    ordered = sorted(values)
    mean = sum(values) / n
    middle = n // 2
    median = ordered[middle] if n % 2 else (ordered[middle - 1] + ordered[middle]) / 2
    if n < 2:
        return Summary(n, mean, None, None, median, ordered[0], ordered[-1])
    sd = math.sqrt(sum((value - mean) ** 2 for value in values) / (n - 1))
    half = t975(n - 1) * sd / math.sqrt(n)
    return Summary(n, mean, mean - half, mean + half, median, ordered[0], ordered[-1])


def _ranks(values: Sequence[float]) -> list[float]:
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return ranks


@lru_cache(maxsize=None)
def _u_counts(n1: int, n2: int) -> tuple[int, ...]:
    """Number of arrangements giving each U = 0..n1*n2, without ties (exact null)."""

    # f[m][k] = arrangements of m and k elements by U; built with the recurrence
    # f(m, k, u) = f(m - 1, k, u - k) + f(m, k - 1, u).
    first: list[tuple[int, ...]] = [(1,)] * (n2 + 1)
    table: list[list[tuple[int, ...]]] = [first]
    for m in range(1, n1 + 1):
        row: list[tuple[int, ...]] = [(1,)]
        for k in range(1, n2 + 1):
            left, up = table[m - 1][k], row[k - 1]
            size = m * k + 1
            counts = [0] * size
            for u, count in enumerate(left):
                if u + k < size:
                    counts[u + k] += count
            for u, count in enumerate(up):
                counts[u] += count
            row.append(tuple(counts))
        table.append(row)
    return table[n1][n2]


@dataclass(frozen=True)
class MannWhitney:
    u: float
    p_value: float
    rank_biserial: float  # P(a > b) - P(a < b); positive when `a` tends to be larger
    exact: bool


def mann_whitney(a: Sequence[float], b: Sequence[float]) -> Optional[MannWhitney]:
    n1, n2 = len(a), len(b)
    if n1 == 0 or n2 == 0:
        return None
    ranks = _ranks([*a, *b])
    u1 = sum(ranks[:n1]) - n1 * (n1 + 1) / 2
    effect = 2 * u1 / (n1 * n2) - 1
    tied = len(set([*a, *b])) < n1 + n2
    if not tied and n1 * n2 <= 625:
        counts = _u_counts(n1, n2)
        total = sum(counts)
        low = sum(counts[: int(min(u1, n1 * n2 - u1)) + 1])
        return MannWhitney(u1, min(1.0, 2 * low / total), effect, True)
    n = n1 + n2
    groups: dict[float, int] = {}
    for value in [*a, *b]:
        groups[value] = groups.get(value, 0) + 1
    tie = sum(t**3 - t for t in groups.values())
    variance = n1 * n2 / 12 * ((n + 1) - tie / (n * (n - 1)))
    if variance <= 0:
        return MannWhitney(u1, 1.0, effect, False)
    z = (abs(u1 - n1 * n2 / 2) - 0.5) / math.sqrt(variance)
    p = math.erfc(max(z, 0.0) / math.sqrt(2))
    return MannWhitney(u1, min(1.0, p), effect, False)


def _number(text: Optional[str]) -> Optional[float]:
    if text is None or text.strip() == "":
        return None
    try:
        value = float(text)
    except ValueError:
        return None
    return value if math.isfinite(value) else None


def read_rows(paths: Iterable[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for path in paths:
        with open(path, newline="", encoding="utf-8") as handle:
            reader = csv.reader(handle)
            header: Optional[list[str]] = None
            for record in reader:
                if not record or all(not cell for cell in record):
                    continue
                if record[0] == "run_id":  # stacked files repeat the header
                    header = record
                    continue
                if header is None:
                    raise ValueError(f"{path}: no results-row header (run_id, ...)")
                rows.append(dict(zip(header, record)))
    return rows


@dataclass
class Cell:
    key: tuple[str, ...]
    runs: list[dict[str, str]] = field(default_factory=list)

    def label(self) -> str:
        return " | ".join(
            f"{name}={value or '-'}" for name, value in zip(CELL_KEYS, self.key)
        )


@dataclass
class Selection:
    cells: list[Cell]
    excluded: list[tuple[str, str]]  # (run id, reason)
    problems: list[str]


def select(
    rows: Iterable[Mapping[str, str]],
    purposes: Sequence[str] = ("held_out",),
    include_invalid: bool = False,
    frozen_at: Optional[datetime] = None,
    allow_mixed_settings: bool = False,
) -> Selection:
    cells: dict[tuple[str, ...], Cell] = {}
    excluded: list[tuple[str, str]] = []
    for row in rows:
        run = row.get("run_id", "?")
        purpose = row.get("purpose", "") or "exploration"
        if purpose not in purposes:
            excluded.append((run, f"purpose {purpose}"))
            continue
        if not include_invalid and row.get("valid", "") != "yes":
            excluded.append(
                (run, "not a valid run: " + (row.get("validity_notes") or ""))
            )
            continue
        if frozen_at is not None:
            started = row.get("started_utc", "")
            try:
                moment = datetime.fromisoformat(started.replace("Z", "+00:00"))
            except ValueError:
                excluded.append((run, "no start time to compare with the freeze"))
                continue
            if moment < frozen_at:
                excluded.append((run, "recorded before the settings were frozen"))
                continue
        key = tuple(row.get(name, "") for name in CELL_KEYS)
        cells.setdefault(key, Cell(key)).runs.append(dict(row))
    problems: list[str] = []
    for cell in cells.values():
        prints = {run.get("settings_fingerprint", "") for run in cell.runs}
        if len(prints) > 1:
            message = (
                f"{cell.label()}: {len(prints)} different settings fingerprints "
                f"({', '.join(sorted(p or 'none' for p in prints))}); these runs were "
                "not judged with the same frozen settings"
            )
            if not allow_mixed_settings:
                raise ValueError(message)
            problems.append(message)
        if len(cell.runs) < MIN_RUNS:
            problems.append(
                f"{cell.label()}: {len(cell.runs)} runs, fewer than the "
                f"{MIN_RUNS} of RFC 8456 §4.7"
            )
    ordered = sorted(cells.values(), key=lambda cell: cell.key)
    return Selection(ordered, excluded, problems)


def _counts(cell: Cell, name: str) -> int:
    return int(sum(_number(run.get(name)) or 0 for run in cell.runs))


def cell_summary(cell: Cell) -> dict[str, object]:
    tp, fn = _counts(cell, "tp"), _counts(cell, "fn")
    fp, tn = _counts(cell, "fp"), _counts(cell, "tn")
    result: dict[str, object] = {
        "cell": cell.label(),
        "runs": len(cell.runs),
        "settings_fingerprint": cell.runs[0].get("settings_fingerprint", ""),
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "detection_rate_pct": wilson(tp, tp + fn),
        "false_alarm_rate_pct": wilson(fp, fp + tn),
    }
    for name in CONTINUOUS:
        values = [
            v for v in (_number(run.get(name)) for run in cell.runs) if v is not None
        ]
        result[name] = summarize(values)
    return result


def comparisons(
    cells: Sequence[Cell], metrics: Sequence[str] = COMPARED
) -> list[dict[str, object]]:
    """Every pair of detectors within the same scenario (all other cell keys equal)."""

    by_scenario: dict[tuple[str, ...], list[Cell]] = {}
    detector = CELL_KEYS.index("detector")
    for cell in cells:
        rest = cell.key[:detector] + cell.key[detector + 1 :]
        by_scenario.setdefault(rest, []).append(cell)
    results: list[dict[str, object]] = []
    for group in by_scenario.values():
        for first, second in combinations(sorted(group, key=lambda c: c.key), 2):
            for name in metrics:
                a = [
                    v
                    for v in (_number(r.get(name)) for r in first.runs)
                    if v is not None
                ]
                b = [
                    v
                    for v in (_number(r.get(name)) for r in second.runs)
                    if v is not None
                ]
                test = mann_whitney(a, b)
                if test is None:
                    continue
                results.append(
                    {
                        "scenario": first.key[0],
                        "a": first.key[detector],
                        "b": second.key[detector],
                        "metric": name,
                        "n_a": len(a),
                        "n_b": len(b),
                        "u": test.u,
                        "p_value": test.p_value,
                        "rank_biserial": test.rank_biserial,
                        "exact": test.exact,
                    }
                )
    return results


def _fmt(value: object) -> str:
    if value is None:
        return "—"
    if isinstance(value, Interval):
        return f"{value.estimate:.1f} [{value.low:.1f}, {value.high:.1f}]"
    if isinstance(value, Summary):
        if value.low is None or value.high is None:
            return f"{value.mean:.3g} (n={value.n})"
        return f"{value.mean:.3g} [{value.low:.3g}, {value.high:.3g}] (n={value.n})"
    if isinstance(value, float):
        return f"{value:.4g}"
    return str(value)


def markdown_report(selection: Selection, tests: Sequence[Mapping[str, object]]) -> str:
    lines = ["# Comparison of detectors", ""]
    if selection.problems:
        lines += ["## Warnings", ""] + [f"* {p}" for p in selection.problems] + [""]
    lines += [
        "## Cells",
        "",
        "DR and FAR: pooled over the runs, Wilson 95 % interval. Other metrics: mean "
        "[Student-t 95 % interval] (n).",
        "",
        "| Cell | Runs | DR % | FAR % | Detection time s | Availability (attack) % | "
        "Time per decision ms | Recovery s |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for cell in selection.cells:
        s = cell_summary(cell)
        lines.append(
            "| "
            + " | ".join(
                _fmt(s[name])
                for name in (
                    "cell",
                    "runs",
                    "detection_rate_pct",
                    "false_alarm_rate_pct",
                    "mean_detection_s",
                    "availability_attack_pct",
                    "time_per_decision_median_ms",
                    "service_recovery_s",
                )
            )
            + " |"
        )
    if tests:
        lines += [
            "",
            "## Mann-Whitney U (two-sided)",
            "",
            "| Scenario | A | B | Metric | n A | n B | U | p | rank-biserial | exact |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        for test in tests:
            lines.append(
                "| "
                + " | ".join(
                    _fmt(test[name])
                    for name in (
                        "scenario",
                        "a",
                        "b",
                        "metric",
                        "n_a",
                        "n_b",
                        "u",
                        "p_value",
                        "rank_biserial",
                        "exact",
                    )
                )
                + " |"
            )
    if selection.excluded:
        lines += ["", f"## Runs left out ({len(selection.excluded)})", ""]
        lines += [f"* {run}: {reason}" for run, reason in selection.excluded]
    return "\n".join(lines) + "\n"


def summary_rows(selection: Selection) -> list[dict[str, str]]:
    """One flat row per cell for a CSV: estimates and interval bounds as columns."""

    rows: list[dict[str, str]] = []
    for cell in selection.cells:
        s = cell_summary(cell)
        row = {name: value for name, value in zip(CELL_KEYS, cell.key)}
        row.update(
            runs=str(s["runs"]),
            settings_fingerprint=str(s["settings_fingerprint"]),
            tp=str(s["tp"]),
            fn=str(s["fn"]),
            fp=str(s["fp"]),
            tn=str(s["tn"]),
        )
        for name in ("detection_rate_pct", "false_alarm_rate_pct"):
            interval = s[name]
            assert interval is None or isinstance(interval, Interval)
            row[name] = "" if interval is None else f"{interval.estimate:.4f}"
            row[f"{name}_low"] = "" if interval is None else f"{interval.low:.4f}"
            row[f"{name}_high"] = "" if interval is None else f"{interval.high:.4f}"
        for name in CONTINUOUS:
            summary = s[name]
            assert summary is None or isinstance(summary, Summary)
            row[f"{name}_n"] = "" if summary is None else str(summary.n)
            row[f"{name}_mean"] = "" if summary is None else f"{summary.mean:.6g}"
            row[f"{name}_low"] = (
                "" if summary is None or summary.low is None else f"{summary.low:.6g}"
            )
            row[f"{name}_high"] = (
                "" if summary is None or summary.high is None else f"{summary.high:.6g}"
            )
            row[f"{name}_median"] = "" if summary is None else f"{summary.median:.6g}"
        rows.append(row)
    return rows
