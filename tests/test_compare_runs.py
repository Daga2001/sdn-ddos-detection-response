import csv
import math
import random
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path

import pytest

from sdn_ddos.analysis.compare import (
    MIN_RUNS,
    comparisons,
    mann_whitney,
    markdown_report,
    read_rows,
    select,
    summarize,
    summary_rows,
    t975,
    wilson,
)


def test_wilson_matches_the_published_interval_and_handles_the_edges():
    # Newcombe (1998), table I: 81/263 -> 0.2553 to 0.3662
    interval = wilson(81, 263)
    assert interval is not None
    assert interval.low == pytest.approx(25.53, abs=0.01)
    assert interval.high == pytest.approx(36.62, abs=0.01)
    zero, full = wilson(0, 10), wilson(10, 10)
    assert (
        zero is not None
        and zero.low == 0
        and zero.high == pytest.approx(27.75, abs=0.01)
    )
    assert (
        full is not None
        and full.high == 100
        and full.low == pytest.approx(72.25, abs=0.01)
    )
    assert wilson(0, 0) is None
    with pytest.raises(ValueError):
        wilson(3, 2)


def test_t_quantiles_and_the_mean_interval():
    assert t975(1) == 12.706 and t975(9) == 2.262
    assert t975(60) == pytest.approx(2.000, abs=0.002)
    assert t975(120) == pytest.approx(1.980, abs=0.002)
    with pytest.raises(ValueError):
        t975(0)
    summary = summarize([10.0, 12.0, 11.0, 13.0, 14.0])
    assert summary is not None and summary.mean == 12.0 and summary.median == 12.0
    half = 2.776 * math.sqrt(2.5) / math.sqrt(5)
    assert summary.low == pytest.approx(12 - half) and summary.high == pytest.approx(
        12 + half
    )
    single = summarize([4.0])
    assert single is not None and single.low is None
    assert summarize([]) is None


def brute_force_p(a, b):
    """Exact two-sided p by enumerating every split of the pooled values."""

    pooled = [*a, *b]
    n1 = len(a)

    def u_of(group):
        return sum(1 for x in group for y in pooled if y not in group and x > y)

    observed = sum(1 for x in a for y in b if x > y)
    total = 0
    extreme = 0
    centre = n1 * len(b) / 2
    for chosen in combinations(pooled, n1):
        u = u_of(set(chosen))
        total += 1
        if abs(u - centre) >= abs(observed - centre) - 1e-9:
            extreme += 1
    return extreme / total


def test_exact_mann_whitney_agrees_with_enumeration():
    rng = random.Random(7)
    for _ in range(20):
        values = rng.sample(range(1000), 9)
        a, b = values[:4], values[4:]
        test = mann_whitney(a, b)
        assert test is not None and test.exact
        assert test.p_value == pytest.approx(brute_force_p(a, b))
    separated = mann_whitney([10, 11, 12, 13, 14], [1, 2, 3, 4, 5])
    assert separated is not None
    assert separated.rank_biserial == 1.0 and separated.p_value == pytest.approx(
        2 / 252
    )


def test_ties_use_the_normal_approximation_and_identical_samples_give_p_one():
    tied = mann_whitney([1, 1, 2, 3], [1, 2, 2, 5])
    assert tied is not None and not tied.exact and 0 < tied.p_value <= 1
    same = mann_whitney([3, 3, 3], [3, 3, 3])
    assert same is not None and same.p_value == 1.0 and same.rank_biserial == 0
    assert mann_whitney([], [1]) is None


HEADER = [
    "run_id",
    "started_utc",
    "purpose",
    "scenario",
    "settings_fingerprint",
    "forwarding",
    "detector",
    "response",
    "traffic",
    "attackers",
    "rate_per_s",
    "tp",
    "fn",
    "fp",
    "tn",
    "mean_detection_s",
    "availability_attack_pct",
    "time_per_decision_median_ms",
    "valid",
    "validity_notes",
]


def run(i, detector, purpose="held_out", fingerprint=None, valid="yes", **values):
    base = {
        "run_id": f"r{i}",
        "started_utc": f"2026-11-20T10:{i % 60:02d}:00+00:00",
        "purpose": purpose,
        "scenario": "TC-2",
        "settings_fingerprint": fingerprint or f"fp-{detector}",
        "forwarding": "port_free",
        "detector": detector,
        "response": "block",
        "traffic": "syn",
        "attackers": "2",
        "rate_per_s": "1000",
        "tp": "2",
        "fn": "0",
        "fp": "0",
        "tn": "20",
        "mean_detection_s": "5",
        "availability_attack_pct": "90",
        "time_per_decision_median_ms": "1",
        "valid": valid,
        "validity_notes": "",
    }
    base.update({k: str(v) for k, v in values.items()})
    return base


def write(path: Path, rows, stacked=False):
    with path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        for index, row in enumerate(rows):
            if index == 0 or stacked:
                writer.writerow(HEADER)
            writer.writerow([row[name] for name in HEADER])


def test_only_valid_held_out_runs_after_the_freeze_are_pooled(tmp_path: Path):
    rows = [run(i, "llm", time_per_decision_median_ms=300 + i) for i in range(10)]
    rows += [
        run(10 + i, "rule", time_per_decision_median_ms=1 + i / 10) for i in range(10)
    ]
    rows += [
        run(20, "llm", purpose="calibration"),
        run(21, "llm", valid="no"),
        run(22, "off", purpose="exploration"),
    ]
    rows[0]["started_utc"] = "2026-11-01T00:00:00+00:00"
    path = tmp_path / "runs.csv"
    write(path, rows, stacked=True)
    loaded = read_rows([str(path)])
    assert len(loaded) == len(rows)
    frozen = datetime(2026, 11, 10, tzinfo=timezone.utc)
    selection = select(loaded, frozen_at=frozen)
    assert [len(cell.runs) for cell in selection.cells] == [9, 10]
    reasons = dict(selection.excluded)
    assert "purpose calibration" in reasons["r20"]
    assert "not a valid run" in reasons["r21"]
    assert "before the settings were frozen" in reasons["r0"]
    assert any(f"fewer than the {MIN_RUNS}" in p for p in selection.problems)
    tests = comparisons(selection.cells)
    timing = next(t for t in tests if t["metric"] == "time_per_decision_median_ms")
    assert (timing["a"], timing["b"]) == ("llm", "rule")
    assert timing["rank_biserial"] == 1.0 and timing["p_value"] < 0.001
    report = markdown_report(selection, tests)
    assert "Wilson" in report and "| TC-2 | llm | rule |" in report
    flat = summary_rows(selection)
    assert flat[0]["detector"] == "llm" and flat[0]["runs"] == "9"
    assert float(flat[0]["detection_rate_pct"]) == 100.0
    assert float(flat[0]["false_alarm_rate_pct_high"]) > 0


def test_mixed_settings_in_one_cell_are_refused_unless_allowed():
    rows = [run(1, "llm", fingerprint="a"), run(2, "llm", fingerprint="b")]
    with pytest.raises(ValueError, match="2 different settings fingerprints"):
        select(rows)
    selection = select(rows, allow_mixed_settings=True)
    assert any("different settings" in p for p in selection.problems)


def test_a_file_without_the_header_is_rejected(tmp_path: Path):
    path = tmp_path / "bad.csv"
    path.write_text("r1,2026,held_out\n")
    with pytest.raises(ValueError, match="no results-row header"):
        read_rows([str(path)])
