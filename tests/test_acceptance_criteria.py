"""Fisher's exact test, Holm correction and acceptance criteria (thesis §3.5.4)."""

import math
import subprocess
import sys
from pathlib import Path

import pytest
from test_compare_runs import run, write

from sdn_ddos.analysis.compare import (
    ALPHA,
    DETECTION_LIMIT_S,
    acceptance,
    comparisons,
    fisher_exact,
    holm,
    markdown_report,
    select,
)

REPO = Path(__file__).resolve().parents[1]


def test_fisher_exact_matches_published_and_reference_values():
    # Fisher's tea-tasting experiment (The Design of Experiments, 1935): 3/4 right.
    assert fisher_exact(3, 1, 1, 3) == pytest.approx(0.4857143, rel=1e-6)
    # Reference values from scipy.stats.fisher_exact (two-sided) for the thesis tables.
    assert fisher_exact(109, 71, 0, 180) == pytest.approx(9.624311e-44, rel=1e-6)
    assert fisher_exact(4, 166, 0, 170) == pytest.approx(0.1227909, rel=1e-6)
    assert fisher_exact(37, 3, 40, 0) == pytest.approx(0.2405063, rel=1e-6)
    assert fisher_exact(9, 171, 0, 180) == pytest.approx(0.00352595, rel=1e-6)
    assert fisher_exact(20, 0, 0, 20) == pytest.approx(1.450889e-11, rel=1e-6)
    # equal tables and empty margins give 1
    assert fisher_exact(20, 0, 20, 0) == 1.0
    assert fisher_exact(0, 0, 0, 0) == 1.0
    with pytest.raises(ValueError):
        fisher_exact(-1, 2, 3, 4)


def test_fisher_exact_is_symmetric_in_rows_and_columns():
    for table in [(5, 2, 1, 7), (0, 10, 4, 6), (12, 3, 9, 9)]:
        a, b, c, d = table
        p = fisher_exact(a, b, c, d)
        assert fisher_exact(c, d, a, b) == pytest.approx(p)
        assert fisher_exact(a, c, b, d) == pytest.approx(p)


def test_holm_steps_down_and_stays_monotone():
    # Holm (1979): sorted p 0.01, 0.02, 0.03, 0.04 with m = 4
    assert holm([0.01, 0.04, 0.03, 0.02]) == pytest.approx([0.04, 0.06, 0.06, 0.06])
    assert holm([0.5, 0.9]) == pytest.approx([1.0, 1.0])
    assert holm([]) == []
    adjusted = holm([0.001, 0.2, 0.0001])
    assert adjusted == pytest.approx([0.002, 0.2, 0.0003])


def scenario(llm_fp=0, llm_tp=2, llm_times=None, off_availability=1.0, rule_tp=2):
    rows = []
    llm_times = llm_times or [5 + i / 10 for i in range(10)]
    for i in range(10):
        rows.append(
            run(
                i,
                "rule",
                tp=rule_tp,
                fn=2 - rule_tp,
                mean_detection_s=2 + i / 100 if rule_tp else "",
                availability_attack_pct=50 + i,
            )
        )
        rows.append(
            run(
                10 + i,
                "llm",
                tp=llm_tp,
                fn=2 - llm_tp,
                fp=llm_fp,
                tn=20 - llm_fp,
                mean_detection_s=llm_times[i],
                availability_attack_pct=40 + i,
            )
        )
        rows.append(
            run(
                20 + i,
                "off",
                response="",
                tp="",
                fn="",
                fp="",
                tn="",
                mean_detection_s="",
                availability_attack_pct=off_availability + i / 100,
            )
        )
    return select(rows)


def verdict(criteria, detector):
    return next(r for r in criteria.verdicts if r["detector"] == detector)


def test_a_detector_that_raises_false_alarms_misses_the_rule_criterion():
    criteria = acceptance(scenario(llm_fp=5).cells)
    llm, rule = verdict(criteria, "llm"), verdict(criteria, "rule")
    assert llm["false_alarm_rate_vs_rule"] == "no"  # 50/200 against 0/200
    assert llm["detection_rate_vs_rule"] == "yes"  # 20/20 against 20/20
    assert rule["detection_rate_vs_rule"] == "--"
    assert llm["detection_within_limit"] == "yes"
    # the service was lost without defense, and both arms raised it
    assert llm["availability_vs_no_defense"] == "yes"
    assert rule["availability_vs_no_defense"] == "yes"
    tests = criteria.tests
    assert {t["measure"] for t in tests} == {
        "detection_rate",
        "false_alarm_rate",
        "mean_detection_s",
        "availability_attack_pct",
    }
    # Holm over the five tests of the scenario: adjusted p >= raw p, at most 1
    assert all(t["p_value"] <= t["p_holm"] <= 1 for t in tests)
    assert all(t["significant"] == (t["p_holm"] < ALPHA) for t in tests)


def test_more_detections_than_the_rule_is_better_and_a_slow_mean_fails_the_limit():
    criteria = acceptance(
        scenario(rule_tp=0, llm_times=[DETECTION_LIMIT_S + 5] * 10).cells
    )
    llm, rule = verdict(criteria, "llm"), verdict(criteria, "rule")
    assert llm["detection_rate_vs_rule"] == "better"  # 20/20 against 0/20
    assert llm["detection_within_limit"] == "no"
    # a rule that flagged nobody has no detection time: it misses the limit
    assert rule["detection_within_limit"] == "no"


def test_availability_is_not_testable_when_no_defense_kept_the_service():
    criteria = acceptance(scenario(off_availability=100).cells)
    assert {r["availability_vs_no_defense"] for r in criteria.verdicts} == {"n.a."}
    assert not [t for t in criteria.tests if t["measure"] == "availability_attack_pct"]


def test_a_scenario_without_the_rule_has_no_criteria_and_duplicates_are_refused():
    rows = [run(i, "llm") for i in range(10)] + [
        run(10 + i, "entropy") for i in range(10)
    ]
    assert acceptance(select(rows).cells).verdicts == []
    rows = [run(i, "rule") for i in range(10)]
    rows += [
        run(10 + i, "rule", response="rate_limit", fingerprint="x") for i in range(10)
    ]
    with pytest.raises(ValueError, match="same detector in one scenario"):
        acceptance(select(rows).cells)


def test_the_report_and_the_cli_carry_the_criteria(tmp_path: Path):
    selection = scenario(llm_fp=5)
    text = markdown_report(
        selection, comparisons(selection.cells), acceptance(selection.cells)
    )
    assert "## Acceptance criteria" in text and "p (Holm)" in text
    rows = [row for cell in selection.cells for row in cell.runs]
    path = tmp_path / "rows.csv"
    write(path, rows)
    out = tmp_path / "criteria.csv"
    result = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts/compare_runs.py"),
            str(path),
            "--criteria-out",
            str(out),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "## Acceptance criteria" in result.stdout
    lines = out.read_text().splitlines()
    assert lines[0].startswith("scenario,detector,measure,value,reference,p_value")
    assert len(lines) == 1 + 5
    assert not math.isnan(float(lines[1].split(",")[5]))


def test_the_same_rows_always_give_the_same_report():
    first = markdown_report(*_report_args())
    second = markdown_report(*_report_args())
    assert first == second


def _report_args():
    selection = scenario(llm_fp=3)
    return selection, comparisons(selection.cells), acceptance(selection.cells)
