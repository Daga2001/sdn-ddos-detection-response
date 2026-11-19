"""The calibration sweep is the grid written in advance, scored by one fixed rule."""

import sys
from pathlib import Path

from test_replay_entropy import ATTACKERS, VICTIM, dump, stamp

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import calibrate_entropy as calibrate


def test_the_grid_has_the_size_written_down_before_the_sweep():
    assert len(calibrate.models()) == 125
    assert len(calibrate.grid("primary")) == 6000
    assert len(calibrate.grid("secondary")) == 24000
    primary = {c["min_total_rate"] for _, c in calibrate.grid("primary")}
    assert primary == {2.0}  # only the secondary variant moves the minimum rate
    names = [name for name, _ in calibrate.grid("primary")]
    assert len(names) == len(set(names))


def test_a_configuration_is_scored_over_every_run_and_phase():
    runs = [
        {
            "run": "r1",
            "label": "S1",
            "a0": stamp(30),
            "a1": stamp(40),
            "attackers": ATTACKERS,
            "victims": [VICTIM],
        },
        {
            "run": "r1",
            "label": "control",
            "a0": stamp(30),
            "a1": stamp(40),
            "benign": True,
            "attackers": ATTACKERS,  # a benign run has none: anyone named is wrong
            "victims": [VICTIM],
        },
    ]
    calibrate.init({"r1": dump()}, runs)
    settings = {
        **calibrate.FIXED,
        "measure": "norm",
        "center": "ewma",
        "k": 2.5,
        "context": "normal",
        "warmup_windows": 8,
        "consecutive_windows": 1,
        "candidate_min_rate": 50.0,
        "candidate_share": 0.3,
        "min_total_rate": 2.0,
    }
    row = calibrate.evaluate(("x", settings))
    attack, control = row["per_run"]
    assert attack["attackers_named"] == 3 and attack["legit_named"] == 0
    assert attack["first"] is not None and attack["first"] <= 2
    # Read as a run without attack, the flood hosts are false accusations.
    assert control["attackers"] == 0 and control["legit_named"] == 3
    assert row["legit"] == 3 and row["attackers"] == 3


def test_the_rank_rule_puts_runs_without_false_accusations_first():
    def row(legit, attackers, first, base):
        return {
            "legit": legit,
            "attackers": attackers,
            "mean_first": first,
            "base_alarms": base,
        }

    ranked = sorted(
        [
            row(1, 7, 0.5, 0),
            row(0, 6, 0.5, 0),
            row(0, 7, 2.0, 5),
            row(0, 7, 1.0, 9),
            row(0, 7, 1.0, 2),
            row(0, 7, None, 0),
        ],
        key=calibrate.rank_key,
    )
    assert [
        (r["legit"], r["attackers"], r["mean_first"], r["base_alarms"]) for r in ranked
    ] == [
        (0, 7, 1.0, 2),
        (0, 7, 1.0, 9),
        (0, 7, 2.0, 5),
        (0, 7, None, 0),
        (0, 6, 0.5, 0),
        (1, 7, 0.5, 0),
    ]


def test_neighbours_move_one_step_on_one_axis():
    margin = {
        "measure": "norm",
        "center": "ewma_margin",
        "margin": 0.1,
        "context": "normal",
        "warmup_windows": 16,
        "consecutive_windows": 2,
        "candidate_min_rate": 50.0,
        "candidate_share": 0.3,
        "min_total_rate": 2.0,
    }
    found = calibrate.neighbours(margin, moves_min_rate=False)
    assert {n["margin"] for n in found if n["margin"] != 0.1} == {0.05, 0.2}
    assert not any(
        n["context"] != "normal" for n in found
    )  # ewma_margin only learns normal
    assert all(sum(1 for k in margin if n[k] != margin[k]) == 1 for n in found)
    band = {**margin, "center": "median", "spread": "mad", "k": 5.0}
    del band["margin"]
    moved = calibrate.neighbours(band, moves_min_rate=True)
    assert {n["k"] for n in moved} == {3.0, 5.0, 8.0}
    assert any(n["context"] == "all" for n in moved)
    assert any(n["min_total_rate"] == 20.0 for n in moved)


def test_analysis_prefers_stability_then_fewer_changes():
    base = {
        "measure": "min",
        "center": "median",
        "spread": "mad",
        "k": 5.0,
        "context": "normal",
        "warmup_windows": 30,
        "consecutive_windows": 1,
        "candidate_min_rate": 50.0,
        "candidate_share": 0.3,
        "min_total_rate": 2.0,
    }

    def entry(settings, legit=0, attackers=7):
        return {
            "name": f"k={settings['k']} rate={settings['candidate_min_rate']}",
            "legit": legit,
            "attackers": attackers,
            "victim": 0,
            "mean_first": 1.0,
            "base_alarms": 0,
            "per_run": [],
            "settings": settings,
        }

    rows = [entry(base)]
    for k in (3.0, 8.0):  # the chosen k has two working neighbours...
        rows.append(entry({**base, "k": k}))
    lone = {**base, "candidate_min_rate": 100.0}
    rows.append(entry(lone))  # ...this one has none that works
    text = calibrate.analyze(rows, top=1)
    assert "4 tied" in text and "k=5.0 rate=50.0" in text.splitlines()[1]
