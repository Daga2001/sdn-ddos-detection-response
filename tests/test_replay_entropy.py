"""The replay tool scores naming, and replays recorded events without the flows."""

import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import replay_entropy as replay

from sdn_ddos.detection.entropy import EntropyDetector, FlowObservation

START = datetime(2026, 11, 15, 8, 0, 0, tzinfo=timezone.utc)
VICTIM = "10.0.0.1"
ATTACKERS = ["10.0.0.11", "10.0.0.31", "10.0.0.41"]
CLIENTS = [f"10.0.0.{n}" for n in range(12, 30)]


def stamp(second: int) -> str:
    return (START + timedelta(seconds=second)).isoformat()


def traffic(second: int, flood: bool) -> List[List[Any]]:
    """Eight steady client/server pairs with a little jitter, then the flood."""

    rng = random.Random(second)
    servers = [VICTIM, "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    flows: List[List[Any]] = [
        [client, servers[n % 4], round(5 * rng.uniform(0.95, 1.05), 3)]
        for n, client in enumerate(CLIENTS[:8])
    ]
    if flood:
        flows += [[a, VICTIM, 300.0] for a in ATTACKERS]
        flows += [[VICTIM, a, 300.0] for a in ATTACKERS]
    return flows


def dump(windows: int = 40, flood_from: int = 30) -> List[Dict[str, Any]]:
    return [
        {
            "run": "r1",
            "window": n,
            "at": stamp(n),
            "state": "x",
            "flows": traffic(n, n >= flood_from),
            "hist": {},
        }
        for n in range(windows)
    ]


SETTINGS = {"warmup_windows": 8, "consecutive_windows": 1, "min_total_rate": 2.0}


def events_of(records: List[Dict[str, Any]], settings: Dict[str, Any]):
    """What the controller would have stored as entropy_window events."""

    detector = EntropyDetector(**{**replay.LAB_DEFAULTS, **settings})
    out = []
    for record in records:
        flows = [FlowObservation(*flow) for flow in record["flows"]]
        result = detector.observe(0, flows, None)
        out.append({"run": "r1", "at": record["at"], "data": result.as_details()})
    return out


@pytest.mark.parametrize(
    "settings",
    [
        SETTINGS,
        {**SETTINGS, "measure": "norm"},
        {**SETTINGS, "measure": "norm", "center": "ewma_margin", "decide": ("dst",)},
        {**SETTINGS, "center": "median", "spread": "mad", "context": "all"},
        {**SETTINGS, "consecutive_windows": 2, "update_hold": 2},
    ],
)
def test_replaying_the_events_gives_the_alarms_of_replaying_the_flows(settings):
    records = dump()
    from_flows = replay.replay_run(records, settings)
    from_events = replay.replay_run(events_of(records, settings), settings, True)
    assert [r.confirmed for _, r in from_flows] == [r.confirmed for _, r in from_events]
    assert [r.reason for _, r in from_flows] == [r.reason for _, r in from_events]
    assert any(r.confirmed for _, r in from_flows)  # the flood is alarmed


def test_events_replay_can_try_another_band_than_the_recorded_one():
    records = dump()
    recorded = events_of(records, {**SETTINGS, "measure": "norm"})
    tight = replay.replay_run(recorded, {**SETTINGS, "measure": "norm", "k": 0.5}, True)
    loose = replay.replay_run(recorded, {**SETTINGS, "measure": "norm", "k": 10}, True)
    assert sum(r.suspicious for _, r in tight) >= sum(r.suspicious for _, r in loose)
    assert not any(r.confirmed for _, r in loose[:30])


def test_a_measure_the_event_does_not_hold_is_refused():
    assert replay.panel_key("norm", 2.0) == "norm"
    assert replay.panel_key("renyi", 10.0) == "renyi10"
    with pytest.raises(ValueError, match="cannot replay"):
        replay.panel_key("renyi", 3.0)


def test_events_are_read_as_json_lines(tmp_path):
    path = tmp_path / "events.jsonl"
    events = events_of(dump(5), SETTINGS)
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n\n")
    assert len(replay.load_events(path)["r1"]) == 5


def test_naming_counts_attackers_legitimate_hosts_and_the_victim():
    records = dump()
    results = replay.replay_run(records, SETTINGS)
    scored = replay.naming(results, ATTACKERS, [VICTIM])
    assert scored["attackers"] == 3 and scored["attackers_named"] == 3
    assert scored["victim_named"] is False and scored["suppressed"] == 0
    assert scored["legit_named"] == 0


def test_the_protected_rule_drops_a_named_victim_and_counts_it():
    results = replay.replay_run(dump(), SETTINGS)
    named = next(r for _, r in results if r.confirmed)
    object.__setattr__(named, "candidates", (*named.candidates, VICTIM))
    plain = replay.naming(results, ATTACKERS, [VICTIM])
    protected = replay.naming(results, ATTACKERS, [VICTIM], protect=True)
    assert plain["victim_named"] is True and plain["suppressed"] == 0
    assert protected["victim_named"] is False and protected["suppressed"] == 1
    assert protected["attackers_named"] == plain["attackers_named"] == 3


def test_compare_reports_naming_only_with_the_flows():
    records = dump()
    run = {
        "run": "r1",
        "label": "t",
        "a0": stamp(30),
        "a1": stamp(40),
        "attackers": ATTACKERS,
        "victims": [VICTIM],
    }
    with_flows = replay.compare({"r1": records}, [run], SETTINGS)
    assert with_flows["attackers_named"] == 3 and with_flows["detected"] == 1
    from_events = replay.compare(
        {"r1": events_of(records, SETTINGS)}, [run], SETTINGS, from_events=True
    )
    assert from_events["detected"] == 1 and from_events["attackers_named"] == 0
