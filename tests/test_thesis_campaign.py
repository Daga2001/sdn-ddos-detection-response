"""The thesis campaign (TP/TC/TH): requests the lab accepts, in balanced rounds."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts" / "campaign"))

import lab_campaign  # noqa: E402
from scenarios import SCENARIOS  # noqa: E402

from sdn_ddos.lab.contracts import StartRequest, validate_experiment  # noqa: E402

THESIS = [s for s in SCENARIOS if s.group in {"TP", "TC", "TH"}]
TOPOLOGY = json.loads(
    (ROOT / "scripts" / "campaign" / "topologia_universidad.json").read_text("utf-8")
)


def test_every_cell_of_the_design_exists() -> None:
    held_out = {
        (s.case, (s.detection or {}).get("mode")) for s in THESIS if s.group == "TH"
    }
    assert held_out == {
        (case, mode)
        for case in ("TC-2", "TC-3", "TC-4", "TC-5")
        for mode in ("off", "rule", "entropy", "llm")
    } | {("TC-2pf", "off")}


@pytest.mark.parametrize("scenario", THESIS, ids=[s.id for s in THESIS])
def test_the_lab_accepts_every_thesis_request(scenario) -> None:
    body = lab_campaign.request_body(lab_campaign.with_poll(scenario, 1.0), TOPOLOGY)
    request = StartRequest.model_validate(body)
    assert request.experiment is not None
    validate_experiment(request.topology, request.experiment)
    experiment = request.experiment
    assert experiment.purpose == scenario.purpose
    assert experiment.scenario.startswith(scenario.case)
    assert experiment.detection is not None
    assert experiment.detection.poll_seconds == 1.0
    if experiment.detection.mode != "off":
        response = experiment.detection.response
        assert experiment.mitigation
        assert (response.policy, response.dry_run) == ("block", False)
        assert (response.confirm_hits, response.confirm_seconds) == (2, 30)
        assert set(response.protected) == {f"10.0.0.{n}/32" for n in range(1, 6)}
    else:
        assert not experiment.mitigation


def test_rounds_are_balanced_and_reproducible() -> None:
    chosen = [s for s in THESIS if s.group == "TH"]
    order = lab_campaign.plan(chosen, repeat=1, rounds=10, seed=2026)
    assert len(order) == 170
    assert set(Counter(s.id for s in order).values()) == {10}
    for start in range(0, 170, 17):  # every round holds every cell once
        assert {s.id for s in order[start : start + 17]} == {s.id for s in chosen}
    again = lab_campaign.plan(chosen, repeat=1, rounds=10, seed=2026)
    assert [s.id for s in order] == [s.id for s in again]
    assert [s.id for s in order[:17]] != [s.id for s in chosen]


def test_pilot_cells_are_labelled_by_interval() -> None:
    pilot = next(s for s in THESIS if s.group == "TP")
    assert lab_campaign.with_poll(pilot, 0.5).case == "TC-3-poll0.5"
    held = next(s for s in THESIS if s.group == "TH")
    assert lab_campaign.with_poll(held, 0.5).case == held.case


def test_the_runner_container_follows_the_compose_project_name() -> None:
    names = "sdn-ddos-detection-response-web-1\nsdn-ddos-detection-response-runner-1\n"
    assert (
        lab_campaign.runner_container({}, names)
        == "sdn-ddos-detection-response-runner-1"
    )
    # An explicit choice wins, and the historical name is the fallback.
    assert (
        lab_campaign.runner_container({"SDN_RUNNER_CONTAINER": "mine"}, names) == "mine"
    )
    assert lab_campaign.runner_container({}, "other-1\n") == "sdn-lab-runner-1"
    two = "a-runner-1\nb-runner-1\n"
    assert lab_campaign.runner_container({}, two) == "sdn-lab-runner-1"
