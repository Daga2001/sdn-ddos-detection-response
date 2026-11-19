"""The thesis campaign (TH): requests the lab accepts, in balanced rounds."""

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

THESIS = [s for s in SCENARIOS if s.group == "TH"]
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
    } | {("TC-2pf", "off"), ("TC-1", "off")}


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
    assert len(order) == 180
    assert set(Counter(s.id for s in order).values()) == {10}
    for start in range(0, 180, 18):  # every round holds every cell once
        assert {s.id for s in order[start : start + 18]} == {s.id for s in chosen}
    again = lab_campaign.plan(chosen, repeat=1, rounds=10, seed=2026)
    assert [s.id for s in order] == [s.id for s in again]
    assert [s.id for s in order[:18]] != [s.id for s in chosen]


def test_tc1_limits_the_table_and_only_tc1() -> None:
    by_case = {s.case: s for s in THESIS}
    body = lab_campaign.request_body(
        lab_campaign.with_poll(by_case["TC-1"], 1.0), TOPOLOGY
    )
    assert StartRequest.model_validate(body).experiment.flow_table_limit == 1500
    assert all(s.flow_table_limit is None for s in THESIS if s.case != "TC-1")


def test_phases_fit_the_fast_entropy_warm_up() -> None:
    for s in THESIS:
        assert (s.baseline, s.duration, s.recovery) == (75, 60, 60)
        if (s.detection or {}).get("mode") == "entropy":
            e = s.detection["entropy"]
            assert e["window_seconds"] * e["warmup_windows"] + 40 <= s.baseline


def test_runner_container_override_and_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lab_campaign.runner_container.cache_clear()
    monkeypatch.setenv("SDN_LAB_RUNNER_CONTAINER", "my-runner")
    assert lab_campaign.runner_container() == "my-runner"

    lab_campaign.runner_container.cache_clear()
    monkeypatch.delenv("SDN_LAB_RUNNER_CONTAINER")

    def no_docker(*_args: object, **_kwargs: object) -> object:
        raise OSError("docker not installed")

    monkeypatch.setattr(lab_campaign.subprocess, "run", no_docker)
    # The current Compose project, never the retired sdn-lab one.
    assert lab_campaign.runner_container() == "sdn-ddos-detection-response-runner-1"
    lab_campaign.runner_container.cache_clear()


def test_campaign_refuses_to_start_without_the_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(lab_campaign, "runner", lambda *_a, **_k: "")
    monkeypatch.setattr(sys, "argv", ["lab_campaign.py", "TH1-none", "--poll", "1"])
    with pytest.raises(SystemExit, match="cannot reach the lab runner"):
        lab_campaign.main()


def test_phases_override_keeps_the_case_and_reaches_the_request() -> None:
    tc1 = lab_campaign.with_poll(next(s for s in SCENARIOS if s.id == "TH1-none"), 1.0)
    longer = lab_campaign.with_phases(tc1, "180,120,120")
    assert (longer.baseline, longer.duration, longer.recovery) == (180, 120, 120)
    body = lab_campaign.request_body(longer, TOPOLOGY)
    experiment = body["experiment"]
    assert (experiment["baseline"], experiment["duration"], experiment["recovery"]) == (
        180,
        120,
        120,
    )
    assert experiment["flow_table_limit"] == 1500
    assert experiment["scenario"] == "TC-1"
    request = StartRequest.model_validate(body)
    validate_experiment(request.topology, request.experiment)
    with pytest.raises(SystemExit, match="three whole numbers"):
        lab_campaign.with_phases(tc1, "180,120")
    with pytest.raises(SystemExit, match="between 10 and 900"):
        lab_campaign.with_phases(tc1, "5,120,120")
