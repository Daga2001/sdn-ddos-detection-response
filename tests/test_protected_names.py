"""A protected host (the victim) is never named, whichever detector speaks."""

import ipaddress
import logging
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

pytest.importorskip("ryu")

from sdn_ddos.controller import app_modes
from sdn_ddos.controller.app import FlowBatch
from sdn_ddos.controller.response import ResponseManager, ResponseSettings

LAB = (ipaddress.IPv4Network("10.0.0.0/8"),)
VICTIM = "10.0.0.1"


class Store:
    def __init__(self) -> None:
        self.detections: List[Dict[str, Any]] = []
        self.rows: List[Dict[str, Any]] = []

    def record_detection(self, row: Dict[str, Any]) -> None:
        self.detections.append(row)

    def add_flow_rows(self, rows: List[Dict[str, Any]]) -> None:
        self.rows.extend(rows)


class Events:
    def __init__(self) -> None:
        self.items: List[Any] = []

    def emit(self, kind: str, data: Dict[str, Any]) -> None:
        self.items.append((kind, data))


class Enforcer:
    def drop(self, source: str, seconds: int) -> int:
        return 1

    def limit(self, source: str, pps: int, burst: int, seconds: int) -> int:
        return 1

    def release(self, source: str) -> None:
        return None


def controller(protected: str = "10.0.0.1/32") -> Any:
    instance = app_modes.ModeSwitchController.__new__(app_modes.ModeSwitchController)
    instance.mode = "llm"
    instance.logger = logging.getLogger("test")
    instance.settings = SimpleNamespace(
        detection_threshold=0.8, mitigation_enabled=False
    )
    instance.store = Store()
    instance.telemetry = Events()
    instance.names_suppressed = {}
    networks = tuple(
        ipaddress.IPv4Network(item) for item in protected.split(",") if item
    )
    instance.responder = ResponseManager(
        ResponseSettings(protected=networks), LAB, Enforcer()
    )
    instance.blocked = []
    instance._maybe_block = lambda source, at: instance.blocked.append(source)
    return instance


def row(source: str, destination: str) -> Dict[str, Any]:
    return {
        "ts": datetime.now(timezone.utc),
        "dpid": 1,
        "ipv4_src": source,
        "ipv4_dst": destination,
        "ip_proto": 6,
        "l4_dst_port": None,
        "label": 0,
        "prob_ddos": None,
    }


def judged_batch() -> FlowBatch:
    rows = [row("10.0.0.11", VICTIM), row(VICTIM, "10.0.0.11"), row("10.0.0.2", VICTIM)]
    return FlowBatch(1, rows[0]["ts"], rows, [], [0, 1, 2])


def test_llm_never_names_the_protected_victim_but_names_the_attacker() -> None:
    instance = controller()
    batch = judged_batch()
    predictions = [{"prob_ddos": 0.95}, {"prob_ddos": 0.95}, {"prob_ddos": 0.1}]
    instance._finish_flow_batch(batch, predictions)
    named = [item["ipv4_src"] for item in instance.store.detections]
    assert named == ["10.0.0.11"]
    assert [d["ipv4_src"] for k, d in instance.telemetry.items if k == "detection"] == [
        "10.0.0.11"
    ]
    assert instance.blocked == ["10.0.0.11"]
    # The model's score stays on the stored row, the label does not.
    assert batch.rows[1]["prob_ddos"] == 0.95 and batch.rows[1]["label"] == 0
    assert batch.rows[0]["label"] == 1
    assert instance.names_suppressed == {f"llm:{VICTIM}": 1}


def test_without_a_protected_list_the_llm_names_the_victim_as_before() -> None:
    instance = controller(protected="")
    instance._finish_flow_batch(judged_batch(), [{"prob_ddos": 0.95}] * 3)
    assert {d["ipv4_src"] for d in instance.store.detections} == {
        "10.0.0.11",
        VICTIM,
        "10.0.0.2",
    }
    assert instance.names_suppressed == {}


def test_entropy_candidates_pass_through_the_same_rule() -> None:
    instance = controller()
    named = instance._unprotected((VICTIM, "10.0.0.11", "10.0.0.31"), "entropy")
    assert named == ("10.0.0.11", "10.0.0.31")
    instance._unprotected((VICTIM,), "entropy")
    assert instance.names_suppressed == {f"entropy:{VICTIM}": 2}
    assert instance._unprotected((VICTIM,), "entropy") == ()


def test_the_suppressed_names_are_part_of_the_controller_sample() -> None:
    instance = controller()
    instance.cost = app_modes.DecisionCost()
    instance._unprotected((VICTIM,), "llm")
    instance._unprotected((VICTIM,), "llm")
    instance.protected_flows_skipped = 5
    row_out = instance._extra_resources()
    assert row_out["protected_flows_skipped_total"] == 5
    assert row_out["names_suppressed_total"] == 2
    assert row_out["names_suppressed"] == {f"llm:{VICTIM}": 2}


def test_the_rule_arm_is_held_to_the_same_protected_rule_and_counted() -> None:
    instance = controller()
    instance.mode = "rule"
    victim_flow = row(VICTIM, "10.0.0.11")
    assert instance._keep_from_the_model(victim_flow) is False
    assert instance._keep_from_the_model(row("10.0.0.11", VICTIM)) is True
    assert instance.protected_flows_skipped == 1
    batch = judged_batch()
    instance._finish_flow_batch(batch, [{"prob_ddos": 1.0}] * 3)
    named = [item["ipv4_src"] for item in instance.store.detections]
    assert named == ["10.0.0.11", "10.0.0.2"]
    assert instance.names_suppressed == {f"rule:{VICTIM}": 1}
