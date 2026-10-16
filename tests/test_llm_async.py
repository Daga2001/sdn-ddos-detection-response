"""The LLM judges polls on its own greenthread so packet-ins are never stalled by it."""

import logging
from typing import Any, Dict, List, Optional

import pytest

pytest.importorskip("ryu")

from ryu.lib import hub

from sdn_ddos.controller import app_modes
from sdn_ddos.controller.app import FlowBatch
from sdn_ddos.controller.judging import PollQueue


def batch(dpid: int, *rates: float) -> FlowBatch:
    samples = [{"pktrate": rate} for rate in rates]
    return FlowBatch(
        dpid, None, [{} for _ in samples], samples, list(range(len(rates)))
    )  # type: ignore[arg-type]


@pytest.fixture
def controller() -> Any:
    instance = app_modes.ModeSwitchController.__new__(app_modes.ModeSwitchController)
    instance.logger = logging.getLogger("test")
    instance._llm_pending = PollQueue()
    instance._llm_wake = hub.Queue(64)
    instance.llm_skipped = 0
    instance.concluded = []
    instance._finish_flow_batch = lambda b, predictions: instance.concluded.append(
        (b, predictions)
    )
    return instance


def test_a_poll_without_samples_is_stored_straight_away(controller: Any) -> None:
    empty = batch(1)
    controller._submit_llm(empty)
    assert controller.concluded == [(empty, None)]
    assert not len(controller._llm_pending)


def test_a_newer_poll_of_a_switch_replaces_the_older_one(controller: Any) -> None:
    first, second = batch(1, 3.0), batch(1, 90.0)
    controller._submit_llm(first)
    assert controller.concluded == []
    controller._submit_llm(second)
    assert controller._llm_pending.get(1) is second
    assert controller.concluded == [(first, None)]  # kept in the tables, not judged
    assert controller.llm_skipped == 1


def test_the_busiest_switch_is_judged_first(controller: Any) -> None:
    controller._submit_llm(batch(1, 2.0, 1.0))
    controller._submit_llm(batch(2, 400.0))
    controller._submit_llm(batch(3, 30.0))
    order = [controller._next_llm_batch().dpid for _ in range(3)]
    assert order == [2, 3, 1]


def test_the_stats_handler_queues_instead_of_judging(
    controller: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked: List[Any] = []
    monkeypatch.setattr(
        app_modes.ModeSwitchController, "_predict", lambda self, s: asked.append(s)
    )
    controller.llm_thread = object()
    controller._submit_llm(batch(1, 120.0))
    assert asked == []  # nothing called the model on the caller's greenthread
    assert controller._llm_pending.get(1).samples == [{"pktrate": 120.0}]


def test_the_judge_loop_survives_a_failing_poll(
    controller: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: List[int] = []

    def predict(
        self: Any, samples: List[Dict[str, Any]], sources: Any = None
    ) -> Optional[List[Any]]:
        calls.append(len(samples))
        if len(calls) == 1:
            raise RuntimeError("model unreachable")
        return [{"prob_ddos": 0.9}]

    monkeypatch.setattr(app_modes.ModeSwitchController, "_predict", predict)
    controller._submit_llm(batch(1, 50.0))
    controller._submit_llm(batch(2, 60.0))
    controller._llm_wake.put(None)
    worker = hub.spawn(controller._llm_loop)
    hub.sleep(0.05)
    hub.kill(worker)
    assert calls == [1, 1]
    # The failed poll raised before it could be concluded; the next one went through.
    assert [p for _, p in controller.concluded] == [[{"prob_ddos": 0.9}]]
