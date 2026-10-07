from collections import OrderedDict
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

pytest.importorskip("ryu")

from sdn_ddos.controller import app_modes
from sdn_ddos.controller.app import EnterpriseDDoSController


class Recorder:
    def __init__(self) -> None:
        self.rows: List[Dict[str, Any]] = []

    def record(self, detector: str, verdict: bool, **kwargs: Any) -> None:
        self.rows.append({"detector": detector, "verdict": verdict, **kwargs})


def sample(rate: float, pkts: int = 10) -> Dict[str, Any]:
    return {
        "packet_count": pkts,
        "byte_count": pkts * 80,
        "pktrate": rate,
        "byterate": rate * 80,
        "ip_proto": 6,
        "l4_dst_port": 8080,
    }


@pytest.fixture
def controller(monkeypatch: pytest.MonkeyPatch) -> Any:
    calls: List[List[Dict[str, Any]]] = []

    def fake_predict(self: Any, samples: List[Dict[str, Any]]) -> Any:
        calls.append(samples)
        return [
            {
                "pred_label": int(s["pktrate"] >= 50),
                "prob_ddos": 0.95 if s["pktrate"] >= 50 else 0.05,
            }
            for s in samples
        ]

    monkeypatch.setattr(EnterpriseDDoSController, "_predict", fake_predict)
    instance = app_modes.ModeSwitchController.__new__(app_modes.ModeSwitchController)
    instance.mode = "llm"
    instance.llm_max_samples = 2
    instance.llm_cache_size = 3
    instance._verdicts = OrderedDict()
    instance.settings = SimpleNamespace(detection_threshold=0.8)
    instance.decisions = Recorder()
    instance.calls = calls
    return instance


def test_only_new_samples_count_against_the_cap_and_repeats_hit_the_cache(
    controller: Any,
) -> None:
    controller.llm_cache_size = 8
    flows = [sample(300.0, 500), sample(1.0), sample(0.0), sample(2.0, 20)]
    first = controller._predict(flows)
    assert [len(c) for c in controller.calls] == [2]  # cap of 2 new calls
    # most active first: 300 and 2.0 are asked, 1.0 and 0.0 are over the cap
    assert first[0]["prob_ddos"] == 0.95 and first[3]["prob_ddos"] == 0.05
    assert first[1]["prob_ddos"] is None and first[2]["prob_ddos"] is None

    second = controller._predict(flows)
    # the 2 known flows were free; the cap went to the 2 that were left out
    assert [len(c) for c in controller.calls] == [2, 2]
    assert all(item["prob_ddos"] is not None for item in second)
    third = controller._predict(flows)
    assert len(controller.calls) == 2  # everything is cached now
    assert [i["prob_ddos"] for i in third] == [i["prob_ddos"] for i in second]
    rows = controller.decisions.rows
    assert [r["details"]["cached"] for r in rows[:2]] == [False, False]
    assert any(r["details"]["cached"] and r["latency_ms"] is None for r in rows)
    assert any(r["verdict"] for r in rows)  # the 300 pkt/s flow is flagged


def test_identical_new_samples_are_asked_once(controller: Any) -> None:
    flows = [sample(1.0), sample(1.0), sample(1.0)]
    result = controller._predict(flows)
    assert len(controller.calls) == 1 and len(controller.calls[0]) == 1
    assert all(item["prob_ddos"] == 0.05 for item in result)


def test_cache_is_bounded_and_off_modes_do_nothing(controller: Any) -> None:
    for rate in (1.0, 2.0, 3.0, 4.0, 5.0):
        controller._predict([sample(rate)])
    assert len(controller._verdicts) == 3
    controller.mode = "entropy"
    assert controller._predict([sample(1.0)]) is None


def test_service_failure_keeps_serving_cached_verdicts(
    controller: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller._predict([sample(300.0, 500)])
    monkeypatch.setattr(EnterpriseDDoSController, "_predict", lambda self, s: None)
    result = controller._predict([sample(300.0, 500), sample(7.0)])
    assert result[0]["prob_ddos"] == 0.95 and result[1]["prob_ddos"] is None
    assert controller._predict([sample(8.0)]) is None
