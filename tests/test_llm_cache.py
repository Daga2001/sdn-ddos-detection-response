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


class Events:
    def __init__(self) -> None:
        self.items: List[Any] = []

    def emit(self, kind: str, data: Dict[str, Any]) -> None:
        self.items.append((kind, data))


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
    instance.telemetry = Events()
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


def test_a_busy_source_not_flagged_yet_is_judged_before_one_already_flagged(
    controller: Any,
) -> None:
    controller.llm_repeat_seconds = 30.0
    controller.llm_busy_rate = 20.0
    controller._flagged_at = {}
    controller.llm_max_samples = 2
    # h1a floods with two flows, h1b (another protocol) is slower but also an attacker.
    flows = [sample(900.0, 900), sample(850.0, 850), sample(500.0, 500), sample(1.0, 5)]
    sources = ["10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.5"]
    controller._predict(flows, sources)
    # Nothing was flagged yet: the two busiest flows are judged, both h1a's.
    assert controller._flagged_at == {"10.0.0.1": controller._flagged_at["10.0.0.1"]}
    controller.calls.clear()
    fresh = [
        sample(910.0, 1800),
        sample(860.0, 1700),
        sample(510.0, 1000),
        sample(1.0, 6),
    ]
    controller._predict(fresh, sources)
    asked = controller.calls[0]
    assert [s["pktrate"] for s in asked] == [510.0, 910.0]  # h1b first, then h1a again
    assert "10.0.0.2" in controller._flagged_at


def test_quiet_flows_are_judged_last_and_without_sources_the_order_is_unchanged(
    controller: Any,
) -> None:
    controller.llm_repeat_seconds = 30.0
    controller.llm_busy_rate = 20.0
    controller._flagged_at = {}
    flows = [sample(2.0), sample(300.0, 500), sample(1.0)]
    order = controller._priority(flows, ["a", "b", "c"])
    assert order == [1, 0, 2]
    controller._flagged_at = {"b": __import__("time").monotonic()}
    # b is flagged and busy, a and c are quiet: b still comes before the quiet ones.
    assert controller._priority(flows, ["a", "b", "c"]) == [1, 0, 2]
    assert controller._priority(flows, None) == [1, 0, 2]


def test_every_model_call_is_timed_and_cached_verdicts_are_counted_apart(
    controller: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = iter([10.0, 10.8, 20.0, 20.3])
    monkeypatch.setattr(app_modes.time, "monotonic", lambda: next(clock))
    flows = [sample(300.0, 500), sample(2.0, 20)]
    controller._predict(flows)  # two new samples, one call of 0.8 s
    controller._predict(flows)  # both cached: no call, no event
    controller._predict([*flows, sample(9.0)])  # one new sample, two reused
    costs = [
        data for kind, data in controller.telemetry.items if kind == "decision_cost"
    ]
    assert [c["decisions"] for c in costs] == [2, 1]
    assert [c["reused"] for c in costs] == [0, 2]
    assert costs[0]["ms_per_decision"] == pytest.approx(400.0)
    assert costs[1]["elapsed_ms"] == pytest.approx(300.0)
    totals = controller.cost.totals()
    assert totals["decisions_total"] == 3 and totals["decisions_reused_total"] == 4
    assert totals["decision_ms_total"] == pytest.approx(1100.0)
    # the per-decision latency in the database log matches the event
    assert controller.decisions.rows[0]["latency_ms"] == pytest.approx(400.0)


def test_a_failed_model_call_still_costs_its_time(
    controller: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(EnterpriseDDoSController, "_predict", lambda self, s: None)
    assert controller._predict([sample(300.0, 500)]) is None
    kind, data = controller.telemetry.items[-1]
    assert kind == "decision_cost" and data["failed"] is True
    assert controller.cost.totals()["decisions_failed_total"] == 1


def test_controller_samples_carry_the_totals_and_the_detector_usage(
    controller: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller.settings = SimpleNamespace(
        detection_threshold=0.8, inference_api_key="secret"
    )
    controller._detector_base = "http://detector:8000"
    controller.llm_skipped = 2
    readings = iter([1.0, 1.5])

    def fake_usage(base: str, key: str) -> Dict[str, float]:
        cpu = next(readings)
        return {
            "cpu_seconds": cpu,
            "rss_bytes": 52428800.0,
            "decision_cpu_seconds": cpu / 10,
        }

    clock = iter([100.0, 102.0])
    monkeypatch.setattr(app_modes, "fetch_usage", fake_usage)
    monkeypatch.setattr(app_modes.time, "monotonic", lambda: next(clock))
    first = controller._extra_resources()  # nothing sampled yet
    assert first["detector"] == "llm" and first["polls_skipped_total"] == 2
    assert first["decisions_total"] == 0 and "detector_cpu_seconds" not in first
    controller._sample_usage()
    sampled = controller._extra_resources()
    assert sampled["detector_rss_bytes"] == 52428800
    assert sampled["detector_decision_cpu_seconds"] == 0.1
    assert sampled["detector_cpu_percent"] is None  # needs two samples
    controller._sample_usage()
    assert controller._extra_resources()["detector_cpu_percent"] == 25.0
    # a failed sample leaves a gap instead of repeating the last value
    monkeypatch.setattr(app_modes, "fetch_usage", lambda base, key: None)
    controller._sample_usage()
    assert "detector_cpu_seconds" not in controller._extra_resources()
    controller._usage_row = {"detector_cpu_seconds": 1.0}
    controller.mode = "off"
    assert "detector_cpu_seconds" not in controller._extra_resources()


class Store:
    def __init__(self) -> None:
        self.rows: List[Dict[str, Any]] = []

    def add_controller_row(self, row: Dict[str, Any]) -> None:
        self.rows.append(row)


def poll_once(controller: Any) -> List[Any]:
    import psutil

    controller.datapaths = {}
    controller.store = Store()
    controller.logger = SimpleNamespace(exception=lambda *args: None)
    controller._monitor_once(psutil.Process())
    return controller.telemetry.items


def test_a_poll_before_the_mode_is_known_still_publishes_the_sample(
    controller: Any,
) -> None:
    # The base class starts polling before the subclass reads its mode from the
    # detector service; that first poll once crashed the poll loop for the run.
    del controller.mode
    items = poll_once(controller)
    kinds = [kind for kind, _ in items]
    assert kinds == ["controller"]
    sample_row = items[0][1]
    assert sample_row["cpu_seconds"] >= 0 and "detector" not in sample_row
    assert controller.store.rows == [sample_row]


def test_an_error_in_the_extra_fields_is_reported_and_the_sample_kept(
    controller: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken() -> Dict[str, Any]:
        raise RuntimeError("boom")

    monkeypatch.setattr(controller, "_extra_resources", broken)
    items = poll_once(controller)
    assert [kind for kind, _ in items] == ["controller_error", "controller"]
    assert items[0][1] == {
        "where": "extra controller fields",
        "error": "RuntimeError('boom')",
    }
