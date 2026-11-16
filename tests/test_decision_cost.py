from typing import Any, Dict

import pytest
import requests
from fastapi.testclient import TestClient

from sdn_ddos.controller.cost import DecisionCost, cpu_percent_since, usage_from
from sdn_ddos.detection.entropy_client import fetch_usage
from sdn_ddos.detection.llm_api import OllamaSettings
from sdn_ddos.detection.service import create_app

KEY = {"X-Api-Key": "secret"}


def test_calls_add_to_the_totals_and_each_one_is_an_event() -> None:
    cost = DecisionCost()
    event = cost.add("llm", 4, 2000.0, reused=3)
    assert event == {
        "detector": "llm",
        "decisions": 4,
        "reused": 3,
        "elapsed_ms": 2000.0,
        "ms_per_decision": 500.0,
        "failed": False,
    }
    failed = cost.add("llm", 1, 30000.0, failed=True)
    assert failed is not None and failed["failed"] is True
    assert cost.totals() == {
        "decisions_total": 5,
        "decisions_reused_total": 3,
        "decisions_failed_total": 1,
        "decision_ms_total": 32000.0,
    }


def test_cached_verdicts_count_as_reused_without_an_event() -> None:
    cost = DecisionCost()
    assert cost.add("llm", 0, 0.0, reused=6) is None
    assert cost.totals()["decisions_reused_total"] == 6
    assert cost.totals()["decisions_total"] == 0


def test_bad_counts_are_refused_and_a_negative_time_counts_as_zero() -> None:
    cost = DecisionCost()
    with pytest.raises(ValueError):
        cost.add("entropy", -1, 5.0)
    with pytest.raises(ValueError):
        cost.add("llm", 1, 5.0, reused=-2)
    event = cost.add("entropy", 1, -3.0)
    assert event is not None and event["elapsed_ms"] == 0.0


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {"cpu_seconds": "1", "rss_bytes": 10},
        {"cpu_seconds": True, "rss_bytes": 10},
        {"cpu_seconds": 1.0, "rss_bytes": 1.5},
        {"cpu_seconds": float("nan"), "rss_bytes": 10},
        {"cpu_seconds": -1.0, "rss_bytes": 10},
        {"cpu_seconds": 1.0, "rss_bytes": -10},
        {"cpu_seconds": 1.0},
    ],
)
def test_malformed_usage_is_ignored(payload: Any) -> None:
    assert usage_from(payload) is None


def test_usage_is_read_as_numbers() -> None:
    assert usage_from({"cpu_seconds": 2, "rss_bytes": 4096, "pid": 1}) == {
        "cpu_seconds": 2.0,
        "rss_bytes": 4096.0,
    }
    assert usage_from(
        {"cpu_seconds": 2, "rss_bytes": 4096, "decision_cpu_seconds": 0.25}
    ) == {"cpu_seconds": 2.0, "rss_bytes": 4096.0, "decision_cpu_seconds": 0.25}
    # a bad decision total is dropped, the rest is kept
    assert "decision_cpu_seconds" not in (
        usage_from({"cpu_seconds": 2, "rss_bytes": 1, "decision_cpu_seconds": -1}) or {}
    )


def test_cpu_percent_is_measured_between_two_samples() -> None:
    percent, first = cpu_percent_since(None, 10.0, 100.0)
    assert percent is None and first == (10.0, 100.0)
    percent, second = cpu_percent_since(first, 10.5, 102.0)
    assert percent == 25.0 and second == (10.5, 102.0)
    # a restarted process (CPU time went down) or a clock that did not move: no value
    assert cpu_percent_since(second, 1.0, 103.0)[0] is None
    assert cpu_percent_since(second, 11.0, 102.0)[0] is None


def service(api_key: str = "secret") -> TestClient:
    settings = OllamaSettings(
        base_url="http://ollama", model="llama3.2:3b", api_key=api_key
    )
    return TestClient(create_app(settings, mode="entropy", http=requests.Session()))


def test_the_detector_reports_its_own_cpu_time_and_memory() -> None:
    api = service()
    assert api.get("/usage").status_code == 401
    assert api.get("/usage", headers={"X-Api-Key": "wrong"}).status_code == 401
    body = api.get("/usage", headers=KEY).json()
    assert body["mode"] == "entropy"
    assert body["cpu_seconds"] >= 0 and body["rss_bytes"] > 0
    assert body["decision_cpu_seconds"] == 0 and body["decision_calls"] == 0
    # an entropy window is one decision; its thread CPU time is counted apart
    window = {"run_id": "r1", "scope": 0, "flows": []}
    assert api.post("/entropy/observe", json=window, headers=KEY).status_code == 200
    counted = api.get("/usage", headers=KEY).json()
    assert counted["decision_calls"] == 1
    assert 0 <= counted["decision_cpu_seconds"] <= counted["cpu_seconds"]
    assert service(api_key="").get("/usage", headers=KEY).status_code == 503


class Adapter:
    def __init__(self, response: Any) -> None:
        self._response = response

    def raise_for_status(self) -> None:
        if self._response.status_code >= 400:
            raise requests.HTTPError(str(self._response.status_code))

    def json(self) -> Any:
        return self._response.json()


def test_the_controller_client_reads_usage_and_survives_failures() -> None:
    api = service()

    class Session:
        def __init__(self, broken: bool = False) -> None:
            self.broken = broken
            self.timeouts: list[float] = []

        def get(self, url: str, headers: Dict[str, str], timeout: float) -> Any:
            self.timeouts.append(timeout)
            if self.broken:
                raise requests.ConnectionError("detector down")
            return Adapter(api.get(url.replace("http://detector", ""), headers=headers))

    session = Session()
    usage = fetch_usage("http://detector", "secret", session=session)  # type: ignore[arg-type]
    assert usage is not None and usage["rss_bytes"] > 0
    assert session.timeouts == [0.5]
    assert fetch_usage("http://detector", "wrong", session=session) is None  # type: ignore[arg-type]
    assert fetch_usage("http://detector", "", session=session) is None  # type: ignore[arg-type]
    broken = Session(broken=True)
    assert fetch_usage("http://detector", "secret", session=broken) is None  # type: ignore[arg-type]
