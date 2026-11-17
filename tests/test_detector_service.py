from typing import Any, Dict, List

import pytest
import requests
from fastapi.testclient import TestClient

from sdn_ddos.detection.entropy import FlowObservation
from sdn_ddos.detection.entropy_client import RemoteEntropy, fetch_remote_config
from sdn_ddos.detection.llm_api import OllamaSettings
from sdn_ddos.detection.service import create_app

KEY = {"X-Api-Key": "secret"}
SAMPLE = {
    "packet_count": 2,
    "byte_count": 120,
    "pktrate": 38461.54,
    "byterate": 2000000.0,
    "ip_proto": 6,
    "l4_dst_port": 8080,
}


class FakeResponse:
    def __init__(self, payload: Dict[str, Any], status: int = 200) -> None:
        self._payload, self.status_code = payload, status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))

    def json(self) -> Dict[str, Any]:
        return self._payload


class FakeOllama:
    """Stands in for Ollama: lists models and always answers 'DDoS'."""

    def __init__(self, models: List[str], up: bool = True) -> None:
        self.models, self.up = models, up
        self.generate_models: List[str] = []
        self.prompts: List[str] = []

    def get(self, url: str, timeout: float) -> FakeResponse:
        if not self.up:
            raise requests.ConnectionError("ollama down")
        return FakeResponse({"models": [{"name": name} for name in self.models]})

    def post(self, url: str, json: Dict[str, Any], timeout: float) -> FakeResponse:
        self.generate_models.append(json["model"])
        self.prompts.append(json["prompt"])
        verdict = '{"comparacion": "x", "is_ddos": true, "confidence": 0.9}'
        return FakeResponse({"response": verdict})


def client(
    mode: str = "llm", ollama: Any = None, api_key: str = "secret"
) -> TestClient:
    settings = OllamaSettings(
        base_url="http://ollama", model="llama3.2:3b", api_key=api_key
    )
    fake = ollama or FakeOllama(["llama3.2:3b", "qwen2.5:3b"])
    return TestClient(create_app(settings, mode=mode, http=fake))


def window(src_count: int, rate: float = 100.0) -> List[Dict[str, Any]]:
    return [
        {"src": f"10.0.0.{i + 1}", "dst": "10.0.0.50", "weight": rate}
        for i in range(src_count)
    ]


def test_requires_authentication_on_every_protected_route() -> None:
    api = client()
    assert api.get("/config").status_code == 401
    assert api.get("/models").status_code == 401
    assert api.post("/predict", json={"samples": [SAMPLE]}).status_code == 401
    assert (
        api.post("/entropy/observe", json={"run_id": "r", "flows": []}).status_code
        == 401
    )
    assert client(api_key="").get("/config", headers=KEY).status_code == 503


def test_health_is_mode_aware_and_reports_missing_model() -> None:
    assert client("llm").get("/health").json()["status"] == "ready"
    down = client("llm", FakeOllama([], up=False)).get("/health").json()
    assert down["status"] == "not_ready" and down["model_loaded"] is False
    entropy = client("entropy", FakeOllama([], up=False)).get("/health").json()
    assert entropy["status"] == "ready" and entropy["model_loaded"] is None
    assert client("llm", api_key="").get("/health").json()["status"] == "not_ready"


def test_predict_uses_llm_only_in_llm_mode() -> None:
    api = client("llm")
    response = api.post("/predict", json={"samples": [SAMPLE]}, headers=KEY)
    assert response.status_code == 200
    item = response.json()["predictions"][0]
    assert item["pred_label"] == 1 and item["prob_ddos"] == 0.9
    assert api.post("/predict", json={"samples": []}, headers=KEY).status_code == 422
    other = client("entropy").post("/predict", json={"samples": [SAMPLE]}, headers=KEY)
    assert other.status_code == 409


def test_the_rule_judges_the_same_samples_by_packet_rate_without_the_model() -> None:
    fake = FakeOllama(["llama3.2:3b"])
    api = client("rule", fake)
    slow = dict(SAMPLE, pktrate=49.99)
    edge = dict(SAMPLE, pktrate=50.0)
    response = api.post("/predict", json={"samples": [slow, edge]}, headers=KEY)
    assert response.status_code == 200
    assert response.json()["predictions"] == [
        {"pred_label": 0, "prob_ddos": 0.0},
        {"pred_label": 1, "prob_ddos": 1.0},
    ]
    assert fake.prompts == []  # the model is never asked
    usage = api.get("/usage", headers=KEY).json()
    assert usage["mode"] == "rule" and usage["decision_calls"] == 2
    health = api.get("/health").json()
    assert health["status"] == "ready" and health["backend"] == "rule"
    body = {"run_id": "r", "flows": window(2)}
    assert api.post("/entropy/observe", json=body, headers=KEY).status_code == 409


def test_the_rule_threshold_is_configurable_and_validated(monkeypatch: Any) -> None:
    api = client("rule")
    assert api.get("/config", headers=KEY).json()["rule_pktrate"] == 50.0
    changed = api.put("/config", json={"rule_pktrate": 10}, headers=KEY)
    assert changed.status_code == 200 and changed.json()["rule_pktrate"] == 10.0
    item = api.post(
        "/predict", json={"samples": [dict(SAMPLE, pktrate=12.0)]}, headers=KEY
    ).json()["predictions"][0]
    assert item["pred_label"] == 1
    for bad in (0, -1, 2_000_000):
        assert (
            api.put("/config", json={"rule_pktrate": bad}, headers=KEY).status_code
            == 422
        )
    monkeypatch.setenv("SDN_RULE_PKTRATE", "95")
    assert client("rule").get("/config", headers=KEY).json()["rule_pktrate"] == 95.0
    monkeypatch.setenv("SDN_RULE_PKTRATE", "fast")
    with pytest.raises(ValueError, match="not a number"):
        client("rule")
    monkeypatch.setenv("SDN_RULE_PKTRATE", "0")
    with pytest.raises(ValueError, match="above 0"):
        client("rule")


def test_entropy_route_is_refused_outside_entropy_mode() -> None:
    body = {"run_id": "r", "flows": window(2)}
    assert (
        client("llm").post("/entropy/observe", json=body, headers=KEY).status_code
        == 409
    )
    assert (
        client("off").post("/entropy/observe", json=body, headers=KEY).status_code
        == 409
    )


def test_put_config_switches_mode_and_model_and_validates() -> None:
    fake = FakeOllama(["llama3.2:3b", "qwen2.5:3b"])
    api = client("llm", fake)
    ok = api.put(
        "/config", json={"model": "qwen2.5:3b", "mode": "entropy"}, headers=KEY
    )
    assert ok.json() == {
        "mode": "entropy",
        "model": "qwen2.5:3b",
        "prompt": "insdn",
        "response": "block",
        "dry_run": False,
        "rule_pktrate": 50.0,
    }
    assert api.get("/health").json()["mode"] == "entropy"
    assert api.get("/models", headers=KEY).json()["active"] == "qwen2.5:3b"
    missing = api.put("/config", json={"model": "nope"}, headers=KEY)
    assert missing.status_code == 422 and "qwen2.5:3b" in missing.json()["detail"]
    assert api.put("/config", json={"mode": "bogus"}, headers=KEY).status_code == 422
    fake.up = False
    assert api.put("/config", json={"model": "x"}, headers=KEY).status_code == 502
    assert api.get("/models", headers=KEY).status_code == 502


def test_warm_model_loads_the_active_model_and_survives_failures() -> None:
    fake = FakeOllama(["llama3.2:3b", "qwen2.5:3b"])
    api = client("llm", fake)
    api.put("/config", json={"model": "qwen2.5:3b"}, headers=KEY)
    service = api.app.state.service  # type: ignore[attr-defined]
    assert service.warm_model() is True
    assert fake.generate_models == ["qwen2.5:3b"]

    class Broken(FakeOllama):
        def post(self, url: str, json: Dict[str, Any], timeout: float) -> FakeResponse:
            raise requests.ConnectionError("down")

    broken = client("llm", Broken(["llama3.2:3b"])).app.state.service  # type: ignore[attr-defined]
    assert broken.warm_model() is False


def test_warm_runs_only_in_llm_mode_when_enabled() -> None:
    settings = OllamaSettings(base_url="http://ollama", api_key="secret")
    fake = FakeOllama(["llama3.2:3b"])
    from sdn_ddos.detection.service import DetectorService

    disabled = DetectorService(settings, "llm", fake, warm=False)
    disabled.maybe_warm(force=True)
    entropy = DetectorService(settings, "entropy", fake, warm=True)
    entropy.maybe_warm(force=True)
    assert fake.generate_models == []


def test_selected_model_is_the_one_sent_to_ollama() -> None:
    fake = FakeOllama(["llama3.2:3b", "qwen2.5:3b"])
    api = client("llm", fake)
    api.put("/config", json={"model": "qwen2.5:3b"}, headers=KEY)
    api.post("/predict", json={"samples": [SAMPLE]}, headers=KEY)
    assert fake.generate_models == ["qwen2.5:3b"]


def test_entropy_state_is_isolated_per_run_and_confirms_an_attack() -> None:
    api = client("entropy")

    def observe(run_id: str, flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        response = api.post(
            "/entropy/observe", json={"run_id": run_id, "flows": flows}, headers=KEY
        )
        assert response.status_code == 200
        return response.json()

    for _ in range(8):
        assert observe("run-a", window(6))["details"]["reason"] == "warmup"
    # run-b has its own state, so it is still warming up
    assert observe("run-b", window(6))["details"]["reason"] == "warmup"
    attack = [{"src": "10.0.0.9", "dst": "10.0.0.50", "weight": 5000.0}]
    first = observe("run-a", attack)
    assert first["details"]["suspicious"] and not first["confirmed"]
    second = observe("run-a", attack)
    assert second["confirmed"] and second["candidates"] == ["10.0.0.9"]
    assert second["target_dst"] == "10.0.0.50"
    assert second["consecutive_windows"] == 2


def test_entropy_rejects_malformed_payloads() -> None:
    api = client("entropy")
    bad_run = {"run_id": "../x", "flows": []}
    assert api.post("/entropy/observe", json=bad_run, headers=KEY).status_code == 422
    negative = {"run_id": "r", "flows": [{"src": "a", "dst": "b", "weight": -1}]}
    assert api.post("/entropy/observe", json=negative, headers=KEY).status_code == 422


class Adapter:
    """Presents a TestClient response with the `requests` error behaviour."""

    def __init__(self, response: Any) -> None:
        self._response = response

    def raise_for_status(self) -> None:
        if self._response.status_code >= 400:
            raise requests.HTTPError(str(self._response.status_code))

    def json(self) -> Any:
        return self._response.json()


def test_remote_entropy_client_roundtrip_and_config_fetch(monkeypatch: Any) -> None:
    api = client("entropy")

    class Session:
        def post(
            self,
            url: str,
            json: Dict[str, Any],
            headers: Dict[str, str],
            timeout: float,
        ) -> Any:
            path = url.replace("http://detector", "")
            return Adapter(api.post(path, json=json, headers=headers))

    remote = RemoteEntropy("http://detector", "secret", "run-c", session=Session())  # type: ignore[arg-type]
    result = remote.observe(0, [FlowObservation("10.0.0.1", "10.0.0.2", 100.0)])
    assert result.reason == "warmup" and result.dpid == 0
    assert remote.consecutive_windows == 2

    def fake_get(url: str, headers: Dict[str, str], timeout: float) -> Any:
        return Adapter(api.get(url.replace("http://detector", ""), headers=headers))

    monkeypatch.setattr(requests, "get", fake_get)
    config = fetch_remote_config("http://detector", "secret")
    assert config is not None
    assert config["mode"] == "entropy" and config["model"] == "llama3.2:3b"
    assert fetch_remote_config("http://detector", "") is None
    assert fetch_remote_config("http://detector", "wrong") is None


def test_prompt_profile_is_selectable_and_validated(monkeypatch: Any) -> None:
    from sdn_ddos.detection import llm_api

    monkeypatch.setitem(
        llm_api.PROMPTS,
        "lab",
        "LAB {pktrate:.2f} {byterate:.2f} "
        "{ip_proto} {l4_dst_port} {packet_count} {byte_count}",
    )
    fake = FakeOllama(["llama3.2:3b"])
    api = client("llm", fake)
    assert api.get("/config", headers=KEY).json()["prompt"] == "insdn"
    api.post("/predict", json={"samples": [SAMPLE]}, headers=KEY)
    assert fake.prompts[-1].startswith("Sos un clasificador")
    switched = api.put("/config", json={"prompt": "lab"}, headers=KEY)
    assert switched.json()["prompt"] == "lab"
    api.post("/predict", json={"samples": [SAMPLE]}, headers=KEY)
    assert fake.prompts[-1].startswith("LAB 38461.54")
    unknown = api.put("/config", json={"prompt": "nope"}, headers=KEY)
    assert unknown.status_code == 422 and "insdn" in unknown.json()["detail"]


def test_build_prompt_rejects_unknown_profile() -> None:
    from sdn_ddos.detection.llm_api import PredictSample, build_prompt

    with pytest.raises(ValueError):
        build_prompt(PredictSample(**SAMPLE), "missing")


def test_response_policy_and_dry_run_are_selectable_and_validated() -> None:
    api = client("llm")
    config = api.get("/config", headers=KEY).json()
    assert config["response"] == "block" and config["dry_run"] is False
    updated = api.put(
        "/config", json={"response": "escalate", "dry_run": True}, headers=KEY
    )
    assert (
        updated.json()["response"] == "escalate" and updated.json()["dry_run"] is True
    )
    after = api.get("/config", headers=KEY).json()
    assert after["response"] == "escalate" and after["dry_run"] is True
    for bad in ({"response": "nuke"}, {"dry_run": "maybe"}):
        assert api.put("/config", json=bad, headers=KEY).status_code == 422


def test_invalid_response_policy_in_env_is_rejected(monkeypatch: Any) -> None:
    monkeypatch.setenv("SDN_RESPONSE_POLICY", "nuke")
    with pytest.raises(ValueError):
        client("llm")


def test_entropy_tuning_is_set_through_config_and_used_by_new_runs() -> None:
    api = client("entropy")
    defaults = api.get("/config", headers=KEY).json()["entropy"]
    assert defaults["k"] == 3.0 and defaults["alpha_run"] is None
    tuned = {
        "k": 2.5,
        "warmup_windows": 16,
        "consecutive_windows": 3,
        "min_total_rate": 1.0,
        "update_hold": 2,
        "alpha_run": 0.05,
    }
    assert api.put("/config", json={"entropy": tuned}, headers=KEY).status_code == 200
    shown = api.get("/config", headers=KEY).json()["entropy"]
    assert shown["k"] == 2.5 and shown["consecutive_windows"] == 3
    assert shown["update_hold"] == 2 and shown["alpha_run"] == 0.05
    assert shown["alpha"] == defaults["alpha"]  # untouched fields keep their defaults
    reply = api.post(
        "/entropy/observe",
        json={"run_id": "tuned", "flows": [{"src": "a", "dst": "b", "weight": 30}]},
        headers=KEY,
    ).json()
    assert reply["consecutive_windows"] == 3  # the new run used the new tuning
    # A new complete set replaces the previous overrides instead of merging.
    api.put("/config", json={"entropy": {"k": 4}}, headers=KEY)
    again = api.get("/config", headers=KEY).json()["entropy"]
    assert again["k"] == 4 and again["update_hold"] == 0 and again["alpha_run"] is None


def test_entropy_tuning_rejects_out_of_range_values() -> None:
    api = client("entropy")
    for bad in ({"k": 0}, {"alpha": 0}, {"warmup_windows": 0}, {"unknown": 1}):
        reply = api.put("/config", json={"entropy": bad}, headers=KEY)
        assert reply.status_code == 422, bad


def test_the_entropy_measure_and_threshold_are_tunable_and_histograms_accepted() -> (
    None
):
    api = client("entropy")
    tuning = {
        "measure": "renyi",
        "order": 10,
        "center": "median",
        "spread": "mad",
        "history": 30,
        "context": "all",
        "features": ["src", "dst", "dport"],
        "warmup_windows": 3,
        "min_total_rate": 1,
    }
    assert api.put("/config", json={"entropy": tuning}, headers=KEY).status_code == 200
    settings = api.get("/config", headers=KEY).json()["entropy"]
    assert (settings["measure"], settings["order"]) == ("renyi", 10.0)
    assert (settings["center"], settings["spread"], settings["history"]) == (
        "median",
        "mad",
        30,
    )
    assert settings["context"] == "all"
    assert settings["features"] == ["src", "dst", "dport"]
    body = {
        "run_id": "tuned",
        "flows": window(6),
        "dports": [{"weight": 100.0, "count": 2}],
    }
    for _ in range(4):
        reply = api.post("/entropy/observe", json=body, headers=KEY).json()
    details = reply["details"]
    assert details["reason"] == "evaluated"
    assert (details["measure"], details["center_kind"]) == ("renyi", "median")
    assert set(details["signals"]) == {"src", "dst", "dport"}
    assert details["panel"]["dport"]["distinct"] == 2.0
    assert details["top_src"][0][1] == 100.0


def test_a_published_threshold_can_be_configured_and_decides_on_the_pairs() -> None:
    api = client("entropy")
    tuning = {
        "measure": "norm",
        "center": "ewma2",
        "alpha": 0.1,
        "k": 4,
        "features": ["src", "dst", "pair"],
        "decide": ["pair"],
        "margin": 0.02,
        "rate_threshold": 500,
        "warmup_windows": 3,
        "consecutive_windows": 1,
        "min_total_rate": 1,
    }
    assert api.put("/config", json={"entropy": tuning}, headers=KEY).status_code == 200
    settings = api.get("/config", headers=KEY).json()["entropy"]
    assert settings["center"] == "ewma2" and settings["decide"] == ["pair"]
    assert (settings["margin"], settings["rate_threshold"]) == (0.02, 500.0)
    for _ in range(4):
        reply = api.post(
            "/entropy/observe",
            json={"run_id": "pairs", "flows": window(6)},
            headers=KEY,
        ).json()
    assert set(reply["details"]["signals"]) == {"src", "dst", "pair"}
    assert reply["details"]["config"]["decide"] == ["pair"]


def test_a_combination_the_detector_rejects_fails_when_configured() -> None:
    api = client("entropy")
    for bad in (
        {"decide": ["pair"]},  # the pairs are not watched
        {"features": ["src", "dst"], "decide": ["pair"]},
        {"margin": -1},
        {"features": ["src", "dport"]},  # destination IPs are always watched
        {"features": ["src"]},
        {"measure": "nope"},
        {"order": 0},
        {"history": 5000},
    ):
        response = api.put("/config", json={"entropy": bad}, headers=KEY)
        assert response.status_code == 422, bad
    assert api.get("/config", headers=KEY).json()["entropy"]["measure"] == "shannon"


def test_remote_entropy_sends_the_histograms_and_reads_the_extra_details() -> None:
    api = client("entropy")
    sent: List[Dict[str, Any]] = []

    class Session:
        def post(
            self,
            url: str,
            json: Dict[str, Any],
            headers: Dict[str, str],
            timeout: float,
        ) -> Any:
            sent.append(json)
            return Adapter(
                api.post(url.replace("http://detector", ""), json=json, headers=headers)
            )

    features = {"features": ["src", "dst", "dport"], "warmup_windows": 1}
    api.put("/config", json={"entropy": features}, headers=KEY)
    remote = RemoteEntropy("http://detector", "secret", "run-d", session=Session())  # type: ignore[arg-type]
    flows = [FlowObservation("10.0.0.1", "10.0.0.2", 100.0)]
    extra = {"dport": [(50.0, 2)], "proto": [(100.0, 1)]}
    result = remote.observe(0, flows, extra)
    assert sent[0]["dports"] == [{"weight": 50.0, "count": 2}]
    assert sent[0]["protos"] == [{"weight": 100.0, "count": 1}]
    assert result.measure == "shannon" and result.center == "ewma"
    assert result.top_src[0][0] == "10.0.0.1" and "dport" in result.panel
    later = remote.observe(0, flows, extra)
    assert "dport" in later.signals and later.evaluated
    remote.observe(0, flows)
    assert "dports" not in sent[2] and "protos" not in sent[2]
