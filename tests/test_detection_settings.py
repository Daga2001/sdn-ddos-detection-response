import time
from unittest.mock import MagicMock

import pytest
import requests
from lab_fakes import FakeRuntime, MemoryRepository
from pydantic import ValidationError

from sdn_ddos.lab.contracts import (
    DetectionConfig,
    Experiment,
    StartRequest,
    validate_experiment,
)
from sdn_ddos.lab.detection_settings import (
    DetectorClient,
    controller_env,
    detector_update,
)
from sdn_ddos.lab.manager import LabManager
from sdn_ddos.lab.topology import presets


def wait_for(manager, states):
    deadline = time.monotonic() + 3
    while manager.status()["state"] not in states:
        assert time.monotonic() < deadline
        time.sleep(0.01)


def experiment(**changes):
    values = {
        "attackers": ["h1"],
        "victims": ["h2"],
        "baseline": 1,
        "duration": 1,
        "recovery": 1,
        "confirm_isolated_lab": True,
    }
    values.update(changes)
    return Experiment(**values)


def test_defaults_are_the_calibrated_lab_values_and_safe():
    config = DetectionConfig()
    assert config.mode == "llm" and config.prompt == "lab"
    assert config.entropy.k == 2.5 and config.entropy.warmup_windows == 16
    assert config.entropy.window_seconds == 5 and config.entropy.window_mode == "mean"
    assert config.response.dry_run is True
    assert experiment().detection is None  # old clients keep working


@pytest.mark.parametrize(
    "bad",
    [
        {"entropy": {"k": 0}},
        {"entropy": {"window_mode": "median"}},
        {"llm_max_samples": 0},
        {"poll_seconds": 0.1},
        {"poll_seconds": 120},
        {"threshold": 1.5},
        {"model": "bad name; rm -rf"},
        {"response": {"policy": "ban"}},
        {"response": {"protected": ["8.8.8.8"]}},
        {"response": {"protected": ["not-an-ip"]}},
        {"unknown": 1},
    ],
)
def test_detection_config_rejects_unsafe_or_unknown_values(bad):
    with pytest.raises(ValidationError):
        DetectionConfig(**bad)


def test_protected_networks_are_normalised():
    config = DetectionConfig(response={"protected": ["10.0.0.5", " 10.0.0.0/30 "]})
    assert config.response.protected == ["10.0.0.5/32", "10.0.0.0/30"]


def test_mitigation_needs_a_detector():
    topology = presets()[2]
    with pytest.raises(ValueError, match="needs a detector"):
        validate_experiment(
            topology,
            experiment(mitigation=True, detection={"mode": "off"}),
        )
    validate_experiment(
        topology, experiment(mitigation=True, detection={"mode": "entropy"})
    )


def test_controller_environment_carries_the_controller_side_settings():
    config = DetectionConfig(
        llm_max_samples=1,
        poll_seconds=2,
        threshold=0.9,
        entropy={
            "window_seconds": 10,
            "window_mode": "snapshot",
            "dedupe_switches": True,
        },
        response={
            "policy": "escalate",
            "dry_run": False,
            "rate_limit_pps": 30,
            "protected": ["10.0.0.1"],
        },
    )
    env = controller_env(config)
    assert env["SDN_LLM_MAX_SAMPLES"] == "1" and env["SDN_DDOS_THRESHOLD"] == "0.9"
    assert env["SDN_ENTROPY_WINDOW_SECONDS"] == "10"
    assert env["SDN_ENTROPY_WINDOW_MODE"] == "snapshot"
    assert env["SDN_ENTROPY_DEDUPE_SWITCHES"] == "true"
    assert env["SDN_RESPONSE_POLICY"] == "escalate"
    assert env["SDN_RESPONSE_DRY_RUN"] == "false"
    assert env["SDN_RATE_LIMIT_PPS"] == "30" and env["SDN_RATE_LIMIT_BURST"] == "60"
    assert env["SDN_RESPONSE_PROTECTED"] == "10.0.0.1/32"
    assert env["SDN_POLL_INTERVAL"] == "2.0"
    assert env["SDN_RESPONSE_CONFIRM_HITS"] == "1"
    assert env["SDN_RESPONSE_CONFIRM_SECONDS"] == "30"
    assert all(isinstance(value, str) for value in env.values())


def test_detector_update_only_names_the_model_for_the_llm_mode():
    llm = detector_update(DetectionConfig(model="gemma2:2b"))
    assert llm["mode"] == "llm" and llm["model"] == "gemma2:2b"
    assert llm["prompt"] == "lab" and llm["dry_run"] is True
    entropy = detector_update(DetectionConfig(mode="entropy"))
    assert "model" not in entropy and "prompt" not in entropy
    assert (
        entropy["entropy"]["k"] == 2.5 and entropy["entropy"]["min_total_rate"] == 2.0
    )
    assert entropy["entropy"]["alpha_run"] is None


class FakeSession:
    def __init__(self, status=200, body=None, error=None):
        self.status, self.body, self.error = status, body or {}, error
        self.calls = []

    def request(self, method, url, json=None, headers=None, timeout=None):
        self.calls.append((method, url, json, headers))
        if self.error:
            raise self.error
        response = MagicMock()
        response.status_code = self.status
        response.ok = self.status < 400
        response.json.return_value = self.body
        return response


def test_client_applies_settings_with_the_access_key():
    session = FakeSession(body={"mode": "llm"})
    client = DetectorClient("http://detector:8000", "key", session)
    client.apply(DetectionConfig(model="qwen2.5:3b"))
    method, url, body, headers = session.calls[0]
    assert (method, url) == ("PUT", "http://detector:8000/config")
    assert body["model"] == "qwen2.5:3b" and headers == {"X-Api-Key": "key"}


@pytest.mark.parametrize(
    "session,message",
    [
        (FakeSession(error=requests.ConnectionError("down")), "not reachable"),
        (FakeSession(status=404), "cannot be configured"),
        (FakeSession(status=401), "access key"),
        (
            FakeSession(status=422, body={"detail": "model 'x' is not installed"}),
            "not installed",
        ),
    ],
)
def test_client_turns_every_problem_into_a_readable_value_error(session, message):
    client = DetectorClient("http://detector:8000", "key", session)
    with pytest.raises(ValueError, match=message):
        client.apply(DetectionConfig())


def test_client_is_only_built_when_the_lab_has_a_detector():
    assert DetectorClient.from_env({}) is None
    assert (
        DetectorClient.from_env({"SDN_DDOS_SERVICE_URL": "http://d:8000/predict"})
        is None
    )
    client = DetectorClient.from_env(
        {"SDN_DDOS_SERVICE_URL": "http://d:8000/predict", "SDN_DDOS_API_KEY": "k"}
    )
    assert client is not None and client.base_url == "http://d:8000"


class RecordingDetector:
    def __init__(self):
        self.applied = []

    def apply(self, detection):
        self.applied.append(detection)
        return {}

    def config(self):
        return {"mode": "llm", "model": "llama3.2:3b", "prompts": ["insdn", "lab"]}

    def models(self):
        return ["llama3.2:3b", "gemma2:2b"]


class ExperimentRuntime(FakeRuntime):
    def serve(self, targets):
        pass

    def attack(self, experiment):
        process = MagicMock()
        process.process.returncode = 0
        process.started_at = "2026-01-01T00:00:00+00:00"
        process.ended_at = "2026-01-01T00:00:01+00:00"
        return [process]

    def probe(self, client, target):
        pass


def start_request(**changes):
    return StartRequest(
        topology=presets()[2],
        experiment=experiment(attackers=["h1"], victims=["h2"], **changes),
        forwarding="per_port",
    )


def instant_run(monkeypatch):
    monkeypatch.setattr(LabManager, "_observe", lambda self, seconds, request: None)


def test_start_applies_detection_before_the_run_and_records_it(monkeypatch):
    instant_run(monkeypatch)
    detector = RecordingDetector()
    manager = LabManager(MemoryRepository(), ExperimentRuntime, detector)
    config = DetectionConfig(mode="entropy")
    manager.start(start_request(detection=config))
    wait_for(manager, {"completed"})
    assert detector.applied == [config]
    assert manager.runtime.detection == config
    announced = [
        e for e in manager.events(0)["events"] if e["kind"] == "detection_config"
    ]
    assert announced[0]["data"]["source"] == "experiment"
    assert announced[0]["data"]["mode"] == "entropy"
    assert announced[0]["data"]["entropy"]["k"] == 2.5
    stored = manager.repository.run(manager.run_id)["settings"]
    assert stored["detection"]["mode"] == "entropy"  # saved with the scenario


def test_start_without_detection_keeps_the_detector_untouched_but_records_it(
    monkeypatch,
):
    instant_run(monkeypatch)
    detector = RecordingDetector()
    manager = LabManager(MemoryRepository(), ExperimentRuntime, detector)
    manager.start(start_request())
    wait_for(manager, {"completed"})
    assert detector.applied == []
    announced = [
        e for e in manager.events(0)["events"] if e["kind"] == "detection_config"
    ]
    assert announced[0]["data"]["source"] == "detector-service"
    assert announced[0]["data"]["model"] == "llama3.2:3b"
    assert manager.runtime.detection is None


def test_detection_without_a_detector_service_is_refused_clearly():
    manager = LabManager(MemoryRepository(), ExperimentRuntime, None)
    with pytest.raises(ValueError, match="no detector service"):
        manager.start(start_request(detection=DetectionConfig()))
    assert manager.status()["state"] == "idle"


def test_a_running_lab_is_never_reconfigured():
    detector = RecordingDetector()
    manager = LabManager(MemoryRepository(), FakeRuntime, detector)
    manager.start(StartRequest(topology=presets()[2], forwarding="per_port"))
    wait_for(manager, {"running"})
    with pytest.raises(ValueError, match="already"):
        manager.start(start_request(detection=DetectionConfig(mode="entropy")))
    assert detector.applied == []
    manager.stop()
    wait_for(manager, {"stopped"})


def test_a_refused_configuration_does_not_create_a_run():
    class Refusing(RecordingDetector):
        def apply(self, detection):
            raise ValueError("model 'x' is not installed")

    repository = MemoryRepository()
    manager = LabManager(repository, ExperimentRuntime, Refusing())
    with pytest.raises(ValueError, match="not installed"):
        manager.start(start_request(detection=DetectionConfig(model="x")))
    assert repository.runs() == []


def test_detection_options_describe_what_the_workspace_may_offer():
    manager = LabManager(MemoryRepository(), FakeRuntime, RecordingDetector())
    options = manager.detection_options()
    assert options["available"] and options["models"] == ["llama3.2:3b", "gemma2:2b"]
    assert options["current"]["model"] == "llama3.2:3b"
    assert (
        LabManager(MemoryRepository(), FakeRuntime).detection_options()["available"]
        is False
    )

    class Broken(RecordingDetector):
        def models(self):
            raise ValueError("cannot list Ollama models")

        def config(self):
            raise ValueError("the detector service is not reachable")

    degraded = LabManager(MemoryRepository(), FakeRuntime, Broken()).detection_options()
    assert degraded == {
        "available": False,
        "reason": "the detector service is not reachable",
    }


def test_the_entropy_measure_and_threshold_are_part_of_the_detection_config():
    default = DetectionConfig().entropy
    assert (default.measure, default.center, default.spread, default.context) == (
        "shannon",
        "ewma",
        "std",
        "normal",
    )
    assert default.history == 0
    assert not default.watch_ports and not default.watch_protocols
    config = DetectionConfig(
        mode="entropy",
        entropy={
            "measure": "renyi",
            "order": 10,
            "center": "median",
            "spread": "mad",
            "history": 40,
            "context": "all",
            "watch_ports": True,
            "watch_protocols": True,
        },
    )
    update = detector_update(config)["entropy"]
    assert (update["measure"], update["order"]) == ("renyi", 10.0)
    assert (update["center"], update["spread"]) == ("median", "mad")
    assert (update["history"], update["context"]) == (40, "all")
    assert update["features"] == ["src", "dst", "dport", "proto"]
    assert controller_env(config)["SDN_ENTROPY_FEATURES"] == "src,dst,dport,proto"
    assert controller_env(DetectionConfig())["SDN_ENTROPY_FEATURES"] == "src,dst"
    for bad in (
        {"measure": "nope"},
        {"center": "mode"},
        {"spread": "range"},
        {"context": "some"},
        {"order": 0},
        {"history": 5000},
    ):
        with pytest.raises(ValidationError):
            DetectionConfig(entropy=bad)


def test_the_published_thresholds_are_part_of_the_detection_config():
    config = DetectionConfig(
        mode="entropy",
        entropy={
            "measure": "norm",
            "center": "ewma2",
            "alpha": 0.1,
            "k": 4,
            "watch_pairs": True,
            "decide": ["pair"],
            "rate_threshold": 500,
        },
    )
    update = detector_update(config)["entropy"]
    assert (update["center"], update["decide"]) == ("ewma2", ["pair"])
    assert update["features"] == ["src", "dst", "pair"]
    assert (update["margin"], update["rate_threshold"]) == (0.01, 500.0)
    assert controller_env(config)["SDN_ENTROPY_FEATURES"] == "src,dst,pair"
    assert DetectionConfig().entropy.decide == []
    ewma_margin = DetectionConfig(entropy={"center": "ewma_margin", "decide": ["dst"]})
    assert detector_update(ewma_margin)["entropy"]["decide"] == ["dst"]
    for bad in (
        {"decide": ["pair"]},  # the pairs are not watched
        {"decide": ["dport"]},
        {"decide": ["ip"]},
        {"margin": -1},
    ):
        with pytest.raises(ValidationError):
            DetectionConfig(entropy=bad)


def test_forwarding_is_not_an_entropy_setting():
    with pytest.raises(ValidationError):
        DetectionConfig(entropy={"match_ports": False})
    assert "SDN_MATCH_L4_PORTS" not in controller_env(DetectionConfig())
