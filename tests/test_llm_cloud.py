"""Optional cloud backend: same prompt, OpenAI-compatible API, Ollama untouched."""

from typing import Any, Dict, List, Optional

import pytest
import requests
from fastapi.testclient import TestClient

from sdn_ddos.detection.llm_api import (
    CLOUD_DEFAULT_MODEL,
    CloudEndpoint,
    OllamaSettings,
    PredictSample,
    _verdict_from_text,
    build_prompt,
    judge_sample,
)
from sdn_ddos.detection.service import create_app

KEY = {"X-Api-Key": "secret"}
SAMPLE = {
    "packet_count": 2,
    "byte_count": 120,
    "pktrate": 900.0,
    "byterate": 48600.0,
    "ip_proto": 6,
    "l4_dst_port": 8080,
}
FALLBACK_MODEL = "openai/gpt-oss-20b"


class Reply:
    def __init__(self, payload: Dict[str, Any], status: int = 200) -> None:
        self._payload, self.status_code = payload, status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))

    def json(self) -> Dict[str, Any]:
        return self._payload


class FakeCloud:
    """Chat Completions stand-in; `down` lists base URLs that fail."""

    def __init__(self, down: Optional[List[str]] = None, content: str = "") -> None:
        self.down = set(down or [])
        self.calls: List[Dict[str, Any]] = []
        self.content = (
            content or '{"comparacion": "x", "is_ddos": true, "confidence": 0.9}'
        )

    def get(self, url: str, timeout: float) -> Reply:
        raise AssertionError(f"the cloud backend must not call Ollama ({url})")

    def post(
        self,
        url: str,
        json: Dict[str, Any],
        timeout: float,
        headers: Optional[Dict[str, str]] = None,
    ) -> Reply:
        self.calls.append({"url": url, "json": json, "headers": headers or {}})
        if any(url.startswith(base) for base in self.down):
            raise requests.ConnectionError("down")
        return Reply({"choices": [{"message": {"content": self.content}}]})


def cloud_settings(fallback: bool = True, provider: str = "") -> OllamaSettings:
    endpoints = [
        CloudEndpoint(
            name="primary",
            base_url="https://openrouter.test/api/v1",
            model=CLOUD_DEFAULT_MODEL,
            api_key="or-key",
            provider=provider,
        )
    ]
    if fallback:
        endpoints.append(
            CloudEndpoint(
                name="fallback",
                base_url="https://groq.test/openai/v1",
                model=FALLBACK_MODEL,
                api_key="groq-key",
            )
        )
    return OllamaSettings(
        model=CLOUD_DEFAULT_MODEL,
        api_key="secret",
        prompt_profile="lab",
        backend="cloud",
        cloud=endpoints,
    )


def test_cloud_call_sends_the_same_prompt_and_decoding() -> None:
    cloud = FakeCloud()
    settings = cloud_settings(provider="parasail")
    item = judge_sample(PredictSample(**SAMPLE), settings, cloud)  # type: ignore[arg-type]
    assert (item.pred_label, item.prob_ddos) == (1, 0.9)
    call = cloud.calls[0]
    assert call["url"] == "https://openrouter.test/api/v1/chat/completions"
    assert call["headers"]["Authorization"] == "Bearer or-key"
    body = call["json"]
    assert body["model"] == CLOUD_DEFAULT_MODEL
    assert body["messages"][0]["content"] == build_prompt(
        PredictSample(**SAMPLE), "lab"
    )
    assert (body["temperature"], body["seed"]) == (0, 42)
    assert body["response_format"] == {"type": "json_object"}
    assert body["provider"] == {"order": ["parasail"], "allow_fallbacks": False}


def test_fallback_answers_only_when_the_primary_fails_and_is_counted() -> None:
    cloud = FakeCloud(down=["https://openrouter.test"])
    answers: Dict[str, int] = {}
    item = judge_sample(
        PredictSample(**SAMPLE),
        cloud_settings(),
        cloud,  # type: ignore[arg-type]
        answers,
    )
    assert item.pred_label == 1
    assert [c["json"]["model"] for c in cloud.calls] == [
        CLOUD_DEFAULT_MODEL,
        FALLBACK_MODEL,
    ]
    assert cloud.calls[1]["headers"]["Authorization"] == "Bearer groq-key"
    assert answers == {f"fallback:{FALLBACK_MODEL}": 1}


def test_every_endpoint_down_fails_safe_to_not_ddos() -> None:
    cloud = FakeCloud(down=["https://openrouter.test", "https://groq.test"])
    answers: Dict[str, int] = {}
    item = judge_sample(
        PredictSample(**SAMPLE),
        cloud_settings(),
        cloud,  # type: ignore[arg-type]
        answers,
    )
    assert (item.pred_label, item.prob_ddos) == (0, 0.0)
    assert answers == {"failed": 1}


def test_a_fenced_json_answer_is_parsed() -> None:
    fenced = '```json\n{"is_ddos": false, "confidence": 0.8}\n```'
    assert _verdict_from_text(fenced) == (False, 0.8)


def test_env_defaults_and_the_fallback_needs_its_own_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SDN_LLM_BACKEND", "cloud")
    monkeypatch.setenv("SDN_LLM_CLOUD_KEY", "or-key")
    monkeypatch.setenv("SDN_LLM_CLOUD_FALLBACK_KEY", "groq-key")
    monkeypatch.delenv("SDN_LLM_CLOUD_FALLBACK_MODEL", raising=False)
    settings = OllamaSettings.from_env()
    assert settings.backend == "cloud"
    assert settings.model == CLOUD_DEFAULT_MODEL
    # No fallback model given: Groq no longer serves Llama 3.2 3B, so no fallback.
    assert [e.name for e in settings.cloud] == ["primary"]
    assert settings.cloud[0].base_url == "https://openrouter.ai/api/v1"

    monkeypatch.setenv("SDN_LLM_CLOUD_FALLBACK_MODEL", FALLBACK_MODEL)
    settings = OllamaSettings.from_env()
    assert [e.model for e in settings.cloud] == [CLOUD_DEFAULT_MODEL, FALLBACK_MODEL]
    assert "or-key" not in repr(settings) and "groq-key" not in repr(settings)


def test_ollama_stays_the_default_and_a_bad_backend_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SDN_LLM_BACKEND", raising=False)
    assert OllamaSettings.from_env().backend == "ollama"
    monkeypatch.setenv("SDN_LLM_BACKEND", "openai")
    with pytest.raises(ValueError, match="SDN_LLM_BACKEND"):
        OllamaSettings.from_env()


def service_client(cloud: FakeCloud) -> TestClient:
    return TestClient(create_app(cloud_settings(), mode="llm", http=cloud))  # type: ignore[arg-type]


def test_service_reports_cloud_provenance_without_keys() -> None:
    api = service_client(FakeCloud())
    health = api.get("/health").json()
    assert health["status"] == "ready"
    assert health["backend"] == "cloud"
    config = api.get("/config", headers=KEY).json()
    assert config["llm_backend"] == "cloud"
    assert [e["model"] for e in config["cloud_endpoints"]] == [
        CLOUD_DEFAULT_MODEL,
        FALLBACK_MODEL,
    ]
    assert "or-key" not in str(config) and "groq-key" not in str(config)
    assert api.get("/models", headers=KEY).json()["models"] == [
        CLOUD_DEFAULT_MODEL,
        FALLBACK_MODEL,
    ]


def test_the_ollama_tag_is_refused_in_cloud_mode() -> None:
    # A thesis scenario asks for llama3.2:3b; in cloud mode that must fail, so a
    # run can never judge with the cloud under the local model's name.
    api = service_client(FakeCloud())
    refused = api.put("/config", headers=KEY, json={"model": "llama3.2:3b"})
    assert refused.status_code == 422


def test_usage_counts_which_endpoint_answered() -> None:
    cloud = FakeCloud(down=["https://openrouter.test"])
    api = service_client(cloud)
    answer = api.post("/predict", headers=KEY, json={"samples": [SAMPLE, SAMPLE]})
    assert answer.status_code == 200
    usage = api.get("/usage", headers=KEY).json()
    assert usage["llm_backend"] == "cloud"
    assert usage["cloud_answers"] == {f"fallback:{FALLBACK_MODEL}": 2}
    assert usage["decision_calls"] == 2
