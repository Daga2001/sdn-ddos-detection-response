# ruff: noqa: E501  (prompt templates are single long lines)
"""Authenticated HTTP inference service backed by a local LLM (Llama 3.2 3B).

Drop-in replacement for detection.api's Random Forest-backed service: it
serves the exact same /predict request/response contract, so
controller/app.py needs zero changes to use it. Point SDN_DDOS_SERVICE_URL
at this service's host/port instead of the Random Forest one to make the
LLM the authoritative decision-maker for DDoS classification.

The model itself does not run in this VM. It runs outside, served by
Ollama on the Windows host machine (reachable over the VMware NAT
network), because a 3B-parameter model performs far better on the host's
CPU/RAM than on this lab VM's 2 vCPUs. This module only builds a
natural-language prompt from the six flow features, calls Ollama's
structured-JSON generation endpoint, and parses the verdict back into the
pred_label/prob_ddos shape the controller already understands.

Run with:
    scripts/run_llm_inference.sh
"""

from __future__ import annotations

import json
import logging
import os
import secrets
from typing import Any, Dict, List, Literal, Optional, Tuple

import requests
from fastapi import FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

LOGGER = logging.getLogger(__name__)


class PredictSample(BaseModel):
    """The ordered flow features accepted by the current baseline model.

    Field-for-field identical to detection.api.PredictSample so both
    services accept the exact same request body from the controller.
    """

    model_config = ConfigDict(extra="forbid")

    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)
    pktrate: float = Field(ge=0, allow_inf_nan=False)
    byterate: float = Field(ge=0, allow_inf_nan=False)
    ip_proto: int = Field(ge=0, le=255)
    l4_dst_port: int = Field(ge=0, le=65535)


class PredictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    samples: List[PredictSample]


class PredictItem(BaseModel):
    pred_label: int
    prob_ddos: float = Field(ge=0, le=1, allow_inf_nan=False)


class PredictResponse(BaseModel):
    predictions: List[PredictItem]


# Optional cloud backend (SDN_LLM_BACKEND=cloud): the same prompt sent to a hosted
# copy of the model through an OpenAI-compatible Chat Completions API. Ollama stays
# the default; the thesis runs use Ollama only.
CLOUD_DEFAULT_URL = "https://openrouter.ai/api/v1"
CLOUD_DEFAULT_MODEL = "meta-llama/llama-3.2-3b-instruct"
CLOUD_FALLBACK_DEFAULT_URL = "https://api.groq.com/openai/v1"
BACKENDS = ("ollama", "cloud")


class CloudEndpoint(BaseModel):
    """One OpenAI-compatible service. The key is never reported or logged."""

    name: str
    base_url: str
    model: str
    api_key: str = Field(default="", repr=False)
    # OpenRouter only: pin one upstream provider (e.g. "parasail") so every call is
    # served by the same deployment; empty lets OpenRouter route the call.
    provider: str = ""

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.model and self.api_key)

    def public(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "base_url": self.base_url,
            "model": self.model,
            "provider": self.provider,
        }


def cloud_endpoints_from_env() -> List[CloudEndpoint]:
    """Primary (OpenRouter by default) and an optional fallback, in that order.

    The fallback has no default model: Groq, its default URL, no longer serves
    Llama 3.2 3B, so a fallback always names its model explicitly and answers only
    when the primary fails (each such answer is counted and logged).
    """

    endpoints = [
        CloudEndpoint(
            name="primary",
            base_url=os.environ.get("SDN_LLM_CLOUD_URL", CLOUD_DEFAULT_URL).rstrip("/"),
            model=os.environ.get("SDN_LLM_CLOUD_MODEL", CLOUD_DEFAULT_MODEL),
            api_key=os.environ.get("SDN_LLM_CLOUD_KEY", ""),
            provider=os.environ.get("SDN_LLM_CLOUD_PROVIDER", ""),
        ),
        CloudEndpoint(
            name="fallback",
            base_url=os.environ.get(
                "SDN_LLM_CLOUD_FALLBACK_URL", CLOUD_FALLBACK_DEFAULT_URL
            ).rstrip("/"),
            model=os.environ.get("SDN_LLM_CLOUD_FALLBACK_MODEL", ""),
            api_key=os.environ.get("SDN_LLM_CLOUD_FALLBACK_KEY", ""),
        ),
    ]
    return [endpoint for endpoint in endpoints if endpoint.configured]


class OllamaSettings(BaseModel):
    """Where to reach the LLM and how long to wait for it."""

    base_url: str = "http://192.168.83.1:11434"
    model: str = "llama3.2:3b"
    timeout_seconds: float = 10.0
    api_key: str = ""
    # Which prompt calibration to use (see PROMPTS): "insdn" is the dataset one.
    prompt_profile: str = "insdn"
    backend: Literal["ollama", "cloud"] = "ollama"
    cloud: List[CloudEndpoint] = Field(default_factory=list)

    @classmethod
    def from_env(cls) -> "OllamaSettings":
        backend = os.environ.get("SDN_LLM_BACKEND", "ollama").strip().lower()
        if backend not in BACKENDS:
            raise ValueError(
                f"SDN_LLM_BACKEND must be one of {BACKENDS}, got {backend!r}"
            )
        cloud = cloud_endpoints_from_env() if backend == "cloud" else []
        model = os.environ.get("SDN_LLM_MODEL", "llama3.2:3b")
        if backend == "cloud":
            # The run's model must be a cloud model name, never the Ollama tag, so
            # cloud runs get their own settings fingerprint.
            model = cloud[0].model if cloud else CLOUD_DEFAULT_MODEL
        return cls(
            base_url=os.environ.get("SDN_LLM_OLLAMA_URL", "http://192.168.83.1:11434"),
            model=model,
            timeout_seconds=float(os.environ.get("SDN_LLM_TIMEOUT_SECONDS", "10")),
            prompt_profile=os.environ.get("SDN_LLM_PROMPT", "insdn"),
            # Reuses the same key the controller already sends so no new
            # secret is needed in .env when switching services.
            api_key=os.environ.get("DDOS_API_KEY", ""),
            backend=backend,  # type: ignore[arg-type]
            cloud=cloud,
        )

    def cloud_order(self) -> List[CloudEndpoint]:
        """The endpoint serving the selected model first, the others after it."""

        first = [e for e in self.cloud if e.model == self.model]
        return first + [e for e in self.cloud if e.model != self.model]

    def cloud_models(self) -> List[str]:
        return list(dict.fromkeys(e.model for e in self.cloud))


PROMPT_TEMPLATE = """Sos un clasificador de trafico de red. Decidis UNICAMENTE con la tasa de \
paquetes por segundo (pktrate). Los contadores acumulados (paquetes y bytes acumulados) \
crecen siempre en flujos normales de larga duracion: NO son la tasa y NO se usan para decidir.

Regla, aplicada comparando numeros:
- pktrate menor que 5000 -> is_ddos=false
- pktrate entre 5000 y 20000 -> zona ambigua, evalua con cautela
- pktrate mayor o igual que 20000 -> is_ddos=true

Ejemplos reales (dataset InSDN; el campo "comparacion" compara pktrate con los umbrales):
pktrate=0.56, paquetes acumulados=62 -> {{"comparacion": "0.56 es menor que 5000", "is_ddos": false, "confidence": 0.97}}
pktrate=897.13, paquetes acumulados=3 -> {{"comparacion": "897.13 es menor que 5000", "is_ddos": false, "confidence": 0.9}}
pktrate=1941.75, paquetes acumulados=4 -> {{"comparacion": "1941.75 es menor que 5000", "is_ddos": false, "confidence": 0.85}}
pktrate=38461.54, paquetes acumulados=2 -> {{"comparacion": "38461.54 es mayor que 20000", "is_ddos": true, "confidence": 0.9}}
pktrate=142857.14, paquetes acumulados=2 -> {{"comparacion": "142857.14 es mayor que 20000", "is_ddos": true, "confidence": 0.95}}
pktrate=2000000.0, paquetes acumulados=2 -> {{"comparacion": "2000000.0 es mayor que 20000", "is_ddos": true, "confidence": 0.97}}

Nota: en trafico de flood real, un flujo "malicioso" a menudo tiene MUY POCOS paquetes \
acumulados (2-3) porque cada conexion se corta o rechaza enseguida -- la senal esta en la \
tasa (muchos paquetes en muy poco tiempo), no en el volumen acumulado.

Flujo a clasificar:
- pktrate (DECISIVO): {pktrate:.2f} paquetes/seg
- Tasa de bytes: {byterate:.2f} bytes/seg
- Protocolo IP: {ip_proto} (6=TCP, 17=UDP, 1=ICMP)
- Puerto destino L4: {l4_dst_port}
- Paquetes acumulados (solo informativo): {packet_count}
- Bytes acumulados (solo informativo): {byte_count}

Responde EXCLUSIVAMENTE con un objeto JSON, sin texto adicional, con estas claves en \
este orden: "comparacion" (compara el pktrate de arriba con los umbrales), "is_ddos" \
(true o false) y "confidence" (numero entre 0.0 y 1.0).
"""


# Same structure as the InSDN prompt, calibrated with the graphical lab's own
# traffic. pktrate is the change in the switch's packet counter divided by the
# change in that flow's OpenFlow age, not the controller's processing delay and
# not CICFlowMeter's packets/duration. In 7792 labeled flow
# samples (9 runs, SYN/UDP at 100-1000 pkt/s) legitimate flows peaked at 3.6 pkt/s
# and attack flows started at 95 pkt/s; the examples are real rows of that data.
LAB_PROMPT_TEMPLATE = """Sos un clasificador de trafico de red. Decidis UNICAMENTE con la tasa de \
paquetes por segundo (pktrate), medida por el controlador sobre el flujo en el ultimo \
sondeo. Los contadores acumulados (paquetes y bytes acumulados) NO son la tasa y NO se \
usan para decidir.

Regla, aplicada comparando numeros:
- pktrate menor que 10 -> is_ddos=false
- pktrate entre 10 y 50 -> zona ambigua, evalua con cautela
- pktrate mayor o igual que 50 -> is_ddos=true

Ejemplos reales (laboratorio SDN; el campo "comparacion" compara pktrate con los umbrales):
pktrate=0.00, paquetes acumulados=15 -> {{"comparacion": "0.00 es menor que 10", "is_ddos": false, "confidence": 0.97}}
pktrate=1.00, paquetes acumulados=10 -> {{"comparacion": "1.00 es menor que 10", "is_ddos": false, "confidence": 0.95}}
pktrate=1.20, paquetes acumulados=10 -> {{"comparacion": "1.20 es menor que 10", "is_ddos": false, "confidence": 0.95}}
pktrate=166.77, paquetes acumulados=5118 -> {{"comparacion": "166.77 es mayor que 50", "is_ddos": true, "confidence": 0.95}}
pktrate=271.45, paquetes acumulados=8695 -> {{"comparacion": "271.45 es mayor que 50", "is_ddos": true, "confidence": 0.97}}
pktrate=760.40, paquetes acumulados=11524 -> {{"comparacion": "760.40 es mayor que 50", "is_ddos": true, "confidence": 0.98}}

Flujo a clasificar:
- pktrate (DECISIVO): {pktrate:.2f} paquetes/seg
- Tasa de bytes: {byterate:.2f} bytes/seg
- Protocolo IP: {ip_proto} (6=TCP, 17=UDP, 1=ICMP)
- Puerto destino L4: {l4_dst_port}
- Paquetes acumulados (solo informativo): {packet_count}
- Bytes acumulados (solo informativo): {byte_count}

Responde EXCLUSIVAMENTE con un objeto JSON, sin texto adicional, con estas claves en \
este orden: "comparacion" (compara el pktrate de arriba con los umbrales), "is_ddos" \
(true o false) y "confidence" (numero entre 0.0 y 1.0).
"""

PROMPTS: Dict[str, str] = {"insdn": PROMPT_TEMPLATE, "lab": LAB_PROMPT_TEMPLATE}


def build_prompt(sample: PredictSample, profile: str = "insdn") -> str:
    if profile not in PROMPTS:
        raise ValueError(f"unknown prompt profile {profile!r}; use {sorted(PROMPTS)}")
    return PROMPTS[profile].format(
        packet_count=sample.packet_count,
        byte_count=sample.byte_count,
        pktrate=sample.pktrate,
        byterate=sample.byterate,
        ip_proto=sample.ip_proto,
        l4_dst_port=sample.l4_dst_port,
    )


def _as_bool(value: Any) -> bool:
    """Strict bool: bool("false") is True, which must never happen here."""

    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
        return value.strip().lower() == "true"
    raise ValueError(f"is_ddos is not a boolean: {value!r}")


def _as_confidence(value: Any) -> float:
    confidence = float(value)
    if 1.0 < confidence <= 100.0:  # some models answer in percent
        confidence /= 100.0
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence out of range")
    return confidence


def _verdict_from_text(text: str) -> Tuple[bool, float]:
    """Parse the JSON verdict; hosted models sometimes wrap it in a code fence."""

    body = text.strip()
    if body.startswith("```"):
        body = body.strip("`").strip()
        if body.lower().startswith("json"):
            body = body[4:].strip()
    verdict = json.loads(body)
    return _as_bool(verdict["is_ddos"]), _as_confidence(verdict["confidence"])


def query_cloud(
    sample: PredictSample,
    endpoint: CloudEndpoint,
    settings: OllamaSettings,
    http: requests.Session,
) -> Tuple[bool, float]:
    """One Chat Completions call to an OpenAI-compatible service."""

    body: Dict[str, Any] = {
        "model": endpoint.model,
        "messages": [
            {"role": "user", "content": build_prompt(sample, settings.prompt_profile)}
        ],
        # Same decoding as the Ollama call; a hosted service may still not honour
        # the seed, which is one reason cloud runs are never pooled with Ollama runs.
        "temperature": 0,
        "seed": 42,
        "max_tokens": 200,
        "response_format": {"type": "json_object"},
    }
    if endpoint.provider:
        body["provider"] = {"order": [endpoint.provider], "allow_fallbacks": False}
    response = http.post(
        f"{endpoint.base_url}/chat/completions",
        json=body,
        headers={"Authorization": f"Bearer {endpoint.api_key}"},
        timeout=settings.timeout_seconds,
    )
    response.raise_for_status()
    return _verdict_from_text(response.json()["choices"][0]["message"]["content"])


CloudAnswers = Dict[str, int]


def query_cloud_chain(
    sample: PredictSample,
    settings: OllamaSettings,
    http: requests.Session,
    answers: Optional[CloudAnswers] = None,
) -> Tuple[bool, float]:
    """Try the endpoints in order; count which one answered ("name:model")."""

    endpoints = settings.cloud_order()
    if not endpoints:
        raise ValueError("cloud backend has no configured endpoint")
    last: Optional[Exception] = None
    for index, endpoint in enumerate(endpoints):
        try:
            verdict = query_cloud(sample, endpoint, settings, http)
        except (
            requests.RequestException,
            KeyError,
            IndexError,
            ValueError,
            TypeError,
        ) as exc:
            LOGGER.warning("cloud endpoint %s failed: %s", endpoint.name, exc)
            last = exc
            continue
        if index > 0:
            LOGGER.warning(
                "verdict answered by %s (%s), not by %s",
                endpoint.name,
                endpoint.model,
                endpoints[0].name,
            )
        if answers is not None:
            key = f"{endpoint.name}:{endpoint.model}"
            answers[key] = answers.get(key, 0) + 1
        return verdict
    assert last is not None
    raise last


def query_llm(
    sample: PredictSample,
    settings: OllamaSettings,
    http: requests.Session,
    answers: Optional[CloudAnswers] = None,
) -> Tuple[bool, float]:
    """One LLM call. Returns (is_ddos, confidence); raises on any failure."""

    if settings.backend == "cloud":
        return query_cloud_chain(sample, settings, http, answers)
    response = http.post(
        f"{settings.base_url}/api/generate",
        json={
            "model": settings.model,
            "prompt": build_prompt(sample, settings.prompt_profile),
            "stream": False,
            "format": "json",
            # temperature=0 makes generation deterministic (always pick the
            # most likely token) instead of sampling -- important for a
            # component meant to have the final say on blocking traffic. seed
            # pins it further across Ollama restarts.
            "options": {"temperature": 0, "seed": 42},
        },
        timeout=settings.timeout_seconds,
    )
    response.raise_for_status()
    verdict = json.loads(response.json()["response"])
    return _as_bool(verdict["is_ddos"]), _as_confidence(verdict["confidence"])


# A "not DDoS" answer is never worth more than this probability of attack.
NEGATIVE_PROB_CAP = 0.5


def to_prediction(is_ddos: bool, confidence: float) -> PredictItem:
    """The model's verdict and confidence on the controller's prob_ddos scale.

    `confidence` is how sure the model is of its own verdict, not P(ddos). A positive
    verdict keeps it as it is. A negative verdict is 1 - confidence, but never above
    `NEGATIVE_PROB_CAP`: "is_ddos=false, confidence=0.0" (the model contradicting itself,
    seen offline on 343 of 503 flagged answers) used to become prob_ddos = 1.0, and a
    verdict of "not an attack" was thresholded as an attack. The cap keeps a negative
    answer under any threshold of 0.5 or more and the probability informative. With a
    configured threshold below 0.5 a negative answer of low confidence can still be
    flagged: that threshold asks for it.
    """

    prob_ddos = confidence if is_ddos else min(1.0 - confidence, NEGATIVE_PROB_CAP)
    return PredictItem(pred_label=1 if is_ddos else 0, prob_ddos=prob_ddos)


def judge_sample(
    sample: PredictSample,
    settings: OllamaSettings,
    http: requests.Session,
    answers: Optional[CloudAnswers] = None,
) -> PredictItem:
    """Ask the LLM for a verdict on one flow. Fails safe (not-DDoS) on any error.

    A parsing/network failure here must never be mistaken for "confirmed
    attack" -- the LLM has the final word only when it actually answers.
    """

    try:
        is_ddos, confidence = query_llm(sample, settings, http, answers)
    except (
        requests.RequestException,
        KeyError,
        IndexError,
        ValueError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        LOGGER.error("LLM judgment failed, defaulting to not-DDoS: %s", exc)
        if answers is not None:
            answers["failed"] = answers.get("failed", 0) + 1
        return PredictItem(pred_label=0, prob_ddos=0.0)
    return to_prediction(is_ddos, confidence)


def create_app(settings: Optional[OllamaSettings] = None) -> FastAPI:
    resolved = settings or OllamaSettings.from_env()
    http = requests.Session()

    application = FastAPI(
        title="SDN DDoS LLM Inference Service",
        version="0.1.0",
    )

    @application.get("/health")
    def health() -> Dict[str, Any]:
        if resolved.backend == "cloud":
            model_loaded = resolved.model in resolved.cloud_models()
        else:
            try:
                tags = http.get(f"{resolved.base_url}/api/tags", timeout=3)
                tags.raise_for_status()
                models = [m["name"] for m in tags.json().get("models", [])]
                model_loaded = resolved.model in models
            except (requests.RequestException, KeyError, ValueError):
                model_loaded = False
        return {
            "status": "ready" if model_loaded and resolved.api_key else "not_ready",
            "model_loaded": model_loaded,
            "authentication_configured": bool(resolved.api_key),
            "backend": resolved.backend,
            "model": resolved.model,
            "ollama_url": resolved.base_url,
        }

    @application.post("/predict", response_model=PredictResponse)
    def predict(
        payload: PredictRequest,
        request: Request,
        x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key"),
    ) -> PredictResponse:
        if not resolved.api_key:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="inference authentication is not configured",
            )
        if x_api_key is None or not secrets.compare_digest(x_api_key, resolved.api_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="unauthorized",
            )
        if not payload.samples:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="samples must contain at least 1 item",
            )

        predictions = [
            judge_sample(sample, resolved, http) for sample in payload.samples
        ]
        return PredictResponse(predictions=predictions)

    return application


app = create_app()
