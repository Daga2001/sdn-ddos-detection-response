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
from typing import Any, Dict, List, Optional, Tuple

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


class OllamaSettings(BaseModel):
    """Where to reach the LLM and how long to wait for it."""

    base_url: str = "http://192.168.83.1:11434"
    model: str = "llama3.2:3b"
    timeout_seconds: float = 10.0
    api_key: str = ""
    # Which prompt calibration to use (see PROMPTS): "insdn" is the dataset one.
    prompt_profile: str = "insdn"

    @classmethod
    def from_env(cls) -> "OllamaSettings":
        return cls(
            base_url=os.environ.get("SDN_LLM_OLLAMA_URL", "http://192.168.83.1:11434"),
            model=os.environ.get("SDN_LLM_MODEL", "llama3.2:3b"),
            timeout_seconds=float(os.environ.get("SDN_LLM_TIMEOUT_SECONDS", "10")),
            prompt_profile=os.environ.get("SDN_LLM_PROMPT", "insdn"),
            # Reuses the same key the controller already sends so no new
            # secret is needed in .env when switching services.
            api_key=os.environ.get("DDOS_API_KEY", ""),
        )


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


def query_llm(
    sample: PredictSample, settings: OllamaSettings, http: requests.Session
) -> Tuple[bool, float]:
    """One Ollama call. Returns (is_ddos, confidence); raises on any failure."""

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
    sample: PredictSample, settings: OllamaSettings, http: requests.Session
) -> PredictItem:
    """Ask Ollama for a verdict on one flow. Fails safe (not-DDoS) on any error.

    A parsing/network failure here must never be mistaken for "confirmed
    attack" -- the LLM has the final word only when it actually answers.
    """

    try:
        is_ddos, confidence = query_llm(sample, settings, http)
    except (
        requests.RequestException,
        KeyError,
        ValueError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        LOGGER.error("LLM judgment failed, defaulting to not-DDoS: %s", exc)
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
            "backend": "ollama",
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
