"""One container, two detectors, never mixed: the DDoS detection service.

Hosts both mechanisms behind a single authenticated HTTP API so the lab's
runner can reach them with the contract it already speaks:

    POST /predict          LLM detector (same contract as detection.api)
    POST /entropy/observe  Shannon-entropy detector (one adaptive state per run)
    GET  /health           unauthenticated readiness probe used by the lab
    GET  /config, PUT /config, GET /models   choose the active mode/LLM

Only the *active* mode answers; the other detector's route returns 409. The
service is stateless with respect to storage: the controller records decisions.
Detector logic is reused from llm_api.py and entropy.py without changes.
"""

from __future__ import annotations

import logging
import os
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Literal, Optional

import requests
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from sdn_ddos.detection.entropy import EntropyDetector, FlowObservation
from sdn_ddos.detection.llm_api import (
    PROMPTS,
    OllamaSettings,
    PredictRequest,
    PredictResponse,
    judge_sample,
)

Mode = Literal["llm", "entropy", "off"]
Policy = Literal["block", "rate_limit", "escalate"]
LOGGER = logging.getLogger(__name__)
HEALTH_CACHE_SECONDS = 5.0
HEALTH_UPSTREAM_TIMEOUT = 0.8  # the lab runner gives /health only ~1 s
WARM_INTERVAL_SECONDS = 240.0  # Ollama unloads idle models after 5 minutes
WARM_TIMEOUT_SECONDS = 120.0
MAX_RUNS = 8
MAX_FLOWS_PER_WINDOW = 5000


class FlowIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    src: str = Field(min_length=1, max_length=64)
    dst: str = Field(min_length=1, max_length=64)
    weight: float = Field(ge=0, allow_inf_nan=False)


class EntropyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    scope: int = Field(default=0, ge=0)
    flows: List[FlowIn] = Field(max_length=MAX_FLOWS_PER_WINDOW)


class ConfigUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Optional[Mode] = None
    model: Optional[str] = Field(default=None, min_length=1, max_length=100)
    prompt: Optional[str] = Field(default=None, min_length=1, max_length=40)
    response: Optional[Policy] = None
    dry_run: Optional[bool] = None


class DetectorService:
    """Mutable runtime state: active mode/model, per-run entropy detectors."""

    def __init__(
        self,
        settings: OllamaSettings,
        mode: str,
        http: Optional[requests.Session] = None,
        warm: bool = False,
    ) -> None:
        if mode not in ("llm", "entropy", "off"):
            raise ValueError(f"mode must be llm, entropy or off, got {mode!r}")
        self.settings = settings
        self.mode: str = mode
        self.model: str = settings.model
        self.prompt: str = settings.prompt_profile
        policy = os.environ.get("SDN_RESPONSE_POLICY", "block").strip().lower()
        if policy not in ("block", "rate_limit", "escalate"):
            raise ValueError(f"SDN_RESPONSE_POLICY is not valid: {policy!r}")
        self.response: str = policy
        dry = os.environ.get("SDN_RESPONSE_DRY_RUN", "false").strip().lower()
        self.dry_run: bool = dry in {"1", "true", "yes", "on"}
        self.http = http or requests.Session()
        self.warm_enabled = warm
        self.lock = threading.Lock()
        self._runs: "OrderedDict[str, EntropyDetector]" = OrderedDict()
        self._health: Optional[Dict[str, Any]] = None
        self._health_at = 0.0
        self._last_warm = -WARM_INTERVAL_SECONDS

    def warm_model(self) -> bool:
        """Load the model into Ollama's memory; a cold load can exceed call timeouts."""

        try:
            response = self.http.post(
                f"{self.settings.base_url}/api/generate",
                json={"model": self.model, "prompt": "", "keep_alive": "30m"},
                timeout=WARM_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            LOGGER.warning("model warm-up failed for %s: %s", self.model, exc)
            return False
        return True

    def maybe_warm(self, force: bool = False) -> None:
        """Warm the active LLM in the background when it may have been unloaded."""

        if not (self.warm_enabled and self.mode == "llm"):
            return
        now = time.monotonic()
        if not force and now - self._last_warm < WARM_INTERVAL_SECONDS:
            return
        self._last_warm = now
        threading.Thread(target=self.warm_model, daemon=True).start()

    def llm_settings(self) -> OllamaSettings:
        return self.settings.model_copy(
            update={"model": self.model, "prompt_profile": self.prompt}
        )

    def installed_models(self, timeout: float) -> List[str]:
        response = self.http.get(f"{self.settings.base_url}/api/tags", timeout=timeout)
        response.raise_for_status()
        return [item["name"] for item in response.json().get("models", [])]

    def entropy_for(self, run_id: str) -> EntropyDetector:
        with self.lock:
            detector = self._runs.get(run_id)
            if detector is None:
                detector = EntropyDetector.from_env()
                self._runs[run_id] = detector
                while len(self._runs) > MAX_RUNS:
                    self._runs.popitem(last=False)
            else:
                self._runs.move_to_end(run_id)
            return detector

    def invalidate_health(self) -> None:
        self._health = None

    def health(self) -> Dict[str, Any]:
        now = time.monotonic()
        if self._health is not None and now - self._health_at < HEALTH_CACHE_SECONDS:
            return self._health
        authenticated = bool(self.settings.api_key)
        model_loaded: Optional[bool] = None
        if self.mode == "llm":
            try:
                model_loaded = self.model in self.installed_models(
                    HEALTH_UPSTREAM_TIMEOUT
                )
            except (requests.RequestException, KeyError, ValueError):
                model_loaded = False
            backend_ok = model_loaded
        else:
            backend_ok = True
        if model_loaded:
            self.maybe_warm()
        result = {
            "status": "ready" if backend_ok and authenticated else "not_ready",
            "mode": self.mode,
            "model": self.model,
            "model_loaded": model_loaded,
            "authentication_configured": authenticated,
            "backend": "ollama" if self.mode == "llm" else self.mode,
            "ollama_url": self.settings.base_url,
        }
        self._health, self._health_at = result, now
        return result


def create_app(
    settings: Optional[OllamaSettings] = None,
    mode: Optional[str] = None,
    http: Optional[requests.Session] = None,
    warm: bool = False,
) -> FastAPI:
    resolved = settings or OllamaSettings.from_env()
    initial_mode = (mode or os.environ.get("SDN_DETECTION_MODE", "llm")).strip().lower()
    service = DetectorService(resolved, initial_mode, http, warm=warm)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        service.maybe_warm(force=True)
        yield

    application = FastAPI(
        title="SDN DDoS Detection Service", version="0.1.0", lifespan=lifespan
    )
    application.state.service = service

    def authorize(x_api_key: Optional[str]) -> None:
        if not resolved.api_key:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "detector authentication is not configured",
            )
        if x_api_key is None or not secrets.compare_digest(x_api_key, resolved.api_key):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unauthorized")

    def require_mode(expected: str) -> None:
        if service.mode != expected:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"detection mode is {service.mode!r}; {expected!r} is not active",
            )

    @application.get("/health")
    def health() -> Dict[str, Any]:
        return service.health()

    @application.get("/config")
    def get_config(
        x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key"),
    ) -> Dict[str, Any]:
        authorize(x_api_key)
        return {
            "mode": service.mode,
            "model": service.model,
            "prompt": service.prompt,
            "prompts": sorted(PROMPTS),
            "response": service.response,
            "dry_run": service.dry_run,
            "ollama_url": resolved.base_url,
            "entropy_runs": len(service._runs),
        }

    @application.put("/config")
    def put_config(
        update: ConfigUpdate,
        x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key"),
    ) -> Dict[str, Any]:
        authorize(x_api_key)
        if update.model is not None and update.model != service.model:
            try:
                installed = service.installed_models(3.0)
            except (requests.RequestException, KeyError, ValueError) as exc:
                raise HTTPException(
                    status.HTTP_502_BAD_GATEWAY, f"cannot list Ollama models: {exc}"
                ) from exc
            if update.model not in installed:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    f"model {update.model!r} is not installed; "
                    f"available: {', '.join(installed) or 'none'}",
                )
            service.model = update.model
        if update.prompt is not None:
            if update.prompt not in PROMPTS:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    f"unknown prompt {update.prompt!r}; available: {sorted(PROMPTS)}",
                )
            service.prompt = update.prompt
        if update.response is not None:
            service.response = update.response
        if update.dry_run is not None:
            service.dry_run = update.dry_run
        if update.mode is not None:
            service.mode = update.mode
        service.invalidate_health()
        service.maybe_warm(force=True)
        return {
            "mode": service.mode,
            "model": service.model,
            "prompt": service.prompt,
            "response": service.response,
            "dry_run": service.dry_run,
        }

    @application.get("/models")
    def models(
        x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key"),
    ) -> Dict[str, Any]:
        authorize(x_api_key)
        try:
            installed = service.installed_models(3.0)
        except (requests.RequestException, KeyError, ValueError) as exc:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY, f"cannot list Ollama models: {exc}"
            ) from exc
        return {"models": installed, "active": service.model}

    @application.post("/predict", response_model=PredictResponse)
    def predict(
        payload: PredictRequest,
        x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key"),
    ) -> PredictResponse:
        authorize(x_api_key)
        require_mode("llm")
        if not payload.samples:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "samples must contain at least 1 item",
            )
        llm = service.llm_settings()
        predictions = [
            judge_sample(sample, llm, service.http) for sample in payload.samples
        ]
        return PredictResponse(predictions=predictions)

    @application.post("/entropy/observe")
    def entropy_observe(
        payload: EntropyRequest,
        x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key"),
    ) -> Dict[str, Any]:
        authorize(x_api_key)
        require_mode("entropy")
        detector = service.entropy_for(payload.run_id)
        flows = [FlowObservation(f.src, f.dst, f.weight) for f in payload.flows]
        with service.lock:
            result = detector.observe(payload.scope, flows)
        return {
            "confirmed": result.confirmed,
            "reason": result.reason,
            "consecutive": result.consecutive,
            "consecutive_windows": detector.consecutive_windows,
            "target_dst": result.target_dst,
            "candidates": list(result.candidates),
            "details": result.as_details(),
        }

    return application


app = create_app(warm=True)
