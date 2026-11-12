"""One container, two detectors, never mixed: the DDoS detection service.

Hosts both mechanisms behind a single authenticated HTTP API so the lab's
runner can reach them with the contract it already speaks:

    POST /predict          LLM detector (same contract as detection.api)
    POST /entropy/observe  entropy detector (one adaptive state per run)
    GET  /health           unauthenticated readiness probe used by the lab
    GET  /config, PUT /config, GET /models   choose the active mode/LLM
    GET  /usage            this process's CPU time and memory (decision cost)

Only the *active* mode answers; the other detector's route returns 409. The
service is stateless with respect to storage: the controller records decisions.
Detector logic is reused from llm_api.py and entropy.py without changes.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Literal, Optional

import psutil
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


class BinIn(BaseModel):
    """`count` distinct values that all carry `weight` (a histogram bin)."""

    model_config = ConfigDict(extra="forbid")

    weight: float = Field(ge=0, allow_inf_nan=False)
    count: int = Field(ge=1, le=10_000_000)


class EntropyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    scope: int = Field(default=0, ge=0)
    flows: List[FlowIn] = Field(max_length=MAX_FLOWS_PER_WINDOW)
    # Destination-port and protocol distributions, only when the run watches them.
    dports: List[BinIn] = Field(default_factory=list, max_length=MAX_FLOWS_PER_WINDOW)
    protos: List[BinIn] = Field(default_factory=list, max_length=MAX_FLOWS_PER_WINDOW)


ENTROPY_FIELDS = (
    "k",
    "alpha",
    "warmup_windows",
    "consecutive_windows",
    "min_total_rate",
    "min_std",
    "candidate_share",
    "candidate_min_rate",
    "update_hold",
    "alpha_run",
    "measure",
    "order",
    "center",
    "spread",
    "history",
    "context",
    "features",
    "decide",
    "margin",
    "rate_threshold",
)
TUPLE_FIELDS = ("features", "decide")


class EntropyUpdate(BaseModel):
    """Tuning of the entropy detector. Applies to runs that start after the change."""

    model_config = ConfigDict(extra="forbid")

    k: Optional[float] = Field(default=None, ge=0.5, le=10)
    alpha: Optional[float] = Field(default=None, gt=0, le=1)
    warmup_windows: Optional[int] = Field(default=None, ge=1, le=120)
    consecutive_windows: Optional[int] = Field(default=None, ge=1, le=20)
    min_total_rate: Optional[float] = Field(default=None, ge=0, le=1_000_000)
    min_std: Optional[float] = Field(default=None, ge=0, le=10)
    candidate_share: Optional[float] = Field(default=None, ge=0, le=1)
    candidate_min_rate: Optional[float] = Field(default=None, ge=0, le=1_000_000)
    update_hold: Optional[int] = Field(default=None, ge=0, le=20)
    alpha_run: Optional[float] = Field(default=None, gt=0, le=1)
    measure: Optional[Literal["shannon", "norm", "renyi", "tsallis", "min"]] = None
    order: Optional[float] = Field(default=None, gt=0, le=64)
    center: Optional[
        Literal["ewma", "mean", "median", "yu", "ewma_margin", "ewma2"]
    ] = None
    spread: Optional[Literal["std", "mad"]] = None
    history: Optional[int] = Field(default=None, ge=0, le=1000)
    context: Optional[Literal["normal", "all"]] = None
    features: Optional[List[Literal["src", "dst", "dport", "proto", "pair"]]] = Field(
        default=None, min_length=2, max_length=5
    )
    decide: Optional[List[Literal["src", "dst", "dport", "proto", "pair"]]] = Field(
        default=None, max_length=5
    )
    margin: Optional[float] = Field(default=None, ge=0, le=1)
    rate_threshold: Optional[float] = Field(default=None, ge=0, le=1_000_000)


class ConfigUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Optional[Mode] = None
    model: Optional[str] = Field(default=None, min_length=1, max_length=100)
    prompt: Optional[str] = Field(default=None, min_length=1, max_length=40)
    response: Optional[Policy] = None
    dry_run: Optional[bool] = None
    entropy: Optional[EntropyUpdate] = None


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
        # Overrides of the environment defaults, set through PUT /config.
        self.entropy_params: Dict[str, Any] = {}
        self._health: Optional[Dict[str, Any]] = None
        self._health_at = 0.0
        self._last_warm = -WARM_INTERVAL_SECONDS
        self._process = psutil.Process()

    def usage(self) -> Dict[str, Any]:
        """CPU seconds used so far and resident memory of this service process.

        The controller samples this to report what each decision costs. With the LLM
        the model itself runs in Ollama, outside this process, so these numbers are
        the service's own work (prompt building, parsing, the entropy computation).
        """

        times = self._process.cpu_times()
        return {
            "pid": self._process.pid,
            "mode": self.mode,
            "cpu_seconds": round(times.user + times.system, 6),
            "rss_bytes": int(self._process.memory_info().rss),
        }

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
                detector = self.new_entropy_detector()
                self._runs[run_id] = detector
                while len(self._runs) > MAX_RUNS:
                    self._runs.popitem(last=False)
            else:
                self._runs.move_to_end(run_id)
            return detector

    def new_entropy_detector(self) -> EntropyDetector:
        detector = EntropyDetector.from_env()
        if self.entropy_params:
            detector = dataclasses.replace(detector, **self.entropy_params)
        return detector

    def entropy_settings(self) -> Dict[str, Any]:
        """The values a run that starts now would use."""

        detector = self.new_entropy_detector()
        settings = {name: getattr(detector, name) for name in ENTROPY_FIELDS}
        for name in TUPLE_FIELDS:
            settings[name] = list(settings[name])
        return settings

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
            "entropy": service.entropy_settings(),
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
        if update.entropy is not None:
            # A complete set replaces the previous overrides; fields left out fall
            # back to the environment defaults.
            params: Dict[str, Any] = {
                name: tuple(value) if name in TUPLE_FIELDS else value
                for name, value in update.entropy.model_dump().items()
                if value is not None
            }
            try:  # a combination the detector rejects must fail here, not mid-run
                dataclasses.replace(EntropyDetector.from_env(), **params)
            except ValueError as exc:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)
                ) from exc
            service.entropy_params = params
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

    @application.get("/usage")
    def usage(
        x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key"),
    ) -> Dict[str, Any]:
        authorize(x_api_key)
        return service.usage()

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
        extra = {
            "dport": [(b.weight, b.count) for b in payload.dports],
            "proto": [(b.weight, b.count) for b in payload.protos],
        }
        with service.lock:
            result = detector.observe(payload.scope, flows, extra)
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
