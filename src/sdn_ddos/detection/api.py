"""Authenticated HTTP API for DDoS model inference."""

from __future__ import annotations

import logging
import secrets
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Callable, Dict, List, Optional

import numpy as np
from fastapi import FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from sdn_ddos.config import DetectionSettings
from sdn_ddos.controller.core import FEATURE_ORDER
from sdn_ddos.detection.model import (
    ModelValidationError,
    load_verified_model,
    predict_probabilities,
)

LOGGER = logging.getLogger(__name__)
ModelLoader = Callable[[Any, str], Any]


class PredictSample(BaseModel):
    """The ordered flow features accepted by the current baseline model."""

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


def create_app(
    settings: Optional[DetectionSettings] = None,
    model_loader: ModelLoader = load_verified_model,
) -> FastAPI:
    """Build an application whose model state is isolated and testable."""

    resolved = settings or DetectionSettings.from_env()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.model = None
        application.state.model_error = "model is not configured"
        if resolved.model_path is not None:
            try:
                application.state.model = model_loader(
                    resolved.model_path, resolved.model_sha256
                )
                application.state.model_error = None
            except (OSError, ModelValidationError, ValueError) as exc:
                # Keep the service alive for diagnostics without exposing local
                # paths or deserialization details through the HTTP API.
                LOGGER.error("Model unavailable: %s", exc)
                application.state.model_error = "model validation failed"
        yield
        application.state.model = None

    application = FastAPI(
        title="SDN DDoS Inference Service",
        version="0.1.0",
        lifespan=lifespan,
    )

    @application.get("/health")
    def health(request: Request) -> Dict[str, Any]:
        ready = request.app.state.model is not None and bool(resolved.api_key)
        return {
            "status": "ready" if ready else "not_ready",
            "model_loaded": request.app.state.model is not None,
            "authentication_configured": bool(resolved.api_key),
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
        if not 1 <= len(payload.samples) <= resolved.max_batch_size:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"samples must contain 1 to {resolved.max_batch_size} items",
            )
        model = request.app.state.model
        if model is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="verified model is unavailable",
            )

        matrix = np.asarray(
            [
                [getattr(sample, name) for name in FEATURE_ORDER]
                for sample in payload.samples
            ],
            dtype=float,
        )
        try:
            labels, probabilities = predict_probabilities(model, matrix)
        except (ModelValidationError, TypeError, ValueError) as exc:
            LOGGER.exception("Model inference failed: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="model inference failed",
            ) from exc
        if len(labels) != len(payload.samples) or len(probabilities) != len(
            payload.samples
        ):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="model returned an invalid result count",
            )
        predictions = [
            PredictItem(pred_label=int(label), prob_ddos=float(probability))
            for label, probability in zip(labels, probabilities)
        ]
        return PredictResponse(predictions=predictions)

    return application


app = create_app()
