"""Private runner API. Never publish this port on the host."""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse

from sdn_ddos.config import DatabaseSettings
from sdn_ddos.lab.contracts import Capture, Diagnostic, StartRequest
from sdn_ddos.lab.detection_settings import DetectorClient
from sdn_ddos.lab.manager import LabManager
from sdn_ddos.lab.repository import PostgreSQLRepository
from sdn_ddos.lab.security import BodyLimit
from sdn_ddos.lab.settings import LabSettings


def create_app() -> FastAPI:
    settings = LabSettings.from_env()
    manager = LabManager(PostgreSQLRepository(DatabaseSettings.from_env()))
    # None when the lab has no detector service (the original compose files).
    manager.detector = DetectorClient.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        manager.repository.recover_runs()
        yield
        manager.close()

    app = FastAPI(lifespan=lifespan)
    app.add_middleware(BodyLimit)

    @app.middleware("http")
    async def authenticate(request: Request, call_next: Any) -> Response:
        if not secrets.compare_digest(
            request.headers.get("Authorization", ""), f"Bearer {settings.runner_token}"
        ):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        response: Response = await call_next(request)
        return response

    @app.exception_handler(ValueError)
    async def invalid(request: Request, error: ValueError) -> JSONResponse:
        return JSONResponse({"detail": str(error)}, status_code=409)

    @app.get("/status")
    def status() -> dict[str, Any]:
        return manager.status()

    @app.get("/events")
    def events(after: int = Query(default=0, ge=0)) -> dict[str, Any]:
        return manager.events(after)

    @app.get("/detection")
    def detection() -> dict[str, Any]:
        return manager.detection_options()

    @app.post("/runs")
    def start(request: StartRequest) -> dict[str, str]:
        return {"run_id": manager.start(request)}

    @app.post("/stop")
    def stop() -> dict[str, bool]:
        manager.stop()
        return {"stopping": True}

    @app.post("/diagnostic")
    def diagnostic(request: Diagnostic) -> dict[str, bool]:
        manager.diagnostic(request)
        return {"accepted": True}

    @app.post("/capture")
    def capture(request: Capture) -> dict[str, bool]:
        manager.capture(request)
        return {"accepted": True}

    return app
