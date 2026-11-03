"""Private runner API. Never publish this port on the host."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import secrets
import signal
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from sdn_ddos.config import DatabaseSettings
from sdn_ddos.lab.contracts import Capture, Diagnostic, StartRequest
from sdn_ddos.lab.detection_settings import DetectorClient
from sdn_ddos.lab.manager import LabManager
from sdn_ddos.lab.repository import PostgreSQLRepository
from sdn_ddos.lab.runner_lock import RunnerLock
from sdn_ddos.lab.security import BodyLimit
from sdn_ddos.lab.settings import LabSettings


class Release(BaseModel):
    reason: str = Field(default="browser disconnected", max_length=100)


def create_app() -> FastAPI:
    settings = LabSettings.from_env()
    manager = LabManager(PostgreSQLRepository(DatabaseSettings.from_env()))
    # None when the lab has no detector service (the original compose files).
    manager.detector = DetectorClient.from_env()
    guard = RunnerLock(DatabaseSettings.from_env())

    async def watch_database() -> None:
        while True:
            await asyncio.sleep(1)
            try:
                await asyncio.to_thread(guard.check)
            except Exception:
                logging.getLogger(__name__).error("Runner database ownership lost")
                await asyncio.to_thread(manager.lose_ownership)
                os.kill(os.getpid(), signal.SIGTERM)
                return

    async def watch_owners() -> None:
        while True:
            await asyncio.sleep(0.25)
            await asyncio.to_thread(manager.expire_owners)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await asyncio.to_thread(guard.acquire)
        tasks: list[asyncio.Task[None]] = []
        try:
            await asyncio.to_thread(manager.repository.recover_runs)
            tasks = [
                asyncio.create_task(watch_database()),
                asyncio.create_task(watch_owners()),
            ]
            yield
        finally:
            for task in tasks:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            await asyncio.to_thread(manager.close)
            guard.close()

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
    def events(after: int = Query(default=0, ge=0), run_id: str = "") -> dict[str, Any]:
        return manager.events(after, run_id)

    @app.post("/owners")
    def create_owner() -> dict[str, str]:
        return {"owner_id": manager.create_owner()}

    @app.post("/owners/{owner}/renew")
    def renew_owner(owner: UUID) -> dict[str, bool]:
        manager.renew_owner(str(owner))
        return {"renewed": True}

    @app.post("/owners/{owner}/release")
    def release_owner(owner: UUID, payload: Release) -> dict[str, bool]:
        manager.release_owner(str(owner), payload.reason)
        return {"released": True}

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
