"""Unprivileged web application and same-origin API for the lab workspace."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional, Union
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError

from sdn_ddos.config import DatabaseSettings
from sdn_ddos.lab.browser_ownership import BrowserOwnership
from sdn_ddos.lab.client import RunnerClient
from sdn_ddos.lab.contracts import (
    FORWARDING_MESSAGE,
    Capture,
    Diagnostic,
    StartRequest,
)
from sdn_ddos.lab.explain import describe, describe_exception
from sdn_ddos.lab.manager import LabManager
from sdn_ddos.lab.repository import PostgreSQLRepository, Repository
from sdn_ddos.lab.security import BodyLimit, Sessions
from sdn_ddos.lab.settings import LabSettings
from sdn_ddos.lab.topology import Topology, export_miniedit, import_miniedit, presets

LOGGER = logging.getLogger(__name__)


def _rejection(errors: list[dict[str, Any]]) -> str:
    if any("forwarding" in (error.get("loc") or ()) for error in errors):
        return FORWARDING_MESSAGE
    return describe(errors)


class Login(BaseModel):
    token: str = Field(max_length=256)


def create_app(
    settings: Optional[LabSettings] = None,
    repository: Optional[Repository] = None,
    runner: Optional[Union[RunnerClient, LabManager]] = None,
) -> FastAPI:
    settings = settings or LabSettings.from_env()
    repository = repository or PostgreSQLRepository(DatabaseSettings.from_env())
    runner = runner or RunnerClient(settings.runner_url, settings.runner_token)
    store, control = repository, runner
    sessions = Sessions(settings.access_token, settings.origin)
    ownership = BrowserOwnership(control, sessions)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        if isinstance(control, LabManager):
            control.close()

    app = FastAPI(title="SDN Lab Workspace", lifespan=lifespan)
    ownership.install(app)
    app.add_middleware(BodyLimit)

    @app.middleware("http")
    async def protect(request: Request, call_next: Any) -> Response:
        if request.headers.get("host") not in sessions.hosts:
            return JSONResponse({"detail": "invalid host"}, status_code=400)
        origin = request.headers.get("origin")
        if origin and origin not in sessions.origins:
            return JSONResponse({"detail": "invalid origin"}, status_code=403)
        if (
            request.url.path.startswith("/api/")
            and request.url.path != "/api/session"
            and not sessions.authenticated(request.cookies.get("sdn_session"))
        ):
            return JSONResponse(
                {"detail": "sign in with your local access token"}, status_code=401
            )
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "font-src 'self'; connect-src 'self'; frame-ancestors 'none'"
        )
        return response

    @app.exception_handler(RequestValidationError)
    async def malformed(
        request: Request, error: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            {"detail": _rejection(list(error.errors()))}, status_code=422
        )

    @app.exception_handler(ValueError)
    async def invalid(request: Request, error: ValueError) -> JSONResponse:
        detail = (
            describe(error.errors())
            if isinstance(error, ValidationError)
            else str(error)
        )
        return JSONResponse({"detail": detail}, status_code=409)

    @app.exception_handler(Exception)
    async def unavailable(request: Request, error: Exception) -> JSONResponse:
        LOGGER.error("Lab request failed", exc_info=error)
        return JSONResponse(
            {
                "detail": "A lab service is unavailable. Check service status "
                "and the explicit database migration."
            },
            status_code=503,
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ready"}

    @app.get("/api/session")
    def session(request: Request) -> dict[str, bool]:
        return {
            "authenticated": sessions.authenticated(request.cookies.get("sdn_session"))
        }

    @app.post("/api/session")
    def login(payload: Login, response: Response) -> dict[str, bool]:
        try:
            token = sessions.login(payload.token)
        except PermissionError:
            raise HTTPException(401, "invalid access token") from None
        except ValueError:
            raise HTTPException(429, "too many attempts; wait a minute") from None
        response.set_cookie(
            "sdn_session", token, httponly=True, samesite="strict", max_age=8 * 3600
        )
        return {"authenticated": True}

    @app.delete("/api/session")
    def logout(request: Request, response: Response) -> dict[str, bool]:
        ownership.logout(request.cookies.get("sdn_session", ""))
        sessions.tokens.pop(request.cookies.get("sdn_session", ""), None)
        response.delete_cookie("sdn_session")
        return {"authenticated": False}

    @app.get("/api/presets")
    def list_presets() -> list[Topology]:
        return presets()

    @app.post("/api/validate")
    def validate(topology: Topology) -> Topology:
        topology.validate_targets()
        return topology

    @app.post("/api/import")
    def import_topology(payload: dict[str, Any]) -> dict[str, Any]:
        miniedit = str(payload.get("version")) == "2"
        if not miniedit and not {"hosts", "switches", "links"} & set(payload):
            raise HTTPException(
                422,
                "This file does not look like a network topology. Export one with "
                "the Download button in this workspace, or save a MiniEdit v2 file.",
            )
        try:
            if miniedit:
                topology, warnings = import_miniedit(payload)
            else:
                topology, warnings = Topology.model_validate(payload), []
            topology.validate_targets()
            return {"topology": topology.model_dump(), "warnings": warnings}
        except (ValueError, TypeError, KeyError, AttributeError, IndexError) as error:
            reason = (
                describe(error.errors())
                if isinstance(error, ValidationError)
                else describe_exception(error) + "."
            )
            source = "MiniEdit file" if miniedit else "topology file"
            raise HTTPException(
                422,
                f"This {source} could not be imported. {reason} "
                "The workspace reads its own project JSON and MiniEdit v2 files "
                "that use plain hosts, OVS switches, and links.",
            ) from None

    @app.post("/api/export/miniedit")
    def miniedit(topology: Topology) -> dict[str, Any]:
        return export_miniedit(topology)

    @app.get("/api/projects")
    def list_projects() -> list[dict[str, Any]]:
        return store.projects()

    @app.post("/api/projects")
    def save_project(topology: Topology) -> dict[str, str]:
        return {"id": store.save_project(topology.model_dump())}

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        return control.status()

    @app.get("/api/detection/options")
    def detection_options() -> dict[str, Any]:
        return control.detection_options()

    @app.post("/api/runs")
    def start(payload: StartRequest, request: Request) -> dict[str, str]:
        if payload.owner_id is not None:
            ownership.require(
                str(payload.owner_id), request.cookies.get("sdn_session", "")
            )
        return {"run_id": control.start(payload)}

    @app.post("/api/stop")
    def stop() -> dict[str, bool]:
        control.stop()
        return {"stopping": True}

    @app.post("/api/diagnostic")
    def diagnostic(payload: Diagnostic) -> dict[str, bool]:
        control.diagnostic(payload)
        return {"accepted": True}

    @app.post("/api/capture")
    def capture(payload: Capture) -> dict[str, bool]:
        control.capture(payload)
        return {"accepted": True}

    @app.get("/api/events")
    async def stream(request: Request) -> StreamingResponse:
        async def generate() -> AsyncIterator[str]:
            after = 0
            run_id = ""
            while not await request.is_disconnected():
                if not sessions.authenticated(request.cookies.get("sdn_session")):
                    yield "event: expired\ndata: {}\n\n"
                    return
                try:
                    page = await asyncio.to_thread(control.events, after, run_id)
                    state = page["status"]
                    if state.get("run_id") != run_id:
                        after, run_id = 0, state.get("run_id") or ""
                    yield "event: status\ndata: " + json.dumps(state) + "\n\n"
                    if page["gap"]:
                        yield (
                            'event: gap\ndata: {"message":"Live observations were '
                            'skipped; open run history for recorded events."}\n\n'
                        )
                    for event in page["events"]:
                        yield "event: observation\ndata: " + json.dumps(event) + "\n\n"
                        after = event["seq"]
                except Exception:
                    yield (
                        'event: unavailable\ndata: {"message":"Observation connection '
                        'lost. Measurements may be stale."}\n\n'
                    )
                await asyncio.sleep(0.5)

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={"X-Accel-Buffering": "no"},
        )

    @app.get("/api/runs")
    def runs() -> list[dict[str, Any]]:
        return store.runs()

    @app.get("/api/runs/{run_id}")
    def run(run_id: UUID) -> dict[str, Any]:
        result = store.run(str(run_id))
        if result is None:
            raise HTTPException(404, "run not found")
        return result

    @app.get("/api/runs/{run_id}/events")
    def history(
        run_id: UUID, after: int = Query(default=0, ge=0)
    ) -> list[dict[str, Any]]:
        return store.events(str(run_id), after)

    @app.get("/api/runs/{run_id}/export")
    def export_run(
        run_id: UUID, format: str = Query(default="json", pattern="^(json|csv)$")
    ) -> StreamingResponse:
        result = run(run_id)

        def records() -> Any:
            cursor = 0
            while True:
                events = store.events(str(run_id), cursor)
                if not events:
                    break
                for event in events:
                    cursor = event["seq"]
                    yield event

        def content() -> Any:
            if format == "json":
                yield '{"run":' + json.dumps(result, default=str) + ',"events":['
                separator = ""
                for event in records():
                    yield separator + json.dumps(event, default=str)
                    separator = ","
                yield "]}"
            else:
                yield "seq,ts,kind,data\r\n"
                for event in records():
                    buffer = io.StringIO()
                    csv.writer(buffer).writerow(
                        [
                            event["seq"],
                            event["ts"],
                            event["kind"],
                            json.dumps(event["data"]),
                        ]
                    )
                    yield buffer.getvalue()

        return StreamingResponse(
            content(),
            media_type="application/json" if format == "json" else "text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="run-{run_id}.{format}"'
            },
        )

    # Registered after every API route and before the static files. Without it
    # a wrong method or a stale path is matched by the StaticFiles mount below
    # and answered with a bare "Not Found" that explains nothing.
    @app.api_route(
        "/api/{rest:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        include_in_schema=False,
    )
    def unknown_operation(rest: str, request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "detail": (
                    f"{request.method} /api/{rest} is not an operation this lab "
                    "provides. Reload the workspace; if this keeps happening, the "
                    "page and the lab service are running different versions."
                )
            },
            status_code=404,
        )

    static = Path(settings.static_dir)
    if static.is_dir():
        app.mount("/", StaticFiles(directory=str(static), html=True), name="web")
    return app
