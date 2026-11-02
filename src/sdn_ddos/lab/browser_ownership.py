"""Bind GUI runs to an authenticated page connection, never to observer streams."""

from __future__ import annotations

import asyncio
import contextlib
import threading
from typing import Union
from uuid import UUID

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect

from sdn_ddos.lab.client import RunnerClient
from sdn_ddos.lab.manager import LabManager
from sdn_ddos.lab.security import Sessions


class BrowserOwnership:
    def __init__(self, control: Union[RunnerClient, LabManager], sessions: Sessions):
        self.control = control
        self.sessions = sessions
        self.owners: dict[str, str] = {}
        self.lock = threading.RLock()

    def require(self, owner: str, session: str) -> None:
        with self.lock:
            if self.owners.get(owner) != session:
                raise ValueError("browser ownership expired; reload before starting")

    def release(self, owner: str, session: str, reason: str) -> None:
        with self.lock:
            if self.owners.get(owner) != session:
                return
            del self.owners[owner]
        # If the runner cannot be reached, its five-second lease still expires.
        self.control.release_owner(owner, reason)

    def logout(self, session: str) -> None:
        with self.lock:
            owners = [owner for owner, value in self.owners.items() if value == session]
        for owner in owners:
            with contextlib.suppress(Exception):
                self.release(owner, session, "operator logged out")

    def install(self, app: FastAPI) -> None:
        @app.post("/api/owners/{owner}/release")
        def release(owner: UUID, request: Request) -> dict[str, bool]:
            self.release(
                str(owner),
                request.cookies.get("sdn_session", ""),
                "page closed or refreshed",
            )
            return {"released": True}

        @app.websocket("/api/ownership")
        async def ownership(socket: WebSocket) -> None:
            session = socket.cookies.get("sdn_session", "")
            if (
                socket.headers.get("host") not in self.sessions.hosts
                or socket.headers.get("origin") not in self.sessions.origins
                or not self.sessions.authenticated(session)
            ):
                await socket.close(code=1008)
                return
            await socket.accept()
            owner = ""
            try:
                owner = await asyncio.to_thread(self.control.create_owner)
                with self.lock:
                    self.owners[owner] = session
                if not self.sessions.authenticated(session):
                    return
                await socket.send_json({"owner_id": owner})
                while self.sessions.authenticated(session):
                    self.require(owner, session)
                    try:
                        # Native transport ping/pong stays active in hidden tabs.
                        # No application messages are accepted on this channel.
                        await asyncio.wait_for(socket.receive_text(), timeout=1)
                        break
                    except asyncio.TimeoutError:
                        await asyncio.to_thread(self.control.renew_owner, owner)
            except (WebSocketDisconnect, RuntimeError, ValueError):
                pass
            finally:
                if owner:
                    with contextlib.suppress(Exception):
                        await asyncio.shield(
                            asyncio.to_thread(
                                self.release, owner, session, "browser disconnected"
                            )
                        )
                with contextlib.suppress(RuntimeError, WebSocketDisconnect):
                    await socket.close()
