"""Request limits, local origin checks, and expiring browser sessions."""

from __future__ import annotations

import secrets
import time
from typing import Any
from urllib.parse import urlsplit

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class BodyLimit:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        data = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            data.extend(message.get("body", b""))
            if len(data) > 1024 * 1024:
                await JSONResponse(
                    {"detail": "request exceeds 1 MiB"}, status_code=413
                )(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": bytes(data), "more_body": False}

        await self.app(scope, replay, send)


class Sessions:
    def __init__(self, access_token: str, origin: str) -> None:
        self.access_token = access_token
        self.tokens: dict[str, float] = {}
        parsed = urlsplit(origin)
        self.hosts = {parsed.netloc}
        self.origins = {origin}
        if parsed.hostname in {"localhost", "127.0.0.1"}:
            port = f":{parsed.port}" if parsed.port else ""
            self.hosts.update({f"localhost{port}", f"127.0.0.1{port}"})
            self.origins.update({f"http://localhost{port}", f"http://127.0.0.1{port}"})
        self.attempts: list[float] = []

    def login(self, candidate: str) -> str:
        now = time.monotonic()
        self.attempts = [
            timestamp for timestamp in self.attempts if now - timestamp < 60
        ]
        if len(self.attempts) >= 10:
            raise ValueError("too many attempts; wait a minute")
        self.attempts.append(now)
        if not secrets.compare_digest(candidate, self.access_token):
            raise PermissionError("invalid access token")
        self.tokens = {
            token: expiry for token, expiry in self.tokens.items() if expiry > now
        }
        if len(self.tokens) >= 20:
            self.tokens.pop(next(iter(self.tokens)))
        token = secrets.token_urlsafe(32)
        self.tokens[token] = now + 8 * 3600
        return token

    def authenticated(self, token: Any) -> bool:
        return isinstance(token, str) and self.tokens.get(token, 0) > time.monotonic()
