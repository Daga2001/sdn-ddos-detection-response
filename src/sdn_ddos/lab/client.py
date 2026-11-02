"""Private HTTP adapter: browser requests never choose runner URLs."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

import requests

from sdn_ddos.lab.contracts import Capture, Diagnostic, StartRequest


class RunnerClient:
    def __init__(self, url: str, token: str) -> None:
        self.url = url.rstrip("/")
        self.token = token

    def _request(self, method: str, path: str, payload: Any = None) -> Any:
        try:
            response = requests.request(
                method,
                self.url + path,
                json=payload,
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=(1, 12),
            )
            if response.status_code == 409:
                raise ValueError(
                    response.json().get("detail", "runner rejected this operation")
                )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:
            raise RuntimeError(
                "lab runner is unavailable; check its service status"
            ) from exc

    def status(self) -> dict[str, Any]:
        return dict(self._request("GET", "/status"))

    def events(self, after: int, run_id: str = "") -> dict[str, Any]:
        query = urlencode({"after": after, "run_id": run_id})
        return dict(self._request("GET", f"/events?{query}"))

    def create_owner(self) -> str:
        return str(self._request("POST", "/owners")["owner_id"])

    def renew_owner(self, owner: str) -> None:
        self._request("POST", f"/owners/{owner}/renew")

    def release_owner(self, owner: str, reason: str = "browser disconnected") -> None:
        self._request("POST", f"/owners/{owner}/release", {"reason": reason})

    def detection_options(self) -> dict[str, Any]:
        return dict(self._request("GET", "/detection"))

    def start(self, request: StartRequest) -> str:
        return str(
            self._request("POST", "/runs", request.model_dump(mode="json"))["run_id"]
        )

    def stop(self) -> None:
        self._request("POST", "/stop")

    def diagnostic(self, request: Diagnostic) -> None:
        self._request("POST", "/diagnostic", request.model_dump())

    def capture(self, request: Capture) -> None:
        self._request("POST", "/capture", request.model_dump())
