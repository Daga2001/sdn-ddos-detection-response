"""Private HTTP adapter: browser requests never choose runner URLs."""

from __future__ import annotations

from typing import Any

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

    def events(self, after: int) -> dict[str, Any]:
        return dict(self._request("GET", f"/events?after={after}"))

    def detection_options(self) -> dict[str, Any]:
        return dict(self._request("GET", "/detection"))

    def start(self, request: StartRequest) -> str:
        return str(self._request("POST", "/runs", request.model_dump())["run_id"])

    def stop(self) -> None:
        self._request("POST", "/stop")

    def diagnostic(self, request: Diagnostic) -> None:
        self._request("POST", "/diagnostic", request.model_dump())

    def capture(self, request: Capture) -> None:
        self._request("POST", "/capture", request.model_dump())
