"""Best-effort local controller observations without blocking OpenFlow handlers."""

from __future__ import annotations

import json
import os
import socket
from datetime import datetime, timezone
from typing import Any


class Telemetry:
    def __init__(self) -> None:
        self.path = os.environ.get("SDN_TELEMETRY_SOCKET", "")
        self.run_id = os.environ.get("SDN_RUN_ID", "")
        self.dropped = 0
        self.socket = (
            socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) if self.path else None
        )
        if self.socket:
            self.socket.setblocking(False)

    def emit(self, kind: str, data: dict[str, Any]) -> None:
        if self.socket is None:
            return
        try:
            payload = json.dumps(
                {
                    "run_id": self.run_id,
                    "kind": kind,
                    "data": dict(
                        data, observed_at=datetime.now(timezone.utc).isoformat()
                    ),
                    "dropped": self.dropped,
                },
                default=str,
                allow_nan=False,
            ).encode()
            if len(payload) > 60000:
                self.dropped += 1
                return
            self.socket.sendto(payload, self.path)
            self.dropped = 0
        except (OSError, ValueError, TypeError):
            self.dropped += 1

    def close(self) -> None:
        if self.socket:
            self.socket.close()
