"""Best-effort local controller observations without blocking OpenFlow handlers."""

from __future__ import annotations

import json
import os
import socket
from collections import deque
from datetime import datetime, timezone
from typing import Any

# What the experiment's results are scored from. Losing a bulk `flows` table only makes
# a chart sparser; losing one of these makes a detected attacker look undetected.
CRITICAL_KINDS = frozenset({"detection", "mitigation_requested"})
PENDING_LIMIT = 256
BUFFER_BYTES = 16 * 1024 * 1024
# Linux option numbers; Python's socket module does not export the *FORCE ones.
FORCE_OPTIONS = {socket.SO_SNDBUF: 32, socket.SO_RCVBUF: 33}


def grow_buffer(sock: Any, option: int, size: int = BUFFER_BYTES) -> None:
    """Ask the kernel for a bigger send/receive buffer on a datagram socket.

    A datagram socket holds only ~200 KB by default (about 25 `flows` messages), so a
    switch burst overflows it. The *FORCE variant ignores net.core.*mem_max but needs
    CAP_NET_ADMIN; without it the plain option still raises the buffer to that cap.
    """

    for name in (FORCE_OPTIONS[option], option):
        try:
            sock.setsockopt(socket.SOL_SOCKET, name, size)
            return
        except OSError:
            continue


class Telemetry:
    def __init__(self) -> None:
        self.path = os.environ.get("SDN_TELEMETRY_SOCKET", "")
        self.run_id = os.environ.get("SDN_RUN_ID", "")
        self.dropped = 0
        # Critical events the receiver had no room for yet; resent before the next emit.
        self.pending: deque[bytes] = deque()
        self.socket = (
            socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) if self.path else None
        )
        if self.socket:
            self.socket.setblocking(False)
            grow_buffer(self.socket, socket.SO_SNDBUF)

    def _flush_pending(self) -> bool:
        """Resend held critical events in order. True when none is left waiting."""

        assert self.socket is not None
        while self.pending:
            try:
                self.socket.sendto(self.pending[0], self.path)
            except BlockingIOError:
                return False
            except OSError:
                self.dropped += 1
            self.pending.popleft()
        return True

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
            clear = self._flush_pending()
            if clear or kind not in CRITICAL_KINDS:
                self.socket.sendto(payload, self.path)
                self.dropped = 0
            else:
                self._hold(payload)
        except BlockingIOError:
            if kind in CRITICAL_KINDS:
                self._hold(payload)
            else:
                self.dropped += 1
        except (OSError, ValueError, TypeError):
            self.dropped += 1

    def _hold(self, payload: bytes) -> None:
        if len(self.pending) >= PENDING_LIMIT:
            self.pending.popleft()
            self.dropped += 1
        self.pending.append(payload)

    def close(self) -> None:
        if self.socket:
            self.socket.close()
