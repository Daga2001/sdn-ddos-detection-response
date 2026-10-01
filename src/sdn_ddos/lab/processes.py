"""Owned subprocess groups with bounded output and deterministic cleanup."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
from collections.abc import Callable
from typing import Any, Optional
from uuid import uuid4

from sdn_ddos.lab.events import utc_now

Emit = Callable[[str, dict[str, Any]], None]


class ManagedProcess:
    def __init__(
        self,
        command: list[str],
        node: str,
        emit: Emit,
        *,
        spawn: Any = subprocess.Popen,
        env: Optional[dict[str, str]] = None,
        line_handler: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.id = str(uuid4())
        self.node = node
        self.started_at = utc_now()
        self.ended_at: Optional[str] = None
        self.emit = emit
        self.line_handler = line_handler
        self.process = spawn(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            start_new_session=True,
            env=env,
            bufsize=0,
        )
        self.emit("command", {"id": self.id, "node": node, "argv": command})
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self) -> None:
        total = 0
        pending = ""
        try:
            while True:
                chunk = self.process.stdout.read(1024)
                if not chunk:
                    break
                text = chunk.decode("utf-8", errors="replace")
                if self.line_handler:
                    pending += text
                    while "\n" in pending:
                        line, pending = pending.split("\n", 1)
                        self.line_handler(line[:16384])
                    if len(pending) > 16384:
                        pending = ""
                        self.emit("output_truncated", {"id": self.id})
                else:
                    remaining = max(0, 16384 - total)
                    if remaining:
                        self.emit(
                            "command_output", {"id": self.id, "text": text[:remaining]}
                        )
                    if total <= 16384 < total + len(text):
                        self.emit("output_truncated", {"id": self.id})
                    total += len(text)
            if pending and self.line_handler:
                self.line_handler(pending)
            code = self.process.wait()
            self.ended_at = utc_now()
            self.emit(
                "command_exit",
                {"id": self.id, "returncode": code, "observed_at": self.ended_at},
            )
        finally:
            self.process.stdout.close()

    def wait(self, timeout: float) -> int:
        code = int(self.process.wait(timeout=timeout))
        self.reader.join(timeout=2)
        return code

    def close(self) -> None:
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
                self.process.wait(timeout=2)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                if self.process.poll() is None:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait(timeout=2)
        self.reader.join(timeout=2)
