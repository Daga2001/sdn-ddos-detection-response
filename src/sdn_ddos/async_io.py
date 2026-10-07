"""Keep blocking PostgreSQL I/O out of Ryu's cooperative event loop.

psycopg2 blocks inside C code, so a stalled or dropped database connection
freezes every greenthread of the controller (including the OpenFlow event
loop). Here the store runs in a real OS thread fed by a bounded queue: the
controller only enqueues (never blocks) and rows are dropped -- and counted --
if the database falls too far behind.
"""

from __future__ import annotations

import contextlib
import logging
from datetime import datetime
from typing import Any, Callable, Dict, List

try:  # inside Ryu threading/queue are monkey-patched; use the real ones
    from eventlet import patcher

    _threading = patcher.original("threading")
    _queue = patcher.original("queue")
except ImportError:  # unit tests / offline scripts
    import queue as _queue
    import threading as _threading

LOGGER = logging.getLogger(__name__)


class BackgroundWorker:
    """Single real thread that runs submitted callables in order."""

    def __init__(self, name: str, max_pending: int = 20000) -> None:
        self._queue: Any = _queue.Queue(maxsize=max_pending)
        self.dropped = 0
        self._thread = _threading.Thread(target=self._run, name=name, daemon=True)
        self._thread.start()

    def submit(self, function: Callable[..., Any], *args: Any) -> None:
        try:
            self._queue.put_nowait((function, args))
        except _queue.Full:
            self.dropped += 1
            if self.dropped % 1000 == 1:
                LOGGER.error(
                    "database writer is behind: %s items dropped", self.dropped
                )

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            function, args = item
            try:
                function(*args)
            except Exception as exc:
                LOGGER.error("database write failed: %s", exc)

    def close(self, timeout: float = 15.0) -> None:
        self._queue.put(None)
        self._thread.join(timeout)


class AsyncMetricsStore:
    """MetricsStore whose calls run on a background thread, reconnecting on failure."""

    def __init__(self, factory: Callable[[], Any]) -> None:
        self._factory = factory
        self._inner: Any = factory()
        self._worker = BackgroundWorker("metrics-writer")

    def _call(self, method: str, *args: Any) -> None:
        try:
            getattr(self._inner, method)(*args)
        except Exception as first_error:
            LOGGER.error(
                "metrics store %s failed (%s); reconnecting", method, first_error
            )
            with contextlib.suppress(Exception):
                self._inner.close()
            self._inner = self._factory()
            getattr(self._inner, method)(*args)

    def add_flow_rows(self, rows: List[Dict[str, Any]]) -> None:
        self._worker.submit(self._call, "add_flow_rows", rows)

    def add_port_rows(self, rows: List[Dict[str, Any]]) -> None:
        self._worker.submit(self._call, "add_port_rows", rows)

    def add_controller_row(self, row: Dict[str, Any]) -> None:
        self._worker.submit(self._call, "add_controller_row", row)

    def record_detection(self, row: Dict[str, Any]) -> None:
        self._worker.submit(self._call, "record_detection", row)

    def record_mitigation(self, row: Dict[str, Any]) -> None:
        self._worker.submit(self._call, "record_mitigation", row)

    def record_attack_window(
        self, start: datetime, end: datetime, attack_type: str, target_ip: str
    ) -> None:
        self._worker.submit(
            self._call, "record_attack_window", start, end, attack_type, target_ip
        )

    def flush(self, force: bool = False) -> None:
        self._worker.submit(self._call, "flush", force)

    def close(self) -> None:
        self._worker.submit(self._call, "close")
        self._worker.close()
