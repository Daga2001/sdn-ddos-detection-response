"""Bounded observation buffers; browser speed never determines lab timing."""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventJournal:
    def __init__(
        self,
        run_id: str = "",
        capacity: int = 5000,
        persist: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> None:
        self.run_id = run_id
        self._events: deque[dict[str, Any]] = deque(maxlen=capacity)
        self._lock = threading.RLock()
        self._seq = 0
        self.persist = persist

    def emit(self, kind: str, data: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            event = {
                "run_id": self.run_id,
                "seq": self._seq,
                "ts": data.get("observed_at", utc_now()),
                "kind": kind,
                "data": data,
            }
            self._events.append(event)
            if self.persist:
                self.persist(event)
            return event

    def since(self, after: int, limit: int = 500) -> dict[str, Any]:
        with self._lock:
            first = self._events[0]["seq"] if self._events else 1
            return {
                "events": [event for event in self._events if event["seq"] > after][
                    :limit
                ],
                "gap": after < first - 1,
                "latest": self._seq,
            }


class RateCounters:
    def __init__(self) -> None:
        self.previous: dict[str, tuple[int, int, float]] = {}

    def observe(
        self, key: str, rx: int, tx: int, now: float
    ) -> Optional[dict[str, float]]:
        old = self.previous.get(key)
        self.previous[key] = (rx, tx, now)
        if old is None or now <= old[2] or rx < old[0] or tx < old[1]:
            return None
        return {
            "rx_bps": (rx - old[0]) * 8 / (now - old[2]),
            "tx_bps": (tx - old[1]) * 8 / (now - old[2]),
        }
