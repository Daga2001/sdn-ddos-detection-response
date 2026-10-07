"""Per-decision log used to compare detectors (LLM vs entropy).

Kept separate from storage.py (the canonical metrics store) so the baseline
schema and code stay untouched. Inserts run on a background thread (see
async_io) so a slow or dropped database connection can never block the
controller, and a failed insert is logged and skipped.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Protocol, Tuple

from sdn_ddos.async_io import BackgroundWorker
from sdn_ddos.config import DatabaseSettings

LOGGER = logging.getLogger(__name__)


class DecisionLog(Protocol):
    def record(
        self,
        detector: str,
        verdict: bool,
        *,
        score: Optional[float] = None,
        dpid: Optional[int] = None,
        latency_ms: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None,
        ts: Optional[datetime] = None,
    ) -> None: ...

    def close(self) -> None: ...


class NullDecisionLog:
    def record(self, detector: str, verdict: bool, **_: Any) -> None:
        return None

    def close(self) -> None:
        return None


class PostgreSQLDecisionLog:
    def __init__(self, settings: DatabaseSettings) -> None:
        self._settings = settings
        self._connection: Any = None
        self._worker = BackgroundWorker("decision-writer")

    def _connect(self) -> Any:
        import psycopg2

        connection = psycopg2.connect(
            host=self._settings.host,
            port=self._settings.port,
            dbname=self._settings.database,
            user=self._settings.user,
            password=self._settings.password,
            connect_timeout=self._settings.connect_timeout_seconds,
            application_name="sdn-ddos-decisions",
        )
        connection.autocommit = True
        return connection

    def _insert(self, params: Tuple[Any, ...]) -> None:  # runs on the background thread
        try:
            if self._connection is None or self._connection.closed:
                self._connection = self._connect()
            with self._connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO detection_decisions "
                    "(ts, detector, dpid, verdict, score, latency_ms, details) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    params,
                )
        except Exception as exc:
            LOGGER.error("decision log insert failed: %s", exc)
            self._connection = None

    def record(
        self,
        detector: str,
        verdict: bool,
        *,
        score: Optional[float] = None,
        dpid: Optional[int] = None,
        latency_ms: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None,
        ts: Optional[datetime] = None,
    ) -> None:
        self._worker.submit(
            self._insert,
            (
                ts or datetime.now(timezone.utc),
                detector,
                dpid,
                verdict,
                score,
                latency_ms,
                json.dumps(details or {}),
            ),
        )

    def close(self) -> None:
        self._worker.close()
        if self._connection is not None and not self._connection.closed:
            self._connection.close()


def create_decision_log(settings: DatabaseSettings) -> DecisionLog:
    if not settings.enabled:
        return NullDecisionLog()
    return PostgreSQLDecisionLog(settings)
