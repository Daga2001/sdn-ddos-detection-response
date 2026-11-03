"""Explicit-schema persistence for saved projects and replayable lab runs."""

from __future__ import annotations

from typing import Any, Optional, Protocol
from uuid import uuid4

from sdn_ddos.config import DatabaseSettings


class Repository(Protocol):
    def health(self) -> bool: ...
    def recover_runs(self) -> None: ...
    def save_project(
        self, topology: dict[str, Any], project_id: Optional[str] = None
    ) -> str: ...
    def projects(self) -> list[dict[str, Any]]: ...
    def create_run(self, run: dict[str, Any]) -> None: ...
    def finish_run(self, run_id: str, status: str) -> None: ...
    def runs(self) -> list[dict[str, Any]]: ...
    def run(self, run_id: str) -> Optional[dict[str, Any]]: ...
    def append_event(self, event: dict[str, Any]) -> None: ...
    def events(
        self, run_id: str, after: int, limit: int = 500
    ) -> list[dict[str, Any]]: ...


class PostgreSQLRepository:
    """Short, independent transactions; no startup DDL and no shared connection."""

    def __init__(self, settings: DatabaseSettings) -> None:
        self.settings = settings

    def _query(
        self, sql: str, params: tuple[Any, ...] = (), fetch: bool = False
    ) -> list[dict[str, Any]]:
        import psycopg2
        from psycopg2.extras import RealDictCursor

        connection = psycopg2.connect(
            host=self.settings.host,
            port=self.settings.port,
            dbname=self.settings.database,
            user=self.settings.user,
            password=self.settings.password,
            connect_timeout=self.settings.connect_timeout_seconds,
            options="-c statement_timeout=3000",
            application_name="sdn-lab-gui",
        )
        try:
            with connection, connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(sql, params)
                return [dict(row) for row in cursor.fetchall()] if fetch else []
        finally:
            connection.close()

    def health(self) -> bool:
        self._query("SELECT id FROM lab_runs LIMIT 0", fetch=True)
        return True

    def recover_runs(self) -> None:
        self._query(
            "UPDATE lab_runs SET status='interrupted', ended_at=now() "
            "WHERE ended_at IS NULL"
        )

    def save_project(
        self, topology: dict[str, Any], project_id: Optional[str] = None
    ) -> str:
        from psycopg2.extras import Json

        identifier = project_id or str(uuid4())
        self._query(
            "INSERT INTO lab_projects (id, topology) VALUES (%s, %s) "
            "ON CONFLICT (id) DO UPDATE SET topology=EXCLUDED.topology, "
            "updated_at=now()",
            (identifier, Json(topology)),
        )
        return identifier

    def projects(self) -> list[dict[str, Any]]:
        return self._query(
            "SELECT id::text, topology, updated_at::text FROM lab_projects "
            "ORDER BY updated_at DESC LIMIT 100",
            fetch=True,
        )

    def create_run(self, run: dict[str, Any]) -> None:
        from psycopg2.extras import Json

        from sdn_ddos.lab.events import utc_now

        self._query(
            "INSERT INTO lab_runs "
            "(id, topology, settings, status, versions, started_at) "
            "VALUES (%s,%s,%s,%s,%s,%s)",
            (
                run["id"],
                Json(run["topology"]),
                Json(run.get("settings")),
                "starting",
                Json(run.get("versions", {})),
                run.get("started_at", utc_now()),
            ),
        )

    def finish_run(self, run_id: str, status: str) -> None:
        self._query(
            "UPDATE lab_runs SET status=%s, ended_at=now() WHERE id=%s",
            (status, run_id),
        )

    def runs(self) -> list[dict[str, Any]]:
        return self._query(
            "SELECT id::text, topology->>'name' AS name, status, started_at::text, "
            "ended_at::text, settings->'detection'->>'mode' AS detector_mode, "
            "settings->'detection'->>'model' AS detector_model, "
            "jsonb_array_length(settings->'attackers') AS attackers, "
            "settings->>'mitigation' AS mitigation, "
            "settings->'detection'->'response'->>'policy' AS policy, "
            "settings->'detection'->'response'->>'dry_run' AS dry_run, "
            "settings->>'forwarding' AS forwarding, "
            "settings->'detection'->'entropy'->>'match_ports' AS match_ports "
            "FROM lab_runs ORDER BY started_at DESC LIMIT 100",
            fetch=True,
        )

    def run(self, run_id: str) -> Optional[dict[str, Any]]:
        rows = self._query(
            "SELECT id::text, topology, settings, status, versions, started_at::text, "
            "ended_at::text FROM lab_runs WHERE id=%s",
            (run_id,),
            True,
        )
        return rows[0] if rows else None

    def append_event(self, event: dict[str, Any]) -> None:
        from psycopg2.extras import Json

        self._query(
            "INSERT INTO lab_events (run_id, seq, ts, kind, data) "
            "VALUES (%s,%s,%s,%s,%s) ON CONFLICT (run_id,seq) DO NOTHING",
            (
                event["run_id"],
                event["seq"],
                event["ts"],
                event["kind"],
                Json(event["data"]),
            ),
        )
        if event["kind"] == "versions":
            self._query(
                "UPDATE lab_runs SET versions=%s WHERE id=%s",
                (Json(event["data"]), event["run_id"]),
            )

    def events(self, run_id: str, after: int, limit: int = 500) -> list[dict[str, Any]]:
        return self._query(
            "SELECT run_id::text, seq, ts::text, kind, data FROM lab_events "
            "WHERE run_id=%s AND seq>%s ORDER BY seq LIMIT %s",
            (run_id, after, min(limit, 500)),
            True,
        )
