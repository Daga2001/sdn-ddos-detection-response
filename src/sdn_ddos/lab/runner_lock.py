"""One runner per database, held on a dedicated PostgreSQL session without DDL."""

from __future__ import annotations

from typing import Any

from sdn_ddos.config import DatabaseSettings


class RunnerLock:
    def __init__(self, settings: DatabaseSettings) -> None:
        self.settings = settings
        self.connection: Any = None

    def acquire(self) -> None:
        import psycopg2

        self.connection = psycopg2.connect(
            host=self.settings.host,
            port=self.settings.port,
            dbname=self.settings.database,
            user=self.settings.user,
            password=self.settings.password,
            connect_timeout=self.settings.connect_timeout_seconds,
            options="-c statement_timeout=1000",
            application_name="sdn-lab-runner-owner",
            keepalives_idle=1,
            keepalives_interval=1,
            keepalives_count=2,
            tcp_user_timeout=3000,
        )
        self.connection.autocommit = True
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_try_advisory_lock(%s, %s)", (0x53444E, 0x4C4142)
                )
                if not cursor.fetchone()[0]:
                    raise RuntimeError("another runner already owns this database")
        except BaseException:
            self.close()
            raise

    def check(self) -> None:
        if self.connection is None:
            raise RuntimeError("runner has no database ownership")
        # Do not reacquire: PostgreSQL advisory locks are reentrant.
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT 1")

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None
