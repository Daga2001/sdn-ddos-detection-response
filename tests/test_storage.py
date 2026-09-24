import sys
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from sdn_ddos.config import DatabaseSettings
from sdn_ddos.storage import (
    NullMetricsStore,
    PostgreSQLMetricsStore,
    create_metrics_store,
)


def test_disabled_database_uses_null_store() -> None:
    store = create_metrics_store(DatabaseSettings(enabled=False))
    assert isinstance(store, NullMetricsStore)
    store.add_flow_rows([{"ignored": True}])
    store.add_port_rows([{"ignored": True}])
    store.add_controller_row({"ignored": True})
    store.record_detection({"ignored": True})
    store.record_mitigation({"ignored": True})
    now = datetime.now(timezone.utc)
    store.record_attack_window(now, now, "TEST", "10.0.0.1")
    store.flush(force=True)
    store.close()


def test_gui_run_tagging_is_parameterized_and_optional():
    from uuid import uuid4

    store = PostgreSQLMetricsStore.__new__(PostgreSQLMetricsStore)
    store._run_id = str(uuid4())
    query, rows = store._tag_run(
        "INSERT INTO controller_stats (ts) VALUES (%(ts)s)", [{"ts": "now"}]
    )
    assert "(run_id, ts) VALUES (%(run_id)s, %(ts)s)" in query
    assert store._run_id not in query
    assert rows[0]["run_id"] == store._run_id
    store._run_id = None
    query, rows = store._tag_run("INSERT INTO t (ts) VALUES (%(ts)s)", [{"ts": "now"}])
    assert "run_id" not in query and "run_id" not in rows[0]


class FakeCursor:
    def __init__(self) -> None:
        self.executed = []

    def execute(self, query, values) -> None:
        self.executed.append((query, values))

    def close(self) -> None:
        return None


class FakeConnection:
    def __init__(self) -> None:
        self.autocommit = None
        self.cursors = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self):
        cursor = FakeCursor()
        self.cursors.append(cursor)
        return cursor

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


def test_postgres_store_batches_rows_and_events(monkeypatch) -> None:
    connection = FakeConnection()
    batches = []

    def execute_batch(cursor, query, rows, page_size):
        batches.append((query, rows, page_size))

    monkeypatch.setitem(
        sys.modules,
        "psycopg2",
        SimpleNamespace(connect=lambda **kwargs: connection),
    )
    monkeypatch.setitem(
        sys.modules,
        "psycopg2.extras",
        SimpleNamespace(execute_batch=execute_batch),
    )
    store = PostgreSQLMetricsStore(DatabaseSettings(enabled=True), flush_rows=100)
    store.add_flow_rows([{"flow": 1}])
    store.add_port_rows([{"port": 1}])
    store.add_controller_row({"controller": 1})
    store.flush(force=True)
    now = datetime.now(timezone.utc)
    store.record_detection({"ts": now})
    store.record_mitigation({"ts": now})
    store.record_attack_window(now, now, "TEST", "10.0.0.1")
    store.close()

    assert len(batches) == 3
    assert connection.commits == 4
    assert connection.closed is True
    assert len(connection.cursors) == 4


def test_postgres_store_keeps_rows_after_batch_failure(monkeypatch) -> None:
    connection = FakeConnection()

    def execute_batch(cursor, query, rows, page_size):
        raise RuntimeError("database unavailable")

    monkeypatch.setitem(
        sys.modules,
        "psycopg2",
        SimpleNamespace(connect=lambda **kwargs: connection),
    )
    monkeypatch.setitem(
        sys.modules,
        "psycopg2.extras",
        SimpleNamespace(execute_batch=execute_batch),
    )
    store = PostgreSQLMetricsStore(DatabaseSettings(enabled=True), flush_rows=1)
    with pytest.raises(RuntimeError, match="unavailable"):
        store.add_flow_rows([{"flow": 1}])
    assert connection.rollbacks == 1
    assert store._flow_rows == [{"flow": 1}]
