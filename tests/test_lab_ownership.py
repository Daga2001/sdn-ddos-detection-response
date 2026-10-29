"""Ownership failures never launch traffic or need a real database."""

import time
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from lab_fakes import FakeRuntime, MemoryRepository

from sdn_ddos.config import DatabaseSettings
from sdn_ddos.lab.contracts import StartRequest
from sdn_ddos.lab.manager import LabManager
from sdn_ddos.lab.runner_lock import RunnerLock
from sdn_ddos.lab.topology import presets


def test_owner_release_is_scoped_and_cannot_be_revived():
    manager = LabManager(MemoryRepository(), FakeRuntime)
    owner = manager.create_owner()
    viewer = manager.create_owner()
    run = manager.start(
        StartRequest(topology=presets()[2], owner_id=owner, forwarding="per_port")
    )
    manager.release_owner(viewer)
    assert not manager.stop_event.is_set()
    manager.release_owner(owner)
    assert manager.stop_event.is_set()
    manager.close()
    assert manager.runtime.closed
    with pytest.raises(ValueError, match="expired"):
        manager.renew_owner(owner)
    with pytest.raises(ValueError, match="expired"):
        manager.start(
            StartRequest(topology=presets()[2], owner_id=owner, forwarding="per_port")
        )
    assert manager.repository.run(run)["status"] == "stopped"
    assert any(e["kind"] == "stop_requested" for e in manager.events(0)["events"])
    second = manager.create_owner()
    manager.start(
        StartRequest(topology=presets()[2], owner_id=second, forwarding="per_port")
    )
    manager.release_owner(owner)
    assert not manager.stop_event.is_set()
    manager.close()


def test_expired_owner_rejected_and_headless_run_survives(monkeypatch):
    manager = LabManager(MemoryRepository(), FakeRuntime)
    clock = [10.0]
    monkeypatch.setattr(manager.owners, "clock", lambda: clock[0])
    owner = manager.create_owner()
    clock[0] += 6
    with pytest.raises(ValueError, match="expired"):
        manager.start(
            StartRequest(topology=presets()[2], owner_id=owner, forwarding="per_port")
        )
    assert not manager.repository.runs()
    manager.start(StartRequest(topology=presets()[2], forwarding="per_port"))
    manager.expire_owners()
    assert not manager.stop_event.is_set()
    manager.close()


def test_owner_watchdog_stops_an_active_run(monkeypatch):
    manager = LabManager(MemoryRepository(), FakeRuntime)
    clock = [10.0]
    monkeypatch.setattr(manager.owners, "clock", lambda: clock[0])
    owner = manager.create_owner()
    manager.start(
        StartRequest(topology=presets()[2], owner_id=owner, forwarding="per_port")
    )
    clock[0] += 4
    manager.renew_owner(owner)
    clock[0] += 4
    manager.expire_owners()
    assert not manager.stop_event.is_set()
    clock[0] += 2
    manager.expire_owners()
    assert manager.stop_event.is_set()
    manager.close()


def test_snapshot_resets_foreign_cursor_and_clock_survives_buffer_loss():
    manager = LabManager(MemoryRepository(), FakeRuntime)
    run = manager.start(StartRequest(topology=presets()[2], forwarding="per_port"))
    try:
        time.sleep(0.02)
        page = manager.events(99999, str(uuid4()))
        assert page["status"]["run_id"] == run
        assert page["events"]
        before = manager.status()
        manager.journal._events.clear()
        after = manager.status()
        assert after["started_at"] == before["started_at"]
        assert after["elapsed_ms"] >= before["elapsed_ms"]
        assert after["runner_instance_id"] == before["runner_instance_id"]
    finally:
        manager.close()
    end = manager.status()
    assert end["ended_at"]
    time.sleep(0.01)
    assert manager.status()["elapsed_ms"] == end["elapsed_ms"]


def test_duplicate_runner_fails_before_recovery_and_releases_connection(monkeypatch):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = (False,)
    monkeypatch.setattr("psycopg2.connect", lambda **kwargs: connection)
    lock = RunnerLock(DatabaseSettings())
    with pytest.raises(RuntimeError, match="another runner"):
        lock.acquire()
    connection.close.assert_called_once()


def test_runner_lock_is_checked_without_reacquiring(monkeypatch):
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = (True,)
    monkeypatch.setattr("psycopg2.connect", lambda **kwargs: connection)
    lock = RunnerLock(DatabaseSettings())
    lock.acquire()
    lock.check()
    queries = [call.args[0] for call in cursor.execute.call_args_list]
    assert sum("pg_try_advisory_lock" in sql for sql in queries) == 1
    cursor.execute.side_effect = OSError("connection lost")
    with pytest.raises(OSError):
        lock.check()
    lock.close()
    connection.close.assert_called_once()


def test_worker_refuses_duplicate_before_recovering_any_runs(monkeypatch):
    import secrets

    from fastapi.testclient import TestClient

    from sdn_ddos.lab import worker

    monkeypatch.setenv("SDN_LAB_TOKEN", secrets.token_urlsafe(32))
    monkeypatch.setenv("SDN_RUNNER_TOKEN", secrets.token_urlsafe(32))
    manager = LabManager(MemoryRepository(), FakeRuntime)
    manager.repository.recover_runs = MagicMock()
    guard = MagicMock()
    guard.acquire.side_effect = RuntimeError("another runner owns the database")
    monkeypatch.setattr(worker, "LabManager", lambda repository: manager)
    monkeypatch.setattr(worker, "RunnerLock", lambda settings: guard)
    with (
        pytest.raises(RuntimeError, match="another runner"),
        TestClient(worker.create_app()),
    ):
        pass
    manager.repository.recover_runs.assert_not_called()


def test_lost_runner_lock_stops_and_rejects_new_work():
    manager = LabManager(MemoryRepository(), FakeRuntime)
    manager.start(StartRequest(topology=presets()[2], forwarding="per_port"))
    manager.lose_ownership()
    assert manager.stop_event.is_set()
    manager.close()
    assert manager.runtime.closed
    assert manager.status()["unavailable"]
    with pytest.raises(ValueError, match="ownership was lost"):
        manager.start(StartRequest(topology=presets()[2], forwarding="per_port"))
    with pytest.raises(ValueError, match="ownership was lost"):
        manager.create_owner()


def test_worker_watchdogs_stop_on_lock_loss_and_release_after_cleanup(monkeypatch):
    import secrets

    from fastapi.testclient import TestClient

    from sdn_ddos.lab import worker

    monkeypatch.setenv("SDN_LAB_TOKEN", secrets.token_urlsafe(32))
    monkeypatch.setenv("SDN_RUNNER_TOKEN", secrets.token_urlsafe(32))
    manager = LabManager(MemoryRepository(), FakeRuntime)
    guard = MagicMock()
    guard.check.side_effect = OSError("database disconnected")
    terminated = MagicMock()
    monkeypatch.setattr(worker, "LabManager", lambda repository: manager)
    monkeypatch.setattr(worker, "RunnerLock", lambda settings: guard)
    monkeypatch.setattr(worker.os, "kill", terminated)
    with TestClient(worker.create_app()):
        manager.start(StartRequest(topology=presets()[2], forwarding="per_port"))
        deadline = time.monotonic() + 3
        while not terminated.called:
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert manager.stop_event.is_set()
        assert manager.unavailable
    assert manager.runtime.closed
    guard.close.assert_called_once()


def test_release_before_start_and_owner_capacity_are_bounded():
    manager = LabManager(MemoryRepository(), FakeRuntime)
    owner = manager.create_owner()
    manager.release_owner(owner)
    with pytest.raises(ValueError, match="expired"):
        manager.start(
            StartRequest(topology=presets()[2], owner_id=owner, forwarding="per_port")
        )
    assert manager.runtime is None
    for _ in range(128):
        manager.create_owner()
    with pytest.raises(ValueError, match="too many"):
        manager.create_owner()
