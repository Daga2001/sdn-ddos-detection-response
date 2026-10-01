import json
import secrets
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests
from fastapi.testclient import TestClient
from lab_fakes import FakeRuntime, MemoryRepository

from sdn_ddos.config import DatabaseSettings
from sdn_ddos.lab import worker
from sdn_ddos.lab.client import RunnerClient
from sdn_ddos.lab.contracts import Capture, Diagnostic, StartRequest
from sdn_ddos.lab.manager import LabManager
from sdn_ddos.lab.repository import PostgreSQLRepository
from sdn_ddos.lab.security import Sessions
from sdn_ddos.lab.settings import LabSettings
from sdn_ddos.lab.telemetry import Telemetry
from sdn_ddos.lab.topology import presets


def test_repository_queries_are_parameterized_and_connections_close(monkeypatch):
    import psycopg2

    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchall.return_value = [{"id": "test"}]
    monkeypatch.setattr(psycopg2, "connect", lambda **kw: connection)
    repository = PostgreSQLRepository(DatabaseSettings())
    assert repository.health()
    identifier = repository.save_project({"name": "'quoted'; harmless"})
    assert identifier
    repository.projects()
    repository.create_run({"id": identifier, "topology": {}})
    repository.finish_run(identifier, "completed")
    repository.runs()
    assert repository.run(identifier) == {"id": "test"}
    repository.append_event(
        {
            "run_id": identifier,
            "seq": 1,
            "ts": "2026-01-01",
            "kind": "versions",
            "data": {"ovs": "test"},
        }
    )
    repository.events(identifier, 0, 1000)
    assert cursor.execute.call_args.args[1] == (identifier, 0, 500)
    assert connection.close.call_count == 10
    for call in cursor.execute.call_args_list:
        assert "'quoted'" not in call.args[0]
    cursor.fetchall.return_value = []
    assert repository.run(identifier) is None
    cursor.execute.side_effect = OSError("unavailable")
    with pytest.raises(OSError):
        repository.health()
    assert connection.close.call_count == 12


def test_private_client_never_accepts_a_browser_url(monkeypatch):
    response = MagicMock(status_code=200)
    response.json.return_value = {"run_id": "test"}
    request = MagicMock(return_value=response)
    monkeypatch.setattr(requests, "request", request)
    client = RunnerClient("http://runner:9001", secrets.token_urlsafe(32))
    client.status()
    client.events(0)
    assert client.start(StartRequest(topology=presets()[2])) == "test"
    client.stop()
    client.diagnostic(Diagnostic(action="interfaces", node="h1"))
    client.capture(Capture(link_id="link-1"))
    assert all(
        call.args[1].startswith("http://runner:9001/")
        for call in request.call_args_list
    )
    response.status_code = 409
    response.json.return_value = {"detail": "already running"}
    with pytest.raises(ValueError, match="already"):
        client.start(StartRequest(topology=presets()[2]))
    request.side_effect = requests.ConnectionError()
    with pytest.raises(RuntimeError, match="unavailable"):
        client.stop()


def test_sessions_expire_and_login_attempts_are_bounded(monkeypatch):
    token = secrets.token_urlsafe(32)
    sessions = Sessions(token, "http://localhost:8080")
    assert "127.0.0.1:8080" in sessions.hosts
    session = sessions.login(token)
    assert sessions.authenticated(session)
    sessions.tokens[session] = 0
    assert not sessions.authenticated(session)
    for _ in range(9):
        with pytest.raises(PermissionError):
            sessions.login("wrong")
    with pytest.raises(ValueError):
        sessions.login(token)
    with pytest.raises(ValueError):
        LabSettings("short", "short")
    monkeypatch.setenv("SDN_LAB_TOKEN", token)
    monkeypatch.setenv("SDN_RUNNER_TOKEN", token)
    assert LabSettings.from_env().access_token == token


def test_telemetry_is_optional_bounded_and_nonblocking(monkeypatch):
    monkeypatch.delenv("SDN_TELEMETRY_SOCKET", raising=False)
    disabled = Telemetry()
    disabled.emit("test", {})
    disabled.close()
    sock = MagicMock()
    monkeypatch.setenv("SDN_TELEMETRY_SOCKET", "/tmp/unused-test-socket")
    monkeypatch.setattr("sdn_ddos.lab.telemetry.socket.socket", lambda *args: sock)
    telemetry = Telemetry()
    telemetry.emit("too-large", {"text": "x" * 60000})
    assert telemetry.dropped == 1
    sock.sendto.side_effect = BlockingIOError()
    telemetry.emit("test", {})
    assert telemetry.dropped == 2
    sock.sendto.side_effect = None
    telemetry.emit("test", {})
    assert json.loads(sock.sendto.call_args.args[0])["dropped"] == 2
    assert telemetry.dropped == 0
    telemetry.emit("invalid", {"rate": float("nan")})
    assert telemetry.dropped == 1
    telemetry.close()


def test_worker_auth_and_fixed_operations(monkeypatch):
    token = secrets.token_urlsafe(32)
    monkeypatch.setenv("SDN_LAB_TOKEN", token)
    monkeypatch.setenv("SDN_RUNNER_TOKEN", token)
    manager = LabManager(MemoryRepository(), FakeRuntime)
    monkeypatch.setattr(worker, "LabManager", lambda repository: manager)
    with TestClient(worker.create_app()) as client:
        assert client.get("/status").status_code == 401
        client.headers["Authorization"] = f"Bearer {token}"
        assert client.get("/status").json()["state"] == "idle"
        assert client.get("/events?after=0").status_code == 200
        assert (
            client.post(
                "/diagnostic", json={"action": "interfaces", "node": "h1"}
            ).status_code
            == 409
        )
        assert client.post("/capture", json={"link_id": "link-1"}).status_code == 409
        assert (
            client.post(
                "/runs", json={"topology": presets()[2].model_dump()}
            ).status_code
            == 200
        )
        assert client.post("/stop").status_code == 200


def test_victim_handler_only_serves_constant_text():
    from sdn_ddos.lab.service import Handler

    handler = SimpleNamespace(
        send_response=MagicMock(),
        send_header=MagicMock(),
        end_headers=MagicMock(),
        wfile=MagicMock(),
    )
    Handler.do_GET(handler)
    handler.send_response.assert_called_once_with(200)
    assert handler.wfile.write.call_count == 1
    Handler.log_message(handler, "nothing")
