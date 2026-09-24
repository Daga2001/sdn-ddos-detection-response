import secrets

from fastapi.testclient import TestClient
from lab_fakes import FakeRuntime, MemoryRepository

from sdn_ddos.lab.api import create_app
from sdn_ddos.lab.manager import LabManager
from sdn_ddos.lab.settings import LabSettings
from sdn_ddos.lab.topology import presets


def client_for_lab():
    repository = MemoryRepository()
    settings = LabSettings(
        access_token=secrets.token_urlsafe(32),
        runner_token=secrets.token_urlsafe(32),
        origin="http://testserver",
    )
    manager = LabManager(repository, FakeRuntime)
    return TestClient(create_app(settings, repository, manager)), settings


def test_authentication_and_origin_checks():
    client, settings = client_for_lab()
    with client:
        assert client.get("/api/presets").status_code == 401
        assert client.post("/api/session", json={"token": "bad"}).status_code == 401
        assert (
            client.post(
                "/api/session",
                json={"token": settings.access_token},
                headers={"Origin": "https://outside.invalid"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/session", json={"token": settings.access_token}
            ).status_code
            == 200
        )
        assert len(client.get("/api/presets").json()) == 4
        assert (
            client.post(
                "/api/projects",
                json=presets()[2].model_dump(),
                headers={"Origin": "https://outside.invalid"},
            ).status_code
            == 403
        )
        assert (
            client.get("/api/presets", headers={"Host": "outside.invalid"}).status_code
            == 400
        )


def test_projects_import_and_validation():
    client, settings = client_for_lab()
    with client:
        client.post("/api/session", json={"token": settings.access_token})
        data = presets()[2].model_dump()
        assert client.post("/api/projects", json=data).status_code == 200
        assert len(client.get("/api/projects").json()) == 1
        data["hosts"][0]["ip"] = "8.8.8.8/24"
        assert client.post("/api/runs", json={"topology": data}).status_code == 422
        assert (
            client.post("/api/import", json={"version": "2", "hosts": [{}]}).status_code
            == 422
        )
        assert (
            client.post("/api/import", content=b"x" * (1024 * 1024 + 1)).status_code
            == 413
        )


def test_run_stop_and_missing_history():
    client, settings = client_for_lab()
    with client:
        client.post("/api/session", json={"token": settings.access_token})
        response = client.post(
            "/api/runs", json={"topology": presets()[2].model_dump()}
        )
        assert response.status_code == 200
        identifier = response.json()["run_id"]
        assert client.get(f"/api/runs/{identifier}").status_code == 200
        assert client.post("/api/stop").status_code == 200
        assert (
            client.get("/api/runs/00000000-0000-0000-0000-000000000000").status_code
            == 404
        )
        assert client.get("/api/runs/not-a-uuid").status_code == 422


def test_import_export_history_and_session_lifecycle():
    from sdn_ddos.lab.topology import export_miniedit

    client, settings = client_for_lab()
    with client:
        assert client.get("/health").json()["status"] == "ready"
        assert not client.get("/api/session").json()["authenticated"]
        client.post("/api/session", json={"token": settings.access_token})
        topology = presets()[2].model_dump()
        assert client.post("/api/validate", json=topology).status_code == 200
        assert client.post("/api/import", json=topology).status_code == 200
        assert (
            client.post("/api/import", json=export_miniedit(presets()[2])).status_code
            == 200
        )
        assert (
            client.post("/api/export/miniedit", json=topology).json()["version"] == "2"
        )
        run_id = client.post("/api/runs", json={"topology": topology}).json()["run_id"]
        assert client.get("/api/status").status_code == 200
        assert client.post("/api/runs", json={"topology": topology}).status_code == 409
        # Control callbacks share the manager held by the closure.
        import time

        for _ in range(100):
            if client.get("/api/status").json()["state"] == "running":
                break
            time.sleep(0.01)
        assert (
            client.post(
                "/api/diagnostic", json={"action": "interfaces", "node": "h1"}
            ).status_code
            == 200
        )
        assert (
            client.post("/api/capture", json={"link_id": "link-1"}).status_code == 200
        )
        assert client.post("/api/stop").status_code == 200
        assert len(client.get("/api/runs").json()) == 1
        assert client.get(f"/api/runs/{run_id}/events").json()
        exported = client.get(f"/api/runs/{run_id}/export").json()
        assert exported["run"]["id"] == run_id
        assert exported["events"]
        assert (
            "seq,ts,kind,data"
            in client.get(f"/api/runs/{run_id}/export?format=csv").text
        )
        assert client.get(f"/api/runs/{run_id}/export?format=sh").status_code == 422
        assert client.delete("/api/session").status_code == 200
        assert client.get("/api/runs").status_code == 401


def test_sse_observations_gaps_unavailable_and_expiry(monkeypatch):
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, MagicMock

    settings = LabSettings(
        secrets.token_urlsafe(32), secrets.token_urlsafe(32), origin="http://testserver"
    )
    control = MagicMock()
    control.status.return_value = {"run_id": "record", "state": "completed"}
    control.events.return_value = {"gap": True, "events": [{"seq": 4, "kind": "test"}]}
    app = create_app(settings, MemoryRepository(), control)
    stream = next(route.endpoint for route in app.routes if route.path == "/api/events")

    async def no_wait(seconds):
        pass

    monkeypatch.setattr("sdn_ddos.lab.api.asyncio.sleep", no_wait)

    async def read(cookies):
        request = SimpleNamespace(
            cookies=cookies, is_disconnected=AsyncMock(side_effect=[False, True])
        )
        response = await stream(request)
        return "".join([part async for part in response.body_iterator])

    with TestClient(app) as client:
        client.post("/api/session", json={"token": settings.access_token})
        content = asyncio.run(read(dict(client.cookies)))
        assert "event: status" in content and "event: gap" in content
        assert "event: observation" in content
        control.status.side_effect = RuntimeError("private internal failure")
        content = asyncio.run(read(dict(client.cookies)))
        assert "event: unavailable" in content
        assert "private internal" not in content
        content = asyncio.run(read({}))
        assert "event: expired" in content
