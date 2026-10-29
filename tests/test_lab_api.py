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
    control.events.return_value = {
        "status": control.status.return_value,
        "gap": True,
        "events": [{"seq": 4, "kind": "test"}],
    }
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
        control.events.side_effect = RuntimeError("private internal failure")
        content = asyncio.run(read(dict(client.cookies)))
        assert "event: unavailable" in content
        assert "private internal" not in content
        content = asyncio.run(read({}))
        assert "event: expired" in content


def test_rejections_are_one_readable_sentence_not_a_validation_dump():
    """The workspace shows `detail` verbatim, so it must always be prose."""

    client, settings = client_for_lab()
    with client:
        client.post("/api/session", json={"token": settings.access_token})
        data = presets()[2].model_dump()
        data["hosts"].append(
            {"name": "h9", "ip": "10.0.0.9/24", "position": {"x": 0, "y": 0}}
        )
        for path, payload in (
            ("/api/runs", {"topology": data}),
            ("/api/validate", data),
            ("/api/export/miniedit", data),
            ("/api/projects", data),
        ):
            detail = client.post(path, json=payload).json()["detail"]
            assert isinstance(detail, str), path
            assert "h9 has no link yet" in detail, path
            assert "drag from" in detail.lower(), path


def test_import_failures_say_what_the_file_got_wrong():
    from sdn_ddos.lab.topology import export_miniedit

    client, settings = client_for_lab()
    with client:
        client.post("/api/session", json={"token": settings.access_token})
        miniedit = export_miniedit(presets()[2])
        miniedit["hosts"][0]["opts"]["startCommand"] = "curl http://example.invalid"
        detail = client.post("/api/import", json=miniedit).json()["detail"]
        assert "MiniEdit file" in detail and "startCommand" in detail

        broken = presets()[2].model_dump()
        broken["hosts"][1]["name"] = broken["hosts"][0]["name"]
        detail = client.post("/api/import", json=broken).json()["detail"]
        assert "used by more than one device" in detail

        detail = client.post("/api/import", json={"note": "grocery list"}).json()
        assert "does not look like a network topology" in detail["detail"]


def test_experiment_limits_name_the_field_and_the_bound():
    client, settings = client_for_lab()
    with client:
        client.post("/api/session", json={"token": settings.access_token})
        response = client.post(
            "/api/runs",
            json={
                "topology": presets()[2].model_dump(),
                "experiment": {
                    "attackers": ["h1"],
                    "victims": ["h2"],
                    "rate": 50000,
                    "confirm_isolated_lab": True,
                },
            },
        )
        assert response.status_code == 422
        assert response.json()["detail"] == (
            "Experiment · rate (packets per second): use a value at most 1000."
        )


def test_every_preset_downloads_and_imports_again_unchanged():
    client, settings = client_for_lab()
    with client:
        client.post("/api/session", json={"token": settings.access_token})
        for preset in presets():
            original = preset.model_dump()
            restored = client.post("/api/import", json=original).json()["topology"]
            assert restored == original, preset.name
            miniedit = client.post("/api/export/miniedit", json=original).json()
            restored = client.post("/api/import", json=miniedit).json()["topology"]
            assert restored == original, preset.name


def test_api_paths_never_fall_through_to_the_static_bundle(tmp_path):
    """A wrong method once reached StaticFiles and answered a bare "Not Found"."""

    (tmp_path / "index.html").write_text("<html></html>")
    repository = MemoryRepository()
    settings = LabSettings(
        access_token=secrets.token_urlsafe(32),
        runner_token=secrets.token_urlsafe(32),
        origin="http://testserver",
        static_dir=str(tmp_path),
    )
    manager = LabManager(repository, FakeRuntime)
    client = TestClient(create_app(settings, repository, manager))
    with client:
        client.post("/api/session", json={"token": settings.access_token})
        assert client.post("/api/stop").status_code == 200
        for method, path in (
            ("GET", "/api/stop"),
            ("POST", "/api/status"),
            ("GET", "/api/does-not-exist"),
        ):
            response = client.request(method, path)
            assert response.status_code == 404, (method, path)
            detail = response.json()["detail"]
            assert detail.startswith(f"{method} {path} is not an operation"), detail
            assert "Reload the workspace" in detail
        # The built web bundle is still served from the same mount.
        assert client.get("/").status_code == 200


def test_detection_options_need_a_session_and_describe_the_detector():
    class Detector:
        def config(self):
            return {"mode": "llm", "model": "llama3.2:3b", "prompts": ["lab"]}

        def models(self):
            return ["llama3.2:3b"]

        def apply(self, detection):
            return {}

    repository = MemoryRepository()
    settings = LabSettings(
        access_token=secrets.token_urlsafe(32),
        runner_token=secrets.token_urlsafe(32),
        origin="http://testserver",
    )
    manager = LabManager(repository, FakeRuntime, Detector())
    client = TestClient(create_app(settings, repository, manager))
    with client:
        assert client.get("/api/detection/options").status_code == 401
        client.post("/api/session", json={"token": settings.access_token})
        body = client.get("/api/detection/options").json()
        assert body["available"] is True and body["models"] == ["llama3.2:3b"]
    bare, creds = client_for_lab()
    with bare:
        bare.post("/api/session", json={"token": creds.access_token})
        assert bare.get("/api/detection/options").json()["available"] is False


def test_an_experiment_with_detection_is_validated_by_the_api():
    client, settings = client_for_lab()
    topology = presets()[2].model_dump()
    with client:
        client.post("/api/session", json={"token": settings.access_token})
        bad = client.post(
            "/api/runs",
            json={
                "topology": topology,
                "experiment": {
                    "attackers": ["h1"],
                    "victims": ["h2"],
                    "confirm_isolated_lab": True,
                    "detection": {"entropy": {"k": 0}},
                },
            },
        )
        assert bad.status_code == 422
        # A lab without a detector service refuses to pick one, and says so.
        refused = client.post(
            "/api/runs",
            json={
                "topology": topology,
                "experiment": {
                    "attackers": ["h1"],
                    "victims": ["h2"],
                    "confirm_isolated_lab": True,
                    "detection": {"mode": "entropy"},
                },
            },
        )
        assert refused.status_code == 409
        assert "no detector service" in refused.json()["detail"]
