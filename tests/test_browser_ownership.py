import time
from uuid import uuid4

import pytest
from starlette.websockets import WebSocketDisconnect
from test_lab_api import client_for_lab

from sdn_ddos.lab.topology import presets


def wait_stopped(client):
    deadline = time.monotonic() + 3
    while client.get("/api/status").json()["state"] not in {"stopped", "idle"}:
        assert time.monotonic() < deadline
        time.sleep(0.01)


@pytest.mark.parametrize("headers", [{}, {"Origin": "https://outside.invalid"}])
def test_owner_socket_requires_same_origin_and_authentication(headers):
    client, settings = client_for_lab()
    with client:
        with (
            pytest.raises(WebSocketDisconnect),
            client.websocket_connect("/api/ownership", headers=headers),
        ):
            pass
        client.post("/api/session", json={"token": settings.access_token})
        with (
            pytest.raises(WebSocketDisconnect),
            client.websocket_connect("/api/ownership", headers=headers),
        ):
            pass


@pytest.mark.parametrize("action", ["disconnect", "release", "logout"])
def test_owned_run_stops_on_browser_departure(action):
    client, settings = client_for_lab()
    with client:
        client.post("/api/session", json={"token": settings.access_token})
        with client.websocket_connect(
            "/api/ownership", headers={"Origin": "http://testserver"}
        ) as socket:
            owner = socket.receive_json()["owner_id"]
            response = client.post(
                "/api/runs",
                json={"topology": presets()[2].model_dump(), "owner_id": owner},
            )
            assert response.status_code == 200
            if action == "release":
                assert client.post(f"/api/owners/{owner}/release").status_code == 200
            elif action == "logout":
                assert client.delete("/api/session").status_code == 200
                client.post("/api/session", json={"token": settings.access_token})
            if action != "disconnect":
                wait_stopped(client)
        wait_stopped(client)
        assert (
            client.post(
                "/api/runs",
                json={"topology": presets()[2].model_dump(), "owner_id": owner},
            ).status_code
            == 409
        )


def test_viewer_release_and_forged_owner_do_not_stop_another_run():
    client, settings = client_for_lab()
    with client:
        client.post("/api/session", json={"token": settings.access_token})
        with client.websocket_connect(
            "/api/ownership", headers={"Origin": "http://testserver"}
        ) as owner_socket:
            owner = owner_socket.receive_json()["owner_id"]
            client.post(
                "/api/runs",
                json={"topology": presets()[2].model_dump(), "owner_id": owner},
            )
            with client.websocket_connect(
                "/api/ownership", headers={"Origin": "http://testserver"}
            ) as viewer:
                viewer.receive_json()
            assert client.post(f"/api/owners/{uuid4()}/release").status_code == 200
            assert client.get("/api/status").json()["state"] in {"starting", "running"}
        wait_stopped(client)


def test_another_login_cannot_start_or_release_using_a_foreign_owner():
    client, settings = client_for_lab()
    with client:
        client.post("/api/session", json={"token": settings.access_token})
        with client.websocket_connect(
            "/api/ownership", headers={"Origin": "http://testserver"}
        ) as socket:
            owner = socket.receive_json()["owner_id"]
            body = {"topology": presets()[2].model_dump(), "owner_id": owner}
            client.post("/api/session", json={"token": settings.access_token})
            assert client.post("/api/runs", json=body).status_code == 409
            assert client.post(f"/api/owners/{owner}/release").status_code == 200
            assert client.get("/api/status").json()["state"] == "idle"
