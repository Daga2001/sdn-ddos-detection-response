from pathlib import Path

import numpy as np
from fastapi.testclient import TestClient

from sdn_ddos.config import DetectionSettings
from sdn_ddos.controller.core import FEATURE_ORDER
from sdn_ddos.detection.api import create_app


class ApiModel:
    classes_ = np.asarray([0, 1])

    def predict(self, matrix: np.ndarray) -> np.ndarray:
        return np.asarray([1] * len(matrix))

    def predict_proba(self, matrix: np.ndarray) -> np.ndarray:
        return np.asarray([[0.1, 0.9]] * len(matrix))


SAMPLE = {
    "packet_count": 20,
    "byte_count": 1000,
    "pktrate": 10.0,
    "byterate": 500.0,
    "ip_proto": 6,
    "l4_dst_port": 80,
}


def test_health_reports_not_ready_without_model() -> None:
    with TestClient(create_app(DetectionSettings(api_key="secret"))) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "not_ready"


def test_predict_requires_authentication() -> None:
    settings = DetectionSettings(
        api_key="secret", model_path=Path("test-model"), model_sha256="0" * 64
    )
    app = create_app(settings, model_loader=lambda path, checksum: ApiModel())
    with TestClient(app) as client:
        assert client.post("/predict", json={"samples": [SAMPLE]}).status_code == 401
        response = client.post(
            "/predict",
            json={"samples": [SAMPLE]},
            headers={"X-Api-Key": "secret"},
        )
    assert response.status_code == 200
    assert response.json() == {"predictions": [{"pred_label": 1, "prob_ddos": 0.9}]}


def test_predict_rejects_empty_and_extra_fields() -> None:
    settings = DetectionSettings(
        api_key="secret", model_path=Path("test-model"), model_sha256="0" * 64
    )
    app = create_app(settings, model_loader=lambda path, checksum: ApiModel())
    headers = {"X-Api-Key": "secret"}
    with TestClient(app) as client:
        empty = client.post("/predict", json={"samples": []}, headers=headers)
        invalid = client.post(
            "/predict",
            json={"samples": [{**SAMPLE, "unexpected": True}]},
            headers=headers,
        )
    assert empty.status_code == 422
    assert invalid.status_code == 422


def test_predict_returns_unavailable_when_model_validation_fails() -> None:
    settings = DetectionSettings(
        api_key="secret", model_path=Path("missing"), model_sha256="0" * 64
    )

    def fail_loader(path: Path, checksum: str):
        raise ValueError("test failure")

    with TestClient(create_app(settings, model_loader=fail_loader)) as client:
        response = client.post(
            "/predict",
            json={"samples": [SAMPLE]},
            headers={"X-Api-Key": "secret"},
        )
    assert response.status_code == 503


def test_feature_contract_has_six_ordered_values() -> None:
    assert FEATURE_ORDER == (
        "packet_count",
        "byte_count",
        "pktrate",
        "byterate",
        "ip_proto",
        "l4_dst_port",
    )
