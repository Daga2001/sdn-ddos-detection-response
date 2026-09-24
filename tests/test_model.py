import hashlib
import sys
from types import SimpleNamespace

import numpy as np
import pytest

from sdn_ddos.controller.core import FEATURE_ORDER
from sdn_ddos.detection.model import (
    ModelValidationError,
    load_verified_model,
    predict_probabilities,
    sha256_file,
)


class FakeModel:
    feature_names_in_ = np.asarray(FEATURE_ORDER)
    n_features_in_ = len(FEATURE_ORDER)
    classes_ = np.asarray([0, 1])

    def predict(self, matrix: np.ndarray) -> np.ndarray:
        return np.asarray([1] * len(matrix))

    def predict_proba(self, matrix: np.ndarray) -> np.ndarray:
        return np.asarray([[0.2, 0.8]] * len(matrix))


def test_sha256_file_and_verified_load(tmp_path, monkeypatch) -> None:
    model_path = tmp_path / "model.joblib"
    model_path.write_bytes(b"trusted-test-model")
    expected = hashlib.sha256(b"trusted-test-model").hexdigest()
    model = FakeModel()
    monkeypatch.setitem(sys.modules, "joblib", SimpleNamespace(load=lambda path: model))

    assert sha256_file(model_path) == expected
    assert load_verified_model(model_path, expected) is model


def test_verified_load_rejects_checksum_before_deserialization(tmp_path) -> None:
    model_path = tmp_path / "model.joblib"
    model_path.write_bytes(b"unexpected")
    with pytest.raises(ModelValidationError, match="checksum"):
        load_verified_model(model_path, "0" * 64)


def test_predict_probabilities_selects_class_one() -> None:
    matrix = np.zeros((2, len(FEATURE_ORDER)))
    labels, probabilities = predict_probabilities(FakeModel(), matrix)
    assert labels.tolist() == [1, 1]
    assert probabilities.tolist() == [0.8, 0.8]


def test_predict_probabilities_supports_models_without_probability() -> None:
    model = SimpleNamespace(predict=lambda matrix: np.asarray([0, 1]))
    labels, probabilities = predict_probabilities(
        model, np.zeros((2, len(FEATURE_ORDER)))
    )
    assert labels.tolist() == [0, 1]
    assert probabilities.tolist() == [0.0, 1.0]
