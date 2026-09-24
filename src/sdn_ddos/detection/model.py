"""Trusted model loading and prediction helpers."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Tuple

import numpy as np

from sdn_ddos.controller.core import FEATURE_ORDER


class ModelValidationError(RuntimeError):
    """Raised when a model artifact fails integrity or interface checks."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as model_file:
        for chunk in iter(lambda: model_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_verified_model(path: Path, expected_sha256: str) -> Any:
    """Load a project-owned joblib model after mandatory hash verification."""

    if not expected_sha256:
        raise ModelValidationError("a model checksum is required")
    if not path.is_file():
        raise ModelValidationError("model file does not exist")
    actual = sha256_file(path)
    if actual != expected_sha256.lower():
        raise ModelValidationError("model checksum does not match")

    # joblib uses pickle internally and can execute code during loading. The
    # checksum is therefore verified before importing and deserializing it.
    import joblib

    model = joblib.load(path)
    if not callable(getattr(model, "predict", None)):
        raise ModelValidationError("model does not implement predict")

    names = getattr(model, "feature_names_in_", None)
    if names is not None and tuple(str(name) for name in names) != FEATURE_ORDER:
        raise ModelValidationError(
            "model feature order does not match the API contract"
        )
    feature_count = getattr(model, "n_features_in_", len(FEATURE_ORDER))
    if int(feature_count) != len(FEATURE_ORDER):
        raise ModelValidationError(
            "model feature count does not match the API contract"
        )
    return model


def predict_probabilities(
    model: Any, matrix: np.ndarray[Any, Any]
) -> Tuple[np.ndarray[Any, Any], np.ndarray[Any, Any]]:
    """Return predicted labels and class-1 probabilities for a feature matrix."""

    predictions = np.asarray(model.predict(matrix))
    if not callable(getattr(model, "predict_proba", None)):
        return predictions, predictions.astype(float)

    probabilities = np.asarray(model.predict_proba(matrix))
    classes = np.asarray(getattr(model, "classes_", []))
    class_one = np.flatnonzero(classes == 1)
    if len(class_one) != 1:
        raise ModelValidationError("model classes must contain class 1 exactly once")
    if probabilities.ndim != 2 or probabilities.shape[0] != matrix.shape[0]:
        raise ModelValidationError("model returned an invalid probability matrix")
    return predictions, probabilities[:, int(class_one[0])]
