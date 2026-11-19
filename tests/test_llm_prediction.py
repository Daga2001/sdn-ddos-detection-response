"""A verdict of "not DDoS" never ends up as an attack (found offline, campaign R7)."""

import json
from typing import Any, List

import pytest
import requests
from pydantic import ValidationError

from sdn_ddos.controller.core import probability_is_attack
from sdn_ddos.detection.llm_api import (
    NEGATIVE_PROB_CAP,
    OllamaSettings,
    PredictSample,
    judge_sample,
    to_prediction,
)

THRESHOLD = 0.8  # SDN_DDOS_THRESHOLD of the lab
SAMPLE = PredictSample(
    packet_count=10,
    byte_count=1004,
    pktrate=0.5,
    byterate=50.6,
    ip_proto=6,
    l4_dst_port=0,
)


def flagged(is_ddos: bool, confidence: float, threshold: float = THRESHOLD) -> bool:
    return probability_is_attack(
        to_prediction(is_ddos, confidence).prob_ddos, threshold
    )


def test_a_negative_answer_with_no_confidence_is_half_and_is_not_flagged() -> None:
    # The offline probe: {"is_ddos": false, "confidence": 0.0} became prob_ddos 1.0.
    item = to_prediction(False, 0.0)
    assert item.pred_label == 0 and item.prob_ddos == 0.5
    assert not flagged(False, 0.0)


def test_a_positive_answer_keeps_its_confidence() -> None:
    item = to_prediction(True, 0.98)
    assert item.pred_label == 1 and item.prob_ddos == 0.98
    assert flagged(True, 0.98)
    assert not flagged(True, 0.79)  # below the threshold, as before
    assert flagged(True, 1.0) and flagged(True, 0.8)


def test_a_confident_negative_answer_is_a_low_probability() -> None:
    item = to_prediction(False, 0.9)
    assert item.pred_label == 0 and item.prob_ddos == pytest.approx(0.1)
    assert to_prediction(False, 1.0).prob_ddos == 0.0


@pytest.mark.parametrize("confidence", [0.0, 0.1, 0.3, 0.5, 0.7, 0.95, 1.0])
def test_a_negative_answer_never_passes_a_threshold_above_one_half(
    confidence: float,
) -> None:
    prob = to_prediction(False, confidence).prob_ddos
    assert 0.0 <= prob <= NEGATIVE_PROB_CAP
    for threshold in (0.51, 0.6, 0.8, 0.9, 1.0):
        assert not probability_is_attack(prob, threshold)


def test_a_threshold_below_one_half_can_still_flag_a_doubtful_negative_answer() -> None:
    # Documented behaviour: the cap is 0.5, so a threshold of 0.3 flags a negative
    # answer whose confidence is 0.7 or less (prob 1 - confidence >= 0.3).
    assert flagged(False, 0.7, threshold=0.3)
    assert flagged(False, 0.0, threshold=0.3)
    assert not flagged(False, 0.9, threshold=0.3)
    # A threshold of exactly 0.5 equals the cap and `>=` flags it (documented edge).
    assert flagged(False, 0.0, threshold=0.5)
    assert to_prediction(False, 0.0).prob_ddos == NEGATIVE_PROB_CAP


def test_values_out_of_range_are_rejected_by_the_response_contract() -> None:
    with pytest.raises(ValidationError):
        to_prediction(True, 1.2)
    with pytest.raises(ValidationError):
        to_prediction(False, 1.5)  # min(1 - 1.5, 0.5) is negative


class Answers:
    """An Ollama that answers with a fixed text for /api/generate."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.calls: List[Any] = []

    def post(self, url: str, json: Any = None, timeout: float = 0) -> Any:
        self.calls.append(json)
        answer = self

        class Reply:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> Any:
                return {"response": answer.text}

        return Reply()


def verdict(text: str) -> Any:
    return judge_sample(SAMPLE, OllamaSettings(), Answers(text))  # type: ignore[arg-type]


def test_the_whole_path_turns_the_offline_answers_into_the_expected_prob() -> None:
    contradictory = {"comparacion": "0.50 es menor que 10", "is_ddos": False}
    item = verdict(json.dumps({**contradictory, "confidence": 0.0}))
    assert (item.pred_label, item.prob_ddos) == (0, 0.5)
    ok = verdict(
        json.dumps(
            {
                "comparacion": "1.00 es menor que 10",
                "is_ddos": False,
                "confidence": 0.95,
            }
        )
    )
    assert ok.prob_ddos == pytest.approx(0.05)
    attack = verdict(
        json.dumps(
            {
                "comparacion": "300.00 es mayor que 50",
                "is_ddos": True,
                "confidence": 0.98,
            }
        )
    )
    assert (attack.pred_label, attack.prob_ddos) == (1, 0.98)
    # The string "false" is false, not truthy, and a percentage is a fraction.
    assert verdict('{"is_ddos": "false", "confidence": 0.0}').prob_ddos == 0.5
    assert verdict('{"is_ddos": true, "confidence": 95}').prob_ddos == pytest.approx(
        0.95
    )


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "{}",
        '{"is_ddos": true}',
        '{"confidence": 0.9}',
        '{"is_ddos": "maybe", "confidence": 0.9}',
        '{"is_ddos": true, "confidence": "high"}',
        '{"is_ddos": true, "confidence": 250}',
        '{"is_ddos": true, "confidence": -0.2}',
        '{"is_ddos": true, "confidence": NaN}',
        "[]",
    ],
)
def test_a_malformed_answer_fails_safe_to_not_ddos(text: str) -> None:
    item = verdict(text)
    assert (item.pred_label, item.prob_ddos) == (0, 0.0)


def test_an_unreachable_model_fails_safe() -> None:
    class Down:
        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise requests.ConnectionError("down")

    item = judge_sample(SAMPLE, OllamaSettings(), Down())  # type: ignore[arg-type]
    assert (item.pred_label, item.prob_ddos) == (0, 0.0)
