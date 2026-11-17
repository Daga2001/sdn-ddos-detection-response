"""The packet-rate rule: the comparison arm for the LLM detector.

The `lab` prompt tells the model to decide only with the flow's packet rate
(below 10 packets/s normal, 50 or more attack). Without a detector that applies
that same threshold with no model at all, a run cannot show whether the LLM adds
anything over a one-line comparison, or at what cost (Arp et al., "Dos and Don'ts
of Machine Learning in Computer Security", USENIX Security 2022, pitfall
"inappropriate baseline").

The rule answers the controller through the same `/predict` contract as the LLM,
so the controller sends it exactly the same flow samples (same per-poll budget,
same judging order, same cache) and applies the same response. It returns a hard
verdict: `prob_ddos` is 1.0 or 0.0, so it has no calibration to measure.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Optional

from sdn_ddos.detection.llm_api import PredictItem, PredictSample

# The lab prompt's attack threshold. Labeled lab data: legitimate flows peaked at
# 3.6 packets/s and attack flows started at 95 packets/s (llm_api.LAB_PROMPT_TEMPLATE).
DEFAULT_RULE_PKTRATE = 50.0
MAX_RULE_PKTRATE = 1_000_000.0


def rule_threshold_from_env(env: Optional[Mapping[str, str]] = None) -> float:
    """`SDN_RULE_PKTRATE`, packets per second at or above which a flow is an attack."""

    source = os.environ if env is None else env
    raw = source.get("SDN_RULE_PKTRATE", "").strip()
    if not raw:
        return DEFAULT_RULE_PKTRATE
    try:
        value = float(raw)
    except ValueError as error:
        raise ValueError(f"SDN_RULE_PKTRATE is not a number: {raw!r}") from error
    if not 0 < value <= MAX_RULE_PKTRATE:
        raise ValueError(
            f"SDN_RULE_PKTRATE must be above 0 and at most {MAX_RULE_PKTRATE:g}, "
            f"got {value:g}"
        )
    return value


def judge_by_rate(sample: PredictSample, threshold: float) -> PredictItem:
    """Attack when the flow's packet rate is at least `threshold` packets/s."""

    attack = sample.pktrate >= threshold
    return PredictItem(pred_label=1 if attack else 0, prob_ddos=1.0 if attack else 0.0)
