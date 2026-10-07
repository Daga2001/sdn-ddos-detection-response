"""Windowed Shannon-entropy DDoS detector (statistical baseline).

Independent from the LLM detector on purpose: the two mechanisms are meant to
be compared, never combined. Pure Python (no Ryu/Mininet imports) so it can be
unit-tested and reused offline over datasets.

Per scope (a switch id, or one id for the whole network) and per window it
computes the entropy of the source-IP and destination-IP distributions,
weighted by packet rate. It keeps an adaptive (EWMA) baseline of each
entropy and flags a window as suspicious when the entropy leaves the
learned band. An alarm is confirmed only after `consecutive_windows`
suspicious windows in a row.
"""

from __future__ import annotations

import math
import os
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple


def shannon_entropy(weights: Iterable[float]) -> float:
    """Shannon entropy (bits) of a weighted categorical distribution."""

    values = [w for w in weights if w > 0]
    total = sum(values)
    if total <= 0:
        return 0.0
    return -sum((w / total) * math.log2(w / total) for w in values)


@dataclass(frozen=True)
class FlowObservation:
    """One flow seen in a window; weight is its packet rate (packets/s)."""

    src: str
    dst: str
    weight: float


class AdaptiveBand:
    """EWMA mean/std of a signal; the 'normal' band is mean +/- k * std."""

    def __init__(self, alpha: float, k: float, min_std: float, warmup: int) -> None:
        self.alpha = alpha
        self.k = k
        self.min_std = min_std
        self.warmup = warmup
        self.count = 0
        self.mean = 0.0
        self._var = 0.0

    @property
    def ready(self) -> bool:
        return self.count >= self.warmup

    @property
    def std(self) -> float:
        return max(math.sqrt(self._var), self.min_std)

    @property
    def lower(self) -> float:
        return self.mean - self.k * self.std

    @property
    def upper(self) -> float:
        return self.mean + self.k * self.std

    def update(self, value: float) -> None:
        if self.count == 0:
            self.mean = value
        else:
            diff = value - self.mean
            increment = self.alpha * diff
            self.mean += increment
            self._var = (1 - self.alpha) * (self._var + diff * increment)
        self.count += 1


@dataclass(frozen=True)
class EntropyResult:
    dpid: int
    evaluated: bool
    reason: str
    h_src: Optional[float] = None
    h_dst: Optional[float] = None
    src_lower: Optional[float] = None
    src_upper: Optional[float] = None
    dst_lower: Optional[float] = None
    total_rate: float = 0.0
    suspicious: bool = False
    confirmed: bool = False
    consecutive: int = 0
    target_dst: Optional[str] = None
    candidates: Tuple[str, ...] = ()

    def as_details(self) -> Dict[str, object]:
        return {
            "evaluated": self.evaluated,
            "reason": self.reason,
            "h_src": self.h_src,
            "h_dst": self.h_dst,
            "src_lower": self.src_lower,
            "src_upper": self.src_upper,
            "dst_lower": self.dst_lower,
            "total_rate": self.total_rate,
            "suspicious": self.suspicious,
            "consecutive": self.consecutive,
            "target_dst": self.target_dst,
            "candidates": list(self.candidates),
        }


@dataclass
class _DpidState:
    src: AdaptiveBand
    dst: AdaptiveBand
    streak: int = 0


@dataclass
class EntropyDetector:
    """Adaptive-threshold entropy detector, one independent state per scope id.

    src entropy is checked on both sides of the band (a flood with spoofed
    sources raises it, a single-source flood lowers it); dst entropy is checked
    only for drops (traffic concentrating on one victim).
    """

    k: float = 3.0
    alpha: float = 0.2
    warmup_windows: int = 8
    consecutive_windows: int = 2
    min_total_rate: float = 20.0
    min_std: float = 0.05
    candidate_share: float = 0.3
    _states: Dict[int, _DpidState] = field(default_factory=dict)

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "EntropyDetector":
        source = os.environ if env is None else env
        return cls(
            k=float(source.get("SDN_ENTROPY_K", "3.0")),
            alpha=float(source.get("SDN_ENTROPY_ALPHA", "0.2")),
            warmup_windows=int(source.get("SDN_ENTROPY_WARMUP", "8")),
            consecutive_windows=int(source.get("SDN_ENTROPY_CONSECUTIVE", "2")),
            min_total_rate=float(source.get("SDN_ENTROPY_MIN_RATE", "20")),
            min_std=float(source.get("SDN_ENTROPY_MIN_STD", "0.05")),
            candidate_share=float(source.get("SDN_ENTROPY_CANDIDATE_SHARE", "0.3")),
        )

    def _state(self, dpid: int) -> _DpidState:
        state = self._states.get(dpid)
        if state is None:
            state = _DpidState(
                src=AdaptiveBand(self.alpha, self.k, self.min_std, self.warmup_windows),
                dst=AdaptiveBand(self.alpha, self.k, self.min_std, self.warmup_windows),
            )
            self._states[dpid] = state
        return state

    def observe(self, dpid: int, flows: Sequence[FlowObservation]) -> EntropyResult:
        state = self._state(dpid)
        total_rate = sum(flow.weight for flow in flows if flow.weight > 0)
        if total_rate < self.min_total_rate:
            state.streak = 0
            return EntropyResult(dpid, False, "idle", total_rate=total_rate)

        src_weights: Dict[str, float] = defaultdict(float)
        dst_weights: Dict[str, float] = defaultdict(float)
        for flow in flows:
            if flow.weight > 0:
                src_weights[flow.src] += flow.weight
                dst_weights[flow.dst] += flow.weight
        h_src = shannon_entropy(src_weights.values())
        h_dst = shannon_entropy(dst_weights.values())

        if not (state.src.ready and state.dst.ready):
            state.src.update(h_src)
            state.dst.update(h_dst)
            return EntropyResult(
                dpid, False, "warmup", h_src=h_src, h_dst=h_dst, total_rate=total_rate
            )

        suspicious = (
            h_src < state.src.lower
            or h_src > state.src.upper
            or h_dst < state.dst.lower
        )
        bounds = {
            "src_lower": state.src.lower,
            "src_upper": state.src.upper,
            "dst_lower": state.dst.lower,
        }
        if suspicious:
            state.streak += 1
        else:
            state.streak = 0
            state.src.update(h_src)
            state.dst.update(h_dst)

        confirmed = suspicious and state.streak >= self.consecutive_windows
        target_dst: Optional[str] = None
        candidates: Tuple[str, ...] = ()
        if confirmed:
            target_dst = max(dst_weights, key=lambda key: dst_weights[key])
            candidates = tuple(
                ip
                for ip, weight in sorted(
                    src_weights.items(), key=lambda item: item[1], reverse=True
                )
                if weight / total_rate >= self.candidate_share
            )
        return EntropyResult(
            dpid,
            True,
            "evaluated",
            h_src=h_src,
            h_dst=h_dst,
            total_rate=total_rate,
            suspicious=suspicious,
            confirmed=confirmed,
            consecutive=state.streak,
            target_dst=target_dst,
            candidates=candidates,
            **bounds,
        )
