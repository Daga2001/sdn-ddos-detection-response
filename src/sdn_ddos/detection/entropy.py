"""Windowed entropy DDoS detector (statistical baseline).

Independent from the LLM detector on purpose: the two mechanisms are meant to
be compared, never combined. Pure Python (no Ryu/Mininet imports) so it can be
unit-tested and reused offline over datasets.

Per scope (a switch id, or one id for the whole network) and per window it
computes the entropy of the source-IP and destination-IP distributions (and,
optionally, of the destination ports and protocols), weighted by packet rate. It
keeps a learned band for each entropy and flags a window as suspicious when the
entropy leaves it. An alarm is confirmed only after `consecutive_windows`
suspicious windows in a row.

Two choices shape the detector and both can be changed per run:

* the entropy measure: Shannon (default), Renyi of any order, Tsallis, normalised
  Shannon or min-entropy (see `entropy_of`);
* the threshold model: how the band is learned from past windows. `ewma` is the
  original exponentially weighted mean and deviation; `mean` and `median` take the
  mean or the median of the last `history` windows (0 = every window of the run);
  `yu` is the improved EWMA of Yu et al. (2024). `context` decides which windows
  feed that history: only the ones that look normal, or all of them.

Two threshold models follow published detectors step by step so they can be run as
they were written (see `MarginBand` and `SecondOrderBand`): `ewma_margin` (Ding, Savi
and Siracusa, IEEE TDSC 2022: normalised entropy of the destination addresses against
an EWMA minus a margin) and `ewma2` (Zhang et al., WF-IoT 2026: normalised entropy of
the source-destination pairs against a second-order EWMA threshold). `decide` limits
which monitored distributions can raise an alarm; the others are only recorded.
"""

from __future__ import annotations

import math
import os
import statistics
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set, Tuple

MEASURES = ("shannon", "norm", "renyi", "tsallis", "min")
CENTERS = ("ewma", "mean", "median", "yu", "ewma_margin", "ewma2")
SPREADS = ("std", "mad")
CONTEXTS = ("normal", "all")
FEATURES = ("src", "dst", "dport", "proto", "pair")
# Which side of the band is an anomaly. A flood from few sources lowers the source
# entropy, spoofed sources raise it; traffic converging on a victim only lowers the
# destination entropy, and so does a concentration on few (source, destination) pairs.
SIDES = {
    "src": "both",
    "dst": "lower",
    "dport": "both",
    "proto": "both",
    "pair": "lower",
}
# Weights histogram: (weight, number of distinct values with that weight).
Histogram = Sequence[Tuple[float, int]]
MAD_TO_STD = 1.4826  # scales the median absolute deviation to a normal std
# An alarm whose window carries less than this share of the traffic it peaked at is the
# tail of a flood that was already answered: the entropy is still out of its (frozen)
# band only because almost nothing is left, and the busiest host of that little is
# usually an innocent one (a legitimate client's burst of packets in a 1 s window).
TAIL_FRACTION = 0.05
# The volume of a flood is remembered with this decay per window, so traffic that is a
# few percent of it still counts as its tail a minute later (1 s windows): the victim
# is still answering the blocked attackers and one legitimate request is enough to put
# the entropy out of its frozen band again.
PEAK_DECAY = 0.97
# With several victims the others look like heavy sources (they answer them). A
# victim receives far more than it sends and takes a large share of what the busiest
# destination takes, while an attacker sends far more than it receives.
CO_VICTIM_SHARE = 0.6
CO_VICTIM_RATIO = 1.5
TOP_ENTRIES = 5


def _distribution(
    weights: Iterable[float], counts: Optional[Iterable[int]] = None
) -> Tuple[List[Tuple[float, int]], int]:
    """Normalised (probability, multiplicity) pairs, and the distinct values."""

    count_iter = iter(counts) if counts is not None else None
    pairs: List[Tuple[float, int]] = []
    for weight in weights:
        multiplicity = next(count_iter) if count_iter is not None else 1
        if weight > 0 and multiplicity > 0:
            pairs.append((weight, multiplicity))
    total = sum(weight * multiplicity for weight, multiplicity in pairs)
    if total <= 0:
        return [], 0
    return (
        [(weight / total, multiplicity) for weight, multiplicity in pairs],
        sum(multiplicity for _, multiplicity in pairs),
    )


def entropy_of(
    weights: Iterable[float],
    measure: str = "shannon",
    order: float = 2.0,
    counts: Optional[Iterable[int]] = None,
) -> float:
    """Entropy of a weighted categorical distribution, in bits unless noted.

    shannon  -sum p log2 p
    norm     Shannon divided by log2(distinct values): 0 (one value) to 1 (uniform)
    renyi    log2(sum p^a) / (1 - a); `order` a (Shannon in the limit a -> 1). High
             orders look at the largest share, so they react to a dominant value
    tsallis  (1 - sum p^q) / (q - 1) with q = `order` (nats-like, no logarithm)
    min      -log2(max p), the limit of Renyi for a -> infinity

    `counts` gives each weight a multiplicity (a histogram), so thousands of equal
    flows need not be listed one by one.
    """

    pairs, distinct = _distribution(weights, counts)
    if measure not in MEASURES:
        raise ValueError(f"unknown entropy measure {measure!r}")
    if not pairs:
        return 0.0
    shannon = -sum(m * p * math.log2(p) for p, m in pairs)
    near_one = abs(order - 1.0) < 1e-9
    if measure == "min":
        return -math.log2(max(p for p, _ in pairs))
    if measure == "tsallis":
        if near_one:  # the limit q -> 1 is Shannon entropy in nats
            return shannon * math.log(2)
        return (1.0 - sum(m * math.pow(p, order) for p, m in pairs)) / (order - 1.0)
    if measure == "renyi" and not near_one:
        return math.log2(sum(m * math.pow(p, order) for p, m in pairs)) / (1.0 - order)
    if measure == "norm":
        return shannon / math.log2(distinct) if distinct > 1 else 0.0
    return shannon


def shannon_entropy(weights: Iterable[float]) -> float:
    """Shannon entropy (bits) of a weighted categorical distribution."""

    return entropy_of(weights, "shannon")


def entropy_panel(
    weights: Iterable[float], counts: Optional[Iterable[int]] = None
) -> Dict[str, float]:
    """The usual entropies of one distribution, side by side (for logs)."""

    values = list(weights)
    multiplicities = list(counts) if counts is not None else None
    return {
        "shannon": entropy_of(values, "shannon", counts=multiplicities),
        "norm": entropy_of(values, "norm", counts=multiplicities),
        "renyi2": entropy_of(values, "renyi", 2.0, multiplicities),
        "renyi10": entropy_of(values, "renyi", 10.0, multiplicities),
        "tsallis2": entropy_of(values, "tsallis", 2.0, multiplicities),
        "min": entropy_of(values, "min", counts=multiplicities),
        "distinct": float(_distribution(values, multiplicities)[1]),
    }


@dataclass(frozen=True)
class FlowObservation:
    """One flow seen in a window; weight is its packet rate (packets/s)."""

    src: str
    dst: str
    weight: float


PairRates = Dict[Tuple[str, str], float]


def mean_rates(polls: Iterable[Tuple[float, PairRates]]) -> PairRates:
    """Packet rate per (src, dst) over several polls of one switch.

    Each poll is (seconds covered, packet delta per pair). The rate is the total
    delta over the total time, so a window uses every poll inside it instead of
    only the last one; this smooths the one-poll noise of the entropy.
    """

    total = 0.0
    packets: Dict[Tuple[str, str], float] = defaultdict(float)
    for elapsed, deltas in polls:
        if elapsed <= 0:
            continue
        total += elapsed
        for pair, delta in deltas.items():
            packets[pair] += delta
    if total <= 0:
        return {}
    return {pair: count / total for pair, count in packets.items()}


def merge_switch_rates(
    per_switch: Mapping[int, Mapping[Tuple[str, str], float]], dedupe: bool
) -> List[FlowObservation]:
    """Flows of a whole-network window from the rates seen at each switch.

    A flow crosses several switches and each one reports it. With `dedupe` the
    flow is counted once (its highest rate); without it every report counts, so
    flows through more switches weigh more.
    """

    if dedupe:
        best: Dict[Tuple[str, str], float] = {}
        for rates in per_switch.values():
            for pair, rate in rates.items():
                if rate > best.get(pair, 0.0):
                    best[pair] = rate
        return [FlowObservation(src, dst, rate) for (src, dst), rate in best.items()]
    return [
        FlowObservation(src, dst, rate)
        for rates in per_switch.values()
        for (src, dst), rate in rates.items()
    ]


# ---------------------------------------------------------------------------
# Threshold models: each learns a band [lower, upper] around a centre from the
# entropies it is shown. `update` is called by the detector, which decides which
# windows are worth learning (see `context` and `update_hold`).
# ---------------------------------------------------------------------------


class Band:
    """A learned 'normal' band: centre +/- k * spread."""

    k: float
    min_std: float
    warmup: int
    count: int

    @property
    def ready(self) -> bool:
        return self.count >= self.warmup

    @property
    def center(self) -> float:
        raise NotImplementedError

    @property
    def spread(self) -> float:
        raise NotImplementedError

    @property
    def lower(self) -> float:
        return self.center - self.k * self.spread

    @property
    def upper(self) -> float:
        return self.center + self.k * self.spread

    def update(self, value: float, rate: float = 0.0) -> None:
        """Learn one window; `rate` is its packet rate (only some models use it)."""

        raise NotImplementedError


class AdaptiveBand(Band):
    """EWMA mean/std of a signal; the 'normal' band is mean +/- k * std."""

    def __init__(
        self,
        alpha: float,
        k: float,
        min_std: float,
        warmup: int,
        alpha_run: Optional[float] = None,
    ) -> None:
        self.alpha = alpha
        # Smoothing used once the warmup is over; a smaller value makes the band
        # follow traffic more slowly, so a flood cannot drag it along.
        self.alpha_run = alpha if alpha_run is None else alpha_run
        self.k = k
        self.min_std = min_std
        self.warmup = warmup
        self.count = 0
        self.mean = 0.0
        self._var = 0.0

    @property
    def center(self) -> float:
        return self.mean

    @property
    def spread(self) -> float:
        return self.std

    @property
    def std(self) -> float:
        return max(math.sqrt(self._var), self.min_std)

    def update(self, value: float, rate: float = 0.0) -> None:
        if self.count == 0:
            self.mean = value
        else:
            alpha = self.alpha if not self.ready else self.alpha_run
            diff = value - self.mean
            increment = alpha * diff
            self.mean += increment
            self._var = (1 - alpha) * (self._var + diff * increment)
        self.count += 1


class RollingBand(Band):
    """Centre = mean or median of the last `history` windows (0 = all of them).

    The spread is the standard deviation or the median absolute deviation (MAD,
    scaled to a normal std). With the median and the MAD, up to about half of the
    remembered windows can be anomalous before the band moves, which is why this
    model is meant to be fed every window (`context="all"`).
    """

    def __init__(
        self,
        k: float,
        min_std: float,
        warmup: int,
        center: str = "median",
        spread: str = "mad",
        history: int = 0,
    ) -> None:
        self.k = k
        self.min_std = min_std
        self.warmup = warmup
        self.center_kind = center
        self.spread_kind = spread
        self.history = history
        self.count = 0
        self._values: Deque[float] = deque(maxlen=history if history > 0 else None)
        self._stats: Optional[Tuple[float, float]] = None

    def _compute(self) -> Tuple[float, float]:
        if self._stats is None:
            values = list(self._values)
            if not values:
                self._stats = (0.0, self.min_std)
            else:
                median = statistics.median(values)
                centre = (
                    median
                    if self.center_kind == "median"
                    else sum(values) / len(values)
                )
                if self.spread_kind == "mad":
                    spread = MAD_TO_STD * statistics.median(
                        abs(v - median) for v in values
                    )
                else:
                    spread = statistics.pstdev(values)
                self._stats = (centre, max(spread, self.min_std))
        return self._stats

    @property
    def center(self) -> float:
        return self._compute()[0]

    @property
    def spread(self) -> float:
        return self._compute()[1]

    def update(self, value: float, rate: float = 0.0) -> None:
        self._values.append(value)
        self._stats = None
        self.count += 1


class YuBand(Band):
    """The improved EWMA of Yu et al. (2024), Cybersecurity 7:64.

    A prediction y_t = beta * R_(t-1) + (1 - beta) * y_(t-1) follows the entropy R;
    beta is derived from how much R moved over the last `history` windows (their
    Eq. 10: the more the entropy varied, the more it is trusted to follow it). The
    band is the mean A of the last `history` predictions plus or minus k times
    their standard deviation C. `history` defaults to 15 windows (the best value
    they report for two of their three datasets).
    """

    EPSILON = 0.1

    def __init__(self, k: float, min_std: float, warmup: int, history: int = 0) -> None:
        self.k = k
        self.min_std = min_std
        self.warmup = warmup
        self.window = history if history > 0 else 15
        self.count = 0
        self._observed: Deque[float] = deque(maxlen=self.window + 1)
        self._predicted: Deque[float] = deque(maxlen=self.window)

    def _beta(self) -> float:
        values = list(self._observed)
        steps = [abs(b - a) for a, b in zip(values, values[1:])]
        if len(steps) < 2:
            return 0.5
        high, low = max(steps), min(steps)
        if high - low < 1e-12:
            return 0.5
        total = sum((step - high) / (low - high) for step in steps)
        return min(max((total + self.EPSILON) / len(steps), 0.05), 0.95)

    @property
    def center(self) -> float:
        values = self._predicted or self._observed
        return sum(values) / len(values) if values else 0.0

    @property
    def spread(self) -> float:
        values = self._predicted or self._observed
        return max(statistics.pstdev(values) if len(values) > 1 else 0.0, self.min_std)

    def update(self, value: float, rate: float = 0.0) -> None:
        if self._observed:
            beta = self._beta()
            previous = self._predicted[-1] if self._predicted else self._observed[-1]
            self._predicted.append(beta * self._observed[-1] + (1 - beta) * previous)
        self._observed.append(value)
        if not self._predicted:
            self._predicted.append(value)
        self.count += 1


class MarginBand(Band):
    """EWMA minus a fixed margin: the threshold of Ding, Savi and Siracusa (TDSC 2022).

    Their P4DDoS detector tracks the normalised entropy H of the destination addresses
    of 1 s intervals with an EWMA, EWMA_k = alpha * H_k + (1 - alpha) * EWMA_(k-1) with
    alpha = 0.13, and raises an alarm when H_k < lambda_k. The threshold is
    lambda_(k+1) = EWMA_k - margin (margin = 0.01) and is left unchanged in an
    interval with an alarm, so an attack does not pull it down: the detector calls
    `update` only for windows that look normal (context `normal`).
    """

    def __init__(self, alpha: float, margin: float, warmup: int) -> None:
        self.alpha = alpha
        self.margin = margin
        self.k = 1.0
        self.min_std = 0.0
        self.warmup = warmup
        self.count = 0
        self.ewma = 0.0

    @property
    def center(self) -> float:
        return self.ewma

    @property
    def spread(self) -> float:
        return self.margin

    def update(self, value: float, rate: float = 0.0) -> None:
        if self.count == 0:
            self.ewma = value
        else:
            self.ewma = self.alpha * value + (1 - self.alpha) * self.ewma
        self.count += 1


class SecondOrderBand(Band):
    """Second-order EWMA threshold: Algorithm 2 of Zhang et al. (WF-IoT 2026).

    The threshold is T_n - kappa * sigma_n, from a second-order EWMA: T_n is the EWMA of
    the entropy H, T2_n the EWMA of H squared and sigma_n = sqrt(max(T2_n - T_n^2, 0)),
    both with smoothing beta (their kappa 4, beta 0.1). Three constraints go with it:

    * cold start: the first `warmup` windows are only cached; at the last one T_0 and
      T2_0 are their mean and mean of squares and the first threshold is set;
    * attack freezing: a window below the threshold changes nothing (the detector calls
      `update` only for windows that look normal);
    * adaptation and smoothing: with a packet rate above `rate_threshold` the threshold
      cannot decrease, and otherwise it falls by at most 10 % per window.
    """

    def __init__(
        self, beta: float, kappa: float, warmup: int, rate_threshold: float
    ) -> None:
        self.beta = beta
        self.k = kappa
        self.min_std = 0.0
        self.warmup = max(1, warmup)
        self.rate_threshold = rate_threshold
        self.count = 0
        self._cold: List[float] = []
        self.trend = 0.0
        self.second = 0.0
        self.threshold = 0.0

    @property
    def center(self) -> float:
        return self.trend

    @property
    def spread(self) -> float:
        return math.sqrt(max(self.second - self.trend**2, 0.0))

    @property
    def lower(self) -> float:
        return self.threshold

    def update(self, value: float, rate: float = 0.0) -> None:
        self.count += 1
        if self.count <= self.warmup:
            self._cold.append(value)
            self.trend = sum(self._cold) / len(self._cold)
            self.second = sum(x * x for x in self._cold) / len(self._cold)
            self.threshold = max(self.trend - self.k * self.spread, 0.0)
            return
        self.trend = self.beta * value + (1 - self.beta) * self.trend
        self.second = self.beta * value * value + (1 - self.beta) * self.second
        candidate = max(self.trend - self.k * self.spread, 0.0)
        if rate > self.rate_threshold:
            self.threshold = max(candidate, self.threshold)
        else:
            self.threshold = max(candidate, 0.9 * self.threshold)


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
    # Per monitored feature: {value, lower, upper, center, spread, out}; any of them
    # can be None before the band exists.
    signals: Dict[str, Dict[str, object]] = field(default_factory=dict)
    # Every usual entropy of every distribution, whatever measure decides (for logs).
    panel: Dict[str, Dict[str, float]] = field(default_factory=dict)
    top_src: Tuple[Tuple[str, float], ...] = ()
    top_dst: Tuple[Tuple[str, float], ...] = ()
    measure: str = "shannon"
    center: str = "ewma"
    # The settings this window was computed with, echoed for logs and the workspace.
    config: Dict[str, object] = field(default_factory=dict)
    # Why a confirmed alarm named nobody ("" when it did, or when it was no alarm).
    note: str = ""

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
            "signals": self.signals,
            "panel": self.panel,
            "top_src": [list(item) for item in self.top_src],
            "top_dst": [list(item) for item in self.top_dst],
            "measure": self.measure,
            "center_kind": self.center,
            "config": self.config,
            "note": self.note,
        }


@dataclass
class _DpidState:
    bands: Dict[str, Band]
    streak: int = 0
    # Entropies of recent non-suspicious windows not yet used to update the band.
    pending: List[Dict[str, float]] = field(default_factory=list)
    # Addresses that were the target of a flood, and the ones named as its attackers.
    # Once the attackers are answered, what is left is the victim's replies to them: the
    # busiest destination is then an attacker and the busiest source the victim, and
    # without this memory the victim would be named (and blocked) as the new culprit.
    victims: Set[str] = field(default_factory=set)
    named: Set[str] = field(default_factory=set)
    # The highest packet rate lately seen, fading by PEAK_DECAY per window.
    recent_peak: float = 0.0

    @property
    def src(self) -> Band:
        return self.bands["src"]

    @property
    def dst(self) -> Band:
        return self.bands["dst"]


def _top(weights: Mapping[str, float]) -> Tuple[Tuple[str, float], ...]:
    ranked = sorted(weights.items(), key=lambda item: item[1], reverse=True)
    return tuple((name, round(weight, 3)) for name, weight in ranked[:TOP_ENTRIES])


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
    # A source must hold this share of the traffic to be named, divided by the number
    # of sources sending above `candidate_min_rate`: one flooder must carry 30 %, but
    # each of seven carries ~7 % and would otherwise never be named (the alarm fired,
    # the victim was found, and nobody was accused).
    candidate_share: float = 0.3
    # A flood source sends a lot: below this packet rate a source is never a
    # candidate, so a quiet window (e.g. after the attacker was blocked) cannot
    # turn an ordinary host into one just because it holds a share of little traffic.
    candidate_min_rate: float = 20.0
    # Number of windows a normal-looking window waits before it may update the band.
    # While a flood starts, its first windows can still look normal; if the next ones
    # are suspicious they are discarded instead of being learned as the new normal.
    # 0 keeps the original behaviour (update immediately).
    update_hold: int = 0
    # Smoothing after the warmup (None = same as `alpha`).
    alpha_run: Optional[float] = None
    # Which entropy is computed (see `entropy_of`) and its order for renyi/tsallis.
    measure: str = "shannon"
    order: float = 2.0
    # How the band is learned: `center` ewma | mean | median | yu, `spread` std | mad
    # (mean/median only), over the last `history` windows (0 = the whole run).
    center: str = "ewma"
    spread: str = "std"
    history: int = 0
    # `normal` learns only windows that look normal (a flood cannot move the band),
    # `all` learns every window (the model must then be robust, e.g. the median).
    context: str = "normal"
    # Distributions monitored besides the IPs; they need the `extra` histograms of
    # `observe` (destination ports and protocols).
    features: Tuple[str, ...] = ("src", "dst")
    # The distributions allowed to raise an alarm (empty: every one of `features`); the
    # others are still computed and shown. `ewma_margin` decides on `dst`, `ewma2` on
    # `pair`.
    decide: Tuple[str, ...] = ()
    # Margin of the `ewma_margin` threshold, EWMA - margin (the paper uses 0.01).
    margin: float = 0.01
    # With a packet rate above this the `ewma2` threshold cannot decrease (800 in the
    # paper).
    rate_threshold: float = 800.0
    _states: Dict[int, _DpidState] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.measure not in MEASURES:
            raise ValueError(f"measure must be one of {MEASURES}, got {self.measure!r}")
        if self.center not in CENTERS:
            raise ValueError(f"center must be one of {CENTERS}, got {self.center!r}")
        if self.spread not in SPREADS:
            raise ValueError(f"spread must be one of {SPREADS}, got {self.spread!r}")
        if self.context not in CONTEXTS:
            raise ValueError(f"context must be one of {CONTEXTS}, got {self.context!r}")
        if self.order <= 0:
            raise ValueError("order must be positive")
        unknown = [name for name in self.features if name not in FEATURES]
        if unknown or "src" not in self.features or "dst" not in self.features:
            raise ValueError(
                "features must include src and dst and only use "
                f"{FEATURES}, got {self.features!r}"
            )
        if any(name not in self.features for name in self.decide):
            raise ValueError(
                f"decide must be a subset of features {self.features!r}, "
                f"got {self.decide!r}"
            )
        if self.margin < 0 or self.rate_threshold < 0:
            raise ValueError("margin and rate_threshold cannot be negative")

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
            candidate_min_rate=float(
                source.get("SDN_ENTROPY_CANDIDATE_MIN_RATE", "20")
            ),
            update_hold=int(source.get("SDN_ENTROPY_UPDATE_HOLD", "0")),
            alpha_run=(
                float(source["SDN_ENTROPY_ALPHA_RUN"])
                if source.get("SDN_ENTROPY_ALPHA_RUN")
                else None
            ),
            measure=source.get("SDN_ENTROPY_MEASURE", "shannon").strip().lower(),
            order=float(source.get("SDN_ENTROPY_ORDER", "2")),
            center=source.get("SDN_ENTROPY_CENTER", "ewma").strip().lower(),
            spread=source.get("SDN_ENTROPY_SPREAD", "std").strip().lower(),
            history=int(source.get("SDN_ENTROPY_HISTORY", "0")),
            context=source.get("SDN_ENTROPY_CONTEXT", "normal").strip().lower(),
            features=tuple(
                name.strip()
                for name in source.get("SDN_ENTROPY_FEATURES", "src,dst").split(",")
                if name.strip()
            ),
            decide=tuple(
                name.strip()
                for name in source.get("SDN_ENTROPY_DECIDE", "").split(",")
                if name.strip()
            ),
            margin=float(source.get("SDN_ENTROPY_MARGIN", "0.01")),
            rate_threshold=float(source.get("SDN_ENTROPY_RATE_THRESHOLD", "800")),
        )

    def _config(self) -> Dict[str, object]:
        return {
            "measure": self.measure,
            "order": self.order,
            "center": self.center,
            "spread": self.spread,
            "history": self.history,
            "context": self.context,
            "k": self.k,
            "features": list(self.features),
            "decide": list(self.decide),
            "margin": self.margin,
            "rate_threshold": self.rate_threshold,
        }

    def _floor(self) -> float:
        # min_std is in bits; normalised and Tsallis entropies live in [0, 1].
        return self.min_std / 5 if self.measure in ("norm", "tsallis") else self.min_std

    def _make_band(self) -> Band:
        floor = self._floor()
        if self.center == "ewma":
            return AdaptiveBand(
                self.alpha, self.k, floor, self.warmup_windows, self.alpha_run
            )
        if self.center == "yu":
            return YuBand(self.k, floor, self.warmup_windows, self.history)
        if self.center == "ewma_margin":
            return MarginBand(self.alpha, self.margin, self.warmup_windows)
        if self.center == "ewma2":
            # alpha is the smoothing factor beta of the paper, k its kappa.
            return SecondOrderBand(
                self.alpha, self.k, self.warmup_windows, self.rate_threshold
            )
        return RollingBand(
            self.k,
            floor,
            self.warmup_windows,
            center=self.center,
            spread=self.spread,
            history=self.history,
        )

    def _state(self, dpid: int) -> _DpidState:
        state = self._states.get(dpid)
        if state is None:
            state = _DpidState({name: self._make_band() for name in self.features})
            self._states[dpid] = state
        return state

    @staticmethod
    def _signal(
        band: Band, value: Optional[float], out: bool = False
    ) -> Dict[str, object]:
        known = band.count > 0
        return {
            "value": value,
            "lower": band.lower if known else None,
            "upper": band.upper if known else None,
            "center": band.center if known else None,
            "spread": band.spread if known else None,
            "out": out,
        }

    def observe(
        self,
        dpid: int,
        flows: Sequence[FlowObservation],
        extra: Optional[Mapping[str, Histogram]] = None,
    ) -> EntropyResult:
        state = self._state(dpid)
        total_rate = sum(flow.weight for flow in flows if flow.weight > 0)
        if total_rate < self.min_total_rate:
            state.streak = 0
            state.recent_peak *= PEAK_DECAY
            return EntropyResult(
                dpid,
                False,
                "idle",
                total_rate=total_rate,
                signals={
                    name: self._signal(band, None) for name, band in state.bands.items()
                },
                measure=self.measure,
                center=self.center,
                config=self._config(),
            )

        src_weights: Dict[str, float] = defaultdict(float)
        dst_weights: Dict[str, float] = defaultdict(float)
        pair_weights: Dict[Tuple[str, str], float] = defaultdict(float)
        for flow in flows:
            if flow.weight > 0:
                src_weights[flow.src] += flow.weight
                dst_weights[flow.dst] += flow.weight
                pair_weights[(flow.src, flow.dst)] += flow.weight
        distributions: Dict[str, Tuple[List[float], Optional[List[int]]]] = {
            "src": (list(src_weights.values()), None),
            "dst": (list(dst_weights.values()), None),
        }
        if "pair" in self.features:
            distributions["pair"] = (list(pair_weights.values()), None)
        for name in ("dport", "proto"):
            histogram = (extra or {}).get(name)
            if histogram:
                distributions[name] = (
                    [weight for weight, _ in histogram],
                    [count for _, count in histogram],
                )
        panel = {
            name: entropy_panel(weights, counts)
            for name, (weights, counts) in distributions.items()
        }
        active = [name for name in self.features if name in distributions]
        values = {
            name: entropy_of(
                distributions[name][0], self.measure, self.order, distributions[name][1]
            )
            for name in active
        }
        h_src, h_dst = values["src"], values["dst"]
        top_src, top_dst = _top(src_weights), _top(dst_weights)

        if not all(state.bands[name].ready for name in active):
            for name in active:
                state.bands[name].update(values[name], total_rate)
            return EntropyResult(
                dpid,
                False,
                "warmup",
                h_src=h_src,
                h_dst=h_dst,
                total_rate=total_rate,
                signals={
                    name: self._signal(state.bands[name], values[name])
                    for name in active
                },
                panel=panel,
                top_src=top_src,
                top_dst=top_dst,
                measure=self.measure,
                center=self.center,
                config=self._config(),
            )

        deciding = [name for name in active if not self.decide or name in self.decide]
        out = {
            name: name in deciding
            and self._outside(state.bands[name], values[name], SIDES[name])
            for name in active
        }
        suspicious = any(out.values())
        state.recent_peak = max(total_rate, state.recent_peak * PEAK_DECAY)
        signals = {
            name: self._signal(state.bands[name], values[name], out[name])
            for name in active
        }
        src_band, dst_band = state.bands["src"], state.bands["dst"]
        bounds = {
            "src_lower": src_band.lower,
            "src_upper": src_band.upper,
            "dst_lower": dst_band.lower,
        }
        if self.context == "all":
            # Every window is learned: the model itself has to resist the outliers.
            state.streak = state.streak + 1 if suspicious else 0
            for name in active:
                state.bands[name].update(values[name], total_rate)
        elif suspicious:
            state.streak += 1
            state.pending.clear()
        else:
            state.streak = 0
            state.pending.append(values)
            while len(state.pending) > self.update_hold:
                old = state.pending.pop(0)
                for name in active:
                    if name in old:
                        state.bands[name].update(old[name], total_rate)

        confirmed = suspicious and state.streak >= self.consecutive_windows
        target_dst: Optional[str] = None
        candidates: Tuple[str, ...] = ()
        note = ""
        if confirmed:
            target_dst = max(dst_weights, key=lambda key: dst_weights[key])
            if target_dst in state.named:
                # The busiest destination is an attacker already named: this is the tail
                # of a flood that was answered (the victim still replying to it), not a
                # new one, and nobody may be accused of it.
                note = (
                    "tail of an answered flood: the busiest destination is an attacker"
                )
            elif total_rate < TAIL_FRACTION * state.recent_peak:
                note = (
                    "tail of an answered flood: the traffic fell to "
                    f"{100 * total_rate / state.recent_peak:.1f} % of its recent peak"
                )
            else:
                victims = state.victims | {target_dst}
                victims |= {
                    ip
                    for ip, received in dst_weights.items()
                    if received >= CO_VICTIM_SHARE * dst_weights[target_dst]
                    and received >= CO_VICTIM_RATIO * src_weights.get(ip, 0.0)
                }
                heavy = [
                    ip
                    for ip, weight in src_weights.items()
                    if ip not in victims and weight >= self.candidate_min_rate
                ]
                share = self.candidate_share / max(1, len(heavy))
                candidates = tuple(
                    ip
                    for ip, weight in sorted(
                        src_weights.items(), key=lambda item: item[1], reverse=True
                    )
                    if ip not in victims
                    and weight >= self.candidate_min_rate
                    and weight / total_rate >= share
                )
                if candidates:
                    state.victims |= victims
                    state.named.update(candidates)
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
            signals=signals,
            panel=panel,
            top_src=top_src,
            top_dst=top_dst,
            measure=self.measure,
            center=self.center,
            config=self._config(),
            note=note,
            **bounds,
        )

    @staticmethod
    def _outside(band: Band, value: float, side: str) -> bool:
        if side == "lower":
            return value < band.lower
        if side == "upper":
            return value > band.upper
        return value < band.lower or value > band.upper


def window_state(result: EntropyResult) -> str:
    """idle | warmup | normal | suspicious | alarm: what a window amounted to."""

    if result.reason in ("idle", "warmup"):
        return result.reason
    if result.confirmed:
        return "alarm"
    return "suspicious" if result.suspicious else "normal"


def format_signal(name: str, signal: Mapping[str, object]) -> str:
    """A signal for a log line: `src=2.310[1.90..3.40 c=2.65]!` (`!` = outside)."""

    value = signal.get("value")
    if not isinstance(value, (int, float)):
        return f"{name}=-"
    text = f"{name}={value:.3f}"
    lower, upper, center = (
        signal.get("lower"),
        signal.get("upper"),
        signal.get("center"),
    )
    if (
        isinstance(lower, (int, float))
        and isinstance(upper, (int, float))
        and isinstance(center, (int, float))
    ):
        text += f"[{lower:.2f}..{upper:.2f} c={center:.2f}]"
    return text + ("!" if signal.get("out") else "")
