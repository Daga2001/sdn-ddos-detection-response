"""Framework-independent controller logic that can be tested without Mininet."""

from __future__ import annotations

import ipaddress
from collections.abc import Hashable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

FEATURE_ORDER = (
    "packet_count",
    "byte_count",
    "pktrate",
    "byterate",
    "ip_proto",
    "l4_dst_port",
)


class FlowRateTracker:
    """Rates from counter deltas over the clock the caller passes in.

    Flow callers must pass the flow's OpenFlow age (`flow_age_seconds`), not
    the controller's clock. Port callers still pass their own sample time.
    If the age or either counter goes backwards, the rule was replaced: this
    sample is a new baseline and the rate is unknown, never negative.
    """

    def __init__(self) -> None:
        self._previous: Dict[Hashable, Tuple[int, int, float]] = {}

    def observe(
        self, key: Hashable, packet_count: int, byte_count: int, observed_at: float
    ) -> Optional[Tuple[float, float]]:
        rates, baseline = rates_from_switch_clock(
            self._previous.get(key), packet_count, byte_count, observed_at
        )
        self._previous[key] = baseline
        return rates


def flow_age_seconds(duration_sec: int, duration_nsec: int) -> float:
    """How long this rule has lived, according to the switch.

    OpenFlow reports that as `duration_sec` plus `duration_nsec`. A rate that
    divides by the controller's own clock instead makes a late reply look like
    a burst.
    """

    return float(duration_sec) + float(duration_nsec) / 1_000_000_000.0


def rates_from_switch_clock(
    previous: Optional[Tuple[int, int, float]],
    packet_count: int,
    byte_count: int,
    age_seconds: float,
) -> Tuple[Optional[Tuple[float, float]], Tuple[int, int, float]]:
    """Packet and byte rates over one flow's own age, plus the new baseline.

    The first sample, a clock that did not move, and a replaced rule (age or
    a counter went down) all return no rate. A replacement is a new flow.
    """

    baseline = (int(packet_count), int(byte_count), float(age_seconds))
    if previous is None:
        return None, baseline
    previous_packets, previous_bytes, previous_age = previous
    if (
        packet_count < previous_packets
        or byte_count < previous_bytes
        or age_seconds < previous_age
    ):
        return None, baseline
    elapsed = age_seconds - previous_age
    if elapsed <= 0:
        return None, baseline
    return (
        (
            (packet_count - previous_packets) / elapsed,
            (byte_count - previous_bytes) / elapsed,
        ),
        baseline,
    )


def observe_flow_rate(
    tracker: FlowRateTracker,
    key: Hashable,
    packet_count: int,
    byte_count: int,
    duration_sec: int,
    duration_nsec: int,
) -> Optional[Tuple[float, float]]:
    """Rate for one flow-stats reply, using only the switch's duration fields."""

    return tracker.observe(
        key,
        packet_count,
        byte_count,
        flow_age_seconds(duration_sec, duration_nsec),
    )


@dataclass(frozen=True)
class CountedFlow:
    """One flow in an entropy poll, already stripped of the controller clock."""

    key: Hashable
    source: Optional[str]
    destination: Optional[str]
    packet_count: int
    byte_count: int
    age_seconds: float
    ip_proto: int
    l4_dst_port: int


@dataclass(frozen=True)
class EntropyPoll:
    """Rates for one switch poll, ready to drop into the entropy window.

    `span_seconds` is the largest age increase among flows that kept the same
    rule: the switch's view of how long this statistics interval lasted. The
    window still wants one span per poll so it can average several polls.
    `pair_packets` and `port_packets` store rate times that span, so dividing
    by the span later returns the same per-flow rates.
    """

    span_seconds: Optional[float]
    flows: Tuple[Tuple[str, str, float], ...]
    pair_packets: Dict[Tuple[str, str], float]
    port_packets: Dict[Tuple[int, int], float]


def entropy_poll_from_switch_clock(
    previous: Mapping[Hashable, Tuple[int, int, float]],
    flows: Sequence[CountedFlow],
) -> Tuple[Dict[Hashable, Tuple[int, int, float]], EntropyPoll]:
    """Build one entropy poll from each flow's own change in age.

    The span is not `time.monotonic()`. A flow seen for the first time, or
    whose rule was replaced, contributes no rate for this poll.
    """

    baselines: Dict[Hashable, Tuple[int, int, float]] = {}
    continuing: list[Tuple[CountedFlow, float, float]] = []
    span = 0.0
    for flow in flows:
        prior = previous.get(flow.key)
        rates, baseline = rates_from_switch_clock(
            prior, flow.packet_count, flow.byte_count, flow.age_seconds
        )
        baselines[flow.key] = baseline
        if (
            rates is None
            or prior is None
            or flow.source is None
            or flow.destination is None
        ):
            continue
        packet_rate = rates[0]
        if packet_rate <= 0:
            continue
        age_delta = flow.age_seconds - prior[2]
        if age_delta > span:
            span = age_delta
        continuing.append((flow, packet_rate, age_delta))
    if not continuing or span <= 0:
        return baselines, EntropyPoll(None, (), {}, {})
    observations: list[Tuple[str, str, float]] = []
    pair_packets: Dict[Tuple[str, str], float] = {}
    port_packets: Dict[Tuple[int, int], float] = {}
    for flow, packet_rate, _age_delta in continuing:
        source = str(flow.source)
        destination = str(flow.destination)
        observations.append((source, destination, packet_rate))
        pair = (source, destination)
        pair_packets[pair] = pair_packets.get(pair, 0.0) + packet_rate * span
        port_key = (int(flow.ip_proto), int(flow.l4_dst_port))
        port_packets[port_key] = port_packets.get(port_key, 0.0) + packet_rate * span
    return baselines, EntropyPoll(span, tuple(observations), pair_packets, port_packets)


@dataclass
class BlockRegistry:
    """Prevent duplicate blocks and keep mitigation inside lab networks."""

    allowed_networks: Sequence[ipaddress.IPv4Network]
    block_seconds: int

    def __post_init__(self) -> None:
        self._expires_at: Dict[ipaddress.IPv4Address, float] = {}

    def reserve(self, source: str, now: float) -> bool:
        try:
            address = ipaddress.ip_address(source)
        except ValueError:
            return False
        if not isinstance(address, ipaddress.IPv4Address):
            return False
        if not any(address in network for network in self.allowed_networks):
            return False
        if self._expires_at.get(address, 0.0) > now:
            return False
        self._expires_at[address] = now + self.block_seconds
        return True


ICMP_PROTOCOL = 1


def build_model_sample(row: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """Build a model sample only when every required feature is available.

    ICMP has no transport ports, so its flows carry no `l4_dst_port`; flow datasets
    record that as 0. Without it an ICMP flood never reached the model at all.
    """

    port = row.get("l4_dst_port")
    if port is None and row.get("ip_proto") == ICMP_PROTOCOL:
        port = 0
    values = {**row, "l4_dst_port": port}
    if any(values.get(name) is None for name in FEATURE_ORDER):
        return None
    return {
        "packet_count": int(values["packet_count"]),
        "byte_count": int(values["byte_count"]),
        "pktrate": float(values["pktrate"]),
        "byterate": float(values["byterate"]),
        "ip_proto": int(values["ip_proto"]),
        "l4_dst_port": int(values["l4_dst_port"]),
    }


def probability_is_attack(value: Any, threshold: float) -> bool:
    """Validate a probability before applying the configured threshold."""

    try:
        probability = float(value)
    except (TypeError, ValueError):
        return False
    return 0.0 <= probability <= 1.0 and probability >= threshold
