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
    """Calculate non-negative rates from monotonically increasing counters."""

    def __init__(self) -> None:
        self._previous: Dict[Hashable, Tuple[int, int, float]] = {}

    def observe(
        self, key: Hashable, packet_count: int, byte_count: int, observed_at: float
    ) -> Optional[Tuple[float, float]]:
        previous = self._previous.get(key)
        self._previous[key] = (packet_count, byte_count, observed_at)
        if previous is None:
            return None
        previous_packets, previous_bytes, previous_at = previous
        elapsed = observed_at - previous_at
        if elapsed <= 0:
            return None
        # OpenFlow counters reset when a rule is replaced; a reset is a new
        # baseline rather than a negative traffic rate.
        packet_delta = max(0, packet_count - previous_packets)
        byte_delta = max(0, byte_count - previous_bytes)
        return packet_delta / elapsed, byte_delta / elapsed


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


def build_model_sample(row: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """Build a model sample only when every required feature is available."""

    if any(row.get(name) is None for name in FEATURE_ORDER):
        return None
    return {
        "packet_count": int(row["packet_count"]),
        "byte_count": int(row["byte_count"]),
        "pktrate": float(row["pktrate"]),
        "byterate": float(row["byterate"]),
        "ip_proto": int(row["ip_proto"]),
        "l4_dst_port": int(row["l4_dst_port"]),
    }


def probability_is_attack(value: Any, threshold: float) -> bool:
    """Validate a probability before applying the configured threshold."""

    try:
        probability = float(value)
    except (TypeError, ValueError):
        return False
    return 0.0 <= probability <= 1.0 and probability >= threshold
