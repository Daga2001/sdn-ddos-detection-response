import ipaddress
from typing import Any, Dict, Optional

from sdn_ddos.controller.core import (
    NO_PORT,
    BlockRegistry,
    CountedFlow,
    FlowRateTracker,
    build_model_sample,
    entropy_poll_from_switch_clock,
    probability_is_attack,
)


def test_flow_rate_tracker_uses_counter_deltas() -> None:
    tracker = FlowRateTracker()
    assert tracker.observe("flow", 10, 1000, 1.0) is None
    assert tracker.observe("flow", 30, 3000, 3.0) == (10.0, 1000.0)


def test_flow_rate_tracker_treats_a_replaced_rule_as_a_new_flow() -> None:
    tracker = FlowRateTracker()
    tracker.observe("flow", 100, 1000, 1.0)
    # The counter went down, so this is a new rule, not a rate of zero.
    assert tracker.observe("flow", 1, 10, 2.0) is None
    assert tracker.observe("flow", 2, 20, 2.0) is None
    assert tracker.observe("flow", 12, 120, 3.0) == (10.0, 100.0)


def test_block_registry_restricts_and_deduplicates_sources() -> None:
    registry = BlockRegistry((ipaddress.ip_network("10.0.0.0/8"),), 30)
    assert registry.reserve("10.0.2.5", 100.0) is True
    assert registry.reserve("10.0.2.5", 110.0) is False
    assert registry.reserve("10.0.2.5", 131.0) is True
    assert registry.reserve("8.8.8.8", 131.0) is False
    assert registry.reserve("invalid", 131.0) is False


def test_model_sample_requires_every_feature() -> None:
    row = {
        "packet_count": 10,
        "byte_count": 200,
        "pktrate": 5.0,
        "byterate": 100.0,
        "ip_proto": 6,
        "l4_dst_port": 80,
    }
    assert build_model_sample(row) == row
    row["pktrate"] = None
    assert build_model_sample(row) is None


def test_icmp_flows_reach_the_model_with_port_zero() -> None:
    icmp = {
        "packet_count": 600,
        "byte_count": 58800,
        "pktrate": 300.0,
        "byterate": 29400.0,
        "ip_proto": 1,
        "l4_dst_port": None,
    }
    assert build_model_sample(icmp) == {**icmp, "l4_dst_port": 0}
    # Only ICMP gets this: a TCP flow without a port is still incomplete.
    assert build_model_sample({**icmp, "ip_proto": 6}) is None
    # The stored row is not rewritten.
    assert icmp["l4_dst_port"] is None


def _flow_row(
    proto: Optional[int], port: Optional[int], rate: Optional[float] = 300.0
) -> Dict[str, Any]:
    return {
        "packet_count": 900,
        "byte_count": 54000,
        "pktrate": rate,
        "byterate": None if rate is None else rate * 60,
        "ip_proto": proto,
        "l4_dst_port": port,
    }


def test_port_free_flows_reach_the_model_with_port_zero() -> None:
    for proto in (6, 17, 1):
        sample = build_model_sample(_flow_row(proto, None), port_free=True)
        assert sample is not None
        assert sample["l4_dst_port"] == NO_PORT == 0
        assert sample["ip_proto"] == proto
    # A port the rule does match is kept.
    assert build_model_sample(_flow_row(6, 80), port_free=True) == _flow_row(6, 80)


def test_per_port_behaviour_is_unchanged() -> None:
    # Without port_free (the default) a TCP/UDP flow without a port stays incomplete.
    assert build_model_sample(_flow_row(6, None)) is None
    assert build_model_sample(_flow_row(17, None), port_free=False) is None
    icmp = build_model_sample(_flow_row(1, None), port_free=False)
    assert icmp is not None and icmp["l4_dst_port"] == 0


def test_port_free_still_needs_a_protocol_and_a_rate() -> None:
    # ARP and other non-IP rules have no protocol; a first poll has no rate yet.
    assert (
        build_model_sample({**_flow_row(6, None), "ip_proto": None}, port_free=True)
        is None
    )
    assert build_model_sample(_flow_row(6, None, rate=None), port_free=True) is None


def test_port_free_row_is_not_rewritten() -> None:
    row = _flow_row(17, None)
    build_model_sample(row, port_free=True)
    assert row["l4_dst_port"] is None


def test_the_model_sees_every_flow_the_entropy_detector_counts_in_port_free() -> None:
    """Both detectors must judge the same flows: TCP, UDP and ICMP alike."""

    flows = [
        CountedFlow("syn", "10.0.0.11", "10.0.0.1", 300, 18000, 1.0, 6, 0),
        CountedFlow("udp", "10.0.0.31", "10.0.0.1", 300, 18000, 1.0, 17, 0),
        CountedFlow("icmp", "10.0.0.2", "10.0.0.1", 5, 490, 1.0, 1, 0),
        CountedFlow("rst", "10.0.0.1", "10.0.0.11", 300, 18000, 1.0, 6, 0),
    ]
    previous = {f.key: (0, 0, 0.0) for f in flows}
    _, poll = entropy_poll_from_switch_clock(previous, flows)
    counted = {(src, dst) for src, dst, _ in poll.flows}
    assert len(counted) == 4
    seen = set()
    for flow in flows:
        row = _flow_row(flow.ip_proto, None, rate=float(flow.packet_count))
        if build_model_sample(row, port_free=True) is not None:
            seen.add((flow.source, flow.destination))
    assert counted <= seen


def test_probability_validation() -> None:
    assert probability_is_attack(0.8, 0.8) is True
    assert probability_is_attack("0.9", 0.8) is True
    assert probability_is_attack(1.1, 0.8) is False
    assert probability_is_attack("bad", 0.8) is False
