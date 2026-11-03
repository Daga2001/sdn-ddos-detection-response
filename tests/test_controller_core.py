import ipaddress

from sdn_ddos.controller.core import (
    BlockRegistry,
    FlowRateTracker,
    build_model_sample,
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


def test_probability_validation() -> None:
    assert probability_is_attack(0.8, 0.8) is True
    assert probability_is_attack("0.9", 0.8) is True
    assert probability_is_attack(1.1, 0.8) is False
    assert probability_is_attack("bad", 0.8) is False
