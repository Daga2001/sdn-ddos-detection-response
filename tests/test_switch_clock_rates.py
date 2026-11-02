"""Packet rates must follow the switch, not how busy the controller is.

A normal client can send 3 packets/s and still look like 50-220 packets/s
when replies pile up on a busy controller. These tests pin the repair:
rate = change in the counters / change in the flow's own age.
"""

from __future__ import annotations

import random
import time
from pathlib import Path

import pytest

from sdn_ddos.controller.core import (
    CountedFlow,
    FlowRateTracker,
    entropy_poll_from_switch_clock,
    observe_flow_rate,
)

ROOT = Path(__file__).resolve().parents[1]


def test_rate_uses_switch_clock_not_controller_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": 1000.0}

    def controller_clock() -> float:
        return clock["now"]

    monkeypatch.setattr(time, "monotonic", controller_clock)
    tracker = FlowRateTracker()
    assert observe_flow_rate(tracker, "client", 0, 0, 0, 0) is None

    # The controller processed the next reply only 0.1 s later. The flow
    # itself is 10 s older and has carried 30 more packets.
    clock["now"] += 0.1
    rates = observe_flow_rate(tracker, "client", 30, 3000, 10, 0)

    assert rates == (3.0, 300.0)
    assert rates[0] != 30 / 0.1


def test_rate_ignores_processing_delay_and_a_replaced_rule_is_a_new_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    delays = [random.Random(7).uniform(0.01, 2.0) for _ in range(6)]
    clock = {"now": 50.0}

    def controller_clock() -> float:
        return clock["now"]

    monkeypatch.setattr(time, "monotonic", controller_clock)
    tracker = FlowRateTracker()
    observe_flow_rate(tracker, "client", 0, 0, 0, 0)
    for step, delay in enumerate(delays, start=1):
        clock["now"] += delay
        rates = observe_flow_rate(
            tracker, "client", 30 * step, 3000 * step, 10 * step, 0
        )
        assert rates == (3.0, 300.0)

    # A counter that goes down is a replaced rule, not negative traffic.
    clock["now"] += 0.2
    assert observe_flow_rate(tracker, "client", 5, 50, 70, 0) is None
    # The next real interval starts from that new rule.
    assert observe_flow_rate(tracker, "client", 35, 3050, 80, 0) == (3.0, 300.0)

    # An age that goes down is the same kind of replacement.
    observe_flow_rate(tracker, "other", 10, 100, 40, 0)
    assert observe_flow_rate(tracker, "other", 40, 400, 3, 0) is None
    # Nanoseconds are part of the switch clock: 21 packets in 10.5 s is 2 pkt/s.
    assert observe_flow_rate(tracker, "other", 61, 610, 13, 500_000_000) == (2.0, 20.0)


def test_entropy_detector_uses_the_same_switch_clock_rate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": 10.0}

    def controller_clock() -> float:
        return clock["now"]

    monkeypatch.setattr(time, "monotonic", controller_clock)
    tracker = FlowRateTracker()
    first = CountedFlow("client", "10.0.0.9", "10.0.0.1", 0, 0, 0.0, 6, 80)
    state, quiet = entropy_poll_from_switch_clock({}, (first,))
    assert quiet.flows == ()
    assert quiet.span_seconds is None

    clock["now"] += 0.1
    second = CountedFlow("client", "10.0.0.9", "10.0.0.1", 30, 3000, 10.0, 6, 80)
    _state, poll = entropy_poll_from_switch_clock(state, (second,))
    observe_flow_rate(tracker, "client", 0, 0, 0, 0)
    flow_rate = observe_flow_rate(tracker, "client", 30, 3000, 10, 0)

    assert poll.flows == (("10.0.0.9", "10.0.0.1", 3.0),)
    assert flow_rate is not None
    assert poll.flows[0][2] == flow_rate[0]
    # The window keeps one span, taken from the switch, so averaging later
    # still returns 3.0 packets/s rather than 300.
    assert poll.span_seconds == 10.0
    assert poll.pair_packets[("10.0.0.9", "10.0.0.1")] / poll.span_seconds == 3.0


def test_entropy_poll_span_is_the_longest_flow_age_not_a_shorter_neighbour() -> None:
    """Two flows in one poll can age by different amounts. The span is the longest."""

    previous = {
        "slow": (0, 0, 0.0),
        "fast": (0, 0, 6.0),
    }
    flows = (
        CountedFlow("slow", "10.0.0.9", "10.0.0.1", 30, 300, 10.0, 6, 80),
        CountedFlow("fast", "10.0.0.8", "10.0.0.1", 20, 200, 10.0, 6, 80),
    )
    _state, poll = entropy_poll_from_switch_clock(previous, flows)
    assert poll.span_seconds == 10.0
    assert poll.span_seconds is not None
    assert poll.flows == (
        ("10.0.0.9", "10.0.0.1", 3.0),
        ("10.0.0.8", "10.0.0.1", 5.0),
    )
    # Stored totals are rate times that span, so a later division still
    # returns 5.0 for the flow that only aged 4 seconds, not 20/10.
    assert poll.pair_packets[("10.0.0.8", "10.0.0.1")] / poll.span_seconds == 5.0


def test_controller_rate_paths_do_not_divide_by_the_controller_clock() -> None:
    app = (ROOT / "src/sdn_ddos/controller/app.py").read_text(encoding="utf-8")
    modes = (ROOT / "src/sdn_ddos/controller/app_modes.py").read_text(encoding="utf-8")
    flow_batch = app.split("def _flow_batch", 1)[1].split("\n    def ", 1)[0]
    entropy = modes.split("def _observe_entropy_window", 1)[1].split("\n    def ", 1)[0]

    assert "time.monotonic()" not in flow_batch
    assert "observe_flow_rate(" in flow_batch
    assert "now - last_poll" not in entropy
    assert "delta / elapsed" not in entropy
    assert "entropy_poll_from_switch_clock(" in entropy
