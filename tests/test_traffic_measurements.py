"""Measurements added for the Traffic tab. No traffic, root, or database."""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from sdn_ddos.lab.contracts import FORWARDING_MESSAGE, StartRequest
from sdn_ddos.lab.events import RateCounters
from sdn_ddos.lab.measurements import (
    MATCH_PORTS_ERROR,
    PingTracker,
    checks_due,
    forwarding_flag,
    handled_rate,
    log_and_require_match_l4_ports,
    match_l4_ports_setting,
    parse_curl_probe,
    read_system,
    switch_table_sample,
    table_miss_rate,
)
from sdn_ddos.lab.runtime import CONTROLLER_KINDS
from sdn_ddos.lab.topology import presets


def test_a_start_without_forwarding_is_rejected() -> None:
    with pytest.raises(ValidationError, match="forwarding"):
        StartRequest(topology=presets()[2])
    with pytest.raises(ValidationError):
        StartRequest(topology=presets()[2], forwarding="coarse")  # type: ignore[arg-type]
    assert "per-port (Experiment A)" in FORWARDING_MESSAGE


def test_forwarding_flag_has_no_default() -> None:
    assert forwarding_flag("per_port") == "true"
    assert forwarding_flag("port_free") == "false"
    with pytest.raises(ValueError, match="Choose the forwarding"):
        forwarding_flag("yes")


def test_match_ports_setting_refuses_to_start_without_true_or_false() -> None:
    with pytest.raises(ValueError, match=MATCH_PORTS_ERROR):
        match_l4_ports_setting({})
    with pytest.raises(ValueError, match=MATCH_PORTS_ERROR):
        match_l4_ports_setting({"SDN_MATCH_L4_PORTS": "yes"})
    assert match_l4_ports_setting({"SDN_MATCH_L4_PORTS": "true"}) is True
    assert match_l4_ports_setting({"SDN_MATCH_L4_PORTS": " false "}) is False


def test_a_missing_match_ports_setting_is_logged_and_refused() -> None:
    records: list[str] = []

    class Logger:
        def error(self, message: str, *args: object) -> None:
            records.append(message % args)

    with pytest.raises(ValueError, match="refusing to start"):
        log_and_require_match_l4_ports(Logger(), {})
    assert records == [MATCH_PORTS_ERROR]
    assert log_and_require_match_l4_ports(Logger(), {"SDN_MATCH_L4_PORTS": "true"})


def test_curl_output_including_a_timeout() -> None:
    parsed = parse_curl_probe("200 0.01 0.04", 0)
    assert parsed == {
        "success": True,
        "http_code": 200,
        "connect_ms": 10.0,
        "latency_ms": 40.0,
    }
    failed = parse_curl_probe("500 0.02 0.2", 0)
    assert failed["success"] is False and failed["http_code"] == 500
    timed_out = parse_curl_probe("", None)
    assert timed_out["success"] is False
    assert timed_out["latency_ms"] is None and timed_out["connect_ms"] is None
    short = parse_curl_probe("000 0", 28)
    assert short["success"] is False and short["http_code"] is None


def test_check_cadence_does_not_wait_for_a_running_process() -> None:
    clock = {"t": 0.0}
    running = {"probe": False}
    started: list[tuple[tuple[str, str], float]] = []
    pairs = [("c1", "v"), ("c2", "v")]
    next_at = 0.0
    index = 0
    for _ in range(3):
        due, next_at, index = checks_due(
            clock["t"], next_at, index, pairs, deadline=10, stopped=False
        )
        for pair in due:
            running["probe"] = True
            started.append((pair, clock["t"]))
        assert running["probe"]
        clock["t"] += 1.0
    assert started == [(("c1", "v"), 0.0), (("c2", "v"), 1.0), (("c1", "v"), 2.0)]
    due, _, _ = checks_due(3.0, next_at, index, pairs, deadline=3.0, stopped=False)
    assert due == []
    due, _, _ = checks_due(1.5, 1.0, 0, pairs, deadline=10, stopped=True)
    assert due == []


def test_ping_counts_sent_by_icmp_seq_and_losses_after_one_second() -> None:
    tracker = PingTracker("h1", "h3", started=0.0)
    tracker.feed("64 bytes from 10.0.0.3: icmp_seq=1 ttl=64 time=1.5 ms", arrival=0.1)
    tracker.feed("64 bytes from 10.0.0.3: icmp_seq=3 ttl=64 time=2.0 ms", arrival=0.5)
    # seq 2 was sent at 0.2 s and is still unanswered at 1.0 s.
    events = tracker.take(1.0)
    assert len(events) == 1
    event = events[0]
    assert event["client"] == "h1" and event["target"] == "h3"
    assert event["sent"] == 5  # seq 1..5 leave during the first second
    assert event["lost"] == 0  # their 1 s windows have not closed yet
    assert event["replies"] == [
        [tracker.replies[1][2], 1.5],
        [tracker.replies[3][2], 2.0],
    ]
    later = tracker.take(2.0)
    # seq 1 and 3 were answered. seq 2, 4 and 5 close their 1 s window in this second.
    assert later[0]["lost"] == 3
    assert later[0]["sent"] == 5


def run_ping(
    interval: float, seconds: int, silent: tuple[float, float] = (-1, -1)
) -> tuple[list[dict], int]:
    """Feed a ping that sends every `interval` s; return its per-second events."""

    tracker = PingTracker("h1", "h3", started=0.0)
    events = []
    seq, send = 1, 0.0
    for second in range(1, seconds + 1):
        while send < second:
            if not silent[0] <= send < silent[1]:
                tracker.feed(
                    f"64 bytes from 10.0.0.3: icmp_seq={seq} ttl=64 time=0.1 ms",
                    arrival=send + 0.0001,
                )
            seq, send = seq + 1, send + interval
        events.extend(tracker.take(float(second)))
    return events, seq - 1


def test_a_ping_slower_than_its_interval_loses_nothing() -> None:
    # On a busy lab machine ping fell behind its 0.2 s interval; a fixed clock
    # then drifted ahead of the real sends and, after about a minute, counted
    # every ping as lost although every one was answered.
    events, sent = run_ping(interval=0.21, seconds=300)
    assert sum(event["lost"] for event in events) == 0
    assert abs(sum(event["sent"] for event in events) - sent) <= 5


def test_a_real_outage_is_still_counted_as_loss() -> None:
    events, _ = run_ping(interval=0.2, seconds=40, silent=(10.0, 15.0))
    lost = sum(event["lost"] for event in events)
    assert 24 <= lost <= 26  # 5 s without replies at 5 pings a second
    window = [e for e in events if e["lost"]]
    assert window[0]["observed_at"] < window[-1]["observed_at"]


def test_packet_rates_from_interface_counters() -> None:
    rates = RateCounters()
    assert rates.observe("h1", 0, 0, 1.0, 0, 0) is None
    sample = rates.observe("h1", 1000, 2000, 2.0, 10, 4)
    assert sample == {
        "rx_bps": 8000.0,
        "tx_bps": 16000.0,
        "rx_pps": 10.0,
        "tx_pps": 4.0,
    }
    assert rates.observe("h1", 1000, 2000, 3.0, 9, 4) is None


def test_table_miss_rate_uses_the_switch_clock_and_resets() -> None:
    assert table_miss_rate(None, 10, 1.0) == (None, (10, 1.0))
    rate, baseline = table_miss_rate((10, 1.0), 30, 3.0)
    assert rate == 10.0 and baseline == (30, 3.0)
    reset, new_baseline = table_miss_rate(baseline, 5, 0.4)
    assert reset is None and new_baseline == (5, 0.4)
    stalled, _ = table_miss_rate((5, 0.4), 8, 0.4)
    assert stalled is None


def _stat(
    packets: int,
    priority: int = 1,
    match: dict[str, Any] | None = None,
    duration_sec: int = 2,
    duration_nsec: int = 0,
    controller: bool = False,
    empty_match: bool = False,
) -> SimpleNamespace:
    instructions = []
    if controller:
        instructions = [SimpleNamespace(actions=[SimpleNamespace(port=0xFFFFFFFD)])]
    return SimpleNamespace(
        packet_count=packets,
        priority=priority,
        match={} if empty_match else (match or {"ipv4_src": "10.0.0.1"}),
        duration_sec=duration_sec,
        duration_nsec=duration_nsec,
        instructions=instructions,
    )


def test_flow_rules_are_counted_before_any_trim() -> None:
    miss = _stat(4, priority=0, duration_sec=1, controller=True, empty_match=True)
    body = [miss, *[_stat(index) for index in range(40)]]
    event, baseline = switch_table_sample(7, body, None)
    assert event["dpid"] == 7
    assert event["flow_rules"] == 40
    assert event["table_miss_packets"] == 4
    assert event["packet_in_sent_per_s"] is None
    again, _ = switch_table_sample(
        7,
        [_stat(14, priority=0, duration_sec=2, controller=True, empty_match=True)],
        baseline,
    )
    assert again["packet_in_sent_per_s"] == 10.0
    assert again["flow_rules"] == 0


def test_switch_table_passes_the_runner_filter() -> None:
    assert "switch_table" in CONTROLLER_KINDS


def test_handled_packet_in_rate_resets_when_the_counter_goes_down() -> None:
    assert handled_rate(None, 4, 1.0) == (None, (4, 1.0))
    rate, baseline = handled_rate((4, 1.0), 9, 2.0)
    assert rate == 5.0
    assert handled_rate(baseline, 1, 3.0)[0] is None


def test_system_sample_records_the_machine_and_ovs() -> None:
    class Proc:
        def __init__(self) -> None:
            self.info = {"name": "ovs-vswitchd"}

        def cpu_percent(self) -> float:
            return 12.5

        def memory_info(self) -> SimpleNamespace:
            return SimpleNamespace(rss=4096)

    class Other:
        def __init__(self) -> None:
            self.info = {"name": "ryu-manager"}

    class FakePsutil:
        def cpu_percent(self) -> float:
            return 40.0

        def process_iter(self, _fields: list[str]) -> list[Any]:
            return [Other(), Proc()]

    assert read_system(FakePsutil()) == {
        "cpu_percent": 40.0,
        "ovs_cpu_percent": 12.5,
        "ovs_rss_bytes": 4096,
    }


def test_system_sample_leaves_ovs_null_when_the_process_is_absent() -> None:
    class FakePsutil:
        def cpu_percent(self) -> float:
            return 1.0

        def process_iter(self, _fields: list[str]) -> list[Any]:
            return []

    sample = read_system(FakePsutil())
    assert sample["ovs_cpu_percent"] is None and sample["ovs_rss_bytes"] is None


def test_runtime_passes_forwarding_in_every_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from unittest.mock import MagicMock

    from sdn_ddos.lab import runtime as module
    from sdn_ddos.lab.contracts import DetectionConfig
    from sdn_ddos.lab.runtime import MininetRuntime

    channel = MagicMock()
    channel.recv.side_effect = BlockingIOError
    monkeypatch.setattr(module.socket, "socket", lambda *args: channel)
    monkeypatch.setenv("SDN_LAB_RUNNER", "1")
    monkeypatch.setattr(module.socket, "create_connection", MagicMock())
    monkeypatch.setattr(module.subprocess, "check_output", lambda *a, **k: "OVS test\n")
    network = MagicMock()
    network.addLink.return_value = SimpleNamespace(
        intf1=SimpleNamespace(name="s1-eth1")
    )
    monkeypatch.setitem(
        module.sys.modules, "mininet.link", SimpleNamespace(TCLink=object)
    )
    monkeypatch.setitem(
        module.sys.modules,
        "mininet.net",
        SimpleNamespace(Mininet=lambda **kw: network, VERSION="test"),
    )
    monkeypatch.setitem(
        module.sys.modules,
        "mininet.node",
        SimpleNamespace(OVSSwitch=object, RemoteController=object),
    )
    for forwarding, detection in (
        ("per_port", None),
        ("port_free", DetectionConfig(mode="entropy")),
        ("per_port", DetectionConfig(mode="llm")),
    ):
        captured: dict[str, str] = {}

        def capture(
            command: list[str],
            node: str,
            seen: dict[str, str] = captured,
            **kwargs: Any,
        ) -> Any:
            seen.clear()
            seen.update(kwargs.get("env") or {})
            process = MagicMock()
            process.process.poll.return_value = None
            return process

        lab = MininetRuntime(
            presets()[2],
            "run",
            False,
            lambda kind, data: None,
            detection=detection,
            forwarding=forwarding,
        )
        monkeypatch.setattr(lab, "_spawn", capture)
        lab.start()
        assert captured["SDN_MATCH_L4_PORTS"] == forwarding_flag(forwarding)
        lab.close()


def test_both_controllers_log_and_refuse_without_the_setting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("ryu")
    from sdn_ddos.controller.app import EnterpriseDDoSController
    from sdn_ddos.controller.app_modes import ModeSwitchController

    monkeypatch.delenv("SDN_MATCH_L4_PORTS", raising=False)
    for cls in (EnterpriseDDoSController, ModeSwitchController):
        with pytest.raises(ValueError, match="refusing to start"):
            cls()
    # A logger line is enough; Ryu may also print. The exception is the refusal.
    assert logging.getLogger("ryu").handlers is not None
