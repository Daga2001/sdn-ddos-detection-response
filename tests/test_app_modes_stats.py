import json
import logging
from types import SimpleNamespace
from typing import Any, List

import pytest

pytest.importorskip("ryu")

from sdn_ddos.controller import app_modes
from sdn_ddos.controller.app import EnterpriseDDoSController
from sdn_ddos.controller.stats_buffer import StatsReassembler
from sdn_ddos.detection.entropy import EntropyDetector, FlowObservation


def stat(count: int) -> Any:
    return SimpleNamespace(packet_count=count)


def reply(xid: int, body: List[Any], more: bool) -> Any:
    datapath = SimpleNamespace(id=1, ofproto=SimpleNamespace(OFPMPF_REPLY_MORE=1))
    message = SimpleNamespace(
        datapath=datapath, xid=xid, flags=1 if more else 0, body=body
    )
    return SimpleNamespace(msg=message)


@pytest.fixture
def controller(monkeypatch: pytest.MonkeyPatch) -> Any:
    seen: List[List[int]] = []

    def record(self: Any, event: Any) -> None:
        seen.append(sorted(int(s.packet_count) for s in event.msg.body))

    monkeypatch.setattr(EnterpriseDDoSController, "flow_stats_reply_handler", record)
    instance = app_modes.ModeSwitchController.__new__(app_modes.ModeSwitchController)
    instance.mode = "llm"
    instance.max_rows = 300
    instance.settings = SimpleNamespace(mitigation_enabled=False)
    instance.logger = logging.getLogger("test")
    instance._stats = StatsReassembler()
    instance._packet_history = {1: {"x": (1, 0, 0.0)}}
    instance._window_flows = {1: (1.0, [], 0)}
    instance._window_polls = {1: [(1.0, 1.0, {})]}
    instance._window_ports = {1: [(1.0, 1.0, {})]}
    instance._tracks_ports = True
    instance._entropy_windows = 0
    instance.entropy_dump = ""
    instance.entropy_window = 10.0
    instance.entropy_window_mode = "snapshot"
    instance.entropy_dedupe = False
    instance.seen = seen
    return instance


def test_two_polls_of_the_same_switch_are_never_merged(controller: Any) -> None:
    controller.flow_stats_reply_handler(reply(10, [stat(1), stat(2)], more=True))
    # the next poll starts before the first reply finished
    controller.flow_stats_reply_handler(reply(11, [stat(30)], more=True))
    controller.flow_stats_reply_handler(reply(11, [stat(40)], more=False))
    assert controller.seen == [[30, 40]]


def test_a_disconnect_discards_the_unfinished_reply_and_entropy_state(
    controller: Any,
) -> None:
    controller.flow_stats_reply_handler(reply(10, [stat(1)], more=True))
    controller._forget_partial_stats(
        SimpleNamespace(state=app_modes.DEAD_DISPATCHER, datapath=SimpleNamespace(id=1))
    )
    assert controller._packet_history == {} and controller._window_flows == {}
    assert controller._window_polls == {} and controller._window_ports == {}
    controller.flow_stats_reply_handler(reply(12, [stat(5)], more=False))
    assert controller.seen == [[5]]


def test_a_dead_datapath_without_an_id_is_ignored(controller: Any) -> None:
    controller._forget_partial_stats(
        SimpleNamespace(
            state=app_modes.DEAD_DISPATCHER, datapath=SimpleNamespace(id=None)
        )
    )
    assert controller._packet_history == {1: {"x": (1, 0, 0.0)}}


def test_snapshot_window_keeps_the_original_flow_list(controller: Any) -> None:
    flows = [
        app_modes.FlowObservation("a", "v", 2.0),
        app_modes.FlowObservation("a", "v", 3.0),
    ]
    fresh = {1: (9.0, flows, 2), 2: (9.0, flows[:1], 1)}
    assert controller._window_observations(10.0, fresh) == [*flows, flows[0]]


def test_mean_window_averages_recent_polls_and_ignores_old_ones(
    controller: Any,
) -> None:
    controller.entropy_window_mode = "mean"
    controller._window_polls = {
        1: [
            (2.0, 5.0, {("a", "v"): 500.0}),  # older than the window: ignored
            (14.0, 5.0, {("a", "v"): 10.0}),
            (19.0, 5.0, {("a", "v"): 20.0, ("b", "v"): 5.0}),
        ],
        2: [(19.0, 5.0, {("a", "v"): 15.0})],
    }
    flows = controller._window_observations(20.0, {})
    rates = sorted((f.src, round(f.weight, 2)) for f in flows)
    # switch 1: a = 30 / 10 s = 3.0, b = 0.5; switch 2: a = 3.0
    # (a is counted twice without dedupe)
    assert rates == [("a", 3.0), ("a", 3.0), ("b", 0.5)]
    controller.entropy_dedupe = True
    unique = controller._window_observations(20.0, {})
    assert sorted((f.src, round(f.weight, 2)) for f in unique) == [
        ("a", 3.0),
        ("b", 0.5),
    ]


def flow_stat(
    source: str,
    destination: str,
    proto: int,
    port: int,
    packets: int,
    duration_sec: int = 0,
) -> Any:
    key = "tcp_dst" if proto == 6 else "udp_dst"
    match = {"ipv4_src": source, "ipv4_dst": destination, "ip_proto": proto}
    if port:
        match[key] = port
    return SimpleNamespace(
        priority=10,
        packet_count=packets,
        byte_count=packets * 100,
        match=match,
        cookie=0,
        duration_sec=duration_sec,
        duration_nsec=0,
    )


def test_ports_are_rates_on_the_switch_clock_when_they_are_watched(
    controller: Any,
) -> None:
    controller._packet_history = {}
    controller._window_ports = {}
    controller._observe_entropy_window(
        1,
        [
            flow_stat("a", "v", 6, 8080, 0),
            flow_stat("v", "a", 6, 40001, 0),
            flow_stat("v", "a", 6, 40002, 0),
            flow_stat("b", "v", 17, 53, 0),
        ],
    )
    assert controller._window_ports == {}
    controller._observe_entropy_window(
        1,
        [
            flow_stat("a", "v", 6, 8080, 500, duration_sec=10),
            flow_stat("v", "a", 6, 40001, 5, duration_sec=10),
            flow_stat("v", "a", 6, 40002, 5, duration_sec=10),
            flow_stat("b", "v", 17, 53, 20, duration_sec=10),
        ],
    )
    ((_, elapsed, ports),) = controller._window_ports[1]
    assert elapsed == 10.0
    # 500 packets in 10 s is 50 pkt/s; the window stores rate * span.
    assert ports == {(6, 8080): 500.0, (6, 40001): 5.0, (6, 40002): 5.0, (17, 53): 20.0}
    controller._tracks_ports = False
    controller._window_ports = {}
    controller._observe_entropy_window(
        1, [flow_stat("a", "v", 6, 8080, 550, duration_sec=20)]
    )
    assert controller._window_ports == {}


def test_port_histograms_merge_equal_rates_and_keep_the_busiest_ports(
    controller: Any,
) -> None:
    controller.entropy_window_mode = "mean"
    controller._window_ports = {
        1: [
            (
                19.0,
                5.0,
                {(6, 8080): 1000.0, (6, 40001): 1.0, (6, 40002): 1.0, (1, 0): 5.0},
            )
        ],
        2: [(19.0, 5.0, {(6, 8080): 500.0})],
    }
    histograms, top = controller._window_histograms(20.0)
    # per switch: 8080 -> 200 and 100 pkt/s, the two replies 0.2 pkt/s, icmp 1 pkt/s
    assert histograms["dport"] == [(0.2, 2), (1.0, 1), (300.0, 1)]
    assert sorted(histograms["proto"]) == [(1.0, 1), (300.4, 1)]
    assert top[0] == ("tcp/8080", 300.0) and ("icmp/0", 1.0) in top
    controller.entropy_dedupe = True
    deduped, _ = controller._window_histograms(20.0)
    assert deduped["dport"] == [(0.2, 2), (1.0, 1), (200.0, 1)]


def test_a_snapshot_window_reads_only_the_last_poll_of_each_switch(
    controller: Any,
) -> None:
    controller.entropy_window_mode = "snapshot"
    controller._window_ports = {
        1: [(2.0, 5.0, {(6, 80): 500.0}), (19.0, 5.0, {(6, 80): 50.0})],
        2: [(-5.0, 5.0, {(6, 99): 500.0})],  # too old to count
    }
    _, top = controller._window_histograms(20.0)
    assert top == [("tcp/80", 10.0)]


def published(controller: Any, **kwargs: Any) -> Any:
    sent: List[Any] = []
    controller.telemetry = SimpleNamespace(
        emit=lambda kind, data: sent.append((kind, data))
    )
    controller.entropy = SimpleNamespace(consecutive_windows=2)
    flows = [FlowObservation("a", "x", 30.0), FlowObservation("b", "y", 30.0)]
    detector = EntropyDetector(warmup_windows=1, min_total_rate=1.0)
    detector.observe(1, flows)
    result = detector.observe(1, flows)
    controller._publish_entropy_window(
        result, {1: (1.0, flows, 7)}, flows, kwargs.get("extra"), [("tcp/8080", 30.0)]
    )
    return sent


def test_every_entropy_window_is_published_and_logged(
    controller: Any, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="test"):
        sent = published(controller)
    ((kind, data),) = sent
    assert kind == "entropy_window"
    assert (data["window"], data["state"], data["switches"]) == (1, "normal", 1)
    assert data["flow_rules"] == 7 and data["pairs"] == 2 and data["needed"] == 2
    assert data["top_dport"] == [["tcp/8080", 30.0]]
    assert (
        data["signals"]["src"]["out"] is False
        and data["panel"]["src"]["shannon"] == 1.0
    )
    assert "ENTROPY w=1 NORMAL" in caplog.text and "src=1.000[" in caplog.text


def test_a_window_can_be_dumped_for_offline_replays(
    controller: Any, tmp_path: Any, caplog: pytest.LogCaptureFixture
) -> None:
    target = tmp_path / "windows.jsonl"
    controller.entropy_dump = str(target)
    published(controller, extra={"dport": [(0.2, 10)]})
    published(controller)
    first, second = (json.loads(line) for line in target.read_text().splitlines())
    assert first["flows"] == [["a", "x", 30.0], ["b", "y", 30.0]]
    assert first["hist"] == {"dport": [[0.2, 10]]} and second["window"] == 2
    controller.entropy_dump = str(tmp_path / "missing" / "windows.jsonl")
    with caplog.at_level(logging.ERROR, logger="test"):
        published(controller)
    assert controller.entropy_dump == "" and "cannot write" in caplog.text


def test_a_flood_with_too_many_distinct_port_rates_is_binned_coarser(
    controller: Any,
) -> None:
    controller.entropy_window_mode = "mean"
    # 3000 reply ports whose rates differ by a thousandth: too many bins as they are
    flows = {(6, 1000 + n): 5.0 * (0.2 + n * 0.001) for n in range(3000)}
    controller._window_ports = {1: [(19.0, 5.0, flows)]}
    histograms, _ = controller._window_histograms(20.0)
    assert len(histograms["dport"]) <= app_modes.MAX_HISTOGRAM_BINS
    assert sum(count for _, count in histograms["dport"]) == 3000
