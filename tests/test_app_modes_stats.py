import logging
from types import SimpleNamespace
from typing import Any, List

import pytest

pytest.importorskip("ryu")

from sdn_ddos.controller import app_modes
from sdn_ddos.controller.app import EnterpriseDDoSController
from sdn_ddos.controller.stats_buffer import StatsReassembler


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
    instance._packet_history = {1: {"x": 1}}
    instance._last_poll = {1: 1.0}
    instance._window_flows = {1: (1.0, [], 0)}
    instance._window_polls = {1: [(1.0, 1.0, {})]}
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
    assert controller._window_polls == {}
    controller.flow_stats_reply_handler(reply(12, [stat(5)], more=False))
    assert controller.seen == [[5]]


def test_a_dead_datapath_without_an_id_is_ignored(controller: Any) -> None:
    controller._forget_partial_stats(
        SimpleNamespace(
            state=app_modes.DEAD_DISPATCHER, datapath=SimpleNamespace(id=None)
        )
    )
    assert controller._packet_history == {1: {"x": 1}}


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
