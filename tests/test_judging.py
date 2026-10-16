from sdn_ddos.controller.judging import PollQueue, judging_order, next_window_due


def test_without_sources_the_busiest_flows_come_first() -> None:
    assert judging_order([2.0, 300.0, 1.0], None, set(), 20.0) == [1, 0, 2]


def test_busy_sources_not_flagged_yet_go_before_flagged_ones() -> None:
    rates = [900.0, 850.0, 500.0, 1.0]
    sources = ["a", "a", "b", "c"]
    assert judging_order(rates, sources, set(), 20.0) == [0, 1, 2, 3]
    # a was just flagged: b (busy, not flagged) is judged before a's flows.
    assert judging_order(rates, sources, {"a"}, 20.0) == [2, 0, 1, 3]


def test_quiet_flows_stay_last_even_when_their_source_is_unflagged() -> None:
    rates = [2.0, 300.0, 1.0]
    sources = ["x", "y", "z"]
    assert judging_order(rates, sources, {"y"}, 20.0) == [1, 0, 2]
    # A quiet flow of a flagged source ranks with the flagged ones, ahead of quiet ones.
    assert judging_order([1.0, 2.0], ["f", "q"], {"f"}, 20.0) == [0, 1]


def test_windows_keep_their_schedule_and_never_burst() -> None:
    # On time: one window after the previous due time, whatever the evaluation cost.
    assert next_window_due(10.0, 5.0, 11.5) == 15.0
    assert next_window_due(15.0, 5.0, 16.4) == 20.0
    # A little late is absorbed; a whole window behind restarts from now.
    assert next_window_due(10.0, 5.0, 14.9) == 15.0
    assert next_window_due(10.0, 5.0, 40.0) == 45.0


def test_poll_queue_keeps_one_poll_per_switch_and_serves_the_busiest() -> None:
    queue: PollQueue[str] = PollQueue()
    assert queue.put(1, "first", 3.0) is None
    assert queue.put(2, "quiet", 1.0) is None
    assert queue.put(3, "busy", 400.0) is None
    assert queue.put(1, "newer", 90.0) == "first"  # replaced, handed back
    assert len(queue) == 3 and queue.get(1) == "newer" and queue.get(9) is None
    assert [queue.pop_busiest() for _ in range(3)] == ["busy", "newer", "quiet"]
    assert len(queue) == 0
