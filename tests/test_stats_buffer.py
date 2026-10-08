from sdn_ddos.controller.stats_buffer import StatsReassembler


def test_chunks_of_one_reply_are_joined_in_order() -> None:
    buffer = StatsReassembler()
    assert buffer.add(1, 10, ["a", "b"], more=True) is None
    assert buffer.add(1, 10, ["c"], more=False) == ["a", "b", "c"]
    assert buffer.abandoned == 0


def test_replies_with_the_same_dpid_and_different_xid_are_not_merged() -> None:
    buffer = StatsReassembler()
    assert buffer.add(1, 10, ["old-1"], more=True) is None
    # the next poll starts before the first reply finished
    assert buffer.add(1, 11, ["new-1"], more=True) is None
    assert buffer.add(1, 11, ["new-2"], more=False) == ["new-1", "new-2"]
    assert buffer.abandoned == 1


def test_late_chunks_of_an_abandoned_reply_are_ignored() -> None:
    buffer = StatsReassembler()
    buffer.add(1, 10, ["old-1"], more=True)
    buffer.add(1, 11, ["new-1"], more=True)
    assert buffer.add(1, 10, ["old-2"], more=False) is None  # not a partial reply
    assert buffer.add(1, 11, ["new-2"], more=False) == ["new-1", "new-2"]


def test_a_single_message_reply_abandons_an_unfinished_older_one() -> None:
    buffer = StatsReassembler()
    buffer.add(1, 10, ["old"], more=True)
    assert buffer.add(1, 11, ["only"], more=False) == ["only"]


def test_disconnect_drops_the_unfinished_reply() -> None:
    buffer = StatsReassembler()
    buffer.add(1, 10, ["old"], more=True)
    buffer.clear(1)
    assert buffer.add(1, 10, ["late"], more=False) is None
    assert buffer.add(1, 12, ["fresh"], more=False) == ["fresh"]
    buffer.clear(1)  # nothing pending: harmless
    buffer.clear(99)


def test_switches_do_not_interfere_with_each_other() -> None:
    buffer = StatsReassembler()
    buffer.add(1, 10, ["s1-a"], more=True)
    buffer.add(2, 10, ["s2-a"], more=True)
    assert buffer.add(2, 10, ["s2-b"], more=False) == ["s2-a", "s2-b"]
    assert buffer.add(1, 10, ["s1-b"], more=False) == ["s1-a", "s1-b"]
    assert buffer.abandoned == 0


def test_the_memory_of_dropped_xids_is_bounded() -> None:
    buffer = StatsReassembler()
    for xid in range(100):
        buffer.add(1, xid, ["x"], more=True)
    assert buffer.abandoned == 99
    assert len(buffer._dropped[1]) <= 16
