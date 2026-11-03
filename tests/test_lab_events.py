import pytest

from sdn_ddos.lab.events import EventJournal, RateCounters


def test_journal_reports_gaps_and_retains_sequence():
    journal = EventJournal(capacity=3)
    for index in range(5):
        journal.emit("status", {"index": index})
    page = journal.since(0)
    assert page["gap"] is True
    assert [event["seq"] for event in page["events"]] == [3, 4, 5]
    assert journal.since(5)["events"] == []


def test_failed_persistence_is_visible_and_event_remains_in_memory():
    def fail(event):
        raise OSError("database unavailable")

    journal = EventJournal(persist=fail)
    with pytest.raises(OSError):
        journal.emit("status", {})
    assert journal.since(0)["events"][0]["kind"] == "status"


def test_link_rates_use_actual_elapsed_time_and_reset_baselines():
    rates = RateCounters()
    assert rates.observe("link", 100, 200, 1.0, 10, 4) is None
    assert rates.observe("link", 300, 600, 3.0, 30, 8) == {
        "rx_bps": 800.0,
        "tx_bps": 1600.0,
        "rx_pps": 10.0,
        "tx_pps": 2.0,
    }
    assert rates.observe("link", 0, 0, 4.0, 0, 0) is None
    assert rates.observe("link", 100, 200, 5.0, 10, 4)["rx_bps"] == 800
    assert rates.observe("link", 100, 200, 6.0, 0, 4) is None
