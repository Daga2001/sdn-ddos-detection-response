import sys
import time

from sdn_ddos.lab.processes import ManagedProcess


def test_process_output_is_capped_and_exit_reported():
    events = []
    process = ManagedProcess(
        [sys.executable, "-c", "print('x' * 20000)"],
        "test",
        lambda kind, data: events.append((kind, data)),
    )
    process.wait(5)
    process.close()
    assert any(kind == "command" for kind, _ in events)
    assert any(kind == "output_truncated" for kind, _ in events)
    assert (
        sum(
            len(data.get("text", ""))
            for kind, data in events
            if kind == "command_output"
        )
        <= 16384
    )
    assert any(
        kind == "command_exit" and data["returncode"] == 0 for kind, data in events
    )


def test_stop_reaps_a_running_process():
    process = ManagedProcess(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        "test",
        lambda *args: None,
    )
    started = time.monotonic()
    process.close()
    process.close()
    assert process.process.poll() is not None
    assert time.monotonic() - started < 5


def test_independent_deadline_ends_a_stalled_command_without_observation():
    # Harmless sleep, not traffic. No manager/sample loop is involved.
    process = ManagedProcess(
        [
            "timeout",
            "--signal=TERM",
            "--kill-after=2",
            "0.1",
            sys.executable,
            "-c",
            "import time; time.sleep(30)",
        ],
        "test",
        lambda *args: None,
    )
    started = time.monotonic()
    assert process.wait(3) == 124
    assert time.monotonic() - started < 2
    assert process.ended_at is not None
    process.close()
