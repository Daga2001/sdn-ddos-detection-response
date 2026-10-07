import threading
import time
from typing import ClassVar

from sdn_ddos.async_io import AsyncMetricsStore, BackgroundWorker


def wait_for(condition, timeout=2.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.01)
    return False


def test_worker_runs_submitted_calls_in_order_off_the_caller_thread():
    seen = []
    caller = threading.get_ident()
    worker = BackgroundWorker("test", max_pending=10)
    worker.submit(lambda value: seen.append((value, threading.get_ident())), 1)
    worker.submit(lambda value: seen.append((value, threading.get_ident())), 2)
    worker.close()
    assert [value for value, _ in seen] == [1, 2]
    assert all(thread != caller for _, thread in seen)


def test_worker_survives_a_failing_call():
    seen = []
    worker = BackgroundWorker("test", max_pending=10)

    def boom():
        raise RuntimeError("db down")

    worker.submit(boom)
    worker.submit(seen.append, "after")
    worker.close()
    assert seen == ["after"]


def test_full_queue_drops_instead_of_blocking():
    gate = threading.Event()
    worker = BackgroundWorker("test", max_pending=1)
    worker.submit(gate.wait, 5)  # occupies the worker
    time.sleep(0.05)
    worker.submit(lambda: None)  # fills the queue
    worker.submit(lambda: None)  # must not block
    assert worker.dropped >= 1
    gate.set()
    worker.close()


class FakeStore:
    instances: ClassVar[list] = []

    def __init__(self, fail_first=False):
        self.calls = []
        self.fail_first = fail_first
        FakeStore.instances.append(self)

    def add_flow_rows(self, rows):
        if self.fail_first:
            self.fail_first = False
            raise ConnectionError("connection lost")
        self.calls.append(("rows", rows))

    def close(self):
        self.calls.append(("close",))


def test_async_store_reconnects_and_retries_after_a_failure():
    FakeStore.instances.clear()
    made = []

    def factory():
        made.append(len(made))
        return FakeStore(fail_first=(len(made) == 1))

    store = AsyncMetricsStore(factory)
    store.add_flow_rows([{"a": 1}])
    assert wait_for(lambda: len(FakeStore.instances) == 2)
    assert wait_for(lambda: ("rows", [{"a": 1}]) in FakeStore.instances[1].calls)
    store.close()
