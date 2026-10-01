import time
from unittest.mock import MagicMock

import pytest
from lab_fakes import FakeRuntime, MemoryRepository

from sdn_ddos.lab.contracts import Capture, Diagnostic, Experiment, StartRequest
from sdn_ddos.lab.manager import LabManager
from sdn_ddos.lab.topology import presets


def wait_for(manager, states):
    deadline = time.monotonic() + 3
    while manager.status()["state"] not in states:
        assert time.monotonic() < deadline
        time.sleep(0.01)


def test_one_lab_and_repeatable_cleanup():
    repository = MemoryRepository()
    manager = LabManager(repository, FakeRuntime)
    run_id = manager.start(StartRequest(topology=presets()[2]))
    wait_for(manager, {"running"})
    with pytest.raises(ValueError, match="already"):
        manager.start(StartRequest(topology=presets()[2]))
    manager.stop()
    manager.stop()
    wait_for(manager, {"stopped"})
    assert repository.run(run_id)["status"] == "stopped"
    assert manager.runtime.closed


def test_startup_failure_is_recorded_and_cleaned():
    class BrokenRuntime(FakeRuntime):
        def start(self):
            raise RuntimeError("could not start")

    manager = LabManager(MemoryRepository(), BrokenRuntime)
    manager.start(StartRequest(topology=presets()[2]))
    wait_for(manager, {"failed"})
    assert manager.runtime.closed
    assert any(event["kind"] == "error" for event in manager.events(0)["events"])


def test_database_failure_stops_runtime_and_marks_failed():
    repository = MemoryRepository()
    manager = LabManager(repository, FakeRuntime)
    manager.start(StartRequest(topology=presets()[2]))
    wait_for(manager, {"running"})
    repository.failed = True
    wait_for(manager, {"failed"})
    assert manager.runtime.closed
    assert manager.status()["persistence_error"]


def test_full_experiment_phases_and_read_only_replay(monkeypatch):
    class ExperimentRuntime(FakeRuntime):
        def serve(self, targets):
            pass

        def attack(self, experiment):
            self.process = MagicMock()
            self.process.process.returncode = 0
            self.process.started_at = "2026-01-01T00:00:00+00:00"
            self.process.ended_at = "2026-01-01T00:00:01+00:00"
            return [self.process]

        def probe(self, client, target):
            self.emit("service", {"success": True})

    repository = MemoryRepository()
    manager = LabManager(repository, ExperimentRuntime)
    # Exercise the timing loop without waiting for a real experiment duration.
    original = manager._observe
    monkeypatch.setattr(
        manager, "_observe", lambda seconds, request: original(0.01, request)
    )
    request = StartRequest(
        topology=presets()[2],
        experiment=Experiment(
            attackers=["h1"], victims=["h2"], confirm_isolated_lab=True
        ),
    )
    identifier = manager.start(request)
    wait_for(manager, {"completed"})
    phases = [
        e["data"]["state"]
        for e in repository.events(identifier, 0)
        if e["kind"] == "phase"
    ]
    assert phases == ["starting", "baseline", "attack", "recovery", "completed"]
    manager.runtime.process.close.assert_called_once()
    assert manager.runtime.closed
    with pytest.raises(ValueError):
        manager.diagnostic(Diagnostic(action="interfaces", node="h1"))
    with pytest.raises(ValueError):
        manager.capture(Capture(link_id="link-1"))


@pytest.mark.parametrize(
    "code, final",
    [
        (0, "completed"),
        (-9, "completed"),
        (-15, "completed"),
        (124, "completed"),
        (137, "completed"),
        (1, "failed"),
        (127, "failed"),
    ],
)
def test_generator_exit_code_decides_pass_or_fail(monkeypatch, code, final):
    class ExperimentRuntime(FakeRuntime):
        def serve(self, targets):
            pass

        def attack(self, experiment):
            process = MagicMock()
            process.node = "h1"
            process.process.returncode = code
            process.started_at = "2026-01-01T00:00:00+00:00"
            process.ended_at = "2026-01-01T00:00:01+00:00"
            return [process]

        def probe(self, client, target):
            pass

    repository = MemoryRepository()
    manager = LabManager(repository, ExperimentRuntime)
    original = manager._observe
    monkeypatch.setattr(
        manager, "_observe", lambda seconds, request: original(0.01, request)
    )
    identifier = manager.start(
        StartRequest(
            topology=presets()[2],
            experiment=Experiment(
                attackers=["h1"], victims=["h2"], confirm_isolated_lab=True
            ),
        )
    )
    wait_for(manager, {final})
    events = repository.events(identifier, 0)
    if final == "failed":
        error = next(e for e in events if e["kind"] == "error")
        # The exact reason is recorded so a failed run can be debugged.
        assert f"code {code}" in error["data"]["detail"]
        assert error["data"]["detail"] != error["data"]["message"]


def test_cleanup_failure_blocks_new_lab():
    class BrokenCleanup(FakeRuntime):
        def close(self):
            raise OSError("cleanup failed")

    manager = LabManager(MemoryRepository(), BrokenCleanup)
    request = StartRequest(topology=presets()[2])
    manager.start(request)
    wait_for(manager, {"running"})
    manager.diagnostic(Diagnostic(action="interfaces", node="h1"))
    manager.capture(Capture(link_id="link-1"))
    manager.stop()
    wait_for(manager, {"failed"})
    with pytest.raises(ValueError, match="recreate"):
        manager.start(request)
