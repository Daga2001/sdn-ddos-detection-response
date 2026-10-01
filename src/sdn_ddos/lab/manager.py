"""Single-run orchestration; the browser never owns experiment lifetime."""

from __future__ import annotations

import contextlib
import logging
import threading
import time
from collections.abc import Callable
from typing import Any, Optional
from uuid import uuid4

from sdn_ddos.lab.contracts import (
    Capture,
    Diagnostic,
    StartRequest,
    probe_pairs,
    validate_experiment,
)
from sdn_ddos.lab.events import EventJournal, utc_now
from sdn_ddos.lab.repository import Repository
from sdn_ddos.lab.runtime import MininetRuntime

LOGGER = logging.getLogger(__name__)
ACTIVE = {"starting", "running", "baseline", "attack", "recovery", "stopping"}


class LabManager:
    def __init__(
        self,
        repository: Repository,
        runtime_factory: Callable[..., Any] = MininetRuntime,
    ) -> None:
        self.repository = repository
        self.runtime_factory = runtime_factory
        self.runtime: Any = None
        self.journal = EventJournal()
        self.state = "idle"
        self.run_id: Optional[str] = None
        self.persistence_error = False
        self.cleanup_error = False
        self.stop_event = threading.Event()
        self.lock = threading.RLock()
        self.thread: Optional[threading.Thread] = None
        self.probe_index = 0

    def status(self) -> dict[str, Any]:
        with self.lock:
            return {
                "state": self.state,
                "run_id": self.run_id,
                "persistence_error": self.persistence_error,
                "cleanup_error": self.cleanup_error,
            }

    def events(self, after: int) -> dict[str, Any]:
        return self.journal.since(after)

    def start(self, request: StartRequest) -> str:
        request.topology.validate_targets()
        if request.experiment:
            validate_experiment(request.topology, request.experiment)
        with self.lock:
            if self.cleanup_error:
                raise ValueError(
                    "cleanup failed; recreate the runner container "
                    "before starting again"
                )
            if self.state in ACTIVE or (self.thread and self.thread.is_alive()):
                raise ValueError("a lab is already running; stop it first")
            self.repository.health()
            identifier = str(uuid4())
            self.repository.create_run(
                {
                    "id": identifier,
                    "topology": request.topology.model_dump(),
                    "settings": request.experiment.model_dump()
                    if request.experiment
                    else None,
                }
            )
            self.run_id = identifier
            self.state = "starting"
            self.persistence_error = False
            self.stop_event = threading.Event()
            self.journal = EventJournal(identifier, persist=self._persist)
            self.runtime = None
            self.thread = threading.Thread(
                target=self._run, args=(request,), daemon=True
            )
            self.thread.start()
            return identifier

    def _persist(self, event: dict[str, Any]) -> None:
        try:
            self.repository.append_event(event)
        except Exception:
            self.persistence_error = True
            self.stop_event.set()
            raise

    def _phase(self, state: str) -> None:
        with self.lock:
            self.state = state
        self.journal.emit("phase", {"state": state})

    def _observe(self, seconds: float, request: StartRequest) -> None:
        deadline = time.monotonic() + seconds
        next_probe = 0.0
        pairs = (
            probe_pairs(request.topology, request.experiment)
            if request.experiment
            else []
        )
        while not self.stop_event.is_set() and time.monotonic() < deadline:
            tick = time.monotonic()
            self.runtime.sample()
            if pairs and tick >= next_probe:
                # One probe per interval, cycling client→victim pairs, so probing
                # cost never grows with the size of the experiment.
                client, target = pairs[self.probe_index % len(pairs)]
                self.probe_index += 1
                self.runtime.probe(client, target)
                next_probe = tick + 3
            self.stop_event.wait(
                max(0, min(1 - (time.monotonic() - tick), deadline - time.monotonic()))
            )

    def _run(self, request: StartRequest) -> None:
        result = "stopped"
        try:
            self.journal.emit("phase", {"state": "starting"})
            self.runtime = self.runtime_factory(
                request.topology,
                self.run_id,
                bool(request.experiment and request.experiment.mitigation),
                self.journal.emit,
            )
            self.runtime.start()
            experiment = request.experiment
            if self.stop_event.is_set():
                return
            if experiment is None:
                self._phase("running")
                # Observation sessions also have a declared lifetime.
                self.journal.emit("session_limit", {"seconds": 3600})
                self._observe(3600, request)
            else:
                self.runtime.serve(experiment.victims)
                self._phase("baseline")
                self._observe(experiment.baseline, request)
                if self.stop_event.is_set():
                    return
                self._phase("attack")
                if self.stop_event.is_set():
                    return
                attack_deadline = time.monotonic() + experiment.duration
                processes = self.runtime.attack(experiment)
                self.journal.emit(
                    "attack_started",
                    dict(
                        experiment.model_dump(),
                        observed_at=min(
                            (p.started_at for p in processes), default=utc_now()
                        ),
                    ),
                )
                try:
                    self._observe(max(0, attack_deadline - time.monotonic()), request)
                finally:
                    for process in processes:
                        process.close()
                    self.runtime.attack_processes = []
                    self.journal.emit(
                        "attack_stopped",
                        {
                            "sources": experiment.attackers,
                            "targets": experiment.victims,
                            "observed_at": max(
                                (p.ended_at for p in processes if p.ended_at),
                                default=utc_now(),
                            ),
                        },
                    )
                # We deliberately tear the generators down at the deadline, so a
                # signal death (negative code) or the bounded `timeout` (124/137)
                # is expected. Only a positive, non-124 exit is the generator
                # reporting a real error of its own.
                broken = [
                    p
                    for p in processes
                    if (p.process.returncode or 0) > 0
                    and p.process.returncode not in (124, 137, 143)
                ]
                if broken and not self.stop_event.is_set():
                    raise RuntimeError(
                        f"traffic generator on {broken[0].node} exited with "
                        f"code {broken[0].process.returncode}"
                    )
                if self.stop_event.is_set():
                    return
                self._phase("recovery")
                self._observe(experiment.recovery, request)
                if not self.stop_event.is_set():
                    result = "completed"
        except Exception as error:
            LOGGER.exception("Lab run failed")
            result = "failed"
            with contextlib.suppress(Exception):
                self.journal.emit(
                    "error",
                    {
                        "message": "The lab stopped because a component failed. "
                        "Check commands and service logs; this run is not successful.",
                        # The exact reason, shown to the local operator so a failed
                        # run can be debugged without digging through the log.
                        "detail": str(error) or error.__class__.__name__,
                    },
                )
        finally:
            if self.runtime:
                try:
                    self.runtime.close()
                    self.runtime.drain()
                except Exception:
                    LOGGER.exception("Lab cleanup failed")
                    self.cleanup_error = True
                    result = "failed"
            if self.persistence_error:
                result = "failed"
                self.journal.persist = None
                self.journal.emit(
                    "error",
                    {
                        "message": "Database recording failed. The experiment was "
                        "stopped; history may be incomplete."
                    },
                )
            try:
                self.journal.emit("phase", {"state": result})
                if self.run_id:
                    self.repository.finish_run(self.run_id, result)
            except Exception:
                self.persistence_error = True
                result = "failed"
                LOGGER.exception("Could not finalize run history")
            with self.lock:
                self.state = result

    def stop(self) -> None:
        with self.lock:
            if self.state in ACTIVE:
                self.state = "stopping"
                self.stop_event.set()

    def close(self) -> None:
        self.stop()
        if self.thread:
            self.thread.join(timeout=30)

    def diagnostic(self, request: Diagnostic) -> None:
        if self.state != "running":
            raise ValueError("diagnostics are available in observation mode only")
        self.runtime.diagnostic(request)

    def capture(self, request: Capture) -> None:
        if self.state not in {"running", "baseline", "attack", "recovery"}:
            raise ValueError("start a lab before capturing packets")
        self.runtime.capture(request)
