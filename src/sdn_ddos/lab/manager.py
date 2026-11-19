"""Single-run orchestration with bounded deadlines and optional browser ownership."""

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
from sdn_ddos.lab.detection_settings import DetectorClient, victim_addresses
from sdn_ddos.lab.events import EventJournal, utc_now
from sdn_ddos.lab.measurements import checks_due
from sdn_ddos.lab.ownership import OwnerLeases
from sdn_ddos.lab.provenance import repository_commit, settings_fingerprint
from sdn_ddos.lab.repository import Repository
from sdn_ddos.lab.runtime import MininetRuntime

LOGGER = logging.getLogger(__name__)
ACTIVE = {"starting", "running", "baseline", "attack", "recovery", "stopping"}


class LabManager:
    def __init__(
        self,
        repository: Repository,
        runtime_factory: Callable[..., Any] = MininetRuntime,
        detector: Optional[DetectorClient] = None,
    ) -> None:
        self.repository = repository
        self.detector = detector
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
        self.probe_thread: Optional[threading.Thread] = None
        self.probe_stop = threading.Event()
        self.probe_index = 0
        self.runner_instance_id = str(uuid4())
        self.owners = OwnerLeases()
        self.owner_id: Optional[str] = None
        self.started_at: Optional[str] = None
        self.ended_at: Optional[str] = None
        self.started_clock = 0.0
        self.finished_elapsed = 0.0
        self.unavailable = False

    def status(self) -> dict[str, Any]:
        with self.lock:
            return {
                "state": self.state,
                "run_id": self.run_id,
                "persistence_error": self.persistence_error,
                "cleanup_error": self.cleanup_error,
                "runner_instance_id": self.runner_instance_id,
                "started_at": self.started_at,
                "ended_at": self.ended_at,
                "elapsed_ms": self._elapsed(),
                "unavailable": self.unavailable,
            }

    def _elapsed(self) -> float:
        if self.started_at is None:
            return 0.0
        if self.ended_at is not None:
            return self.finished_elapsed
        return max(0.0, (time.monotonic() - self.started_clock) * 1000)

    def events(self, after: int, run_id: Optional[str] = None) -> dict[str, Any]:
        with self.lock:
            if run_id is not None and run_id != self.run_id:
                after = 0
            return {**self.journal.since(after), "status": self.status()}

    def create_owner(self) -> str:
        with self.lock:
            if self.unavailable:
                raise ValueError("runner ownership was lost; restart the service")
            return self.owners.create()

    def renew_owner(self, owner: str) -> None:
        with self.lock:
            self.owners.renew(owner)

    def release_owner(self, owner: str, reason: str = "browser disconnected") -> None:
        with self.lock:
            self.owners.release(owner)
            if self.owner_id == owner:
                self.stop(reason)

    def expire_owners(self) -> None:
        with self.lock:
            for owner in self.owners.expired():
                self.release_owner(owner, "browser ownership expired")

    def lose_ownership(self) -> None:
        with self.lock:
            self.unavailable = True
            self.stop("runner database ownership lost")

    def start(self, request: StartRequest) -> str:
        request.topology.validate_targets()
        if request.experiment:
            validate_experiment(request.topology, request.experiment)
        with self.lock:
            if self.unavailable:
                raise ValueError("runner ownership was lost; restart the service")
            if self.cleanup_error:
                raise ValueError(
                    "cleanup failed; recreate the runner container "
                    "before starting again"
                )
            if self.state in ACTIVE or (self.thread and self.thread.is_alive()):
                raise ValueError("a lab is already running; stop it first")
            owner = str(request.owner_id) if request.owner_id is not None else None
            if owner is not None:
                self.owners.require(owner)
            self.repository.health()
            detection = request.experiment.detection if request.experiment else None
            if detection is not None:
                if self.detector is None:
                    raise ValueError(
                        "this lab has no detector service to configure; start it "
                        "with docker compose up or run without a detection "
                        "setting"
                    )
                # Done only after the busy checks above, so a running experiment's
                # detector is never changed under it.
                self.detector.apply(detection)
            identifier = str(uuid4())
            if owner is not None:
                self.owners.require(owner)
            started_at = utc_now()
            self.repository.create_run(
                {
                    "id": identifier,
                    "started_at": started_at,
                    "topology": request.topology.model_dump(),
                    "settings": self._settings(request),
                }
            )
            self.run_id = identifier
            self.owner_id = owner
            self.started_at = started_at
            self.ended_at = None
            self.started_clock = time.monotonic()
            self.finished_elapsed = 0.0
            self.state = "starting"
            self.persistence_error = False
            self.stop_event = threading.Event()
            self.journal = EventJournal(identifier, persist=self._persist)
            self.runtime = None
            self.probe_thread = None
            self.probe_stop = threading.Event()
            self.thread = threading.Thread(
                target=self._run, args=(request,), daemon=True
            )
            self.thread.start()
            return identifier

    @staticmethod
    def _settings(request: StartRequest) -> dict[str, Any]:
        settings = (
            request.experiment.model_dump() if request.experiment is not None else {}
        )
        settings["forwarding"] = request.forwarding
        return settings

    def detection_options(self) -> dict[str, Any]:
        """What the workspace may offer: the detector's current setup and its LLMs."""

        if self.detector is None:
            return {
                "available": False,
                "reason": "this lab was started without a detector service",
            }
        try:
            current = self.detector.config()
        except ValueError as error:
            return {"available": False, "reason": str(error)}
        result: dict[str, Any] = {"available": True, "current": current, "models": []}
        try:
            result["models"] = self.detector.models()
        except ValueError as error:
            result["models_error"] = str(error)
        return result

    def _announce_detection(self, request: StartRequest) -> None:
        """Record which detector judged this run, so a replay shows its criteria."""

        experiment = request.experiment
        code = repository_commit()
        if experiment is None:
            self.journal.emit(
                "detection_config",
                {
                    "source": "observation",
                    "forwarding": request.forwarding,
                    "repository_commit": code["commit"],
                    "repository_branch": code["branch"],
                },
            )
            return
        if experiment.detection is not None:
            data: dict[str, Any] = {"source": "experiment"}
            data.update(experiment.detection.model_dump())
        elif self.detector is not None:
            try:
                data = {"source": "detector-service", **self.detector.config()}
            except ValueError:
                data = {"source": "detector-service"}
        else:
            data = {"source": "unconfigured"}
        if experiment.detection is not None and self.detector is not None:
            # What the detector service reports about itself (prompt text hash,
            # Ollama version, model digest), so a frozen prompt can be checked.
            try:
                service = self.detector.config()
            except ValueError:
                service = {}
            for key in (
                "prompt_sha256",
                "ollama_version",
                "model_details",
                "llm_backend",
                "cloud_endpoints",
            ):
                if key in service:
                    data[f"detector_{key}"] = service[key]
        data["mitigation"] = experiment.mitigation
        data["forwarding"] = request.forwarding
        data["protected_hosts"] = victim_addresses(request.topology, experiment)
        data["purpose"] = experiment.purpose
        data["scenario"] = experiment.scenario
        data["settings_fingerprint"] = settings_fingerprint(
            experiment.detection, request.forwarding
        )
        data["repository_commit"] = code["commit"]
        data["repository_branch"] = code["branch"]
        self.journal.emit("detection_config", data)

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
        """Sample once a second. Website checks run on their own thread."""

        deadline = time.monotonic() + seconds
        while not self.stop_event.is_set() and time.monotonic() < deadline:
            tick = time.monotonic()
            self.runtime.sample()
            self.stop_event.wait(
                max(0, min(1 - (time.monotonic() - tick), deadline - time.monotonic()))
            )

    def _service_checks(self, request: StartRequest, deadline: float) -> None:
        experiment = request.experiment
        if experiment is None:
            return
        pairs = probe_pairs(request.topology, experiment)
        next_at = time.monotonic()
        index = 0
        while not self.stop_event.is_set() and not self.probe_stop.is_set():
            now = time.monotonic()
            if now >= deadline:
                return
            due, next_at, index = checks_due(
                now,
                next_at,
                index,
                pairs,
                deadline,
                self.stop_event.is_set() or self.probe_stop.is_set(),
            )
            for client, target in due:
                self.runtime.start_probe(client, target, utc_now())
            remaining = min(deadline, next_at) - time.monotonic()
            if remaining > 0 and self.stop_event.wait(min(remaining, 0.2)):
                return
            if self.probe_stop.is_set():
                return

    def _start_service_checks(self, request: StartRequest, seconds: float) -> None:
        if request.experiment is None:
            return
        if not probe_pairs(request.topology, request.experiment):
            return
        self.probe_stop = threading.Event()
        deadline = time.monotonic() + seconds
        self.probe_thread = threading.Thread(
            target=self._service_checks,
            args=(request, deadline),
            name="service-checks",
            daemon=True,
        )
        self.probe_thread.start()

    def _stop_service_checks(self) -> None:
        self.probe_stop.set()
        thread = self.probe_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)

    def _stop_measurements(self) -> None:
        self._stop_service_checks()
        runtime = self.runtime
        if runtime is not None and hasattr(runtime, "stop_pings"):
            runtime.stop_pings()

    def _run(self, request: StartRequest) -> None:
        result = "stopped"
        try:
            self.journal.emit(
                "phase", {"state": "starting", "observed_at": self.started_at}
            )
            self._announce_detection(request)
            extra: dict[str, Any] = {}
            if request.experiment and request.experiment.detection is not None:
                extra["detection"] = request.experiment.detection
            if request.experiment and request.experiment.flow_table_limit is not None:
                extra["flow_table_limit"] = request.experiment.flow_table_limit
            if request.experiment:
                extra["protected_hosts"] = victim_addresses(
                    request.topology, request.experiment
                )
            self.runtime = self.runtime_factory(
                request.topology,
                self.run_id,
                bool(request.experiment and request.experiment.mitigation),
                self.journal.emit,
                forwarding=request.forwarding,
                **extra,
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
                span = experiment.baseline + experiment.duration + experiment.recovery
                self._start_service_checks(request, span)
                self.runtime.start_pings(experiment)
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
                self._stop_measurements()
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
            self._stop_measurements()
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
                self.finished_elapsed = self._elapsed()
                self.ended_at = utc_now()
                self.state = result

    def stop(self, reason: str = "operator stopped the lab") -> None:
        with self.lock:
            if self.state in ACTIVE and not self.stop_event.is_set():
                self.state = "stopping"
                self.stop_event.set()
                # Cleanup must still happen when recording the reason fails.
                with contextlib.suppress(Exception):
                    self.journal.emit("stop_requested", {"reason": reason})

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
