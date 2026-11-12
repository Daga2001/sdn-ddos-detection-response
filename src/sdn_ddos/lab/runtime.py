"""Linux/Mininet boundary. Importing this module needs neither Mininet nor root."""

from __future__ import annotations

import contextlib
import functools
import json
import os
import platform
import queue
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Optional

import psutil
import requests

from sdn_ddos.config import ControllerSettings, validate_lab_target
from sdn_ddos.experiments.attack_launcher import build_hping_command
from sdn_ddos.lab.contracts import (
    Capture,
    DetectionConfig,
    Diagnostic,
    Experiment,
    attack_plan,
    legitimate_clients,
)
from sdn_ddos.lab.detection_settings import controller_env as controller_env_for
from sdn_ddos.lab.events import RateCounters, utc_now
from sdn_ddos.lab.measurements import (
    PingTracker,
    forwarding_flag,
    parse_curl_probe,
    read_system,
)
from sdn_ddos.lab.processes import Emit, ManagedProcess
from sdn_ddos.lab.telemetry import grow_buffer
from sdn_ddos.lab.topology import Topology

CONTROLLER_KINDS = frozenset(
    {
        "controller",
        "flows",
        "detection",
        "mitigation_requested",
        "entropy_window",
        "switch_table",
        "decision_cost",
    }
)
INBOX_LIMIT = 20000
DGRAM_QUEUE = 4096
DGRAM_QUEUE_SYSCTL = Path("/proc/sys/net/unix/max_dgram_qlen")
SAMPLE_EVENT_LIMIT = 5000

PACKET_FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "udp.srcport",
    "udp.dstport",
    "icmp.type",
    "arp.opcode",
]


def packet_summary(line: str) -> Optional[dict[str, str]]:
    fields = line.rstrip("\r\n").split("\t")
    if len(fields) != len(PACKET_FIELDS):
        return None
    try:
        float(fields[0])
    except ValueError:
        return None
    return dict(zip(PACKET_FIELDS, fields))


def widen_dgram_queue(length: int = DGRAM_QUEUE) -> int:
    """Let a datagram socket queue more than the container's default of 10 messages.

    The limit is read when the socket is created, so this runs first. It only touches
    this container's network namespace and is best effort: without the privilege the
    listener thread alone keeps up with most bursts.
    """

    try:
        current = int(DGRAM_QUEUE_SYSCTL.read_text())
        if current < length:
            DGRAM_QUEUE_SYSCTL.write_text(str(length))
            current = length
        return current
    except (OSError, ValueError):
        return 0


class MininetRuntime:
    def __init__(
        self,
        topology: Topology,
        run_id: str,
        mitigation: bool,
        emit: Emit,
        detection: Optional[DetectionConfig] = None,
        *,
        forwarding: str,
    ) -> None:
        self.topology = topology
        self.run_id = run_id
        self.emit = emit
        self.mitigation = mitigation
        self.detection = detection
        self.forwarding = forwarding
        self.network: Any = None
        self.processes: list[ManagedProcess] = []
        self.controller: Optional[ManagedProcess] = None
        self.capture_process: Optional[ManagedProcess] = None
        self.attack_processes: list[ManagedProcess] = []
        self.service_processes: list[ManagedProcess] = []
        self.ping_processes: list[ManagedProcess] = []
        self.ping_trackers: list[PingTracker] = []
        self.probe_processes: list[Any] = []
        self.interfaces: dict[str, str] = {}
        self.counters = RateCounters()
        self.temp = tempfile.TemporaryDirectory(prefix="sdn-lab-")
        widen_dgram_queue()
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.socket.setblocking(False)
        grow_buffer(self.socket, socket.SO_RCVBUF)
        self.socket_path = str(Path(self.temp.name) / "telemetry.sock")
        self.socket.bind(self.socket_path)
        self.lock = threading.RLock()
        self.queue: queue.Queue[tuple[str, dict[str, Any]]] = queue.Queue(maxsize=1024)
        self.dropped = 0
        # Controller datagrams read off the socket, waiting for the next sample. The
        # kernel keeps only `net.unix.max_dgram_qlen` of them (10 in the runner
        # container), so a listener thread empties the socket as they arrive.
        self.inbox: deque[dict[str, Any]] = deque(maxlen=INBOX_LIMIT)
        self.inbox_lost = 0
        self.listener: Optional[threading.Thread] = None
        self.last_health = 0.0
        self.last_rules = 0.0
        self.closed = False

    def enqueue(self, kind: str, data: dict[str, Any]) -> None:
        data = dict(data)
        data.setdefault("observed_at", utc_now())
        try:
            self.queue.put_nowait((kind, data))
        except queue.Full:
            self.dropped += 1

    def versions(self) -> dict[str, str]:
        from mininet.net import VERSION

        result = {
            "python": platform.python_version(),
            "kernel": platform.release(),
            "mininet": VERSION,
            "ryu": "4.34",
            "poll_interval_seconds": os.environ.get("SDN_POLL_INTERVAL", "5"),
            "model_sha256": os.environ.get("DDOS_MODEL_SHA256") or "not_configured",
        }
        result["ovs"] = subprocess.check_output(
            ["ovs-vsctl", "--version"], text=True, timeout=3
        ).splitlines()[0]
        return result

    def start(self) -> None:
        from mininet.link import TCLink
        from mininet.net import Mininet
        from mininet.node import OVSSwitch, RemoteController

        if os.environ.get("SDN_LAB_RUNNER") != "1":
            raise RuntimeError(
                "Mininet runtime is only enabled in the dedicated lab runner"
            )
        self.topology.validate_targets()
        self.listener = threading.Thread(
            target=self._listen, name="telemetry-listener", daemon=True
        )
        self.listener.start()
        controller_env = dict(
            os.environ,
            SDN_TELEMETRY_SOCKET=self.socket_path,
            SDN_RUN_ID=self.run_id,
            SDN_MITIGATION_ENABLED=str(self.mitigation).lower(),
            SDN_MATCH_L4_PORTS=forwarding_flag(self.forwarding),
        )
        if self.detection is not None:
            controller_env.update(controller_env_for(self.detection))
        self.controller = self._spawn(
            [
                os.environ.get("SDN_RYU_MANAGER", "/opt/ryu/bin/ryu-manager"),
                "--ofp-tcp-listen-port",
                "6653",
                "--ofp-listen-host",
                "127.0.0.1",
                "sdn_ddos.controller.app",
            ],
            "controller",
            env=controller_env,
        )
        deadline = time.monotonic() + 15
        while True:
            if self.controller.process.poll() is not None:
                raise RuntimeError("Ryu could not start; inspect command output")
            try:
                with socket.create_connection(("127.0.0.1", 6653), timeout=0.25):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise RuntimeError(
                        "Ryu did not open its OpenFlow listener"
                    ) from None
                time.sleep(0.1)
        self.network = Mininet(
            controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True
        )
        self.network.addController(
            "c0", controller=RemoteController, ip="127.0.0.1", port=6653
        )
        for switch in self.topology.switches:
            self.network.addSwitch(
                switch.name,
                dpid=f"{switch.dpid:016x}",
                protocols="OpenFlow13",
                failMode="secure",
            )
        for host in self.topology.hosts:
            self.network.addHost(host.name, ip=host.ip)
        switch_names = {switch.name for switch in self.topology.switches}
        for link in self.topology.links:
            options: dict[str, Any] = {
                "delay": f"{link.delay_ms}ms",
                "loss": link.loss_percent,
            }
            if link.bandwidth_mbps is not None:
                options["bw"] = link.bandwidth_mbps
            created = self.network.addLink(link.source, link.target, **options)
            interface = created.intf1 if link.source in switch_names else created.intf2
            self.interfaces[link.id] = interface.name
        self.network.start()
        self.enqueue("versions", self.versions())

    def _spawn(
        self,
        command: list[str],
        node: str,
        *,
        env: Optional[dict[str, str]] = None,
        line_handler: Any = None,
    ) -> ManagedProcess:
        self.processes = [
            p for p in self.processes if p.process.poll() is None or p.reader.is_alive()
        ]
        spawn: Any = subprocess.Popen
        if self.network is not None and node in {
            host.name for host in self.topology.hosts
        }:
            host = self.network.get(node)
            # Mininet's default mnexec -d detaches a session leader and makes
            # Popen track the exited wrapper, not our owned process group.
            spawn = functools.partial(host.popen, mncmd=["mnexec", "-a", str(host.pid)])
        process = ManagedProcess(
            command, node, self.enqueue, spawn=spawn, env=env, line_handler=line_handler
        )
        self.processes.append(process)
        return process

    def address(self, host_name: str) -> str:
        host = next(
            (host for host in self.topology.hosts if host.name == host_name), None
        )
        if host is None:
            raise ValueError("select a host in this topology")
        return str(
            validate_lab_target(
                host.ip.split("/")[0],
                ControllerSettings.from_env().allowed_target_networks,
            )
        )

    def serve(self, targets: list[str]) -> None:
        self.service_processes = [
            self._spawn(
                [
                    sys.executable,
                    "-m",
                    "sdn_ddos.lab.service",
                    "--bind",
                    self.address(target),
                ],
                target,
            )
            for target in targets
        ]

    def attack(self, experiment: Experiment) -> list[ManagedProcess]:
        self.attack_processes = [
            self._spawn(
                [
                    "timeout",
                    "--signal=TERM",
                    "--kill-after=2",
                    str(experiment.duration),
                    *build_hping_command(
                        self.address(victim),
                        8080,
                        experiment.rate,
                        experiment.duration,
                        kind,
                    ),
                ],
                attacker,
            )
            for attacker, victim, kind in attack_plan(experiment)
        ]
        return self.attack_processes

    def start_probe(self, client: str, target: str, started_at: str) -> None:
        """One website check on its own thread. The sampler never waits for it."""

        thread = threading.Thread(
            target=self.probe,
            args=(client, target, started_at),
            name="service-check",
            daemon=True,
        )
        thread.start()

    def probe(self, client: str, target: str, started_at: Optional[str] = None) -> None:
        command = [
            "curl",
            "--silent",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code} %{time_connect} %{time_total}",
            "--max-time",
            "2",
            "--noproxy",
            "*",
            f"http://{self.address(target)}:8080/",
        ]
        started_at = started_at or utc_now()
        process = self.network.get(client).popen(
            command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        with self.lock:
            self.probe_processes.append(process)
        output = b""
        try:
            if self.closed:
                process.kill()
                process.wait()
                return
            output, _ = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            output = b""
        finally:
            with self.lock:
                if process in self.probe_processes:
                    self.probe_processes.remove(process)
        if self.closed:
            return
        parsed = parse_curl_probe(output.decode(errors="replace"), process.returncode)
        self.emit(
            "service",
            {
                "client": client,
                "target": target,
                "success": parsed["success"],
                "latency_ms": parsed["latency_ms"],
                "connect_ms": parsed["connect_ms"],
                "http_code": parsed["http_code"],
                "argv": command,
                "observed_at": started_at,
            },
        )

    def start_pings(self, experiment: Experiment) -> None:
        """5 ICMP/s from the first legitimate client to each victim, for the run."""

        clients = legitimate_clients(self.topology, experiment)
        if not clients:
            return
        client = clients[0]
        deadline = experiment.baseline + experiment.duration + experiment.recovery + 5
        for victim in experiment.victims:
            tracker = PingTracker(client, victim, time.monotonic())
            self.ping_trackers.append(tracker)
            command = [
                "ping",
                "-n",
                "-i",
                "0.2",
                "-W",
                "1",
                "-w",
                str(deadline),
                self.address(victim),
            ]
            self.ping_processes.append(
                self._spawn(command, client, line_handler=tracker.feed)
            )

    def stop_pings(self) -> None:
        for process in self.ping_processes:
            process.close()
        self.ping_processes = []

    def sample(self) -> None:
        if any(
            service.process.poll() is not None for service in self.service_processes
        ):
            raise RuntimeError("victim service stopped unexpectedly")
        # A generator that is still running polls None; one we tore down exits via
        # a signal (negative code) or the bounded `timeout` (124). Only a positive,
        # non-124 exit is the generator itself reporting an error (e.g. 127 when
        # hping3 is missing), so treat just that as a real failure.
        for attack in self.attack_processes:
            code = attack.process.poll()
            if code is not None and code > 0 and code != 124:
                raise RuntimeError(
                    f"traffic generator on {attack.node} exited with code {code}"
                )
        if self.controller and self.controller.process.poll() is not None:
            raise RuntimeError("controller stopped unexpectedly")
        now = time.monotonic()
        rows = json.loads(
            subprocess.check_output(
                ["ip", "-j", "-s", "link", "show"], text=True, timeout=3
            )
        )
        interfaces = {row["ifname"]: row for row in rows}
        rates = []
        for link_id, interface in self.interfaces.items():
            row = interfaces.get(interface)
            if row:
                stats = row.get("stats64", row.get("stats", {}))
                rate = self.counters.observe(
                    link_id,
                    int(stats["rx"]["bytes"]),
                    int(stats["tx"]["bytes"]),
                    now,
                    int(stats["rx"].get("packets", 0)),
                    int(stats["tx"].get("packets", 0)),
                )
                rates.append(
                    {"link_id": link_id, "interface": interface, "rates": rate}
                )
        self.emit("links", {"links": rates, "interval_seconds": 1})
        for tracker in self.ping_trackers:
            for event in tracker.take(now):
                self.emit("ping", event)
        try:
            self.emit("system", read_system(psutil))
        except Exception:
            self.emit(
                "system",
                {
                    "cpu_percent": None,
                    "ovs_cpu_percent": None,
                    "ovs_rss_bytes": None,
                },
            )
        self.pump()
        for _ in range(SAMPLE_EVENT_LIMIT):
            try:
                payload = self.inbox.popleft()
            except IndexError:
                break
            if payload.get("dropped"):
                self.emit("gap", {"count": payload["dropped"], "source": "controller"})
            self.emit(payload["kind"], payload["data"])
        if self.inbox_lost:
            self.emit("gap", {"count": self.inbox_lost, "source": "runner"})
            self.inbox_lost = 0
        self.drain()
        if self.mitigation and now - self.last_rules >= 5:
            self.last_rules = now
            for switch in self.topology.switches:
                command = ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch.name]
                output = subprocess.check_output(command, text=True, timeout=2)
                rules = [
                    line.strip()
                    for line in output.splitlines()
                    if "priority=100," in line and "actions=drop" in line
                ]
                self.emit(
                    "mitigation_observed",
                    {"switch": switch.name, "rules": rules[:100], "argv": command},
                )
        if now - self.last_health >= 5:
            self.last_health = now
            try:
                url = (
                    os.environ.get(
                        "SDN_DDOS_SERVICE_URL", "http://inference:8000/predict"
                    ).rsplit("/", 1)[0]
                    + "/health"
                )
                response = requests.get(
                    url,
                    timeout=(0.5, 1),
                    headers={"X-Api-Key": os.environ.get("SDN_DDOS_API_KEY", "")},
                )
                response.raise_for_status()
                self.emit(
                    "detector", {"status": response.json().get("status", "not_ready")}
                )
            except (requests.RequestException, ValueError):
                self.emit("detector", {"status": "unavailable"})

    def pump(self) -> None:
        """Move every datagram waiting on the telemetry socket into the inbox."""

        while True:
            try:
                payload = json.loads(self.socket.recv(65536))
            except ValueError:
                continue  # not JSON: skip it and keep reading
            except OSError:
                return  # nothing waiting (or the socket is closed)
            if (
                isinstance(payload, dict)
                and payload.get("run_id") == self.run_id
                and payload.get("kind") in CONTROLLER_KINDS
            ):
                if len(self.inbox) == INBOX_LIMIT:
                    self.inbox_lost += 1
                self.inbox.append(payload)

    def _listen(self) -> None:
        while not self.closed:
            try:
                select.select([self.socket], [], [], 0.2)
            except (TypeError, ValueError, OSError):
                # A closed socket ends the run; anything else is retried shortly.
                time.sleep(0.05)
                continue
            try:
                self.pump()
            except Exception:  # the listener must outlive odd datagrams
                time.sleep(0.05)

    def drain(self) -> None:
        packets = []
        for _ in range(256):
            try:
                kind, data = self.queue.get_nowait()
            except queue.Empty:
                break
            if kind == "packet":
                packets.append(data)
            else:
                self.emit(kind, data)
        if packets:
            self.emit("packets", {"items": packets})
        if self.dropped:
            self.emit("gap", {"count": self.dropped, "source": "command/capture"})
            self.dropped = 0

    def diagnostic(self, request: Diagnostic) -> None:
        with self.lock:
            if self.closed or self.network is None:
                raise ValueError("start a lab before running diagnostics")
            hosts = {host.name for host in self.topology.hosts}
            if request.action == "flows":
                if request.node not in {
                    switch.name for switch in self.topology.switches
                }:
                    raise ValueError("select a switch")
                command = ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", request.node]
            elif request.action == "interfaces":
                if request.node not in hosts:
                    raise ValueError("select a host")
                command = ["ip", "-j", "address", "show"]
            else:
                if request.node not in hosts or request.target not in hosts:
                    raise ValueError("select two hosts in this topology")
                command = [
                    "ping",
                    "-n",
                    "-c",
                    "3",
                    "-W",
                    "1",
                    self.address(request.target),
                ]
            process = self._spawn(command, request.node)
            try:
                process.wait(5)
            finally:
                process.close()

    def capture(self, request: Capture) -> None:
        with self.lock:
            if self.closed or request.link_id not in self.interfaces:
                raise ValueError("select a link in the running topology")
            if self.capture_process and self.capture_process.process.poll() is None:
                raise ValueError("a packet capture is already running")
            command = [
                "tshark",
                "-n",
                "-l",
                "-i",
                self.interfaces[request.link_id],
                "-a",
                f"duration:{request.duration}",
                "-c",
                str(request.packets),
                "-s",
                "256",
                "-T",
                "fields",
                "-E",
                "occurrence=f",
            ]
            if request.protocol != "all":
                command += ["-f", request.protocol]
            for field in PACKET_FIELDS:
                command += ["-e", field]

            def handle_line(line: str) -> None:
                packet = packet_summary(line)
                if packet:
                    self.enqueue(
                        "packet", {"link_id": request.link_id, "headers": packet}
                    )
                elif line:
                    self.enqueue("capture_message", {"text": line[:500]})

            self.capture_process = self._spawn(
                command, "capture", line_handler=handle_line
            )
            self.enqueue(
                "capture_started",
                {
                    "link_id": request.link_id,
                    "duration": request.duration,
                    "packet_limit": request.packets,
                    "snaplen": 256,
                },
            )

    def close(self) -> None:
        with self.lock:
            if self.closed:
                return
            self.closed = True
            for process in list(self.probe_processes):
                with contextlib.suppress(Exception):
                    process.kill()
            errors = []
            if (
                self.listener is not None
                and self.listener is not threading.current_thread()
            ):
                self.listener.join(timeout=1)
            cleanup = [process.close for process in reversed(self.processes)]
            if self.network is not None:
                cleanup.append(self.network.stop)
            cleanup.extend([self.socket.close, self.temp.cleanup])
            for operation in cleanup:
                try:
                    operation()
                except Exception as error:
                    errors.append(error)
            if errors:
                raise RuntimeError(
                    "one or more lab resources could not be cleaned up"
                ) from errors[0]
