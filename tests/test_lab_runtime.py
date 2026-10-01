import json
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from sdn_ddos.lab import runtime as module
from sdn_ddos.lab.contracts import Capture, Diagnostic, Experiment
from sdn_ddos.lab.runtime import PACKET_FIELDS, MininetRuntime, packet_summary
from sdn_ddos.lab.topology import presets


@pytest.fixture
def runtime(monkeypatch):
    channel = MagicMock()
    channel.recv.side_effect = BlockingIOError
    monkeypatch.setattr(module.socket, "socket", lambda *args: channel)
    events = []
    lab = MininetRuntime(presets()[2], "run", False, lambda k, d: events.append((k, d)))
    lab.events = events
    yield lab
    lab.close()


def test_header_parser_never_retains_payload():
    assert packet_summary("bad") is None
    assert packet_summary("\t".join(["bad"] * len(PACKET_FIELDS))) is None
    parsed = packet_summary("\t".join(["1"] * len(PACKET_FIELDS)))
    assert set(parsed) == set(PACKET_FIELDS)
    assert not any("payload" in field for field in parsed)


def test_start_boundary_and_cleanup(runtime, monkeypatch):
    network = MagicMock()
    network.addLink.return_value = SimpleNamespace(
        intf1=SimpleNamespace(name="s1-eth1")
    )
    monkeypatch.setitem(sys.modules, "mininet.link", SimpleNamespace(TCLink=object))
    monkeypatch.setitem(
        sys.modules,
        "mininet.net",
        SimpleNamespace(Mininet=lambda **kw: network, VERSION="test"),
    )
    monkeypatch.setitem(
        sys.modules,
        "mininet.node",
        SimpleNamespace(OVSSwitch=object, RemoteController=object),
    )
    with pytest.raises(RuntimeError, match="dedicated"):
        runtime.start()
    monkeypatch.setenv("SDN_LAB_RUNNER", "1")
    monkeypatch.setattr(module.socket, "create_connection", MagicMock())
    monkeypatch.setattr(
        module.subprocess, "check_output", lambda *a, **kw: "OVS test\n"
    )
    fake = MagicMock()
    fake.process.poll.return_value = None
    constructor = MagicMock(return_value=fake)
    monkeypatch.setattr(module, "ManagedProcess", constructor)
    runtime.start()
    assert constructor.call_args.args[0][1:3] == ["--ofp-tcp-listen-port", "6653"]
    assert constructor.call_args.kwargs["env"]["SDN_MITIGATION_ENABLED"] == "false"
    assert network.addHost.call_count == 3
    assert network.addSwitch.call_args.kwargs["protocols"] == "OpenFlow13"
    runtime.close()
    runtime.close()
    network.stop.assert_called_once()
    fake.close.assert_called_once()


def test_guided_commands_and_capture(runtime, monkeypatch):
    fake = MagicMock()
    fake.process.poll.return_value = 0
    fake.reader.is_alive.return_value = False
    constructor = MagicMock(return_value=fake)
    monkeypatch.setattr(module, "ManagedProcess", constructor)
    runtime.network = MagicMock()
    runtime.interfaces = {"link-1": "s1-eth1"}
    with pytest.raises(ValueError):
        runtime.address("external")
    runtime.serve(["h2"])
    assert constructor.call_args.args[0][-1] == "10.0.0.2"
    host_spawn = constructor.call_args.kwargs["spawn"]
    assert host_spawn.keywords["mncmd"] == [
        "mnexec",
        "-a",
        str(runtime.network.get("h2").pid),
    ]
    runtime.attack(Experiment(attackers=["h1"], victims=["h2"]))
    assert "--flood" not in constructor.call_args.args[0]
    assert constructor.call_args.args[0][:4] == [
        "timeout",
        "--signal=TERM",
        "--kill-after=2",
        "20",
    ]
    for request in [
        Diagnostic(action="flows", node="s1"),
        Diagnostic(action="interfaces", node="h1"),
        Diagnostic(action="ping", node="h1", target="h2"),
    ]:
        runtime.diagnostic(request)
    assert "10.0.0.2" in constructor.call_args.args[0]
    for request in [
        Diagnostic(action="flows", node="h1"),
        Diagnostic(action="interfaces", node="s1"),
        Diagnostic(action="ping", node="h1", target="8.8.8.8"),
    ]:
        with pytest.raises(ValueError):
            runtime.diagnostic(request)
    with pytest.raises(ValueError):
        runtime.capture(Capture(link_id="external"))
    runtime.capture(Capture(link_id="link-1", protocol="tcp"))
    command = constructor.call_args.args[0]
    assert command[command.index("-i") + 1] == "s1-eth1"
    assert command[command.index("-c") + 1] == "500"
    assert command[command.index("-s") + 1] == "256"
    assert "-w" not in command
    handler = constructor.call_args.kwargs["line_handler"]
    handler("\t".join(["1"] * len(PACKET_FIELDS)))
    handler("capture info")
    runtime.drain()
    assert any(k == "packets" for k, _ in runtime.events)
    fake.process.poll.return_value = None
    with pytest.raises(ValueError, match="already"):
        runtime.capture(Capture(link_id="link-1"))
    runtime.closed = True
    with pytest.raises(ValueError):
        runtime.diagnostic(Diagnostic(action="interfaces", node="h1"))
    runtime.closed = False


def test_sample_counters_controller_events_and_failures(runtime, monkeypatch):
    runtime.interfaces = {"link-1": "s1-eth1"}
    monkeypatch.setattr(
        module.subprocess,
        "check_output",
        lambda *a, **kw: json.dumps(
            [
                {
                    "ifname": "s1-eth1",
                    "stats64": {"rx": {"bytes": 100}, "tx": {"bytes": 200}},
                }
            ]
        ),
    )
    response = MagicMock()
    response.json.return_value = {"status": "not_ready"}
    monkeypatch.setattr(module.requests, "get", lambda *a, **kw: response)
    runtime.socket.recv.side_effect = [
        b"malformed",
        json.dumps(
            {
                "run_id": "run",
                "kind": "detection",
                "data": {"probability": 0.9},
                "dropped": 2,
            }
        ).encode(),
        BlockingIOError,
    ]
    runtime.sample()
    assert any(k == "detection" for k, _ in runtime.events)
    assert any(
        k == "detector" and d["status"] == "not_ready" for k, d in runtime.events
    )
    assert any(k == "gap" for k, _ in runtime.events)
    runtime.last_health = 0
    runtime.socket.recv.side_effect = BlockingIOError
    response.raise_for_status.side_effect = module.requests.RequestException()
    runtime.sample()
    assert runtime.events[-1] == ("detector", {"status": "unavailable"})
    for attribute, empty in (
        ("controller", None),
        ("service_processes", []),
        ("attack_processes", []),
    ):
        process = MagicMock()
        process.process.poll.return_value = 1
        setattr(runtime, attribute, process if attribute == "controller" else [process])
        with pytest.raises(RuntimeError):
            runtime.sample()
        setattr(runtime, attribute, empty)


def test_queue_is_bounded_and_reports_gaps(runtime):
    for _ in range(1030):
        runtime.enqueue("test", {})
    assert runtime.queue.qsize() == 1024
    runtime.drain()
    assert runtime.events[-1] == ("gap", {"count": 6, "source": "command/capture"})


def test_probe_success_and_timeout(runtime):
    runtime.network = MagicMock()
    process = runtime.network.get.return_value.popen.return_value
    process.communicate.return_value = (b"200 0.012", None)
    process.returncode = 0
    runtime.probe("h3", "h2")
    assert runtime.events[-1][1]["latency_ms"] == 12
    assert runtime.events[-1][1]["success"]
    process.communicate.side_effect = subprocess.TimeoutExpired("curl", 3)
    runtime.probe("h3", "h2")
    process.kill.assert_called_once()
    assert not runtime.events[-1][1]["success"]


def test_cleanup_attempts_every_resource_after_failures(runtime):
    failed, remaining = MagicMock(), MagicMock()
    failed.close.side_effect = OSError("cannot kill")
    runtime.processes = [remaining, failed]
    runtime.network = MagicMock()
    runtime.network.stop.side_effect = OSError("cannot delete interface")
    with pytest.raises(RuntimeError, match="cleaned up"):
        runtime.close()
    remaining.close.assert_called_once()
    runtime.socket.close.assert_called_once()


def test_observed_drop_rules_are_distinct_from_requests(runtime, monkeypatch):
    runtime.mitigation = True
    runtime.last_health = float("inf")

    def output(command, **kwargs):
        return (
            "[]"
            if command[0] == "ip"
            else "priority=100,ip,nw_src=10.0.0.1 actions=drop\n"
            "priority=1 actions=output:2"
        )

    monkeypatch.setattr(module.subprocess, "check_output", output)
    runtime.sample()
    observed = [data for kind, data in runtime.events if kind == "mitigation_observed"]
    assert len(observed) == 1
    assert len(observed[0]["rules"]) == 1
