"""Declarative topology contract and deliberately limited MiniEdit interchange."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from typing_extensions import Self

from sdn_ddos.config import ControllerSettings, validate_lab_target
from sdn_ddos.topology.spec import ACCESS_SWITCHES, CORE_SWITCH, HOSTS


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


def _repeated(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    repeats: list[str] = []
    for value in values:
        if value in seen and value not in repeats:
            repeats.append(value)
        seen.add(value)
    return repeats


def _listed(values: Iterable[str]) -> str:
    """Join names the way a sentence would, and stop before a wall of text."""

    items = sorted(set(values))
    shown = items[:6]
    text = ", ".join(shown[:-1]) + " and " + shown[-1] if len(shown) > 1 else shown[0]
    return text + f", and {len(items) - 6} more" if len(items) > 6 else text


class Position(StrictModel):
    x: float = Field(default=0, ge=-10000, le=10000)
    y: float = Field(default=0, ge=-10000, le=10000)


class Host(StrictModel):
    name: str = Field(pattern=r"^h[a-zA-Z0-9_]{1,8}$")
    ip: str
    position: Position = Field(default_factory=Position)

    @field_validator("ip")
    @classmethod
    def valid_address(cls, value: str) -> str:
        interface = ipaddress.IPv4Interface(value)
        if not any(
            interface.ip in ipaddress.ip_network(cidr)
            for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        ):
            raise ValueError("hosts must use private IPv4 addresses")
        if not 1 <= interface.network.prefixlen <= 30 or interface.ip in (
            interface.network.network_address,
            interface.network.broadcast_address,
        ):
            raise ValueError("host address must be usable in a /1 through /30 subnet")
        return str(interface)


class Switch(StrictModel):
    name: str = Field(pattern=r"^s[a-zA-Z0-9_]{1,8}$")
    dpid: int = Field(ge=1, le=2**53 - 1)
    position: Position = Field(default_factory=Position)


class Link(StrictModel):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,40}$")
    source: str
    target: str
    bandwidth_mbps: Optional[float] = Field(default=None, gt=0, le=10000)
    delay_ms: float = Field(default=0, ge=0, le=1000)
    loss_percent: float = Field(default=0, ge=0, le=100)


class Topology(StrictModel):
    version: Literal[1] = 1
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=1000)
    hosts: list[Host] = Field(min_length=1, max_length=32)
    switches: list[Switch] = Field(min_length=1, max_length=16)
    links: list[Link] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def graph_is_supported(self) -> Self:
        names = [host.name for host in self.hosts] + [s.name for s in self.switches]
        if repeats := _repeated(names):
            raise ValueError(
                f"the name {_listed(repeats)} is used by more than one device; "
                "give every host and switch its own name"
            )
        if repeats := _repeated(host.ip.split("/")[0] for host in self.hosts):
            raise ValueError(
                f"the address {_listed(repeats)} is used by more than one host; "
                "give every host its own IPv4 address"
            )
        if repeats := _repeated(str(switch.dpid) for switch in self.switches):
            raise ValueError(
                f"the datapath ID (DPID) {_listed(repeats)} is used by more than "
                "one switch; every switch needs its own DPID"
            )
        if repeats := _repeated(link.id for link in self.links):
            raise ValueError(
                f"the link identifier {_listed(repeats)} appears more than once; "
                "every link needs its own identifier"
            )
        host_names = {host.name for host in self.hosts}
        degree = dict.fromkeys(names, 0)
        parent = {name: name for name in names}

        def root(name: str) -> str:
            while parent[name] != name:
                name = parent[name]
            return name

        for link in self.links:
            if unknown := [n for n in (link.source, link.target) if n not in parent]:
                raise ValueError(
                    f"link {link.id} points at {_listed(unknown)}, which is not a "
                    "device in this topology; delete the link or add the device"
                )
            if link.source in host_names and link.target in host_names:
                raise ValueError(
                    f"link {link.id} joins two hosts ({link.source} and "
                    f"{link.target}); every host connects to a switch instead"
                )
            left, right = root(link.source), root(link.target)
            if left == right:
                raise ValueError(
                    f"link {link.id} between {link.source} and {link.target} repeats "
                    "an existing connection or closes a loop; this lab needs exactly "
                    "one path between any two devices"
                )
            parent[left] = right
            degree[link.source] += 1
            degree[link.target] += 1
        if alone := sorted(name for name in host_names if degree[name] == 0):
            raise ValueError(
                f"{_listed(alone)} has no link yet; drag from a host handle to a "
                "switch so every host reaches the network"
                if len(alone) == 1
                else f"{_listed(alone)} have no link yet; drag from each host "
                "handle to a switch so every host reaches the network"
            )
        if crowded := sorted(name for name in host_names if degree[name] > 1):
            raise ValueError(
                f"{_listed(crowded)} uses more than one link; a host here has a "
                "single network interface, so keep exactly one link per host"
            )
        groups = {name: root(name) for name in names}
        if len(set(groups.values())) != 1:
            largest = max(
                set(groups.values()),
                key=lambda group: sum(1 for value in groups.values() if value == group),
            )
            stranded = sorted(n for n, group in groups.items() if group != largest)
            raise ValueError(
                f"{_listed(stranded)} cannot reach the rest of the network; add a "
                "link so all devices belong to one connected network"
            )
        return self

    def validate_targets(self) -> None:
        networks = ControllerSettings.from_env().allowed_target_networks
        for host in self.hosts:
            address = host.ip.split("/")[0]
            try:
                validate_lab_target(address, networks)
            except ValueError as error:
                allowed = ", ".join(str(network) for network in networks)
                raise ValueError(
                    f"host {host.name} uses {address}, which is outside the "
                    f"networks this lab may touch ({allowed}); change the address "
                    "or widen SDN_ALLOWED_TARGET_CIDRS"
                ) from error


def presets() -> list[Topology]:
    switches = [
        Switch(name=name, dpid=i + 1, position=Position(x=200 + i * 300, y=250))
        for i, name in enumerate(ACCESS_SWITCHES)
    ]
    switches.append(Switch(name=CORE_SWITCH, dpid=4, position=Position(x=500, y=90)))
    hosts = [
        Host(
            name=host.name,
            ip=host.ip,
            position=Position(x=95 + (i // 3) * 300 + (i % 3) * 105, y=440),
        )
        for i, host in enumerate(HOSTS)
    ]
    links = [
        Link(id=f"link-{host.name}", source=host.switch, target=host.name)
        for host in HOSTS
    ]
    links += [
        Link(id=f"core-{name}", source=CORE_SWITCH, target=name)
        for name in ACCESS_SWITCHES
    ]
    original = Topology(
        name="Original enterprise",
        description=(
            "Research baseline · 4 switches / 9 hosts. Separate /24 subnets "
            "have no router; choose experiment hosts in the same subnet."
        ),
        hosts=hosts,
        switches=switches,
        links=links,
    )
    connected = original.model_copy(deep=True)
    connected.name = "Connected enterprise"
    connected.description = (
        "4 switches / 9 hosts · one subnet for experiments across departments. "
        "Distinct from the original research baseline."
    )
    for index, host in enumerate(connected.hosts, start=1):
        host.ip = f"10.0.0.{index}/24"
    small = Topology(
        name="Small teaching network",
        description="A client, a source, and a victim. A clear first experiment.",
        hosts=[
            Host(name=f"h{i}", ip=f"10.0.0.{i}/24", position=Position(x=i * 160, y=320))
            for i in range(1, 4)
        ],
        switches=[Switch(name="s1", dpid=1, position=Position(x=320, y=120))],
        links=[Link(id=f"link-{i}", source="s1", target=f"h{i}") for i in range(1, 4)],
    )
    linear = Topology(
        name="Linear network",
        description="3 switches / 6 hosts · follow traffic across a chain.",
        hosts=[
            Host(
                name=f"h{i}",
                ip=f"10.0.0.{i}/24",
                position=Position(
                    x=125 + ((i - 1) // 2) * 250 + ((i - 1) % 2) * 105, y=360
                ),
            )
            for i in range(1, 7)
        ],
        switches=[
            Switch(name=f"s{i}", dpid=i, position=Position(x=i * 250 - 80, y=170))
            for i in range(1, 4)
        ],
        links=[
            Link(id=f"host-{i}", source=f"s{(i - 1) // 2 + 1}", target=f"h{i}")
            for i in range(1, 7)
        ]
        + [
            Link(id=f"switch-{i}", source=f"s{i}", target=f"s{i + 1}")
            for i in range(1, 3)
        ],
    )
    return [original, connected, small, linear]


def export_miniedit(topology: Topology) -> dict[str, Any]:
    if any(
        (
            link.bandwidth_mbps is not None
            and not float(link.bandwidth_mbps).is_integer()
        )
        or not float(link.loss_percent).is_integer()
        for link in topology.links
    ):
        raise ValueError(
            "MiniEdit needs whole-number bandwidth and loss; "
            "use JSON for fractional values"
        )
    return {
        "version": "2",
        "lab_name": topology.name,
        "lab_description": topology.description,
        "application": {
            "openFlowVersions": {
                "ovsOf10": "0",
                "ovsOf11": "0",
                "ovsOf12": "0",
                "ovsOf13": "1",
            }
        },
        "controllers": [
            {
                # Where the workspace draws it: centred above the switch row.
                "x": str(
                    round(
                        (
                            min(s.position.x for s in topology.switches)
                            + max(s.position.x for s in topology.switches)
                        )
                        / 2
                    )
                ),
                "y": str(
                    max(0, round(min(s.position.y for s in topology.switches) - 135))
                ),
                "opts": {
                    "hostname": "c0",
                    "controllerType": "remote",
                    "remoteIP": "127.0.0.1",
                    "remotePort": 6653,
                },
            }
        ],
        "hosts": [
            {
                "number": str(i),
                "x": str(h.position.x),
                "y": str(h.position.y),
                "opts": {"hostname": h.name, "ip": h.ip},
            }
            for i, h in enumerate(topology.hosts, start=1)
        ],
        "switches": [
            {
                "number": str(i),
                "x": str(s.position.x),
                "y": str(s.position.y),
                "opts": {
                    "hostname": s.name,
                    "switchType": "ovs",
                    "dpid": f"{s.dpid:016x}",
                    "controllers": ["c0"],
                },
            }
            for i, s in enumerate(topology.switches, start=1)
        ],
        "links": [
            {
                "src": link.source,
                "dest": link.target,
                "opts": {
                    **(
                        {"bw": int(link.bandwidth_mbps)}
                        if link.bandwidth_mbps is not None
                        else {}
                    ),
                    "delay": f"{link.delay_ms}ms",
                    "loss": int(link.loss_percent),
                    "lab_id": link.id,
                },
            }
            for link in topology.links
        ],
    }


def import_miniedit(data: dict[str, Any]) -> tuple[Topology, list[str]]:
    if str(data.get("version")) != "2":
        raise ValueError(
            "this is not a MiniEdit version 2 file; save it again from MiniEdit, "
            "or import project JSON exported by this workspace"
        )
    warnings: list[str] = []
    hosts: list[Host] = []
    switches: list[Switch] = []
    links: list[Link] = []
    allowed = {
        "host": {"hostname", "ip", "nodeNum"},
        "switch": {"hostname", "nodeNum", "dpid", "controllers", "switchType"},
    }
    for kind, entries in (
        ("host", data.get("hosts", [])),
        ("switch", data.get("switches", [])),
    ):
        if not isinstance(entries, list):
            raise ValueError(f"the “{kind}s” section of this file is not a list")
        if len(entries) > 32:
            raise ValueError(
                f"this file holds {len(entries)} {kind}s; the lab supports at most 32"
            )
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("opts"), dict):
                raise ValueError(f"a {kind} in this file has no readable settings")
            opts = dict(entry["opts"])
            label = opts.get("hostname") or f"{kind} {entry.get('number', '?')}"
            harmless = (
                {"sched": "host"} if kind == "host" else {"sflow": "0", "netflow": "0"}
            )
            for key, default in harmless.items():
                if opts.get(key) == default:
                    del opts[key]
            extra = [
                key
                for key, value in opts.items()
                if key not in allowed[kind] and value not in (None, "", [], {})
            ]
            if extra:
                raise ValueError(
                    f"{label} uses the unsupported MiniEdit setting "
                    f"“{extra[0]}”; this lab runs plain hosts and OVS switches, so "
                    "remove startup commands, routes, external interfaces, and "
                    "other custom settings before importing"
                )
            if "x" not in entry or "y" not in entry:
                raise ValueError(f"{label} has no canvas position in this file")
            position = Position(x=float(entry["x"]), y=float(entry["y"]))
            name = opts.get("hostname", f"{kind[0]}{entry.get('number', '')}")
            if kind == "host":
                if not opts.get("ip"):
                    raise ValueError(
                        f"{label} has no IP address; give every MiniEdit host a "
                        "private address such as 10.0.0.1/24"
                    )
                hosts.append(Host(name=name, ip=opts["ip"], position=position))
            else:
                if opts.get("switchType", "ovs") not in ("ovs", "default"):
                    raise ValueError(
                        f"{label} is a “{opts['switchType']}” switch; this lab runs "
                        "Open vSwitch datapaths only"
                    )
                digits = "".join(re.findall(r"\d", name))
                if not opts.get("dpid") and not digits:
                    raise ValueError(
                        f"{label} has no datapath ID and no number in its name; "
                        "set a DPID in MiniEdit or rename the switch to s1, s2, …"
                    )
                switches.append(
                    Switch(
                        name=name,
                        dpid=int(str(opts["dpid"]).replace(":", ""), 16)
                        if opts.get("dpid")
                        else int(digits),
                        position=position,
                    )
                )
    controllers = data.get("controllers", [])
    if len(controllers) != 1:
        raise ValueError(
            f"this file declares {len(controllers)} controllers; the lab runs one "
            "managed Ryu controller, so keep exactly one controller in MiniEdit"
        )
    controller = dict(controllers[0]["opts"])
    if controller.get("controllerProtocol") == "tcp":
        del controller["controllerProtocol"]
    for entry in data.get("switches", []):
        if entry["opts"].get("controllers") != [controller.get("hostname")]:
            warnings.append(
                "Switch controller association mapped to the managed Ryu controller."
            )
    if (
        controller.get("controllerType") != "remote"
        or controller.get("remoteIP") != "127.0.0.1"
        or str(controller.get("remotePort")) != "6653"
    ):
        warnings.append(
            "Controller settings will be mapped to this lab's managed Ryu controller."
        )
    extra_controller = [
        key
        for key, value in controller.items()
        if key not in {"hostname", "controllerType", "remoteIP", "remotePort"}
        and value not in (None, "", [], {})
    ]
    if extra_controller:
        raise ValueError(
            f"the controller uses the unsupported setting “{extra_controller[0]}”; "
            "this lab always supplies its own Ryu controller"
        )
    application = data.get("application", {})
    if any(
        key != "openFlowVersions" and value not in (None, "", [], {})
        for key, value in application.items()
    ):
        warnings.append(
            "MiniEdit application preferences are not imported. "
            "Runtime configuration is managed by this lab."
        )
    for entry in data.get("links", []):
        opts = entry.get("opts", {})
        if unsupported := sorted(set(opts) - {"bw", "delay", "loss", "lab_id"}):
            raise ValueError(
                f"the link {entry.get('src', '?')} ↔ {entry.get('dest', '?')} uses "
                f"the unsupported setting “{unsupported[0]}”; this lab reads "
                "bandwidth, delay, and loss only"
            )
        delay = str(opts.get("delay", "0ms"))
        if not delay.endswith("ms"):
            raise ValueError(
                f"the link {entry.get('src', '?')} ↔ {entry.get('dest', '?')} sets a "
                f"delay of “{delay}”; write link delays in milliseconds, like 5ms"
            )
        links.append(
            Link(
                id=opts.get("lab_id", f"link-{len(links) + 1}"),
                source=entry["src"],
                target=entry["dest"],
                bandwidth_mbps=opts.get("bw"),
                delay_ms=float(delay[:-2]),
                loss_percent=opts.get("loss", 0),
            )
        )
    name = data.get("lab_name")
    description = data.get("lab_description")
    return Topology(
        name=name[:80]
        if isinstance(name, str) and name.strip()
        else "Imported MiniEdit network",
        description=description[:1000] if isinstance(description, str) else "",
        hosts=hosts,
        switches=switches,
        links=links,
    ), warnings
