"""Declarative topology contract and deliberately limited MiniEdit interchange."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from typing_extensions import Self

from sdn_ddos.config import ControllerSettings, validate_lab_target
from sdn_ddos.topology.spec import ACCESS_SWITCHES, CORE_SWITCH, HOSTS


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


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
        if len(set(names)) != len(names):
            raise ValueError("node names must be unique")
        if len({host.ip.split("/")[0] for host in self.hosts}) != len(self.hosts):
            raise ValueError("host addresses must be unique")
        if len({switch.dpid for switch in self.switches}) != len(self.switches):
            raise ValueError("switch DPIDs must be unique")
        if len({link.id for link in self.links}) != len(self.links):
            raise ValueError("link identifiers must be unique")
        host_names = {host.name for host in self.hosts}
        degree = dict.fromkeys(names, 0)
        parent = {name: name for name in names}

        def root(name: str) -> str:
            while parent[name] != name:
                name = parent[name]
            return name

        for link in self.links:
            if link.source not in parent or link.target not in parent:
                raise ValueError("link endpoint does not exist")
            if link.source in host_names and link.target in host_names:
                raise ValueError("hosts must connect to switches")
            left, right = root(link.source), root(link.target)
            if left == right:
                raise ValueError("switching loops and duplicate links are unsupported")
            parent[left] = right
            degree[link.source] += 1
            degree[link.target] += 1
        if any(degree[name] != 1 for name in host_names):
            raise ValueError("each host needs exactly one link")
        if len({root(name) for name in names}) != 1:
            raise ValueError("connect every node into one network")
        return self

    def validate_targets(self) -> None:
        networks = ControllerSettings.from_env().allowed_target_networks
        for host in self.hosts:
            validate_lab_target(host.ip.split("/")[0], networks)


def presets() -> list[Topology]:
    switches = [
        Switch(name=name, dpid=i + 1, position=Position(x=200 + i * 260, y=250))
        for i, name in enumerate(ACCESS_SWITCHES)
    ]
    switches.append(Switch(name=CORE_SWITCH, dpid=4, position=Position(x=460, y=90)))
    hosts = [
        Host(
            name=host.name,
            ip=host.ip,
            position=Position(x=80 + (i // 3) * 260 + (i % 3) * 85, y=440),
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
                    x=120 + ((i - 1) // 2) * 250 + ((i - 1) % 2) * 100, y=360
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
                "x": "460",
                "y": "0",
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
        raise ValueError("only MiniEdit version 2 is supported")
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
        if not isinstance(entries, list) or len(entries) > 32:
            raise ValueError("invalid or oversized MiniEdit node collection")
        for entry in entries:
            opts = dict(entry["opts"])
            harmless = (
                {"sched": "host"} if kind == "host" else {"sflow": "0", "netflow": "0"}
            )
            for key, default in harmless.items():
                if opts.get(key) == default:
                    del opts[key]
            if any(
                value not in (None, "", [], {})
                for key, value in opts.items()
                if key not in allowed[kind]
            ):
                raise ValueError(
                    "unsupported MiniEdit node settings; remove startup commands, "
                    "routes, external interfaces, or other custom settings"
                )
            position = Position(x=float(entry["x"]), y=float(entry["y"]))
            name = opts.get("hostname", f"{kind[0]}{entry['number']}")
            if kind == "host":
                hosts.append(Host(name=name, ip=opts["ip"], position=position))
            else:
                if opts.get("switchType", "ovs") not in ("ovs", "default"):
                    raise ValueError("unsupported MiniEdit switch type")
                switches.append(
                    Switch(
                        name=name,
                        dpid=int(str(opts["dpid"]).replace(":", ""), 16)
                        if opts.get("dpid")
                        else int("".join(re.findall(r"\d", name))),
                        position=position,
                    )
                )
    controllers = data.get("controllers", [])
    if len(controllers) != 1:
        raise ValueError("exactly one MiniEdit controller is supported")
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
    if any(
        key not in {"hostname", "controllerType", "remoteIP", "remotePort"}
        and value not in (None, "", [], {})
        for key, value in controller.items()
    ):
        raise ValueError("unsupported MiniEdit controller settings")
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
        if set(opts) - {"bw", "delay", "loss", "lab_id"}:
            raise ValueError("unsupported MiniEdit link settings")
        delay = str(opts.get("delay", "0ms"))
        if not delay.endswith("ms"):
            raise ValueError("MiniEdit link delay must use milliseconds")
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
    return Topology(
        name="Imported MiniEdit network", hosts=hosts, switches=switches, links=links
    ), warnings
