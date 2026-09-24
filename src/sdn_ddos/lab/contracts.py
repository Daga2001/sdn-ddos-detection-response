"""Validated operations accepted by the local lab runner."""

from __future__ import annotations

import ipaddress
from typing import Literal, Optional

from pydantic import Field

from sdn_ddos.experiments.attack_launcher import (
    MAX_DURATION_SECONDS,
    MAX_PACKETS_PER_SECOND,
)
from sdn_ddos.lab.topology import StrictModel, Topology


class Experiment(StrictModel):
    source: str
    target: str
    client: str
    rate: int = Field(default=100, ge=1, le=MAX_PACKETS_PER_SECOND)
    duration: int = Field(default=20, ge=1, le=MAX_DURATION_SECONDS)
    baseline: int = Field(default=30, ge=1, le=300)
    recovery: int = Field(default=30, ge=1, le=300)
    mitigation: bool = False
    confirm_isolated_lab: bool = False


class StartRequest(StrictModel):
    topology: Topology
    experiment: Optional[Experiment] = None


class Diagnostic(StrictModel):
    action: Literal["ping", "interfaces", "flows"]
    node: str
    target: Optional[str] = None


class Capture(StrictModel):
    link_id: str
    protocol: Literal["all", "tcp", "udp", "icmp", "arp"] = "all"
    duration: int = Field(default=20, ge=1, le=60)
    packets: int = Field(default=500, ge=1, le=2000)


def validate_experiment(topology: Topology, experiment: Experiment) -> None:
    if not experiment.confirm_isolated_lab:
        raise ValueError(
            "confirm that this is your isolated lab before starting an experiment"
        )
    names = [experiment.source, experiment.target, experiment.client]
    if len(set(names)) != 3:
        raise ValueError(
            "source, victim, and legitimate client must be different hosts"
        )
    hosts = {host.name: host for host in topology.hosts}
    if any(name not in hosts for name in names):
        raise ValueError("all experiment hosts must belong to the active topology")
    interfaces = [ipaddress.IPv4Interface(hosts[name].ip) for name in names]
    if any(
        other.ip not in interface.network
        for interface in interfaces
        for other in interfaces
    ):
        raise ValueError(
            "choose hosts in the same subnet; this lab has no inter-subnet router"
        )
    topology.validate_targets()
