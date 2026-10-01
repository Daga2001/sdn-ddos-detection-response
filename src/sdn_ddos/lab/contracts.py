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

TrafficKind = Literal["syn", "udp", "icmp"]


def _default_traffic() -> list[TrafficKind]:
    return ["syn"]


# Attackers and victims are chosen freely, but every attacker floods every
# victim, so the number of concurrent generators is their product. Cap that
# product to keep the emulated run bounded regardless of how the two lists grow.
MAX_ATTACKERS = 8
MAX_VICTIMS = 8
MAX_GENERATORS = 16


class Experiment(StrictModel):
    attackers: list[str] = Field(min_length=1, max_length=MAX_ATTACKERS)
    victims: list[str] = Field(min_length=1, max_length=MAX_VICTIMS)
    traffic: list[TrafficKind] = Field(default_factory=_default_traffic, min_length=1)
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


def attack_plan(experiment: Experiment) -> list[tuple[str, str, str]]:
    """Every (attacker, victim, traffic kind) flow the experiment will launch.

    The selected traffic kinds are spread across the attackers in order, so a
    run that picks SYN and UDP has its odd attackers send SYN and its even ones
    send UDP — the mixed-signature assault the multi-source scenarios describe.
    Each attacker then drives its assigned kind at every victim.
    """

    kinds = experiment.traffic
    plan: list[tuple[str, str, str]] = []
    for index, attacker in enumerate(experiment.attackers):
        kind = kinds[index % len(kinds)]
        for victim in experiment.victims:
            plan.append((attacker, victim, kind))
    return plan


def legitimate_clients(topology: Topology, experiment: Experiment) -> list[str]:
    """Hosts that stand in for ordinary users during an experiment.

    They are inferred, never chosen: any host that is neither an attacker nor a
    victim and that shares the victims' subnet, so a normal HTTP probe can still
    reach the service under test while the flood runs.
    """

    involved = set(experiment.attackers) | set(experiment.victims)
    addresses = {host.name: host.ip for host in topology.hosts}
    victim_networks = [
        ipaddress.IPv4Interface(addresses[name]).network
        for name in experiment.victims
        if name in addresses
    ]
    clients: list[str] = []
    for host in topology.hosts:
        if host.name in involved:
            continue
        address = ipaddress.IPv4Interface(host.ip).ip
        if any(address in network for network in victim_networks):
            clients.append(host.name)
    return clients


def probe_pairs(topology: Topology, experiment: Experiment) -> list[tuple[str, str]]:
    """Client→victim pairs to probe for legitimate reachability, sampled in turn."""

    clients = legitimate_clients(topology, experiment)
    return [(client, victim) for client in clients for victim in experiment.victims]


def validate_experiment(topology: Topology, experiment: Experiment) -> None:
    if not experiment.confirm_isolated_lab:
        raise ValueError(
            "confirm that this is your isolated lab before starting an experiment"
        )
    hosts = {host.name: host for host in topology.hosts}
    attackers, victims = experiment.attackers, experiment.victims
    if len(set(attackers)) != len(attackers):
        raise ValueError("list each attacker only once")
    if len(set(victims)) != len(victims):
        raise ValueError("list each victim only once")
    if unknown := [name for name in attackers + victims if name not in hosts]:
        raise ValueError(
            "all experiment hosts must belong to the active topology; "
            f"{', '.join(sorted(set(unknown)))} is not in it"
        )
    if overlap := sorted(set(attackers) & set(victims)):
        raise ValueError(
            f"{', '.join(overlap)} is listed as both an attacker and a victim; "
            "a host can only play one role in a run"
        )
    if len(attackers) * len(victims) > MAX_GENERATORS:
        raise ValueError(
            f"{len(attackers)} attackers against {len(victims)} victims would open "
            f"{len(attackers) * len(victims)} traffic flows; keep the product at or "
            f"below {MAX_GENERATORS} so the emulated run stays bounded"
        )
    interfaces = [
        ipaddress.IPv4Interface(hosts[name].ip) for name in attackers + victims
    ]
    if any(
        other.ip not in interface.network
        for interface in interfaces
        for other in interfaces
    ):
        raise ValueError(
            "choose attackers and victims in the same subnet; this lab has no "
            "inter-subnet router"
        )
    if not legitimate_clients(topology, experiment):
        raise ValueError(
            "leave at least one host free to act as a legitimate client — a host in "
            "the victims' subnet that is neither an attacker nor a victim — so normal "
            "traffic can be measured during the run"
        )
    topology.validate_targets()
