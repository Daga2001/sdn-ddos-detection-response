"""Validated operations accepted by the local lab runner."""

from __future__ import annotations

import ipaddress
from typing import Literal, Optional
from uuid import UUID

from pydantic import Field, field_validator, model_validator

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


DetectionMode = Literal["llm", "rule", "entropy", "off"]
ResponsePolicy = Literal["block", "rate_limit", "escalate"]
Forwarding = Literal["per_port", "port_free"]
MODEL_NAME = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$"
FORWARDING_MESSAGE = (
    "Choose the forwarding rules: per-port (Experiment A) or port-free (Experiment B)."
)


class EntropyParams(StrictModel):
    """Tuning of the entropy detector; the defaults are the calibrated lab values."""

    k: float = Field(default=2.5, ge=0.5, le=10)
    alpha: float = Field(default=0.2, gt=0, le=1)
    warmup_windows: int = Field(default=16, ge=1, le=120)
    consecutive_windows: int = Field(default=2, ge=1, le=20)
    min_rate: float = Field(default=2.0, ge=0, le=1_000_000)
    min_std: float = Field(default=0.05, ge=0, le=10)
    candidate_share: float = Field(default=0.3, ge=0, le=1)
    candidate_min_rate: float = Field(default=20.0, ge=0, le=1_000_000)
    update_hold: int = Field(default=0, ge=0, le=20)
    alpha_run: Optional[float] = Field(default=None, gt=0, le=1)
    window_seconds: int = Field(default=5, ge=1, le=60)
    window_mode: Literal["snapshot", "mean"] = "mean"
    dedupe_switches: bool = False
    # Which entropy is computed and how its normal band is learned (see
    # detection/entropy.py). The defaults are the original detector: Shannon entropy,
    # EWMA mean and deviation, learned from the windows that look normal.
    measure: Literal["shannon", "norm", "renyi", "tsallis", "min"] = "shannon"
    order: float = Field(default=2.0, gt=0, le=64)
    center: Literal["ewma", "mean", "median", "yu", "ewma_margin", "ewma2"] = "ewma"
    spread: Literal["std", "mad"] = "std"
    history: int = Field(default=0, ge=0, le=1000)
    context: Literal["normal", "all"] = "normal"
    # Distributions watched besides the IPs.
    watch_ports: bool = False
    watch_protocols: bool = False
    # The entropy of the (source, destination) pairs, which `ewma2` decides on.
    watch_pairs: bool = False
    # The distributions allowed to raise an alarm (empty: all of them); the published
    # detectors decide on one: `dst` for `ewma_margin`, `pair` for `ewma2`.
    decide: list[Literal["src", "dst", "dport", "proto", "pair"]] = Field(
        default_factory=list, max_length=5
    )
    # Margin of the `ewma_margin` threshold (EWMA - margin) and packet rate above which
    # the `ewma2` threshold cannot decrease; the defaults are the values of the papers.
    margin: float = Field(default=0.01, ge=0, le=1)
    rate_threshold: float = Field(default=800.0, ge=0, le=1_000_000)

    @model_validator(mode="after")
    def decide_only_on_watched_distributions(self) -> "EntropyParams":
        watched = {"src", "dst"}
        if self.watch_ports:
            watched.add("dport")
        if self.watch_protocols:
            watched.add("proto")
        if self.watch_pairs:
            watched.add("pair")
        missing = [name for name in self.decide if name not in watched]
        if missing:
            raise ValueError(
                f"decide names {missing}, which are not watched; turn them on first"
            )
        return self


class ResponseParams(StrictModel):
    """What the controller does with a detection (a dry run unless told otherwise)."""

    policy: ResponsePolicy = "block"
    dry_run: bool = True
    rate_limit_pps: int = Field(default=50, ge=1, le=1_000_000)
    rate_limit_burst: Optional[int] = Field(default=None, ge=1, le=10_000_000)
    rate_limit_seconds: int = Field(default=120, ge=1, le=3600)
    escalate_after_seconds: int = Field(default=20, ge=0, le=3600)
    block_seconds: int = Field(default=300, ge=1, le=86400)
    max_active: int = Field(default=16, ge=1, le=256)
    confirm_hits: int = Field(default=1, ge=1, le=10)
    confirm_seconds: int = Field(default=30, ge=1, le=600)
    protected: list[str] = Field(default_factory=list, max_length=16)

    @field_validator("protected")
    @classmethod
    def private_networks_only(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            try:
                network = ipaddress.IPv4Network(value.strip(), strict=False)
            except ValueError as error:
                raise ValueError(
                    f"{value!r} is not an IPv4 address or network"
                ) from error
            if not network.is_private:
                raise ValueError(f"{value!r} is not a private network")
            cleaned.append(str(network))
        return cleaned


class DetectionConfig(StrictModel):
    """Which detector judges the run and how it is tuned; saved with the experiment."""

    mode: DetectionMode = "llm"
    model: str = Field(default="llama3.2:3b", pattern=MODEL_NAME)
    prompt: Literal["insdn", "lab"] = "lab"
    llm_max_samples: int = Field(default=5, ge=1, le=50)
    # How often the controller asks every switch for its flow statistics, which is
    # also how soon a flood can be seen: both detectors work from those polls.
    poll_seconds: float = Field(default=5.0, ge=0.5, le=60)
    threshold: float = Field(default=0.8, ge=0, le=1)
    # The packet-rate rule (mode "rule"): a judged flow at or above this many
    # packets/s is an attack. 50 is the lab prompt's attack threshold.
    rule_pktrate: float = Field(default=50.0, gt=0, le=1_000_000)
    entropy: EntropyParams = Field(default_factory=EntropyParams)
    response: ResponseParams = Field(default_factory=ResponseParams)


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
    detection: Optional[DetectionConfig] = None


class StartRequest(StrictModel):
    topology: Topology
    experiment: Optional[Experiment] = None
    owner_id: Optional[UUID] = None
    # Required for observation sessions and experiments. No default: a start that
    # does not choose is rejected with FORWARDING_MESSAGE.
    forwarding: Forwarding


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
    if experiment.mitigation and (
        experiment.detection is not None and experiment.detection.mode == "off"
    ):
        raise ValueError(
            "mitigation needs a detector: choose an LLM or entropy detection, "
            "or turn mitigation off"
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
