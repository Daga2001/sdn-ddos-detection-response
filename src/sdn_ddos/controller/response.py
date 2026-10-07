"""Response policy: what to do about a source a detector has flagged.

Pure logic (no Ryu, no OpenFlow) so it can be tested and reused by any detector.
Detectors only say "this source looks malicious"; this module decides the action
and an `Enforcer` (controller/enforcer.py) carries it out on the switches.

Policies (SDN_RESPONSE_POLICY):
  block       temporary drop of everything from the source (the baseline behaviour)
  rate_limit  OpenFlow meter: the source keeps working but is capped at N packets/s
  escalate    rate-limit first; if the source is flagged again after
              SDN_RESPONSE_ESCALATE_AFTER seconds, block it

Safety rails: only addresses inside the allowed lab networks are ever touched,
SDN_RESPONSE_PROTECTED addresses/networks are never touched, every action expires
by itself, at most SDN_RESPONSE_MAX_ACTIVE sources are handled at once, and
SDN_RESPONSE_DRY_RUN records what would have been done without sending anything.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Dict, List, Optional, Protocol, Tuple

LOGGER = logging.getLogger(__name__)

POLICIES = ("block", "rate_limit", "escalate")
DROP = "temporary_drop"
LIMIT = "rate_limit"
OVER_FACTOR = 2.0  # "still ignoring the limit" means offering more than 2x the cap

Network = ipaddress.IPv4Network


def _flag(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _networks(raw: str) -> Tuple[Network, ...]:
    result: List[Network] = []
    for item in raw.split(","):
        item = item.strip()
        if item:
            result.append(ipaddress.IPv4Network(item, strict=False))
    return tuple(result)


@dataclass(frozen=True)
class ResponseSettings:
    policy: str = "block"
    dry_run: bool = False
    block_seconds: int = 300
    limit_pps: int = 50
    limit_burst: int = 100
    limit_seconds: int = 120
    escalate_after: int = 20
    protected: Tuple[Network, ...] = ()
    max_active: int = 16

    def __post_init__(self) -> None:
        if self.policy not in POLICIES:
            raise ValueError(f"SDN_RESPONSE_POLICY must be one of {POLICIES}")
        if not 1 <= self.limit_pps <= 1_000_000:
            raise ValueError("SDN_RATE_LIMIT_PPS must be between 1 and 1000000")
        if self.limit_burst < 1:
            raise ValueError("SDN_RATE_LIMIT_BURST must be at least 1")
        if not 1 <= self.limit_seconds <= 3600 or not 1 <= self.block_seconds <= 86400:
            raise ValueError("response durations are out of range")
        if self.escalate_after < 0 or self.max_active < 1:
            raise ValueError("escalate_after must be >= 0 and max_active >= 1")

    @classmethod
    def from_env(
        cls, env: Mapping[str, str], block_seconds: int = 300
    ) -> "ResponseSettings":
        pps = int(env.get("SDN_RATE_LIMIT_PPS", "50"))
        return cls(
            policy=env.get("SDN_RESPONSE_POLICY", "block").strip().lower(),
            dry_run=_flag(env.get("SDN_RESPONSE_DRY_RUN", "false")),
            block_seconds=block_seconds,
            limit_pps=pps,
            limit_burst=int(env.get("SDN_RATE_LIMIT_BURST", str(pps * 2))),
            limit_seconds=int(env.get("SDN_RATE_LIMIT_SECONDS", "120")),
            escalate_after=int(env.get("SDN_RESPONSE_ESCALATE_AFTER", "20")),
            protected=_networks(env.get("SDN_RESPONSE_PROTECTED", "")),
            max_active=int(env.get("SDN_RESPONSE_MAX_ACTIVE", "16")),
        )


class Enforcer(Protocol):
    """Carries an action out on the switches; returns how many switches got it."""

    def drop(self, source: str, seconds: int) -> int: ...

    def limit(self, source: str, pps: int, burst: int, seconds: int) -> int: ...

    def release(self, source: str) -> None:
        """Remove the rate limit of `source` (its meter and the rule using it)."""


@dataclass(frozen=True)
class Action:
    kind: str
    source: str
    seconds: int
    switches: int
    pps: Optional[int] = None
    dry_run: bool = False
    reason: str = ""

    @property
    def label(self) -> str:
        """Value for mitigation_events.action (the table has no pps column)."""

        name = DROP if self.kind == DROP else f"{LIMIT}_{self.pps}pps"
        return f"dry_run_{name}" if self.dry_run else name


@dataclass
class _Active:
    kind: str
    started: float
    expires: float
    dry_run: bool
    over_since: Optional[float] = None


class ResponseManager:
    def __init__(
        self,
        settings: ResponseSettings,
        allowed_networks: Sequence[Network],
        enforcer: Enforcer,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings
        self.allowed = tuple(allowed_networks)
        self.enforcer = enforcer
        self.clock = clock
        self._active: Dict[ipaddress.IPv4Address, _Active] = {}

    def active(self) -> Dict[str, str]:
        return {str(ip): state.kind for ip, state in self._active.items()}

    def expire(self) -> List[str]:
        """Forget finished actions and free their meters; returns the sources."""

        now = self.clock()
        finished = [ip for ip, state in self._active.items() if state.expires <= now]
        for ip in finished:
            state = self._active.pop(ip)
            if state.kind == LIMIT and not state.dry_run:
                self.enforcer.release(str(ip))
        return [str(ip) for ip in finished]

    def _eligible(self, source: Optional[str]) -> Optional[ipaddress.IPv4Address]:
        if not source:
            return None
        try:
            address = ipaddress.ip_address(source)
        except ValueError:
            return None
        if not isinstance(address, ipaddress.IPv4Address):
            return None
        if not any(address in network for network in self.allowed):
            return None
        if any(address in network for network in self.settings.protected):
            LOGGER.info("response skipped: %s is protected", address)
            return None
        return address

    def _decide(self, state: Optional[_Active], now: float) -> Optional[str]:
        policy = self.settings.policy
        if policy == "block":
            return DROP if state is None else None
        if policy == "rate_limit":
            return LIMIT if state is None else None
        if state is None:
            return LIMIT
        if state.kind == LIMIT and now - state.started >= self.settings.escalate_after:
            return DROP
        return None

    def review(self, offered: Mapping[str, float]) -> List[Action]:
        """Escalate limited sources that keep sending far above their limit.

        A limit rule shadows the flow the detectors watch, so a source that ignores
        the cap yields no new detections. Its offered rate (the packet counter of
        the limit rule itself, taken before the meter drops anything) is the
        evidence instead. Only the `escalate` policy uses it.
        """

        if self.settings.policy != "escalate":
            return []
        self.expire()
        now = self.clock()
        actions: List[Action] = []
        for address, state in list(self._active.items()):
            if state.kind != LIMIT or state.dry_run:
                continue
            rate = offered.get(str(address))
            if rate is None:
                continue
            if rate <= self.settings.limit_pps * OVER_FACTOR:
                state.over_since = None
                continue
            if state.over_since is None:
                state.over_since = now
                continue
            if now - state.over_since < self.settings.escalate_after:
                continue
            seconds = self.settings.block_seconds
            switches = self.enforcer.drop(str(address), seconds)
            if switches == 0:
                continue
            self.enforcer.release(str(address))
            self._active[address] = _Active(DROP, now, now + seconds, False)
            actions.append(
                Action(
                    DROP, str(address), seconds, switches, None, False, "exceeds_limit"
                )
            )
        return actions

    def respond(self, source: Optional[str], reason: str = "") -> Optional[Action]:
        """Act on a flagged source; None when nothing needs to (or can) be done."""

        self.expire()
        address = self._eligible(source)
        if address is None:
            return None
        now = self.clock()
        state = self._active.get(address)
        kind = self._decide(state, now)
        if kind is None:
            return None
        if state is None and len(self._active) >= self.settings.max_active:
            LOGGER.warning(
                "response skipped: %s sources already handled", len(self._active)
            )
            return None

        settings = self.settings
        seconds = settings.block_seconds if kind == DROP else settings.limit_seconds
        pps = settings.limit_pps if kind == LIMIT else None
        if settings.dry_run:
            switches = 0
        elif kind == DROP:
            switches = self.enforcer.drop(str(address), seconds)
        else:
            switches = self.enforcer.limit(
                str(address), settings.limit_pps, settings.limit_burst, seconds
            )
        if not settings.dry_run and switches == 0:
            return None  # no switch took it, so do not remember it as handled
        if (
            kind == DROP
            and state is not None
            and state.kind == LIMIT
            and not state.dry_run
        ):
            self.enforcer.release(str(address))
        self._active[address] = _Active(kind, now, now + seconds, settings.dry_run)
        return Action(
            kind, str(address), seconds, switches, pps, settings.dry_run, reason
        )
