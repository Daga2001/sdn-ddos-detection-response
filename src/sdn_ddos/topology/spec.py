"""Framework-independent description of the implemented enterprise topology."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class HostSpec:
    name: str
    ip: str
    switch: str


ACCESS_SWITCHES: Tuple[str, ...] = ("s1", "s2", "s3")
CORE_SWITCH = "s4"
HOSTS: Tuple[HostSpec, ...] = (
    HostSpec("h1a", "10.0.1.1/24", "s1"),
    HostSpec("h1b", "10.0.1.2/24", "s1"),
    HostSpec("h1c", "10.0.1.3/24", "s1"),
    HostSpec("h2a", "10.0.2.1/24", "s2"),
    HostSpec("h2b", "10.0.2.2/24", "s2"),
    HostSpec("h2c", "10.0.2.3/24", "s2"),
    HostSpec("h3a", "10.0.3.1/24", "s3"),
    HostSpec("h3b", "10.0.3.2/24", "s3"),
    HostSpec("h3c", "10.0.3.3/24", "s3"),
)


def expected_link_count() -> int:
    """Nine host links plus three access-to-core links."""

    return len(HOSTS) + len(ACCESS_SWITCHES)
