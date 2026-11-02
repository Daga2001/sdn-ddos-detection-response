"""Short, bounded browser leases. Access is serialized by the manager lock."""

from __future__ import annotations

import time
from collections.abc import Callable
from uuid import uuid4


class OwnerLeases:
    def __init__(self) -> None:
        self.clock: Callable[[], float] = time.monotonic
        self.deadlines: dict[str, float] = {}

    def create(self) -> str:
        # Expired entries are collected by the runner watchdog.
        if len(self.deadlines) >= 128:
            raise ValueError("too many browser connections; close unused tabs")
        owner = str(uuid4())
        self.deadlines[owner] = self.clock() + 5
        return owner

    def require(self, owner: str) -> None:
        if self.deadlines.get(owner, 0) <= self.clock():
            raise ValueError("browser ownership expired; reload before starting")

    def renew(self, owner: str) -> None:
        self.require(owner)
        self.deadlines[owner] = self.clock() + 5

    def release(self, owner: str) -> None:
        self.deadlines.pop(owner, None)

    def expired(self) -> list[str]:
        now = self.clock()
        return [owner for owner, deadline in self.deadlines.items() if deadline <= now]
