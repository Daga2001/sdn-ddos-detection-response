"""Which flows the LLM judges first, and how polls wait for it (no Ryu needed)."""

from __future__ import annotations

from collections.abc import Collection, Sequence
from typing import Dict, Generic, List, Optional, Tuple, TypeVar

T = TypeVar("T")


def next_window_due(due: float, window: float, now: float) -> float:
    """When the following window is due: one window after the last due time, or one
    window from now when the loop has fallen a whole window behind (no bursts)."""

    following = due + window
    return now + window if following < now else following


def judging_order(
    rates: Sequence[float],
    sources: Optional[Sequence[Optional[str]]],
    flagged: Collection[str],
    busy_rate: float,
) -> List[int]:
    """Indexes of the flows in the order the model should judge them.

    Busiest first. Given the source of each flow, busy sources the model has not
    flagged lately come before everything else, then the rest of the busy flows and
    the flows of sources already flagged, and the quiet flows last: a small sample
    budget is not spent re-judging the same attackers while another one (other
    protocol, lower rate) is never looked at, nor on legitimate traffic.
    """

    ranked = sorted(range(len(rates)), key=lambda i: rates[i], reverse=True)
    if sources is None:
        return ranked
    first: List[int] = []
    second: List[int] = []
    third: List[int] = []
    for index in ranked:
        busy = rates[index] >= busy_rate
        known = sources[index] in flagged
        if busy and not known:
            first.append(index)
        elif busy or known:
            second.append(index)
        else:
            third.append(index)
    return first + second + third


class PollQueue(Generic[T]):
    """Polls waiting to be judged: one per switch, the busiest served first.

    A newer poll of a switch replaces its older one, so the backlog never grows
    beyond one poll per switch however slow the model is.
    """

    def __init__(self) -> None:
        self._pending: Dict[int, Tuple[float, T]] = {}

    def put(self, key: int, item: T, busiest: float) -> Optional[T]:
        """Queue `item`; returns the older poll of the same switch it replaced."""

        older = self._pending.get(key)
        self._pending[key] = (busiest, item)
        return None if older is None else older[1]

    def pop_busiest(self) -> T:
        key = max(self._pending, key=lambda k: self._pending[k][0])
        return self._pending.pop(key)[1]

    def __len__(self) -> int:
        return len(self._pending)

    def get(self, key: int) -> Optional[T]:
        entry = self._pending.get(key)
        return None if entry is None else entry[1]
