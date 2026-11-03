"""Reassembly of multipart OpenFlow replies, one buffer per (switch, transaction).

A flow-stats reply can arrive in several messages (flag MORE on all but the
last). Under a flood the flow table is large, so multipart replies are the normal
case, and the monitor asks again every poll whether or not the previous reply
finished. Chunks therefore must never be merged across transactions:

* a buffer belongs to one (dpid, xid);
* when a different xid starts for the same switch, the unfinished buffer is
  dropped and its late chunks are ignored;
* a switch that disconnects loses its unfinished buffer.

Pure Python (no Ryu) so it can be tested with plain objects.
"""

from __future__ import annotations

import logging
from collections import deque
from collections.abc import Iterable
from typing import Any, Deque, Dict, List, Optional, Tuple

LOGGER = logging.getLogger(__name__)
REMEMBER_DROPPED = 16


class StatsReassembler:
    def __init__(self) -> None:
        self._buffers: Dict[Tuple[int, int], List[Any]] = {}
        self._current: Dict[int, int] = {}
        self._dropped: Dict[int, Deque[int]] = {}
        self.abandoned = 0

    def add(
        self, dpid: int, xid: int, items: Iterable[Any], more: bool
    ) -> Optional[List[Any]]:
        """Add one chunk; returns the complete list when the reply is finished."""

        if xid in self._dropped.get(dpid, ()):
            return None  # late chunk of a reply that was already abandoned
        current = self._current.get(dpid)
        if current is not None and current != xid:
            self._abandon(dpid, current)
        self._current[dpid] = xid
        buffer = self._buffers.setdefault((dpid, xid), [])
        buffer.extend(items)
        if more:
            return None
        del self._buffers[(dpid, xid)]
        self._current.pop(dpid, None)
        return buffer

    def clear(self, dpid: int) -> None:
        """Forget what is pending for a switch (it disconnected)."""

        current = self._current.get(dpid)
        if current is not None:
            self._abandon(dpid, current)

    def _abandon(self, dpid: int, xid: int) -> None:
        self._buffers.pop((dpid, xid), None)
        self._current.pop(dpid, None)
        self._dropped.setdefault(dpid, deque(maxlen=REMEMBER_DROPPED)).append(xid)
        self.abandoned += 1
        LOGGER.warning(
            "dropped an unfinished flow-stats reply dpid=%s xid=%s", dpid, xid
        )
