"""OpenFlow 1.3 enforcement of response actions (drop rule, rate-limit meter).

Does not import Ryu: everything it needs (message classes, constants) is read
from each datapath, so it can be unit-tested with fakes. `datapaths` is the live
dict the controller keeps, so switches that connect later are covered too.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, Dict, List

LOGGER = logging.getLogger(__name__)

ETH_TYPE_IP = 0x0800
DROP_PRIORITY = 100  # same level the baseline drop rule uses
LIMIT_PRIORITY = 90  # above learned forwarding rules, below any drop
MAX_METERS = 4096


class OpenFlowEnforcer:
    def __init__(self, datapaths: Mapping[int, Any]) -> None:
        self.datapaths = datapaths
        self._meters: Dict[str, int] = {}

    def _targets(self) -> List[Any]:
        return list(self.datapaths.values())

    def _meter_for(self, source: str) -> int:
        existing = self._meters.get(source)
        if existing is not None:
            return existing
        used = set(self._meters.values())
        meter_id = next(i for i in range(1, MAX_METERS + 1) if i not in used)
        self._meters[source] = meter_id
        return meter_id

    @staticmethod
    def _match(datapath: Any, source: str) -> Any:
        return datapath.ofproto_parser.OFPMatch(eth_type=ETH_TYPE_IP, ipv4_src=source)

    def drop(self, source: str, seconds: int) -> int:
        count = 0
        for datapath in self._targets():
            parser, proto = datapath.ofproto_parser, datapath.ofproto
            datapath.send_msg(
                parser.OFPFlowMod(
                    datapath=datapath,
                    priority=DROP_PRIORITY,
                    match=self._match(datapath, source),
                    instructions=[
                        parser.OFPInstructionActions(proto.OFPIT_APPLY_ACTIONS, [])
                    ],
                    hard_timeout=int(seconds),
                )
            )
            count += 1
        return count

    def limit(self, source: str, pps: int, burst: int, seconds: int) -> int:
        """Cap `source` at `pps` packets/s on every switch; excess is dropped.

        The rule forwards with the switch's own NORMAL pipeline (Open vSwitch),
        because one meter rule must serve every destination of that source.
        """

        if not self._targets():
            return 0
        meter_id = self._meter_for(source)
        count = 0
        for datapath in self._targets():
            parser, proto = datapath.ofproto_parser, datapath.ofproto
            datapath.send_msg(
                parser.OFPMeterMod(
                    datapath=datapath,
                    command=proto.OFPMC_ADD,
                    flags=proto.OFPMF_PKTPS | proto.OFPMF_BURST,
                    meter_id=meter_id,
                    bands=[
                        parser.OFPMeterBandDrop(rate=int(pps), burst_size=int(burst))
                    ],
                )
            )
            datapath.send_msg(
                parser.OFPFlowMod(
                    datapath=datapath,
                    priority=LIMIT_PRIORITY,
                    match=self._match(datapath, source),
                    instructions=[
                        parser.OFPInstructionMeter(meter_id),
                        parser.OFPInstructionActions(
                            proto.OFPIT_APPLY_ACTIONS,
                            [parser.OFPActionOutput(proto.OFPP_NORMAL)],
                        ),
                    ],
                    hard_timeout=int(seconds),
                )
            )
            count += 1
        return count

    def release(self, source: str) -> None:
        meter_id = self._meters.pop(source, None)
        if meter_id is None:
            return
        for datapath in self._targets():
            parser, proto = datapath.ofproto_parser, datapath.ofproto
            # Deleting a meter also removes the flow entries that reference it.
            datapath.send_msg(
                parser.OFPMeterMod(
                    datapath=datapath,
                    command=proto.OFPMC_DELETE,
                    flags=proto.OFPMF_PKTPS,
                    meter_id=meter_id,
                    bands=[],
                )
            )
