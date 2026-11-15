"""Ryu OpenFlow 1.3 controller for the current research baseline.

The app acts as a learning switch, polls flow/port statistics, submits complete
flow samples to the local inference API, and can install temporary drop rules.
Mitigation is deliberately disabled unless SDN_MITIGATION_ENABLED is true.
"""

from __future__ import annotations

import contextlib
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, ClassVar, Dict, List, Optional, Sequence, Tuple

import psutil
import requests
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.lib import hub
from ryu.lib.packet import ether_types, ethernet, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3

from sdn_ddos.config import ControllerSettings, DatabaseSettings
from sdn_ddos.controller.core import (
    BlockRegistry,
    FlowRateTracker,
    build_model_sample,
    observe_flow_rate,
    probability_is_attack,
)
from sdn_ddos.lab.measurements import (
    handled_rate,
    log_and_require_match_l4_ports,
    switch_table_sample,
)
from sdn_ddos.lab.telemetry import Telemetry
from sdn_ddos.storage import MetricsStore, create_metrics_store

# Set when the controller starts. None until then: there is no default.
MATCH_L4_PORTS: Optional[bool] = None


@dataclass
class FlowBatch:
    """One switch's flow table as of one poll, ready to be judged and stored."""

    dpid: int
    observed_at: datetime
    rows: List[Dict[str, Any]]
    samples: List[Dict[str, Any]]
    sample_indexes: List[int]


class EnterpriseDDoSController(app_manager.RyuApp):
    """Learning-switch controller with monitoring and guarded mitigation."""

    OFP_VERSIONS: ClassVar[list[int]] = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        global MATCH_L4_PORTS
        MATCH_L4_PORTS = log_and_require_match_l4_ports(self.logger)
        self.match_l4_ports = MATCH_L4_PORTS
        self._packet_ins = 0
        self._packet_in_sample: Optional[Tuple[int, float]] = None
        self._table_miss_baselines: Dict[int, Tuple[int, float]] = {}
        self.settings = ControllerSettings.from_env()
        self.datapaths: Dict[int, Any] = {}
        self.mac_to_port: Dict[int, Dict[str, int]] = {}
        self.flow_rates = FlowRateTracker()
        self.port_rates = FlowRateTracker()
        self.blocks = BlockRegistry(
            self.settings.allowed_target_networks,
            self.settings.block_seconds,
        )
        self.http = requests.Session()
        self.telemetry = Telemetry()
        self.store: MetricsStore = create_metrics_store(
            DatabaseSettings.from_env(),
            flush_rows=self.settings.database_flush_rows,
        )
        self.monitor_thread = hub.spawn(self._monitor_loop)
        self.logger.info(
            "Controller started: OpenFlow=1.3 mitigation_enabled=%s "
            "database_enabled=%s",
            self.settings.mitigation_enabled,
            DatabaseSettings.from_env().enabled,
        )

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, event: Any) -> None:
        datapath = event.datapath
        if event.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info("Switch connected: dpid=%016x", datapath.id)
        elif event.state == DEAD_DISPATCHER:
            # A datapath can reach DEAD_DISPATCHER before it ever reported an id
            # (a connection dropped during handshake); guard the %x formatting so
            # a teardown never raises a logging TypeError on a None dpid.
            if datapath.id is None:
                self.logger.info("Switch disconnected before it reported a dpid")
            else:
                self.datapaths.pop(datapath.id, None)
                self.logger.info("Switch disconnected: dpid=%016x", datapath.id)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event: Any) -> None:
        datapath = event.msg.datapath
        parser = datapath.ofproto_parser
        actions = [
            parser.OFPActionOutput(
                datapath.ofproto.OFPP_CONTROLLER,
                datapath.ofproto.OFPCML_NO_BUFFER,
            )
        ]
        self.add_flow(datapath, 0, parser.OFPMatch(), actions)

    @staticmethod
    def add_flow(
        datapath: Any,
        priority: int,
        match: Any,
        actions: List[Any],
        idle_timeout: int = 0,
        hard_timeout: int = 0,
    ) -> None:
        parser = datapath.ofproto_parser
        instructions = [
            parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS,
                actions,
            )
        ]
        datapath.send_msg(
            parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=instructions,
                idle_timeout=int(idle_timeout),
                hard_timeout=int(hard_timeout),
            )
        )

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, event: Any) -> None:
        # Every Packet-In, including the ones this handler ignores.
        self._packet_ins = getattr(self, "_packet_ins", 0) + 1
        message = event.msg
        datapath = message.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        parsed = packet.Packet(message.data)
        ethernet_frame = parsed.get_protocol(ethernet.ethernet)
        if (
            ethernet_frame is None
            or ethernet_frame.ethertype == ether_types.ETH_TYPE_LLDP
        ):
            return

        dpid = datapath.id
        input_port = message.match["in_port"]
        self.mac_to_port.setdefault(dpid, {})[ethernet_frame.src] = input_port
        output_port = self.mac_to_port[dpid].get(ethernet_frame.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(output_port)]

        if output_port != ofproto.OFPP_FLOOD:
            match = self._packet_match(
                parser,
                parsed,
                input_port,
                ethernet_frame.src,
                ethernet_frame.dst,
            )
            self.add_flow(
                datapath,
                1,
                match,
                actions,
                idle_timeout=self.settings.flow_idle_timeout_seconds,
            )

        data = message.data if message.buffer_id == ofproto.OFP_NO_BUFFER else None
        datapath.send_msg(
            parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=message.buffer_id,
                in_port=input_port,
                actions=actions,
                data=data,
            )
        )

    @staticmethod
    def _packet_match(
        parser: Any,
        parsed: Any,
        input_port: int,
        source_mac: str,
        destination_mac: str,
    ) -> Any:
        ip_packet = parsed.get_protocol(ipv4.ipv4)
        tcp_packet = parsed.get_protocol(tcp.tcp)
        udp_packet = parsed.get_protocol(udp.udp)
        if ip_packet is None or (tcp_packet is None and udp_packet is None):
            return parser.OFPMatch(
                in_port=input_port,
                eth_src=source_mac,
                eth_dst=destination_mac,
            )
        fields: Dict[str, Any] = {
            "in_port": input_port,
            "eth_src": source_mac,
            "eth_dst": destination_mac,
            "eth_type": ether_types.ETH_TYPE_IP,
            "ipv4_src": ip_packet.src,
            "ipv4_dst": ip_packet.dst,
            "ip_proto": int(ip_packet.proto),
        }
        if MATCH_L4_PORTS:
            if tcp_packet is not None:
                fields["tcp_dst"] = int(tcp_packet.dst_port)
            elif udp_packet is not None:
                fields["udp_dst"] = int(udp_packet.dst_port)
        return parser.OFPMatch(**fields)

    def _monitor_loop(self) -> None:
        process = psutil.Process(os.getpid())
        process.cpu_percent(interval=None)
        while True:
            # This loop polls the switches; every detector depends on it. An error
            # in one poll is reported and the next poll goes ahead, instead of the
            # greenthread dying and leaving the run without statistics.
            try:
                self._monitor_once(process)
            except Exception as exc:
                self._report_error("monitor", exc)
            hub.sleep(self.settings.poll_interval_seconds)

    def _report_error(self, where: str, exc: BaseException) -> None:
        """Log an internal error and tell the lab about it (`controller_error`)."""

        self.logger.exception("controller error in %s", where)
        self.telemetry.emit(
            "controller_error", {"where": where, "error": repr(exc)[:500]}
        )

    def _monitor_once(self, process: Any) -> None:
        """One poll: ask the switches for statistics, publish the controller sample."""

        observed_at = datetime.now(timezone.utc)
        for datapath in list(self.datapaths.values()):
            self._request_stats(datapath)
        times = process.cpu_times()
        resource_row = {
            "ts": observed_at,
            "cpu_percent": float(process.cpu_percent(interval=None)),
            "rss_bytes": int(process.memory_info().rss),
            "cpu_seconds": round(times.user + times.system, 6),
        }
        count = int(getattr(self, "_packet_ins", 0))
        rate, baseline = handled_rate(
            getattr(self, "_packet_in_sample", None),
            count,
            time.monotonic(),
        )
        self._packet_in_sample = baseline
        resource_row["packet_in_handled"] = count
        resource_row["packet_in_handled_per_s"] = rate
        try:
            resource_row.update(self._extra_resources())
        except Exception as exc:  # the sample itself still goes out
            self._report_error("extra controller fields", exc)
        self.telemetry.emit("controller", resource_row)
        self.store.add_controller_row(resource_row)

    def _extra_resources(self) -> Dict[str, Any]:
        """More fields for the controller sample; the detection modes add their cost."""

        return {}

    @staticmethod
    def _request_stats(datapath: Any) -> None:
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowStatsRequest(datapath))
        datapath.send_msg(
            parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY)
        )

    def _predict(self, samples: List[Dict[str, Any]]) -> Optional[List[Dict[str, Any]]]:
        if not samples or not self.settings.inference_api_key:
            return None
        predictions: List[Dict[str, Any]] = []
        try:
            for offset in range(0, len(samples), 500):
                chunk = samples[offset : offset + 500]
                response = self.http.post(
                    self.settings.inference_url,
                    json={"samples": chunk},
                    headers={"X-Api-Key": self.settings.inference_api_key},
                    timeout=(0.5, 2.0),
                )
                response.raise_for_status()
                payload = response.json()
                chunk_predictions = payload.get("predictions")
                if not isinstance(chunk_predictions, list) or len(
                    chunk_predictions
                ) != len(chunk):
                    raise ValueError("inference response has an invalid result count")
                predictions.extend(chunk_predictions)
        except (requests.RequestException, ValueError, TypeError) as exc:
            self.logger.error("DDoS inference request failed: %s", exc)
            return None
        return predictions

    def _maybe_block(self, source_ip: Optional[str], detected_at: datetime) -> bool:
        if not self.settings.mitigation_enabled or not source_ip:
            return False
        if not self.blocks.reserve(source_ip, time.time()):
            return False
        affected = 0
        for datapath in list(self.datapaths.values()):
            match = datapath.ofproto_parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=source_ip,
            )
            self.add_flow(
                datapath,
                100,
                match,
                [],
                hard_timeout=self.settings.block_seconds,
            )
            affected += 1
        self.store.record_mitigation(
            {
                "ts": detected_at,
                "ipv4_src": source_ip,
                "action": "temporary_drop",
                "duration_seconds": self.settings.block_seconds,
                "affected_switches": affected,
            }
        )
        self.telemetry.emit(
            "mitigation_requested",
            {
                "ipv4_src": source_ip,
                "duration_seconds": self.settings.block_seconds,
                "affected_switches": affected,
            },
        )
        self.logger.warning(
            "MITIGATION temporary_drop ipv4_src=%s duration=%ss switches=%s",
            source_ip,
            self.settings.block_seconds,
            affected,
        )
        return True

    @staticmethod
    def _safe_int(value: Any) -> Optional[int]:
        try:
            return None if value is None else int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _flow_key(dpid: int, stat: Any) -> Tuple[Any, ...]:
        match = stat.match
        return (
            dpid,
            match.get("in_port"),
            match.get("eth_src"),
            match.get("eth_dst"),
            match.get("ipv4_src"),
            match.get("ipv4_dst"),
            match.get("ip_proto"),
            match.get("tcp_src", match.get("udp_src")),
            match.get("tcp_dst", match.get("udp_dst")),
            stat.priority,
            stat.cookie,
        )

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, event: Any) -> None:
        if not getattr(self, "_switch_table_already_emitted", False):
            self._emit_switch_table(event.msg.datapath.id, event.msg.body)
        self._switch_table_already_emitted = False
        batch = self._flow_batch(event)
        self._finish_flow_batch(batch, self._predict(batch.samples))

    def _emit_switch_table(self, dpid: int, body: List[Any]) -> None:
        """Rule count and table-miss rate from the full reply, before any trim."""

        telemetry = getattr(self, "telemetry", None)
        if telemetry is None:
            return
        baselines = getattr(self, "_table_miss_baselines", None)
        if baselines is None:
            baselines = {}
            self._table_miss_baselines = baselines
        event, baseline = switch_table_sample(int(dpid), body, baselines.get(int(dpid)))
        if baseline is None:
            baselines.pop(int(dpid), None)
        else:
            baselines[int(dpid)] = baseline
        telemetry.emit("switch_table", event)

    def _flow_batch(self, event: Any) -> FlowBatch:
        dpid = event.msg.datapath.id
        observed_at = datetime.now(timezone.utc)
        rows: List[Dict[str, Any]] = []
        samples: List[Dict[str, Any]] = []
        sample_indexes: List[int] = []

        for stat in event.msg.body:
            if stat.priority == 0:
                continue
            packet_count = int(stat.packet_count)
            byte_count = int(stat.byte_count)
            rates = observe_flow_rate(
                self.flow_rates,
                self._flow_key(dpid, stat),
                packet_count,
                byte_count,
                int(getattr(stat, "duration_sec", 0)),
                int(getattr(stat, "duration_nsec", 0)),
            )
            match = stat.match
            l4_source = match.get("tcp_src", match.get("udp_src"))
            l4_destination = match.get("tcp_dst", match.get("udp_dst"))
            row: Dict[str, Any] = {
                "ts": observed_at,
                "dpid": int(dpid),
                "table_id": self._safe_int(getattr(stat, "table_id", None)),
                "priority": int(stat.priority),
                "cookie": int(getattr(stat, "cookie", 0)),
                "eth_src": match.get("eth_src"),
                "eth_dst": match.get("eth_dst"),
                "ipv4_src": match.get("ipv4_src"),
                "ipv4_dst": match.get("ipv4_dst"),
                "ip_proto": self._safe_int(match.get("ip_proto")),
                "l4_src_port": self._safe_int(l4_source),
                "l4_dst_port": self._safe_int(l4_destination),
                "packet_count": packet_count,
                "byte_count": byte_count,
                "duration_sec": int(getattr(stat, "duration_sec", 0)),
                "duration_nsec": int(getattr(stat, "duration_nsec", 0)),
                "pktrate": None if rates is None else rates[0],
                "byterate": None if rates is None else rates[1],
                "label": 0,
                "prob_ddos": None,
            }
            sample = build_model_sample(
                row, port_free=not getattr(self, "match_l4_ports", True)
            )
            if sample is not None:
                samples.append(sample)
                sample_indexes.append(len(rows))
            rows.append(row)
        return FlowBatch(dpid, observed_at, rows, samples, sample_indexes)

    def _is_protected(self, source: Optional[str]) -> bool:
        """Whether `source` may never be named as an attacker. The baseline names
        anyone; `ModeSwitchController` answers from the protected list."""

        return False

    def _name_refused(self, source: Optional[str], detector: str) -> bool:
        """True when a detector tried to name a protected host: the name is dropped and
        counted, so a run can say how often the victim would have been named."""

        if not self._is_protected(source):
            return False
        counts = getattr(self, "names_suppressed", None)
        if counts is None:
            counts = self.names_suppressed = {}
        key = f"{detector}:{source}"
        first = key not in counts
        counts[key] = counts.get(key, 0) + 1
        if first:
            self.logger.warning(
                "NAME SUPPRESSED detector=%s host=%s is protected (counted, "
                "not logged again)",
                detector,
                source,
            )
        return True

    def _unprotected(self, sources: Sequence[str], detector: str) -> Tuple[str, ...]:
        """The sources a detector may name: `sources` minus the protected hosts."""

        return tuple(s for s in sources if not self._name_refused(s, detector))

    def _finish_flow_batch(
        self, batch: FlowBatch, predictions: Optional[List[Dict[str, Any]]]
    ) -> None:
        dpid, observed_at, rows = batch.dpid, batch.observed_at, batch.rows
        sample_indexes = batch.sample_indexes
        if predictions is not None:
            for prediction, row_index in zip(predictions, sample_indexes):
                probability = prediction.get("prob_ddos")
                if not probability_is_attack(
                    probability, self.settings.detection_threshold
                ):
                    with contextlib.suppress(TypeError, ValueError):
                        rows[row_index]["prob_ddos"] = float(probability)
                    continue
                probability_value = float(probability)
                row = rows[row_index]
                row["prob_ddos"] = probability_value
                if self._name_refused(row["ipv4_src"], "llm"):
                    continue  # the model's score stays on the row; nobody is named
                row["label"] = 1
                self.store.record_detection(
                    {
                        "ts": observed_at,
                        "dpid": row["dpid"],
                        "ipv4_src": row["ipv4_src"],
                        "ipv4_dst": row["ipv4_dst"],
                        "ip_proto": row["ip_proto"],
                        "l4_dst_port": row["l4_dst_port"],
                        "probability": probability_value,
                        "threshold": self.settings.detection_threshold,
                        "mitigation_enabled": self.settings.mitigation_enabled,
                    }
                )
                self.logger.warning(
                    "DDoS DETECTED dpid=%s src=%s dst=%s probability=%.4f",
                    row["dpid"],
                    row["ipv4_src"],
                    row["ipv4_dst"],
                    probability_value,
                )
                self.telemetry.emit(
                    "detection",
                    {
                        "dpid": dpid,
                        "ipv4_src": row["ipv4_src"],
                        "ipv4_dst": row["ipv4_dst"],
                        "probability": probability_value,
                        "threshold": self.settings.detection_threshold,
                    },
                )
                self._maybe_block(row["ipv4_src"], observed_at)
        for offset in range(0, len(rows), 20):
            self.telemetry.emit(
                "flows", {"dpid": dpid, "rows": rows[offset : offset + 20]}
            )
        self.store.add_flow_rows(rows)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, event: Any) -> None:
        dpid = event.msg.datapath.id
        observed_at = datetime.now(timezone.utc)
        observed_clock = time.monotonic()
        rows: List[Dict[str, Any]] = []
        for stat in event.msg.body:
            rates = self.port_rates.observe(
                (dpid, int(stat.port_no)),
                int(stat.rx_bytes),
                int(stat.tx_bytes),
                observed_clock,
            )
            rows.append(
                {
                    "ts": observed_at,
                    "dpid": int(dpid),
                    "port_no": int(stat.port_no),
                    "rx_packets": int(stat.rx_packets),
                    "tx_packets": int(stat.tx_packets),
                    "rx_bytes": int(stat.rx_bytes),
                    "tx_bytes": int(stat.tx_bytes),
                    "rx_dropped": int(stat.rx_dropped),
                    "tx_dropped": int(stat.tx_dropped),
                    "rx_errors": int(stat.rx_errors),
                    "tx_errors": int(stat.tx_errors),
                    "rx_byterate": None if rates is None else rates[0],
                    "tx_byterate": None if rates is None else rates[1],
                }
            )
        self.store.add_port_rows(rows)

    def close(self) -> None:
        try:
            self.store.close()
        finally:
            self.telemetry.close()
            self.http.close()
            super().close()
