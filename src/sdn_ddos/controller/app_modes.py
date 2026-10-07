"""Controller with a user-selectable detection mode (LLM or entropy, never mixed).

Subclasses the baseline EnterpriseDDoSController without modifying it.

    SDN_DETECTION_MODE=llm      flow samples go to the LLM inference service
                                (same /predict contract as the baseline).
    SDN_DETECTION_MODE=entropy  network-wide Shannon-entropy detector runs
                                inside the controller; the LLM is not used.
    SDN_DETECTION_MODE=off      monitoring only (metrics still stored).

Only one detector is active per run so their behaviour can be compared. Every
decision is logged to `detection_decisions` (detector column) and mitigation,
when enabled, reuses the baseline guarded `_maybe_block`.

Robustness changes over the baseline (all opt-out through env vars):

* Flow-stats replies arrive in several multipart chunks; they are reassembled so
  each poll is handled once per switch.
* Under a flood the flow tables explode (a SYN flood makes every RST reply a new
  flow). At most SDN_MAX_FLOW_ROWS_PER_POLL rows per switch and poll (the most
  active flows) are persisted/analysed by the baseline pipeline; entropy is
  still computed over ALL flows.
* Only SDN_LLM_MAX_SAMPLES samples per poll (highest packet rate) are sent to
  the LLM, which costs ~0.5 s each; the rest keep prob_ddos NULL.
* SDN_FINE_GRAINED_MATCH (default true): forwarding rules always include
  eth_type and, for IPv4, the addresses and protocol. The baseline installs an
  Ethernet-only rule after the first ARP/ICMP packet of a host pair, which then
  also swallows later TCP/UDP traffic and leaves ip_proto/l4_dst_port empty.
"""

from __future__ import annotations

import os
import time
from collections import OrderedDict
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

import requests
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, ipv4, tcp, udp

from sdn_ddos.async_io import AsyncMetricsStore
from sdn_ddos.config import DatabaseSettings
from sdn_ddos.controller.app import EnterpriseDDoSController
from sdn_ddos.controller.core import probability_is_attack
from sdn_ddos.controller.enforcer import LIMIT_PRIORITY, OpenFlowEnforcer
from sdn_ddos.controller.response import (
    LIMIT,
    POLICIES,
    Action,
    ResponseManager,
    ResponseSettings,
)
from sdn_ddos.decision_log import create_decision_log
from sdn_ddos.detection.entropy import EntropyDetector, FlowObservation
from sdn_ddos.detection.entropy_client import RemoteEntropy, fetch_remote_config
from sdn_ddos.storage import create_metrics_store


class _TimeoutSession(requests.Session):
    """The baseline hard-codes a 2 s read timeout, shorter than a batch of LLM calls."""

    def __init__(self, timeout: float) -> None:
        super().__init__()
        self._timeout = timeout

    def request(  # type: ignore[override]
        self, method: str, url: str, **kwargs: Any
    ) -> Any:
        kwargs["timeout"] = self._timeout
        return super().request(method, url, **kwargs)


MODES = ("llm", "entropy", "off")
NETWORK_SCOPE = 0  # dpid slot used by the entropy detector for the whole network


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


FINE_GRAINED_MATCH = _truthy(os.environ.get("SDN_FINE_GRAINED_MATCH", "true"))


class ModeSwitchController(EnterpriseDDoSController):
    """Baseline controller plus a selectable detection mechanism."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # With the detector service the mode is chosen there (PUT /config) and
        # fixed for this run; without it (standalone scripts) the env decides.
        detector_base = self.settings.inference_url.rsplit("/", 1)[0]
        remote = fetch_remote_config(detector_base, self.settings.inference_api_key)
        mode = (
            str(
                remote["mode"]
                if remote
                else os.environ.get("SDN_DETECTION_MODE", "llm")
            )
            .strip()
            .lower()
        )
        if mode not in MODES:
            raise ValueError(f"detection mode must be one of {MODES}, got {mode!r}")
        self.mode = mode
        database = DatabaseSettings.from_env()
        self.decisions = create_decision_log(database)
        if database.enabled:
            # Blocking psycopg2 calls would freeze the whole event loop if the
            # connection stalls (observed under flood); run them on a thread.
            self.store.close()
            flush_rows = self.settings.database_flush_rows
            self.store = AsyncMetricsStore(
                lambda: create_metrics_store(database, flush_rows=flush_rows)
            )
        self.max_rows = int(os.environ.get("SDN_MAX_FLOW_ROWS_PER_POLL", "300"))
        self.llm_max_samples = int(os.environ.get("SDN_LLM_MAX_SAMPLES", "5"))
        # The LLM is deterministic (temperature 0, fixed seed), so a sample the
        # model has already judged needs no second call; this keeps the event loop
        # free (each call blocks the app's event queue for ~0.3 s).
        self.llm_cache_size = int(os.environ.get("SDN_LLM_CACHE_SIZE", "4096"))
        self._verdicts: "OrderedDict[Tuple[Any, ...], Dict[str, Any]]" = OrderedDict()
        self.http = _TimeoutSession(float(os.environ.get("SDN_LLM_HTTP_TIMEOUT", "30")))
        self.entropy: Any = (
            RemoteEntropy(
                detector_base,
                self.settings.inference_api_key,
                os.environ.get("SDN_RUN_ID") or "standalone",
            )
            if remote
            else EntropyDetector.from_env()
        )
        self.entropy_window = float(os.environ.get("SDN_ENTROPY_WINDOW_SECONDS", "10"))
        self._pending_stats: Dict[int, List[Any]] = {}
        self._packet_history: Dict[int, Dict[Any, int]] = {}
        self._last_poll: Dict[int, float] = {}
        self._window_flows: Dict[int, Tuple[float, List[FlowObservation], int]] = {}
        response_settings = ResponseSettings.from_env(
            os.environ, self.settings.block_seconds
        )
        if remote and remote.get("response") in POLICIES:
            # chosen in the detector service (like the mode), fixed for this run
            response_settings = replace(
                response_settings,
                policy=remote["response"],
                dry_run=bool(remote.get("dry_run", response_settings.dry_run)),
            )
        self.responder = ResponseManager(
            response_settings,
            self.settings.allowed_target_networks,
            OpenFlowEnforcer(self.datapaths),
        )
        self._limit_seen: Dict[Tuple[int, str], Tuple[int, float]] = {}
        self._offered: Dict[str, Dict[int, float]] = {}
        self.response_thread = hub.spawn(self._response_loop)
        if self.mode == "entropy":
            self.entropy_thread = hub.spawn(self._entropy_loop)
        self.logger.info(
            "Detection mode=%s source=%s fine_grained_match=%s max_rows=%s",
            self.mode,
            "detector-service" if remote else "environment",
            FINE_GRAINED_MATCH,
            self.max_rows,
        )

    # -- forwarding rules -------------------------------------------------

    @staticmethod
    def _packet_match(
        parser: Any,
        parsed: Any,
        input_port: int,
        source_mac: str,
        destination_mac: str,
    ) -> Any:
        if not FINE_GRAINED_MATCH:
            return EnterpriseDDoSController._packet_match(
                parser, parsed, input_port, source_mac, destination_mac
            )
        frame = parsed.get_protocol(ethernet.ethernet)
        fields: Dict[str, Any] = {
            "in_port": input_port,
            "eth_src": source_mac,
            "eth_dst": destination_mac,
            "eth_type": frame.ethertype,
        }
        ip_packet = parsed.get_protocol(ipv4.ipv4)
        if ip_packet is not None:
            fields["ipv4_src"] = ip_packet.src
            fields["ipv4_dst"] = ip_packet.dst
            fields["ip_proto"] = int(ip_packet.proto)
            tcp_packet = parsed.get_protocol(tcp.tcp)
            udp_packet = parsed.get_protocol(udp.udp)
            if tcp_packet is not None:
                fields["tcp_dst"] = int(tcp_packet.dst_port)
            elif udp_packet is not None:
                fields["udp_dst"] = int(udp_packet.dst_port)
        return parser.OFPMatch(**fields)

    # -- flow statistics --------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)  # type: ignore[untyped-decorator]
    def flow_stats_reply_handler(self, event: Any) -> None:
        message = event.msg
        datapath = message.datapath
        dpid = int(datapath.id)
        chunks = self._pending_stats.setdefault(dpid, [])
        chunks.extend(message.body)
        if message.flags & datapath.ofproto.OFPMPF_REPLY_MORE:
            return
        body = self._pending_stats.pop(dpid)
        total_flows = len(body)
        if self.settings.mitigation_enabled:
            self._review_limits(dpid, body)

        if self.mode == "entropy":
            self._observe_entropy_window(dpid, body)

        kept = sorted(body, key=lambda stat: int(stat.packet_count), reverse=True)
        kept = kept[: self.max_rows]
        if total_flows > len(kept):
            self.logger.warning(
                "dpid=%s reports %s flows; analysing/persisting the %s most active",
                dpid,
                total_flows,
                len(kept),
            )
        super().flow_stats_reply_handler(
            SimpleNamespace(msg=SimpleNamespace(datapath=datapath, body=kept))
        )

    # -- LLM mode ---------------------------------------------------------

    def _predict(self, samples: List[Dict[str, Any]]) -> Optional[List[Dict[str, Any]]]:
        if self.mode != "llm" or not samples:
            return None
        keys = [self._sample_key(sample) for sample in samples]
        ranked = sorted(
            range(len(samples)), key=lambda i: samples[i]["pktrate"], reverse=True
        )
        # Most active flows first. Known samples are free; only NEW ones count
        # against the per-poll cap, and identical new ones are asked once.
        selected: List[int] = []
        fresh: Dict[Tuple[Any, ...], int] = {}
        for index in ranked:
            key = keys[index]
            if key in self._verdicts or key in fresh:
                selected.append(index)
            elif len(fresh) < self.llm_max_samples:
                fresh[key] = index
                selected.append(index)
        # Read what is already known BEFORE adding new verdicts: inserting may evict.
        verdict_of: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        for i in selected:
            if keys[i] in self._verdicts:
                verdict_of[keys[i]] = self._verdicts[keys[i]]
                self._verdicts.move_to_end(keys[i])
        fresh_ms = 0.0
        if fresh:
            started = time.monotonic()
            answered = super()._predict([samples[i] for i in fresh.values()])
            fresh_ms = (time.monotonic() - started) * 1000.0 / len(fresh)
            if answered is None:
                selected = [i for i in selected if keys[i] in verdict_of]
                fresh = {}
            else:
                for key, prediction in zip(fresh, answered):
                    verdict_of[key] = prediction
                    self._verdicts[key] = prediction
                while len(self._verdicts) > self.llm_cache_size:
                    self._verdicts.popitem(last=False)
        if not selected:
            return None
        neutral: Dict[str, Any] = {"pred_label": 0, "prob_ddos": None}
        full: List[Dict[str, Any]] = [dict(neutral) for _ in samples]
        asked = set(fresh.values())
        for index in sorted(selected):
            prediction = verdict_of[keys[index]]
            full[index] = prediction
            probability = float(prediction.get("prob_ddos", 0.0))
            self.decisions.record(
                "llm",
                probability_is_attack(probability, self.settings.detection_threshold),
                score=probability,
                latency_ms=fresh_ms if index in asked else None,
                details={
                    "sample": samples[index],
                    "evaluated": len(selected),
                    "new_calls": len(fresh),
                    "cached": index not in asked,
                    "flows_in_poll": len(samples),
                },
            )
        return full

    @staticmethod
    def _sample_key(sample: Dict[str, Any]) -> Tuple[Any, ...]:
        """What the model actually sees (the prompt prints rates with 2 decimals)."""

        return (
            int(sample["packet_count"]),
            int(sample["byte_count"]),
            round(float(sample["pktrate"]), 2),
            round(float(sample["byterate"]), 2),
            int(sample["ip_proto"]),
            int(sample["l4_dst_port"]),
        )

    # -- entropy mode -----------------------------------------------------

    def _observe_entropy_window(self, dpid: int, body: List[Any]) -> None:
        """Turn one switch's full flow list into packet-rate weighted flows."""

        now = time.monotonic()
        previous = self._packet_history.get(dpid, {})
        last_poll = self._last_poll.get(dpid)
        elapsed = None if last_poll is None else now - last_poll
        current: Dict[Any, int] = {}
        flows: List[FlowObservation] = []
        for stat in body:
            if stat.priority == 0:
                continue
            key = self._flow_key(dpid, stat)
            count = int(stat.packet_count)
            current[key] = count
            source = stat.match.get("ipv4_src")
            destination = stat.match.get("ipv4_dst")
            if source is None or destination is None or not elapsed:
                continue
            before = previous.get(key, 0)
            delta = count - before if count >= before else count
            if delta > 0:
                flows.append(
                    FlowObservation(str(source), str(destination), delta / elapsed)
                )
        self._packet_history[dpid] = current
        self._last_poll[dpid] = now
        if elapsed:
            self._window_flows[dpid] = (now, flows, len(body))

    def _entropy_loop(self) -> None:
        while True:
            hub.sleep(self.entropy_window)
            now = time.monotonic()
            fresh = {
                dpid: entry
                for dpid, entry in self._window_flows.items()
                if now - entry[0] <= 2 * self.entropy_window
            }
            flows = [flow for _, per_switch, _ in fresh.values() for flow in per_switch]
            try:
                result = self.entropy.observe(NETWORK_SCOPE, flows)
            except (requests.RequestException, KeyError, ValueError) as exc:
                self.logger.error("entropy window skipped, detector failed: %s", exc)
                continue
            if result.reason == "idle":
                continue
            observed_at = datetime.now(timezone.utc)
            details = result.as_details()
            details["flows_per_switch"] = {str(d): e[2] for d, e in fresh.items()}
            score = (
                min(1.0, result.consecutive / self.entropy.consecutive_windows)
                if result.evaluated
                else None
            )
            self.decisions.record(
                "entropy",
                result.confirmed,
                score=score,
                details=details,
                ts=observed_at,
            )
            if not result.confirmed:
                continue
            self.logger.warning(
                "ENTROPY ALARM target=%s candidates=%s h_src=%.3f h_dst=%.3f",
                result.target_dst,
                result.candidates,
                result.h_src,
                result.h_dst,
            )
            self.telemetry.emit(
                "detection",
                {
                    "dpid": NETWORK_SCOPE,
                    "ipv4_src": result.candidates[0] if result.candidates else None,
                    "ipv4_dst": result.target_dst,
                    "probability": score,
                    "threshold": 1.0,
                    "detector": "entropy",
                    "candidates": list(result.candidates),
                },
            )
            for source in result.candidates:
                self._maybe_block(source, observed_at)

    # -- response ---------------------------------------------------------

    def _maybe_block(self, source_ip: Optional[str], detected_at: datetime) -> bool:
        """Both detectors report here; the policy picks drop, rate limit or nothing."""

        if not self.settings.mitigation_enabled or not source_ip:
            return False
        action = self.responder.respond(source_ip, reason=self.mode)
        if action is None:
            return False
        self._record_response(action, detected_at)
        return True

    def _record_response(self, action: Action, detected_at: datetime) -> None:
        self.store.record_mitigation(
            {
                "ts": detected_at,
                "ipv4_src": action.source,
                "action": action.label,
                "duration_seconds": action.seconds,
                "affected_switches": action.switches,
            }
        )
        if not action.dry_run:
            # A dry run changes nothing, so it must not count as a request in the GUI.
            self.telemetry.emit(
                "mitigation_requested",
                {
                    "ipv4_src": action.source,
                    "action": action.label,
                    "rate_limit_pps": action.pps,
                    "duration_seconds": action.seconds,
                    "affected_switches": action.switches,
                },
            )
        self.logger.warning(
            "RESPONSE %s source=%s duration=%ss switches=%s trigger=%s",
            action.label,
            action.source,
            action.seconds,
            action.switches,
            action.reason,
        )

    def _review_limits(self, dpid: int, body: List[Any]) -> None:
        """Give the policy the rate each limited source still offers.

        The limit rule shadows the flow the detectors watch, so its own counter
        (read before the meter drops) is the only evidence left of the source.
        """

        now = time.monotonic()
        for stat in body:
            if stat.priority != LIMIT_PRIORITY:
                continue
            source = stat.match.get("ipv4_src")
            if source is None:
                continue
            count = int(stat.packet_count)
            key = (dpid, str(source))
            seen = self._limit_seen.get(key)
            self._limit_seen[key] = (count, now)
            if seen is None or now <= seen[1]:
                continue
            before, then = seen
            delta = count - before if count >= before else count
            self._offered.setdefault(str(source), {})[dpid] = delta / (now - then)
        limited = {s for s, kind in self.responder.active().items() if kind == LIMIT}
        for source in [s for s in self._offered if s not in limited]:
            del self._offered[source]
            for key in [k for k in self._limit_seen if k[1] == source]:
                del self._limit_seen[key]
        if not self._offered:
            return
        rates = {s: max(per_switch.values()) for s, per_switch in self._offered.items()}
        for action in self.responder.review(rates):
            self._record_response(action, datetime.now(timezone.utc))

    def _response_loop(self) -> None:
        while True:
            hub.sleep(5)
            for source in self.responder.expire():
                self.logger.info("response finished source=%s", source)

    # -- lifecycle --------------------------------------------------------

    def close(self) -> None:
        try:
            self.decisions.close()
        finally:
            super().close()
