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
* SDN_MATCH_L4_PORTS is required and is true or false. Missing or any other
  value refuses to start. False omits the layer-4 port; see MATCH_L4_PORTS.
* SDN_FINE_GRAINED_MATCH (default true): forwarding rules always include
  eth_type and, for IPv4, the addresses and protocol. The baseline installs an
  Ethernet-only rule after the first ARP/ICMP packet of a host pair, which then
  also swallows later TCP/UDP traffic and leaves ip_proto/l4_dst_port empty.
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter, OrderedDict, defaultdict
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

import requests
from ryu.controller import ofp_event
from ryu.controller.handler import DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, ipv4, tcp, udp

from sdn_ddos.async_io import AsyncMetricsStore
from sdn_ddos.config import DatabaseSettings
from sdn_ddos.controller.app import EnterpriseDDoSController, FlowBatch
from sdn_ddos.controller.core import (
    CountedFlow,
    entropy_poll_from_switch_clock,
    flow_age_seconds,
    probability_is_attack,
)
from sdn_ddos.controller.cost import DecisionCost, cpu_percent_since
from sdn_ddos.controller.enforcer import LIMIT_PRIORITY, OpenFlowEnforcer
from sdn_ddos.controller.judging import PollQueue, judging_order, next_window_due
from sdn_ddos.controller.response import (
    LIMIT,
    POLICIES,
    Action,
    ResponseManager,
    ResponseSettings,
)
from sdn_ddos.controller.stats_buffer import StatsReassembler
from sdn_ddos.decision_log import create_decision_log
from sdn_ddos.detection.entropy import (
    EntropyDetector,
    EntropyResult,
    FlowObservation,
    Histogram,
    format_signal,
    mean_rates,
    merge_switch_rates,
    window_state,
)
from sdn_ddos.detection.entropy_client import (
    RemoteEntropy,
    fetch_remote_config,
    fetch_usage,
)
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


MODES = ("llm", "rule", "entropy", "off")
# Modes that judge flow samples through the detector's /predict: the LLM and the
# packet-rate rule that is its comparison arm. Both get exactly the same samples
# (same per-poll budget, judging order and cache) and the same response.
FLOW_MODES = ("llm", "rule")
MAX_HISTOGRAM_BINS = 2000  # the detector service accepts at most 5000 per request
NETWORK_SCOPE = 0  # dpid slot used by the entropy detector for the whole network


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


FINE_GRAINED_MATCH = _truthy(os.environ.get("SDN_FINE_GRAINED_MATCH", "true"))
# No default. EnterpriseDDoSController.__init__ refuses to start unless the variable
# is true or false, then copies the choice here for _packet_match.
MATCH_L4_PORTS: Optional[bool] = None


class ModeSwitchController(EnterpriseDDoSController):
    """Baseline controller plus a selectable detection mechanism."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        global MATCH_L4_PORTS
        MATCH_L4_PORTS = self.match_l4_ports
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
        # What each decision costs (see controller/cost.py): running totals sent with
        # every controller sample, and the detector service's own CPU time and memory.
        self.cost = DecisionCost()
        self._detector_base = detector_base if remote else ""
        self._usage_sample: Optional[Tuple[float, float]] = None
        self._usage_row: Dict[str, Any] = {}
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
        # A source the model has just flagged is judged after the busy sources not
        # flagged yet, so a small sample budget is not spent re-judging the same
        # attackers while another one (other protocol, lower rate) is never looked at.
        self.llm_repeat_seconds = float(os.environ.get("SDN_LLM_REPEAT_SECONDS", "30"))
        self.llm_busy_rate = float(os.environ.get("SDN_LLM_BUSY_RATE", "20"))
        self._flagged_at: Dict[str, float] = {}
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
        self._stats = StatsReassembler()
        self._packet_history: Dict[int, Dict[Any, Tuple[int, int, float]]] = {}
        self._window_flows: Dict[int, Tuple[float, List[FlowObservation], int]] = {}
        # How a window is built (see _window_observations); the defaults keep the
        # original behaviour.
        window_mode = os.environ.get("SDN_ENTROPY_WINDOW_MODE", "snapshot")
        self.entropy_window_mode = window_mode.strip().lower()
        if self.entropy_window_mode not in ("snapshot", "mean"):
            raise ValueError(
                f"SDN_ENTROPY_WINDOW_MODE must be snapshot or mean, got {window_mode!r}"
            )
        self.entropy_dedupe = os.environ.get(
            "SDN_ENTROPY_DEDUPE_SWITCHES", "false"
        ).strip().lower() in ("1", "true", "yes", "on")
        self._window_polls: Dict[
            int, List[Tuple[float, float, Dict[Tuple[str, str], float]]]
        ] = {}
        # Destination ports and protocols are only gathered when the detector is told
        # to watch them (SDN_ENTROPY_FEATURES); polls are kept per switch like the
        # pairs above, as (read time, seconds covered, packets per (proto, port)).
        features = os.environ.get("SDN_ENTROPY_FEATURES", "src,dst")
        self._tracks_ports = any(
            name.strip() in ("dport", "proto") for name in features.split(",")
        )
        self._window_ports: Dict[
            int, List[Tuple[float, float, Dict[Tuple[int, int], float]]]
        ] = {}
        # Every window is published as an `entropy_window` event; with
        # SDN_ENTROPY_DUMP the full window (flows and histograms) is also appended to
        # that file, for offline replays of the detector.
        self.entropy_dump = os.environ.get("SDN_ENTROPY_DUMP", "").strip()
        self._entropy_windows = 0
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
        # The model answers in seconds, but this app handles every packet-in on the same
        # greenthread as the stats replies, so a judgement made inline stalls new flows
        # (legitimate clients included). With SDN_LLM_ASYNC the judging happens on its
        # own greenthread; the handler only queues the poll.
        self._llm_pending: PollQueue[FlowBatch] = PollQueue()
        self._llm_wake: Any = hub.Queue(64)
        self.llm_skipped = 0
        if self.mode in FLOW_MODES and _truthy(os.environ.get("SDN_LLM_ASYNC", "true")):
            self.llm_thread: Any = hub.spawn(self._llm_loop)
        if self.mode == "entropy":
            self.entropy_thread = hub.spawn(self._entropy_loop)
        if self.mode != "off" and self._detector_base:
            # Its own greenthread: a slow /usage answer must never delay the
            # statistics polls that the detectors depend on.
            self.usage_thread = hub.spawn(self._usage_loop)
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
            if not MATCH_L4_PORTS:
                pass
            elif tcp_packet is not None:
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
        more = bool(message.flags & datapath.ofproto.OFPMPF_REPLY_MORE)
        body = self._stats.add(dpid, int(message.xid), message.body, more)
        if body is None:
            return
        # Full reply, before the row cap, in every detection mode.
        self._emit_switch_table(dpid, body)
        self._switch_table_already_emitted = True
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
        trimmed = SimpleNamespace(msg=SimpleNamespace(datapath=datapath, body=kept))
        if getattr(self, "llm_thread", None) is None:
            super().flow_stats_reply_handler(trimmed)
            return
        self._submit_llm(self._flow_batch(trimmed))

    @set_ev_cls(  # type: ignore[untyped-decorator]
        ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER]
    )
    def _forget_partial_stats(self, event: Any) -> None:
        """A reply cut off by a disconnect must not be glued to the next poll."""

        datapath = event.datapath
        if event.state != DEAD_DISPATCHER or datapath.id is None:
            return
        dpid = int(datapath.id)
        self._stats.clear(dpid)
        self._packet_history.pop(dpid, None)
        self._window_flows.pop(dpid, None)
        self._window_polls.pop(dpid, None)
        self._window_ports.pop(dpid, None)

    # -- decision cost ------------------------------------------------------

    def _record_cost(
        self,
        detector: str,
        decisions: int,
        elapsed_ms: float,
        *,
        reused: int = 0,
        failed: bool = False,
    ) -> None:
        """Add one detector call to the totals and publish it as `decision_cost`."""

        cost = getattr(self, "cost", None)
        if cost is None:
            cost = self.cost = DecisionCost()
        event = cost.add(detector, decisions, elapsed_ms, reused=reused, failed=failed)
        telemetry = getattr(self, "telemetry", None)
        if event is not None and telemetry is not None:
            telemetry.emit("decision_cost", event)

    def _extra_resources(self) -> Dict[str, Any]:
        """Decision totals, and the detector's latest CPU and memory sample."""

        # The base class starts its poll loop before this class has read the mode
        # from the detector service (that read yields to other greenthreads), so the
        # first samples can arrive while the mode is still unknown.
        mode = getattr(self, "mode", None)
        if mode is None:
            return {}
        row: Dict[str, Any] = {"detector": mode}
        row.update(getattr(self, "cost", DecisionCost()).totals())
        row["polls_skipped_total"] = int(getattr(self, "llm_skipped", 0))
        if mode != "off":
            row.update(getattr(self, "_usage_row", {}))
        return row

    def _sample_usage(self) -> None:
        """Read the detector service's CPU time and memory once."""

        base = getattr(self, "_detector_base", "")
        usage = fetch_usage(base, self.settings.inference_api_key) if base else None
        if usage is None:
            self._usage_row = {}  # a gap, never a stale value
            return
        percent, self._usage_sample = cpu_percent_since(
            getattr(self, "_usage_sample", None),
            usage["cpu_seconds"],
            time.monotonic(),
        )
        self._usage_row = {
            "detector_cpu_seconds": usage["cpu_seconds"],
            "detector_rss_bytes": int(usage["rss_bytes"]),
            "detector_cpu_percent": percent,
        }
        if "decision_cpu_seconds" in usage:
            self._usage_row["detector_decision_cpu_seconds"] = usage[
                "decision_cpu_seconds"
            ]

    def _usage_loop(self) -> None:
        interval = max(1.0, float(self.settings.poll_interval_seconds))
        while True:
            try:
                self._sample_usage()
            except Exception:  # the sampler must outlive one bad answer
                self.logger.exception("detector usage sample failed")
            hub.sleep(interval)

    # -- LLM judging off the event loop -------------------------------------

    def _submit_llm(self, batch: FlowBatch) -> None:
        """Queue a poll for the judging greenthread (see `PollQueue`)."""

        if not batch.samples:
            self._finish_flow_batch(batch, None)
            return
        busiest = max(float(sample["pktrate"]) for sample in batch.samples)
        older = self._llm_pending.put(batch.dpid, batch, busiest)
        if older is not None:
            self.llm_skipped += 1
            self._finish_flow_batch(older, None)  # kept in the tables, never judged
        if not self._llm_wake.qsize():  # one pending wake-up is enough
            self._llm_wake.put_nowait(None)

    def _next_llm_batch(self) -> FlowBatch:
        """The poll holding the busiest flow first: an attack is worth judging before
        the quiet switches."""

        return self._llm_pending.pop_busiest()

    def _llm_loop(self) -> None:
        while True:
            self._llm_wake.get()
            while self._llm_pending:
                batch = self._next_llm_batch()
                try:
                    sources = [
                        batch.rows[i].get("ipv4_src") for i in batch.sample_indexes
                    ]
                    predictions = self._predict(batch.samples, sources)
                    self._finish_flow_batch(batch, predictions)
                except Exception:  # the judge must outlive one bad poll
                    self.logger.exception("LLM judging of dpid=%s failed", batch.dpid)

    # -- LLM mode ---------------------------------------------------------

    def _priority(
        self, samples: List[Dict[str, Any]], sources: Optional[List[Optional[str]]]
    ) -> List[int]:
        """Judging order, see `judging_order`; the original busiest-first order when
        the sources are unknown or the repeat window is off."""

        rates = [float(sample["pktrate"]) for sample in samples]
        if not getattr(self, "llm_repeat_seconds", 0):
            return judging_order(rates, None, (), 0.0)
        now = time.monotonic()
        flagged = {
            source
            for source, at in self._flagged_at.items()
            if now - at < self.llm_repeat_seconds
        }
        return judging_order(rates, sources, flagged, self.llm_busy_rate)

    def _predict(
        self,
        samples: List[Dict[str, Any]],
        sources: Optional[List[Optional[str]]] = None,
    ) -> Optional[List[Dict[str, Any]]]:
        if self.mode not in FLOW_MODES or not samples:
            return None
        keys = [self._sample_key(sample) for sample in samples]
        ranked = self._priority(samples, sources)
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
        reused = len(selected) - len(fresh)
        if fresh:
            started = time.monotonic()
            answered = super()._predict([samples[i] for i in fresh.values()])
            elapsed_ms = (time.monotonic() - started) * 1000.0
            fresh_ms = elapsed_ms / len(fresh)
            self._record_cost(
                self.mode,
                len(fresh),
                elapsed_ms,
                reused=reused,
                failed=answered is None,
            )
            if answered is None:
                selected = [i for i in selected if keys[i] in verdict_of]
                fresh = {}
            else:
                for key, prediction in zip(fresh, answered):
                    verdict_of[key] = prediction
                    self._verdicts[key] = prediction
                while len(self._verdicts) > self.llm_cache_size:
                    self._verdicts.popitem(last=False)
        elif reused:
            self._record_cost(self.mode, 0, 0.0, reused=reused)  # all from the cache
        if not selected:
            return None
        neutral: Dict[str, Any] = {"pred_label": 0, "prob_ddos": None}
        full: List[Dict[str, Any]] = [dict(neutral) for _ in samples]
        asked = set(fresh.values())
        for index in sorted(selected):
            prediction = verdict_of[keys[index]]
            full[index] = prediction
            probability = float(prediction.get("prob_ddos", 0.0))
            if (
                sources is not None
                and sources[index] is not None
                and probability_is_attack(
                    probability, self.settings.detection_threshold
                )
            ):
                self._flagged_at[str(sources[index])] = time.monotonic()
            self.decisions.record(
                self.mode,
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
        """Turn one switch's full flow list into packet-rate weighted flows.

        Each flow's rate is the change in its packet count divided by the
        change in its own OpenFlow age, the same clock `_flow_batch` uses.
        The window still needs one time span per poll so later averaging
        (`mean_rates`) can combine several polls. That span is the largest
        age increase among flows that kept the same rule: the switch's view
        of how long this statistics interval lasted. That span is not taken
        from `time.monotonic()`. Packet totals stored for the window are
        rate times that span, so dividing by the span returns the same rates.
        A rule whose age or counters went down is a new flow and adds nothing
        this poll. The timestamp stored with the poll only says when the
        controller received it, so an old poll can be dropped; it is not the
        divisor.
        """

        previous = self._packet_history.get(dpid, {})
        counted: List[CountedFlow] = []
        for stat in body:
            if stat.priority == 0:
                continue
            match = stat.match
            destination_port = stat.match.get("tcp_dst", stat.match.get("udp_dst"))
            counted.append(
                CountedFlow(
                    self._flow_key(dpid, stat),
                    None
                    if match.get("ipv4_src") is None
                    else str(match.get("ipv4_src")),
                    None
                    if match.get("ipv4_dst") is None
                    else str(match.get("ipv4_dst")),
                    int(stat.packet_count),
                    int(getattr(stat, "byte_count", 0)),
                    flow_age_seconds(
                        int(getattr(stat, "duration_sec", 0)),
                        int(getattr(stat, "duration_nsec", 0)),
                    ),
                    int(match.get("ip_proto") or 0),
                    int(destination_port or 0),
                )
            )
        baselines, poll = entropy_poll_from_switch_clock(previous, counted)
        self._packet_history[dpid] = baselines
        if not poll.span_seconds:
            return
        now = time.monotonic()
        flows = [
            FlowObservation(source, destination, rate)
            for source, destination, rate in poll.flows
        ]
        self._window_flows[dpid] = (now, flows, len(body))
        polls = self._window_polls.setdefault(dpid, [])
        polls.append((now, poll.span_seconds, dict(poll.pair_packets)))
        horizon = 2 * self.entropy_window
        polls[:] = [item for item in polls if now - item[0] <= horizon]
        if self._tracks_ports:
            port_polls = self._window_ports.setdefault(dpid, [])
            port_polls.append((now, poll.span_seconds, dict(poll.port_packets)))
            port_polls[:] = [item for item in port_polls if now - item[0] <= horizon]

    def _window_histograms(
        self, now: float
    ) -> Tuple[Dict[str, Histogram], List[Tuple[str, float]]]:
        """Destination-port and protocol distributions of the window.

        Under a SYN flood every reply is a flow of its own, so thousands of ports
        carry the same tiny rate; they are sent as a (weight, count) histogram
        instead of one entry each. Also returns the busiest ports, for the log.
        """

        per_switch: Dict[int, Dict[Tuple[int, int], float]] = {}
        for dpid, polls in self._window_ports.items():
            if self.entropy_window_mode == "mean":
                recent = [p for p in polls if now - p[0] < self.entropy_window]
            else:
                recent = [
                    p for p in polls[-1:] if now - p[0] <= 2 * self.entropy_window
                ]
            total = sum(elapsed for _, elapsed, _ in recent if elapsed > 0)
            if total <= 0:
                continue
            packets: Dict[Tuple[int, int], float] = defaultdict(float)
            for _, elapsed, ports in recent:
                if elapsed > 0:
                    for key, delta in ports.items():
                        packets[key] += delta
            per_switch[dpid] = {key: count / total for key, count in packets.items()}
        by_port: Dict[Tuple[int, int], float] = {}
        by_proto: Dict[int, float] = defaultdict(float)
        for rates in per_switch.values():
            for key, rate in rates.items():
                if self.entropy_dedupe:
                    by_port[key] = max(by_port.get(key, 0.0), rate)
                else:
                    by_port[key] = by_port.get(key, 0.0) + rate
        for (proto, _), rate in by_port.items():
            by_proto[proto] += rate
        # Equal rates share a bin. If a flood still leaves too many distinct rates for
        # the detector service to accept, they are rounded harder until they fit.
        for digits in (3, 2, 1, 0):
            port_hist = Counter(
                round(rate, digits) for rate in by_port.values() if rate > 0
            )
            if len(port_hist) <= MAX_HISTOGRAM_BINS:
                break
        histograms: Dict[str, Histogram] = {
            "dport": sorted(port_hist.items()),
            "proto": [(round(rate, 3), 1) for rate in by_proto.values() if rate > 0],
        }
        names = {1: "icmp", 6: "tcp", 17: "udp"}
        top = [
            (f"{names.get(proto, proto)}/{port}", round(rate, 3))
            for (proto, port), rate in sorted(
                by_port.items(), key=lambda item: item[1], reverse=True
            )[:5]
        ]
        return histograms, top

    def _window_observations(
        self, now: float, fresh: Dict[int, Tuple[float, List[FlowObservation], int]]
    ) -> List[FlowObservation]:
        """Flows of the whole-network window, as chosen by SDN_ENTROPY_WINDOW_MODE.

        snapshot  the packet rates of each switch's last poll (original behaviour)
        mean      the rates averaged over every poll inside the window
        """

        if self.entropy_window_mode == "snapshot" and not self.entropy_dedupe:
            return [flow for _, per_switch, _ in fresh.values() for flow in per_switch]
        per_switch_rates: Dict[int, Dict[Tuple[str, str], float]] = {}
        if self.entropy_window_mode == "mean":
            for dpid, polls in self._window_polls.items():
                recent = [
                    (elapsed, pairs)
                    for stamp, elapsed, pairs in polls
                    if now - stamp < self.entropy_window
                ]
                rates = mean_rates(recent)
                if rates:
                    per_switch_rates[dpid] = rates
        else:
            for dpid, (_, per_switch, _) in fresh.items():
                totals: Dict[Tuple[str, str], float] = {}
                for flow in per_switch:
                    pair = (flow.src, flow.dst)
                    totals[pair] = totals.get(pair, 0.0) + flow.weight
                per_switch_rates[dpid] = totals
        return merge_switch_rates(per_switch_rates, self.entropy_dedupe)

    def _entropy_loop(self) -> None:
        # Windows are paced against a fixed schedule: sleeping a full window after
        # each evaluation (a call to the detector service, a database row) drifted
        # them to ~6.5 s apart, so a 16-window warm-up took ~104 s instead of 80 s
        # and a short baseline ended with the flood still inside the warm-up.
        due = time.monotonic() + self.entropy_window
        while True:
            hub.sleep(max(0.0, due - time.monotonic()))
            due = next_window_due(due, self.entropy_window, time.monotonic())
            now = time.monotonic()
            fresh = {
                dpid: entry
                for dpid, entry in self._window_flows.items()
                if now - entry[0] <= 2 * self.entropy_window
            }
            flows = self._window_observations(now, fresh)
            extra: Optional[Dict[str, Histogram]] = None
            top_ports: List[Tuple[str, float]] = []
            if self._tracks_ports:
                extra, top_ports = self._window_histograms(now)
            started = time.monotonic()
            try:
                result = self.entropy.observe(NETWORK_SCOPE, flows, extra)
            except (requests.RequestException, KeyError, ValueError) as exc:
                self._record_cost(
                    "entropy", 1, (time.monotonic() - started) * 1000.0, failed=True
                )
                self.logger.error("entropy window skipped, detector failed: %s", exc)
                continue
            self._record_cost("entropy", 1, (time.monotonic() - started) * 1000.0)
            self._publish_entropy_window(result, fresh, flows, extra, top_ports)
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
            if result.note:
                self.logger.info("ENTROPY ALARM named nobody: %s", result.note)
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
                if source == result.target_dst:
                    continue  # never act on the address named as the victim
                self._maybe_block(source, observed_at)

    def _publish_entropy_window(
        self,
        result: EntropyResult,
        fresh: Dict[int, Tuple[float, List[FlowObservation], int]],
        flows: List[FlowObservation],
        extra: Optional[Dict[str, Histogram]],
        top_ports: List[Tuple[str, float]],
    ) -> None:
        """Show what the detector saw in this window: values, bands, busiest talkers.

        Published for every window (idle and warm-up ones too) so the workspace can
        draw how the band moves, and written to the log in one readable line.
        """

        self._entropy_windows += 1
        state = window_state(result)
        payload = result.as_details()
        payload.update(
            {
                "window": self._entropy_windows,
                "state": state,
                "seconds": self.entropy_window,
                "switches": len(fresh),
                "flow_rules": sum(entry[2] for entry in fresh.values()),
                "pairs": len(flows),
                "streak": result.consecutive,
                "needed": self.entropy.consecutive_windows,
                "top_dport": [list(item) for item in top_ports],
            }
        )
        self.telemetry.emit("entropy_window", payload)
        signals = " ".join(
            format_signal(name, signal) for name, signal in result.signals.items()
        )
        self.logger.info(
            "ENTROPY w=%d %s rate=%.0f/s pairs=%d rules=%s %s streak=%d/%d "
            "top_src=%s top_dst=%s",
            self._entropy_windows,
            state.upper(),
            result.total_rate,
            len(flows),
            payload["flow_rules"],
            signals or "-",
            result.consecutive,
            self.entropy.consecutive_windows,
            list(result.top_src[:2]),
            list(result.top_dst[:2]),
        )
        if self.entropy_dump:
            record = {
                "run": os.environ.get("SDN_RUN_ID", ""),
                "window": self._entropy_windows,
                "at": datetime.now(timezone.utc).isoformat(),
                "state": state,
                "flows": [[f.src, f.dst, round(f.weight, 4)] for f in flows],
                "hist": {
                    name: [list(item) for item in histogram]
                    for name, histogram in (extra or {}).items()
                },
            }
            try:
                with open(self.entropy_dump, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record) + "\n")
            except OSError as exc:
                self.logger.error("cannot write %s: %s", self.entropy_dump, exc)
                self.entropy_dump = ""

    # -- response ---------------------------------------------------------

    def _maybe_block(self, source_ip: Optional[str], detected_at: datetime) -> bool:
        """Both detectors report here; the policy picks drop, rate limit or nothing."""

        if not self.settings.mitigation_enabled or not source_ip:
            return False
        action = self.responder.respond(
            source_ip, reason=self.mode, detected_at=detected_at.timestamp()
        )
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
