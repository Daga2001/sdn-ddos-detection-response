"""Pure measurement helpers. No Mininet, no traffic, no database.

The runner and the controllers call these so a test can feed counters, curl
text, or ping lines without starting a process.
"""

from __future__ import annotations

import math
import os
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

FORWARDING_MESSAGE = (
    "Choose the forwarding rules: per-port (Experiment A) or port-free (Experiment B)."
)
MATCH_PORTS_ERROR = "SDN_MATCH_L4_PORTS must be true or false; refusing to start"
# OpenFlow OFPP_CONTROLLER. A table-miss rule outputs here.
OFPP_CONTROLLER = 0xFFFFFFFD
PING_INTERVAL = 0.2
PING_LOSS_AFTER = 1.0
_PING_REPLY = re.compile(r"icmp_seq=(\d+).*?time=([0-9.]+)\s*ms")


def match_l4_ports_setting(source: Optional[Mapping[str, str]] = None) -> bool:
    """True when forwarding rules match the layer-4 port. No default.

    Missing or anything other than true/false is a start failure. The caller
    logs MATCH_PORTS_ERROR and does not start the controller.
    """

    values = os.environ if source is None else source
    raw = values.get("SDN_MATCH_L4_PORTS")
    normalized = raw.strip().lower() if isinstance(raw, str) else ""
    if normalized not in {"true", "false"}:
        raise ValueError(MATCH_PORTS_ERROR)
    return normalized == "true"


def log_and_require_match_l4_ports(
    logger: Any, source: Optional[Mapping[str, str]] = None
) -> bool:
    """Log a clear error and refuse to start when the setting is unusable."""

    try:
        return match_l4_ports_setting(source)
    except ValueError as error:
        logger.error("%s", error)
        raise


def forwarding_flag(forwarding: str) -> str:
    """The SDN_MATCH_L4_PORTS value for one run. No default."""

    if forwarding == "per_port":
        return "true"
    if forwarding == "port_free":
        return "false"
    raise ValueError(FORWARDING_MESSAGE)


def parse_curl_probe(output: str, returncode: Optional[int]) -> dict[str, Any]:
    """Read `http_code time_connect time_total` from curl --write-out.

    A timeout, a short line, or a non-200 code is a failed check. Times stay
    null when the line cannot be read, so a gap is never drawn as a latency.
    """

    fields = output.split()
    http_code: Optional[int] = None
    connect_ms: Optional[float] = None
    latency_ms: Optional[float] = None
    if len(fields) >= 3:
        try:
            http_code = int(fields[0])
            connect_ms = float(fields[1]) * 1000
            latency_ms = float(fields[2]) * 1000
        except ValueError:
            http_code = None
            connect_ms = None
            latency_ms = None
    return {
        "success": returncode == 0 and http_code == 200,
        "http_code": http_code,
        "connect_ms": connect_ms,
        "latency_ms": latency_ms,
    }


def checks_due(
    now: float,
    next_at: float,
    index: int,
    pairs: Sequence[tuple[str, str]],
    deadline: float,
    stopped: bool,
) -> tuple[list[tuple[str, str]], float, int]:
    """Checks whose start time has arrived. Does not look at running checks.

    A check that is still in flight does not move `next_at`, so the next pair
    is due on the 1 s grid anyway.
    """

    due: list[tuple[str, str]] = []
    if stopped or not pairs or now >= deadline:
        return due, next_at, index
    while next_at <= now and next_at < deadline:
        due.append(pairs[index % len(pairs)])
        index += 1
        next_at += 1.0
    return due, next_at, index


def _match_keys(match: Any) -> list[Any]:
    if match is None:
        return []
    if hasattr(match, "items"):
        return [key for key, value in match.items() if value is not None]
    if hasattr(match, "keys"):
        return list(match.keys())
    return []


def _outputs_to_controller(stat: Any) -> bool:
    for instruction in getattr(stat, "instructions", []) or []:
        for action in getattr(instruction, "actions", []) or []:
            if getattr(action, "port", None) in (OFPP_CONTROLLER, "CONTROLLER"):
                return True
    return False


def table_miss_rule(body: Sequence[Any]) -> Any:
    """The priority-0 empty-match rule that sends packets to the controller."""

    empty = [
        stat
        for stat in body
        if int(getattr(stat, "priority", -1)) == 0
        and not _match_keys(getattr(stat, "match", None))
    ]
    for stat in empty:
        if _outputs_to_controller(stat):
            return stat
    return empty[0] if empty else None


def table_miss_rate(
    previous: Optional[tuple[int, float]],
    packets: int,
    age_seconds: float,
) -> tuple[Optional[float], tuple[int, float]]:
    """Packets/s of one table-miss rule on the switch clock.

    A counter or an age that goes down, or an age that did not move, starts
    over: this sample is the new baseline and the rate is null, never negative.
    """

    baseline = (int(packets), float(age_seconds))
    if previous is None:
        return None, baseline
    previous_packets, previous_age = previous
    if packets < previous_packets or age_seconds <= previous_age:
        return None, baseline
    return (packets - previous_packets) / (age_seconds - previous_age), baseline


def switch_table_sample(
    dpid: int,
    body: Sequence[Any],
    previous: Optional[tuple[int, float]],
) -> tuple[dict[str, Any], Optional[tuple[int, float]]]:
    """One switch's rule count and table-miss rate, before any row cap.

    The count excludes the table-miss rule itself. A poll with no such rule
    keeps the previous baseline and reports a null rate.
    """

    miss = table_miss_rule(body)
    flow_rules = len(body) - (1 if miss is not None else 0)
    if miss is None:
        return {
            "dpid": int(dpid),
            "flow_rules": flow_rules,
            "table_miss_packets": None,
            "packet_in_sent_per_s": None,
        }, previous
    packets = int(miss.packet_count)
    age = (
        float(getattr(miss, "duration_sec", 0))
        + float(getattr(miss, "duration_nsec", 0)) / 1_000_000_000.0
    )
    rate, baseline = table_miss_rate(previous, packets, age)
    return {
        "dpid": int(dpid),
        "flow_rules": flow_rules,
        "table_miss_packets": packets,
        "packet_in_sent_per_s": rate,
    }, baseline


def handled_rate(
    previous: Optional[tuple[int, float]], count: int, now: float
) -> tuple[Optional[float], tuple[int, float]]:
    """Packet-Ins/s handled since the previous controller sample."""

    baseline = (int(count), float(now))
    if previous is None or now <= previous[1] or count < previous[0]:
        return None, baseline
    return (count - previous[0]) / (now - previous[1]), baseline


def read_system(psutil_module: Any) -> dict[str, Any]:
    """Whole-machine CPU, plus the ovs-vswitchd process. Missing process is null.

    The kernel's packet forwarding is not in ovs-vswitchd's CPU; that note
    belongs in the docs, not in this number.
    """

    cpu = float(psutil_module.cpu_percent())
    ovs_cpu: Optional[float] = None
    ovs_rss: Optional[int] = None
    for proc in psutil_module.process_iter(["name"]):
        info = proc.info if isinstance(getattr(proc, "info", None), dict) else {}
        if info.get("name") != "ovs-vswitchd":
            continue
        ovs_cpu = float(proc.cpu_percent())
        ovs_rss = int(proc.memory_info().rss)
        break
    return {
        "cpu_percent": cpu,
        "ovs_cpu_percent": ovs_cpu,
        "ovs_rss_bytes": ovs_rss,
    }


class PingTracker:
    """One continuous ping. Sent counts follow icmp_seq; a silent seq is a loss.

    ping does not print a line when it sends. The sequence number is the send
    count: seq 1 leaves at `started`, seq n at started + (n - 1) * 0.2 s. A
    seq with no reply within 1 s of that send is lost. Replies that arrive
    later do not un-lose it.
    """

    def __init__(self, client: str, target: str, started: float) -> None:
        self.client = client
        self.target = target
        self.started = started
        self.wall_start = datetime.now(timezone.utc)
        self.replies: dict[int, tuple[float, float, str]] = {}
        self.emitted_until = started

    def feed(self, line: str, arrival: Optional[float] = None) -> None:
        match = _PING_REPLY.search(line)
        if match is None:
            return
        seq = int(match.group(1))
        rtt = float(match.group(2))
        if arrival is None:
            import time

            when = time.monotonic()
        else:
            when = arrival
        stamp = self._wall(when)
        # The first printed reply for a seq wins; a duplicate does not recount.
        self.replies.setdefault(seq, (when, rtt, stamp))

    def _send_time(self, seq: int) -> float:
        return self.started + (seq - 1) * PING_INTERVAL

    def _wall(self, mono: float) -> str:
        return (self.wall_start + timedelta(seconds=mono - self.started)).isoformat()

    def _sent_through(self, moment: float) -> int:
        if moment < self.started:
            return 0
        expected = int((moment - self.started) / PING_INTERVAL) + 1
        seen = max(self.replies) if self.replies else 0
        return max(expected, seen)

    def _lost(self, seq: int, moment: float) -> bool:
        send = self._send_time(seq)
        if moment < send + PING_LOSS_AFTER:
            return False
        reply = self.replies.get(seq)
        if reply is None:
            return True
        return reply[1] > PING_LOSS_AFTER * 1000

    def take(self, now: float) -> list[dict[str, Any]]:
        """One event per completed second. Safe to call from the sampler."""

        events: list[dict[str, Any]] = []
        while self.emitted_until + 1 <= now:
            start = self.emitted_until
            end = start + 1
            self.emitted_until = end
            events.append(self._event(start, end))
        return events

    def _event(self, start: float, end: float) -> dict[str, Any]:
        first = (
            1
            if start <= self.started
            else math.ceil((start - self.started) / PING_INTERVAL) + 1
        )
        last = math.floor((end - self.started - 1e-12) / PING_INTERVAL) + 1
        sent = list(range(first, last + 1)) if last >= first else []
        # Losses are reported in the second their 1 s window closes, so the
        # count is final. `sent` is the seqs that left during this second.
        lost_seqs = [
            seq
            for seq in range(1, self._sent_through(end - 1e-9) + 1)
            if start <= self._send_time(seq) + PING_LOSS_AFTER < end
            and self._lost(seq, end)
        ]
        replies = [
            [stamp, rtt]
            for _seq, (arrival, rtt, stamp) in sorted(self.replies.items())
            if start <= arrival < end
        ]
        answered = [
            [seq, rtt]
            for seq, (arrival, rtt, _stamp) in sorted(self.replies.items())
            if start <= arrival < end and rtt <= PING_LOSS_AFTER * 1000
        ]
        return {
            "client": self.client,
            "target": self.target,
            "sent": len(sent),
            "lost": len(lost_seqs),
            "replies": replies,
            "answered": answered,
            "lost_at": [self._wall(self._send_time(seq)) for seq in lost_seqs],
            "observed_at": self._wall(end),
        }
