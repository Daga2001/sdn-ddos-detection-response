#!/usr/bin/env python3
"""Standalone baseline traffic generator for unattended (cron-driven) data
collection into the metrics database.

Builds the existing enterprise topology via the repo's own
sdn_ddos.topology.enterprise.build_topology() helper (no changes to that
module), connects it to the already-running Ryu controller, generates real
intra-area traffic (ping + iperf3) for a fixed duration so flow_stats /
port_stats / controller_stats are non-trivial, then tears everything down.

Only same-subnet host pairs are used: this topology has no inter-area
routing, so cross-area traffic would just fail and waste the window.

This script intentionally does NOT run any attack traffic. The attack
protocol in docs/experiments.md remains a deliberate, manual step.
"""

from __future__ import annotations

import argparse
import time

from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

from sdn_ddos.topology.enterprise import build_topology

TRAFFIC_PAIRS = (("h1a", "h1b"), ("h2a", "h2b"), ("h3a", "h3b"))
IPERF_PORT = 5201


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-host", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="seconds of active traffic generation (default: 60)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    setLogLevel("info")

    net = Mininet(
        topo=build_topology(),
        controller=None,
        switch=OVSSwitch,
        autoSetMacs=True,
    )
    net.addController(
        "c0",
        controller=RemoteController,
        ip=args.controller_host,
        port=args.controller_port,
    )

    net.start()
    try:
        info("*** Baseline: initial connectivity check\n")
        net.pingAll()

        info(f"*** Baseline: generating traffic for {args.duration}s\n")
        for src_name, dst_name in TRAFFIC_PAIRS:
            src, dst = net.get(src_name), net.get(dst_name)
            dst.cmd(f"iperf3 -s -p {IPERF_PORT} -D")
            src.cmd(f"ping -i 0.5 {dst.IP()} > /tmp/ping_{src_name}.log 2>&1 &")

        iperf_seconds = max(5, min(args.duration - 5, 30))
        for src_name, dst_name in TRAFFIC_PAIRS:
            src, dst = net.get(src_name), net.get(dst_name)
            src.cmd(
                f"iperf3 -c {dst.IP()} -p {IPERF_PORT} -t {iperf_seconds} "
                f"> /tmp/iperf_{src_name}.log 2>&1 &"
            )

        time.sleep(args.duration)

        for src_name, dst_name in TRAFFIC_PAIRS:
            net.get(src_name).cmd("pkill -f ping || true")
            net.get(src_name).cmd("pkill -f iperf3 || true")
            net.get(dst_name).cmd("pkill -f iperf3 || true")

        info("*** Baseline: done\n")
        return 0
    finally:
        net.stop()


if __name__ == "__main__":
    raise SystemExit(main())
