#!/usr/bin/env python3
# ruff: noqa: E501  (CLI help and messages)
"""Baseline -> attack -> recovery experiment on the enterprise topology.

Legitimate traffic (rate-limited iperf3 in a ring inside every segment, plus
ping) runs during the whole experiment. In the middle, the repo's bounded
attack launcher (with its safety limits and --confirm-isolated-lab) is run
from one or more attacker hosts against a victim host of the isolated Mininet
lab ("multiple attackers vs 1 host"). Phase timestamps are written to a JSON
file and the attack window is stored in `attack_windows` (ground truth) so the
detectors can be evaluated afterwards (scripts/report_experiment.py).

The topology has no routing between segments, so attackers and victim must be
in the same segment (default: h2b and h2c -> h2a).

The controller (and its detection mode) must already be running; use
scripts/run_experiment.sh to start everything together.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

from sdn_ddos.config import DatabaseSettings
from sdn_ddos.storage import create_metrics_store
from sdn_ddos.topology.enterprise import build_topology

SEGMENTS = (("h1a", "h1b", "h1c"), ("h2a", "h2b", "h2c"), ("h3a", "h3b", "h3c"))
IPERF_PORT = 5201


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-host", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--baseline-seconds", type=int, default=120)
    parser.add_argument("--attack-seconds", type=int, default=30)
    parser.add_argument("--recovery-seconds", type=int, default=60)
    parser.add_argument(
        "--attack-rate",
        type=int,
        default=1000,
        help="packets/s per attacker (max 1000)",
    )
    parser.add_argument("--attackers", default="h2b,h2c", help="comma separated hosts")
    parser.add_argument("--victim", default="h2a")
    parser.add_argument("--attack-port", type=int, default=80)
    parser.add_argument(
        "--legit-rate", default="1M", help="iperf3 -b for legitimate flows"
    )
    parser.add_argument(
        "--mode", default=os.environ.get("SDN_DETECTION_MODE", "unknown")
    )
    parser.add_argument("--out-dir", default="logs")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    setLogLevel("info")
    total = args.baseline_seconds + args.attack_seconds + args.recovery_seconds + 15

    net = Mininet(
        topo=build_topology(), controller=None, switch=OVSSwitch, autoSetMacs=True
    )
    net.addController(
        "c0",
        controller=RemoteController,
        ip=args.controller_host,
        port=args.controller_port,
    )
    net.start()
    phases: dict[str, str] = {}
    try:
        time.sleep(3)
        info("*** Legitimate traffic starts\n")
        phases["baseline_start"] = utcnow().isoformat()
        for segment in SEGMENTS:
            for name in segment:
                net.get(name).cmd(f"iperf3 -s -p {IPERF_PORT} -D")
        time.sleep(1)
        for segment in SEGMENTS:
            for index, name in enumerate(segment):
                src = net.get(name)
                dst = net.get(segment[(index + 1) % len(segment)])
                src.cmd(f"ping -i 0.2 {dst.IP()} > /dev/null 2>&1 &")
                src.cmd(
                    f"iperf3 -c {dst.IP()} -p {IPERF_PORT} -b {args.legit_rate} "
                    f"-t {total} > /dev/null 2>&1 &"
                )
        time.sleep(args.baseline_seconds)

        victim = net.get(args.victim)
        attackers = [net.get(name) for name in args.attackers.split(",")]
        info(
            f"*** Attack: {args.attackers} -> {victim.IP()} for {args.attack_seconds}s\n"
        )
        phases["attack_start"] = utcnow().isoformat()
        started = utcnow()
        # The launcher runs inside the hosts' network namespaces, which have no
        # route to the database, so its own DB writes are disabled here and the
        # ground-truth window is recorded from this process instead.
        attack_pids = {}
        for attacker in attackers:
            attack_pids[attacker] = attacker.cmd(
                f"SDN_DB_ENABLED=false PYTHONPATH={os.environ.get('PYTHONPATH', '')} "
                f"{sys.executable} -m sdn_ddos.experiments.attack_launcher "
                f"--target {victim.IP()} --port {args.attack_port} "
                f"--rate {args.attack_rate} --duration {args.attack_seconds} "
                f"--confirm-isolated-lab > /tmp/attack_{attacker.name}.log 2>&1 & echo $!"
            ).strip()
        # Wait only for the attack processes: the hosts' shells also own the
        # long-running legitimate ping/iperf3 background jobs.
        for attacker, pid in attack_pids.items():
            attacker.cmd(f"wait {pid}")
        ended = utcnow()
        phases["attack_end"] = ended.isoformat()
        store = create_metrics_store(DatabaseSettings.from_env())
        try:
            store.record_attack_window(started, ended, "SYN_RATE", victim.IP())
        finally:
            store.close()

        info("*** Recovery window\n")
        time.sleep(args.recovery_seconds)
        phases["recovery_end"] = utcnow().isoformat()

        for host in net.hosts:
            host.cmd("pkill -f 'ping -i' ; pkill -f iperf3")
    finally:
        net.stop()

    out = Path(args.out_dir)
    out.mkdir(exist_ok=True)
    record = {"mode": args.mode, "args": vars(args), "phases": phases}
    path = out / f"experiment_{args.mode}_{utcnow():%Y%m%dT%H%M%S}.json"
    path.write_text(json.dumps(record, indent=2))
    info(f"*** Experiment record: {path}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
