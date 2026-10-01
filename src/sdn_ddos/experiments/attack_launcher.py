"""Launch a bounded SYN-rate experiment against an isolated Mininet host.

This utility intentionally refuses public targets, requires an explicit lab
acknowledgement, caps duration and rate, and never invokes a shell.
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import List, Optional

from sdn_ddos.config import (
    ConfigurationError,
    ControllerSettings,
    DatabaseSettings,
    validate_lab_target,
)
from sdn_ddos.storage import create_metrics_store

MAX_PACKETS_PER_SECOND = 1000
MAX_DURATION_SECONDS = 300

# The flows the proposal's DDoS scenarios call for. Every kind stays bounded the
# same way; only the protocol the packets carry changes.
TRAFFIC_KINDS = ("syn", "udp", "icmp")
_TRAFFIC_MODE = {"syn": ["--syn"], "udp": ["--udp"], "icmp": ["--icmp"]}


def build_hping_command(
    target: str, port: int, rate: int, duration: int, kind: str = "syn"
) -> List[str]:
    """Build a bounded hping3 command with a deterministic packet count.

    ``kind`` selects the flow under test — a TCP SYN flood, a UDP flood, or an
    ICMP echo flood. Whatever the protocol, the generator keeps the same hard
    ceiling: a fixed ``--count`` of ``rate * duration`` packets sent at a fixed
    interval, never ``--flood``. The destination port only applies to the
    transport floods; an ICMP echo flood has none.
    """

    if kind not in TRAFFIC_KINDS:
        raise ConfigurationError(
            f"traffic kind must be one of {', '.join(TRAFFIC_KINDS)}"
        )
    interval_microseconds = max(1, round(1_000_000 / rate))
    command = ["hping3", *_TRAFFIC_MODE[kind]]
    if kind != "icmp":
        command += ["--destport", str(port)]
    command += [
        "--interval",
        f"u{interval_microseconds}",
        "--count",
        str(rate * duration),
        target,
    ]
    return command


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="10.0.2.1")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--rate", type=int, default=100, help="packets per second")
    parser.add_argument("--duration", type=int, default=20, help="seconds")
    parser.add_argument(
        "--confirm-isolated-lab",
        action="store_true",
        help="confirm the target is an authorized isolated Mininet lab",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and print without sending traffic",
    )
    return parser


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=3)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    settings = ControllerSettings.from_env()
    target = str(validate_lab_target(args.target, settings.allowed_target_networks))
    if not 1 <= args.port <= 65535:
        raise ConfigurationError("port must be between 1 and 65535")
    if not 1 <= args.rate <= MAX_PACKETS_PER_SECOND:
        raise ConfigurationError(
            f"rate must be between 1 and {MAX_PACKETS_PER_SECOND} packets/second"
        )
    if not 1 <= args.duration <= MAX_DURATION_SECONDS:
        raise ConfigurationError(
            f"duration must be between 1 and {MAX_DURATION_SECONDS} seconds"
        )
    command = build_hping_command(target, args.port, args.rate, args.duration)
    if args.dry_run:
        print("Validated command:", " ".join(command))
        return 0
    if not args.confirm_isolated_lab:
        raise ConfigurationError(
            "--confirm-isolated-lab is required before traffic can be generated"
        )
    if shutil.which("hping3") is None:
        raise RuntimeError("hping3 is not installed")

    store = create_metrics_store(DatabaseSettings.from_env())
    started_at = datetime.now(timezone.utc)
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        process.wait(timeout=args.duration + 10)
        if process.returncode != 0:
            raise RuntimeError(f"hping3 exited with status {process.returncode}")
    except KeyboardInterrupt:
        return_code = 130
        return return_code
    except subprocess.TimeoutExpired:
        raise RuntimeError("hping3 exceeded its bounded experiment window") from None
    finally:
        _stop_process(process)
        ended_at = datetime.now(timezone.utc)
        try:
            store.record_attack_window(started_at, ended_at, "SYN_RATE", target)
        finally:
            store.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ConfigurationError, RuntimeError) as error:
        raise SystemExit(f"error: {error}") from error
