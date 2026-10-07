#!/usr/bin/env python3
# ruff: noqa: E501  (CLI help and messages)
"""Start lab experiments through the graphical lab's own HTTP API (no browser).

Runs on the VM, talks to http://127.0.0.1:8080 with the token in .lab/env and
waits for each run to finish. Used to collect repeatable, labeled traffic.

  python3 scripts/lab_runs.py --rate 1000 --kind syn --baseline 40 --duration 30 --recovery 20
  python3 scripts/lab_runs.py --grid 100:syn,500:syn,1000:udp ...   # one run per rate:kind

Prints one `RUN <id> rate=<r> kind=<k>` line per finished run.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:8080"
HEADERS = {"Host": "localhost:8080", "Origin": "http://localhost:8080"}


def token() -> str:
    for line in Path(".lab/env").read_text().splitlines():
        if line.startswith("SDN_LAB_TOKEN="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("SDN_LAB_TOKEN not found in .lab/env")


class Lab:
    def __init__(self) -> None:
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def call(self, method: str, path: str, body: object = None) -> object:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            BASE + path,
            data=data,
            method=method,
            headers={**HEADERS, "Content-Type": "application/json"},
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            raise SystemExit(
                f"{method} {path} -> {error.code}: {error.read().decode()}"
            ) from None

    def login(self) -> None:
        self.call("POST", "/api/session", {"token": token()})


def wait_idle(lab: Lab, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = lab.call("GET", "/api/status")
        if not isinstance(status, dict):
            raise SystemExit(f"unexpected status: {status!r}")
        if status.get("state") in ("idle", "stopped", "completed", "failed", "error"):
            return status
        time.sleep(3)
    raise SystemExit("timed out waiting for the run to finish")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preset", default="Connected enterprise")
    parser.add_argument("--attackers", default="h1a")
    parser.add_argument("--victims", default="h1b")
    parser.add_argument("--rate", type=int, default=1000)
    parser.add_argument("--kind", default="syn", choices=("syn", "udp", "icmp"))
    parser.add_argument("--baseline", type=int, default=40)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--recovery", type=int, default=20)
    parser.add_argument(
        "--grid", help="comma list of rate:kind, overrides --rate/--kind"
    )
    parser.add_argument(
        "--mitigation",
        action="store_true",
        help="let the controller act on detections (response policy applies)",
    )
    parser.add_argument(
        "--repeat", type=int, default=1, help="repeat the whole plan N times"
    )
    parser.add_argument(
        "--tag", default="", help="condition label printed with every run"
    )
    args = parser.parse_args()
    if not 1 <= args.repeat <= 50:
        raise SystemExit("--repeat must be between 1 and 50")

    lab = Lab()
    lab.login()
    topology = next(
        (t for t in lab.call("GET", "/api/presets") if t["name"] == args.preset), None
    )
    if topology is None:
        raise SystemExit(f"preset {args.preset!r} not found")
    plan = (
        [(int(r), k) for r, k in (item.split(":") for item in args.grid.split(","))]
        if args.grid
        else [(args.rate, args.kind)]
    )
    for rate, kind in plan * args.repeat:
        wait_idle(lab, 60)
        experiment = {
            "attackers": args.attackers.split(","),
            "victims": args.victims.split(","),
            "traffic": [kind],
            "rate": rate,
            "duration": args.duration,
            "baseline": args.baseline,
            "recovery": args.recovery,
            "mitigation": args.mitigation,
            "confirm_isolated_lab": True,
        }
        started = lab.call(
            "POST", "/api/runs", {"topology": topology, "experiment": experiment}
        )
        run_id = started["run_id"]  # type: ignore[index]
        time.sleep(5)
        total = args.baseline + args.duration + args.recovery + 60
        final = wait_idle(lab, total)
        print(
            f"RUN {run_id} rate={rate} kind={kind} final={final.get('state')} tag={args.tag}",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
