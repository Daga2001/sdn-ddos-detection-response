"""Run the implemented four-switch, nine-host Mininet topology."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from typing import Any, Optional

from sdn_ddos.topology.spec import ACCESS_SWITCHES, CORE_SWITCH, HOSTS


def build_topology() -> Any:
    """Create a Mininet Topo while keeping Mininet optional for unit tests."""

    try:
        from mininet.topo import Topo
    except ImportError as exc:
        raise RuntimeError(
            "Mininet is not installed; follow docs/setup.md inside the lab VM"
        ) from exc

    class EnterpriseTopology(Topo):
        def build(self) -> None:
            for switch in ACCESS_SWITCHES:
                self.addSwitch(switch, protocols="OpenFlow13")
            self.addSwitch(CORE_SWITCH, protocols="OpenFlow13")
            for host in HOSTS:
                self.addHost(host.name, ip=host.ip)
                self.addLink(host.name, host.switch)
            for switch in ACCESS_SWITCHES:
                self.addLink(switch, CORE_SWITCH)

    return EnterpriseTopology()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-host", default="127.0.0.1")
    parser.add_argument("--controller-port", default=6653, type=int)
    parser.add_argument(
        "--skip-ping", action="store_true", help="do not run the initial pingAll check"
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        from mininet.cli import CLI
        from mininet.log import info, setLogLevel
        from mininet.net import Mininet
        from mininet.node import OVSSwitch, RemoteController
    except ImportError as exc:
        raise RuntimeError(
            "Mininet is not installed; follow docs/setup.md inside the lab VM"
        ) from exc

    if not 1 <= args.controller_port <= 65535:
        raise ValueError("controller port must be between 1 and 65535")
    setLogLevel("info")
    network = Mininet(
        topo=build_topology(),
        controller=None,
        switch=OVSSwitch,
        autoSetMacs=True,
    )
    network.addController(
        "c0",
        controller=RemoteController,
        ip=args.controller_host,
        port=args.controller_port,
    )
    try:
        info("*** Starting OpenFlow 1.3 enterprise topology\n")
        network.start()
        if not args.skip_ping:
            info("*** Testing baseline connectivity\n")
            network.pingAll()
        CLI(network)
    finally:
        info("*** Stopping topology\n")
        network.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
