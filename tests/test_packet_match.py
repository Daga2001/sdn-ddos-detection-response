import pytest

pytest.importorskip("ryu")

from ryu.lib.packet import ethernet, ipv4, packet, tcp, udp

from sdn_ddos.controller import app_modes


class Parser:
    @staticmethod
    def OFPMatch(**fields):
        return fields


def frame(transport):
    built = packet.Packet()
    built.add_protocol(
        ethernet.ethernet(
            ethertype=0x0800, dst="00:00:00:00:00:02", src="00:00:00:00:00:01"
        )
    )
    built.add_protocol(
        ipv4.ipv4(proto=6 if transport == "tcp" else 17, src="10.0.0.1", dst="10.0.0.2")
    )
    if transport == "tcp":
        built.add_protocol(tcp.tcp(src_port=40001, dst_port=8080))
    else:
        built.add_protocol(udp.udp(src_port=40001, dst_port=53))
    built.serialize()
    return packet.Packet(built.data)


def rule(transport):
    return app_modes.ModeSwitchController._packet_match(
        Parser, frame(transport), 1, "00:00:00:00:00:01", "00:00:00:00:00:02"
    )


def test_forwarding_rules_match_the_port_when_asked(monkeypatch):
    monkeypatch.setattr(app_modes, "MATCH_L4_PORTS", True)
    assert rule("tcp")["tcp_dst"] == 8080
    assert rule("udp")["udp_dst"] == 53
    assert rule("tcp")["ipv4_src"] == "10.0.0.1"


def test_forwarding_rules_can_stop_matching_the_port(monkeypatch):
    monkeypatch.setattr(app_modes, "MATCH_L4_PORTS", False)
    for transport in ("tcp", "udp"):
        fields = rule(transport)
        assert "tcp_dst" not in fields and "udp_dst" not in fields
        assert fields["ipv4_dst"] == "10.0.0.2"
    assert rule("tcp")["ip_proto"] == 6 and rule("udp")["ip_proto"] == 17
