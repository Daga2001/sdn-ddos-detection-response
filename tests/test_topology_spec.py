from sdn_ddos.topology.spec import (
    ACCESS_SWITCHES,
    CORE_SWITCH,
    HOSTS,
    expected_link_count,
)


def test_implemented_topology_inventory() -> None:
    assert ACCESS_SWITCHES == ("s1", "s2", "s3")
    assert CORE_SWITCH == "s4"
    assert len(HOSTS) == 9
    assert expected_link_count() == 12
    assert {host.switch for host in HOSTS} == set(ACCESS_SWITCHES)
    assert len({host.ip for host in HOSTS}) == 9
