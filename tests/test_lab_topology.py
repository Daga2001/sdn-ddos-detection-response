import copy

import pytest

from sdn_ddos.lab.topology import Topology, export_miniedit, import_miniedit, presets


def test_presets_preserve_baseline_and_roundtrip():
    items = presets()
    assert len(items) == 4
    baseline = items[0]
    assert len(baseline.hosts) == 9
    assert len(baseline.switches) == 4
    assert len(baseline.links) == 12
    assert baseline.hosts[0].ip == "10.0.1.1/24"
    for topology in items:
        result, warnings = import_miniedit(export_miniedit(topology))
        assert result.hosts == topology.hosts
        assert result.switches == topology.switches
        assert result.links == topology.links
        assert warnings == []
        assert Topology.model_validate(topology.model_dump()) == topology


@pytest.mark.parametrize(
    "mutation", ["public", "duplicate", "missing", "loop", "unsafe"]
)
def test_reject_invalid_topology(mutation):
    data = presets()[1].model_dump()
    if mutation == "public":
        data["hosts"][0]["ip"] = "8.8.8.8/24"
    elif mutation == "duplicate":
        data["hosts"][1]["name"] = data["hosts"][0]["name"]
    elif mutation == "missing":
        data["links"][0]["source"] = "missing"
    elif mutation == "loop":
        data["links"].append({"id": "loop", "source": "s1", "target": "s2"})
    else:
        data["hosts"][0]["name"] = "h1; id"
    with pytest.raises(ValueError):
        Topology.model_validate(data)


@pytest.mark.parametrize(
    "setting", ["startCommand", "stopCommand", "externalInterfaces", "privateDirectory"]
)
def test_miniedit_cannot_execute_or_attach_external_resources(setting):
    data = export_miniedit(presets()[2])
    data["hosts"][0]["opts"][setting] = "untrusted"
    with pytest.raises(ValueError, match="unsupported"):
        import_miniedit(data)


def test_miniedit_remote_controller_requires_visible_remapping():
    data = export_miniedit(presets()[2])
    data["controllers"][0]["opts"]["remoteIP"] = "192.168.1.10"
    _, warnings = import_miniedit(data)
    assert any("controller" in warning.lower() for warning in warnings)


def test_multi_interface_host_is_rejected():
    data = copy.deepcopy(presets()[1].model_dump())
    data["links"] = [link for link in data["links"] if link["id"] != "core-s2"]
    data["links"].append({"id": "extra", "source": "h1a", "target": "s2"})
    with pytest.raises(ValueError, match="one link"):
        Topology.model_validate(data)


def test_miniedit_native_defaults_and_decimal_dpid():
    data = export_miniedit(presets()[2])
    data["hosts"][0]["opts"]["sched"] = "host"
    switch = data["switches"][0]["opts"]
    switch.update(hostname="s10", dpid="", sflow="0", netflow="0")
    for link in data["links"]:
        link["src"] = "s10"
    data["controllers"][0]["opts"]["controllerProtocol"] = "tcp"
    topology, warnings = import_miniedit(data)
    assert topology.switches[0].dpid == 10
    assert not warnings


def test_interface_name_budget():
    data = presets()[2].model_dump()
    data["hosts"][0]["name"] = "h123456789"
    with pytest.raises(ValueError):
        Topology.model_validate(data)


def test_browser_dpid_precision_is_not_silently_lost():
    data = export_miniedit(presets()[2])
    data["switches"][0]["opts"]["dpid"] = "0100000000000001"
    with pytest.raises(ValueError):
        import_miniedit(data)


def test_miniedit_link_properties_are_editable_and_no_fraction_is_lost():
    topology = presets()[2]
    exported = export_miniedit(topology)
    assert "bw" not in exported["links"][0]["opts"]
    assert isinstance(exported["links"][0]["opts"]["loss"], int)
    topology.links[0].bandwidth_mbps = 0.5
    with pytest.raises(ValueError, match="whole-number"):
        export_miniedit(topology)
