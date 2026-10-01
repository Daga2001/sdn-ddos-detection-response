import copy
import re

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


def test_miniedit_round_trip_keeps_the_project_name_and_notes():
    topology = presets()[1]
    exported = export_miniedit(topology)
    assert exported["lab_name"] == topology.name
    restored, warnings = import_miniedit(exported)
    assert restored.name == topology.name
    assert restored.description == topology.description
    assert not warnings


def test_unnamed_miniedit_files_still_import():
    data = export_miniedit(presets()[2])
    del data["lab_name"], data["lab_description"]
    restored, _ = import_miniedit(data)
    assert restored.name == "Imported MiniEdit network"


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("unlinked", "h9 has no link yet"),
        ("duplicate_name", "the name h1 is used by more than one device"),
        ("duplicate_address", "the address 10.0.0.1 is used by more than one host"),
        ("duplicate_dpid", "the datapath ID (DPID) 1 is used by more than one switch"),
        ("host_to_host", "joins two hosts"),
        ("loop", "repeats an existing connection or closes a loop"),
        ("split", "cannot reach the rest of the network"),
        ("public", "hosts must use private IPv4 addresses"),
        ("off_limits", "outside the networks this lab may touch"),
    ],
)
def test_rejections_name_the_device_and_the_fix(mutation, expected):
    """A student must read what is wrong, not that something is wrong."""

    data = presets()[2].model_dump()
    blank = {"x": 0, "y": 0}
    wire = {"bandwidth_mbps": None, "delay_ms": 0, "loss_percent": 0}
    if mutation == "unlinked":
        data["hosts"].append({"name": "h9", "ip": "10.0.0.9/24", "position": blank})
    elif mutation == "duplicate_name":
        data["hosts"][1]["name"] = "h1"
    elif mutation == "duplicate_address":
        data["hosts"][1]["ip"] = "10.0.0.1/24"
    elif mutation == "duplicate_dpid":
        data["switches"].append({"name": "s2", "dpid": 1, "position": blank})
        data["links"].append({"id": "join", "source": "s1", "target": "s2", **wire})
    elif mutation == "host_to_host":
        data["links"].append({"id": "peer", "source": "h1", "target": "h2", **wire})
    elif mutation == "loop":
        data["links"].append({"id": "again", "source": "s1", "target": "h1", **wire})
    elif mutation == "split":
        data["switches"].append({"name": "s2", "dpid": 2, "position": blank})
    elif mutation == "public":
        data["hosts"][0]["ip"] = "8.8.8.8/24"
    else:
        # Private, so the field accepts it, but outside SDN_ALLOWED_TARGET_CIDRS.
        data["hosts"][0]["ip"] = "192.168.1.5/24"

    if mutation == "off_limits":
        topology = Topology.model_validate(data)
        with pytest.raises(ValueError, match=re.escape(expected)):
            topology.validate_targets()
    else:
        with pytest.raises(ValueError, match=re.escape(expected)):
            Topology.model_validate(data)


def test_miniedit_import_names_the_node_that_cannot_be_read():
    data = export_miniedit(presets()[2])
    del data["hosts"][1]["opts"]["ip"]
    with pytest.raises(ValueError, match="h2 has no IP address"):
        import_miniedit(data)
