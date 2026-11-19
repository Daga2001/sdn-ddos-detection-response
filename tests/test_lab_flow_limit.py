"""TC-1: the emulated hardware flow table."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sdn_ddos.lab.contracts import Experiment
from sdn_ddos.lab.runtime import flow_limit_command


def test_command_caps_table_zero_and_refuses_when_full() -> None:
    assert flow_limit_command("s_nucleo", 1500) == [
        "ovs-vsctl", "--", "--id=@ft", "create", "Flow_Table", "flow_limit=1500",
        "overflow_policy=refuse", "--", "set", "Bridge", "s_nucleo",
        "flow_tables:0=@ft",
    ]  # fmt: skip


def test_limit_is_optional_and_bounded() -> None:
    base = {"attackers": ["a"], "victims": ["v"]}
    assert Experiment.model_validate(base).flow_table_limit is None
    assert (
        Experiment.model_validate({**base, "flow_table_limit": 1500}).flow_table_limit
        == 1500
    )
    with pytest.raises(ValidationError):
        Experiment.model_validate({**base, "flow_table_limit": 5})


def test_manager_passes_the_limit_to_the_runtime() -> None:
    import time

    from lab_fakes import FakeRuntime, MemoryRepository

    from sdn_ddos.lab.contracts import StartRequest
    from sdn_ddos.lab.manager import LabManager
    from sdn_ddos.lab.topology import presets

    seen: dict[str, object] = {}

    class LimitedRuntime(FakeRuntime):
        def __init__(self, *args, flow_table_limit=None, **kwargs):
            super().__init__(*args, **kwargs)
            seen["limit"] = flow_table_limit

        def start(self):
            raise RuntimeError("stop here")

    manager = LabManager(MemoryRepository(), LimitedRuntime)
    manager.start(
        StartRequest(
            topology=presets()[2],
            experiment=Experiment(
                attackers=["h1"], victims=["h2"], confirm_isolated_lab=True,
                flow_table_limit=1500,
            ),
            forwarding="per_port",
        )
    )  # fmt: skip
    deadline = time.monotonic() + 3
    while "limit" not in seen:
        assert time.monotonic() < deadline
        time.sleep(0.01)
    assert seen["limit"] == 1500
