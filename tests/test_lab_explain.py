"""The workspace shows these strings to students, so they must read as English."""

import pytest
from pydantic import ValidationError

from sdn_ddos.lab.contracts import Experiment
from sdn_ddos.lab.explain import describe, describe_exception
from sdn_ddos.lab.topology import Topology, presets


def errors_for(model, payload):
    with pytest.raises(ValidationError) as caught:
        model.model_validate(payload)
    return caught.value.errors()


def test_field_problems_are_located_and_explained():
    data = presets()[2].model_dump()
    data["hosts"][0]["ip"] = "8.8.8.8/24"
    assert describe(errors_for(Topology, data)) == (
        "Host 1 · IPv4 address / prefix: hosts must use private IPv4 addresses."
    )


def test_patterns_become_naming_rules():
    data = presets()[2].model_dump()
    data["hosts"][0]["name"] = "laptop"
    message = describe(errors_for(Topology, data))
    assert "Host 1 · name" in message
    assert "start with “h”" in message


def test_unknown_settings_are_called_out_as_removable():
    data = presets()[2].model_dump()
    data["hosts"][0]["gateway"] = "10.0.0.254"
    assert "remove it and try again" in describe(errors_for(Topology, data))


def test_bounds_state_the_limit_that_was_crossed():
    payload = {"attackers": ["h1"], "victims": ["h2"], "baseline": 0}
    assert describe(errors_for(Experiment, payload)) == (
        "baseline seconds: use a value at least 1."
    )


def test_long_error_lists_are_summarised_rather_than_dumped():
    errors = errors_for(Topology, {})
    assert describe(errors).endswith("1 further problem not listed.")
    assert describe(errors, limit=1).endswith("3 further problems not listed.")


def test_file_parsing_failures_keep_their_own_wording():
    assert describe_exception(KeyError("ip")) == "a required field (ip) is missing"
    assert describe_exception(ValueError("delay must use milliseconds")) == (
        "delay must use milliseconds"
    )
