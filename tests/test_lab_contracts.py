import pytest

from sdn_ddos.lab.contracts import Experiment, validate_experiment
from sdn_ddos.lab.topology import presets


def test_experiment_defaults_and_target_membership():
    topology = presets()[1]
    settings = Experiment(
        source="h1b", target="h2a", client="h3a", confirm_isolated_lab=True
    )
    validate_experiment(topology, settings)
    assert (settings.baseline, settings.duration, settings.recovery, settings.rate) == (
        30,
        20,
        30,
        100,
    )
    assert not settings.mitigation
    with pytest.raises(ValueError):
        validate_experiment(topology, settings.model_copy(update={"target": "outside"}))


@pytest.mark.parametrize(
    "values", [{"rate": 1001}, {"duration": 301}, {"rate": 0}, {"baseline": -1}]
)
def test_experiment_hard_limits(values):
    with pytest.raises(ValueError):
        Experiment(
            source="h1b",
            target="h2a",
            client="h3a",
            confirm_isolated_lab=True,
            **values,
        )


def test_confirmation_and_reachable_distinct_hosts_required():
    for updates in ({"confirm_isolated_lab": False}, {"source": "h2a"}):
        settings = (
            Experiment(source="h1b", target="h2a", client="h3a", **updates)
            if "source" not in updates
            else Experiment(
                source="h2a", target="h2a", client="h3a", confirm_isolated_lab=True
            )
        )
        with pytest.raises(ValueError):
            validate_experiment(presets()[1], settings)
    settings = Experiment(
        source="h1b", target="h2a", client="h3a", confirm_isolated_lab=True
    )
    with pytest.raises(ValueError, match="subnet"):
        validate_experiment(presets()[0], settings)
