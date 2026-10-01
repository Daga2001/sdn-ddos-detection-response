import pytest

from sdn_ddos.lab.contracts import (
    Experiment,
    attack_plan,
    legitimate_clients,
    probe_pairs,
    validate_experiment,
)
from sdn_ddos.lab.topology import presets


def test_experiment_defaults_and_target_membership():
    topology = presets()[1]
    settings = Experiment(attackers=["h1b"], victims=["h2a"], confirm_isolated_lab=True)
    validate_experiment(topology, settings)
    assert (settings.baseline, settings.duration, settings.recovery, settings.rate) == (
        30,
        20,
        30,
        100,
    )
    assert settings.traffic == ["syn"]
    assert not settings.mitigation
    with pytest.raises(ValueError):
        validate_experiment(
            topology, settings.model_copy(update={"victims": ["outside"]})
        )


@pytest.mark.parametrize(
    "values",
    [
        {"rate": 1001},
        {"duration": 301},
        {"rate": 0},
        {"baseline": -1},
        {"attackers": []},
        {"traffic": []},
        {"traffic": ["fin"]},
    ],
)
def test_experiment_hard_limits(values):
    fields = {
        "attackers": ["h1b"],
        "victims": ["h2a"],
        "confirm_isolated_lab": True,
        **values,
    }
    with pytest.raises(ValueError):
        Experiment(**fields)


def test_multiple_attackers_and_victims_infer_clients():
    topology = presets()[1]
    settings = Experiment(
        attackers=["h1b", "h1c"],
        victims=["h2a", "h2b"],
        traffic=["syn", "udp"],
        confirm_isolated_lab=True,
    )
    validate_experiment(topology, settings)
    # Every attacker floods every victim; kinds are spread across the attackers.
    plan = attack_plan(settings)
    assert plan == [
        ("h1b", "h2a", "syn"),
        ("h1b", "h2b", "syn"),
        ("h1c", "h2a", "udp"),
        ("h1c", "h2b", "udp"),
    ]
    # Legitimate clients are inferred: neither attacker nor victim.
    clients = legitimate_clients(topology, settings)
    assert set(clients).isdisjoint({"h1b", "h1c", "h2a", "h2b"})
    assert clients
    pairs = probe_pairs(topology, settings)
    assert all(victim in settings.victims for _, victim in pairs)


def test_confirmation_and_distinct_roles_and_bounds_required():
    topology = presets()[1]
    with pytest.raises(ValueError, match="isolated lab"):
        validate_experiment(topology, Experiment(attackers=["h1b"], victims=["h2a"]))
    with pytest.raises(ValueError, match="both an attacker and a victim"):
        validate_experiment(
            topology,
            Experiment(attackers=["h2a"], victims=["h2a"], confirm_isolated_lab=True),
        )
    with pytest.raises(ValueError, match="bounded"):
        validate_experiment(
            topology,
            Experiment(
                attackers=["h1a", "h1b", "h1c", "h2a", "h2b"],
                victims=["h2c", "h3a", "h3b", "h3c"],
                confirm_isolated_lab=True,
            ),
        )
    with pytest.raises(ValueError, match="subnet"):
        validate_experiment(
            presets()[0],
            Experiment(attackers=["h1b"], victims=["h2a"], confirm_isolated_lab=True),
        )
