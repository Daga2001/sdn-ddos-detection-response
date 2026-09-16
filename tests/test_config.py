import ipaddress

import pytest

from sdn_ddos.config import (
    ConfigurationError,
    ControllerSettings,
    DatabaseSettings,
    DetectionSettings,
    validate_lab_target,
)


def test_database_is_disabled_without_credentials() -> None:
    settings = DatabaseSettings.from_env({})
    assert settings.enabled is False
    assert settings.host == "127.0.0.1"


def test_enabled_database_requires_password() -> None:
    with pytest.raises(ConfigurationError, match="SDN_PG_PASSWORD"):
        DatabaseSettings.from_env({"SDN_DB_ENABLED": "true"})


def test_controller_parses_private_target_networks() -> None:
    settings = ControllerSettings.from_env(
        {
            "SDN_MITIGATION_ENABLED": "yes",
            "SDN_ALLOWED_TARGET_CIDRS": "10.0.0.0/8,192.168.0.0/16",
        }
    )
    assert settings.mitigation_enabled is True
    assert settings.allowed_target_networks == (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("192.168.0.0/16"),
    )


@pytest.mark.parametrize(
    "environment",
    [
        {"SDN_MITIGATION_ENABLED": "maybe"},
        {"SDN_POLL_INTERVAL": "0"},
        {"SDN_ALLOWED_TARGET_CIDRS": "8.8.8.0/24"},
        {"SDN_ALLOWED_TARGET_CIDRS": "10.0.0.1/24"},
    ],
)
def test_controller_rejects_invalid_environment(environment: dict[str, str]) -> None:
    with pytest.raises(ConfigurationError):
        ControllerSettings.from_env(environment)


def test_detection_checksum_must_be_sha256() -> None:
    with pytest.raises(ConfigurationError, match="64 hexadecimal"):
        DetectionSettings.from_env({"DDOS_MODEL_SHA256": "not-a-checksum"})


def test_lab_target_must_be_inside_allowlist() -> None:
    networks = (ipaddress.ip_network("10.0.0.0/8"),)
    assert str(validate_lab_target("10.0.2.1", networks)) == "10.0.2.1"
    with pytest.raises(ConfigurationError, match="outside"):
        validate_lab_target("192.168.1.2", networks)
    with pytest.raises(ConfigurationError, match="literal"):
        validate_lab_target("example.com", networks)
