"""Environment-backed configuration shared by the research components.

Configuration parsing lives in one module so the controller, inference service,
and experiment tools agree on defaults and reject malformed values early.
"""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple


class ConfigurationError(ValueError):
    """Raised when an environment variable has an invalid value."""


def _env(source: Optional[Mapping[str, str]]) -> Mapping[str, str]:
    return os.environ if source is None else source


def _boolean(values: Mapping[str, str], name: str, default: bool) -> bool:
    raw = values.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be true or false")


def _integer(
    values: Mapping[str, str],
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = values.get(name, str(default))
    try:
        parsed = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _floating(
    values: Mapping[str, str],
    name: str,
    default: float,
    *,
    minimum: float,
    maximum: float,
) -> float:
    raw = values.get(name, str(default))
    try:
        parsed = float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number") from exc
    if not minimum <= parsed <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _networks(raw: str) -> Tuple[ipaddress.IPv4Network, ...]:
    parsed = []
    for value in raw.split(","):
        candidate = value.strip()
        if not candidate:
            continue
        try:
            network = ipaddress.ip_network(candidate, strict=True)
        except ValueError as exc:
            raise ConfigurationError(
                f"SDN_ALLOWED_TARGET_CIDRS contains an invalid network: {candidate}"
            ) from exc
        if network.version != 4 or not network.is_private:
            raise ConfigurationError(
                "SDN_ALLOWED_TARGET_CIDRS may contain only private IPv4 networks"
            )
        if not isinstance(network, ipaddress.IPv4Network):
            raise ConfigurationError("SDN_ALLOWED_TARGET_CIDRS must use IPv4 networks")
        parsed.append(network)
    if not parsed:
        raise ConfigurationError("SDN_ALLOWED_TARGET_CIDRS must not be empty")
    return tuple(parsed)


@dataclass(frozen=True)
class DatabaseSettings:
    """PostgreSQL settings for metrics and experiment ground truth."""

    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 5432
    database: str = "sdn_monitor"
    user: str = "sdn_user"
    password: str = ""
    connect_timeout_seconds: int = 5

    @classmethod
    def from_env(cls, source: Optional[Mapping[str, str]] = None) -> DatabaseSettings:
        values = _env(source)
        enabled = _boolean(values, "SDN_DB_ENABLED", False)
        password = values.get("SDN_PG_PASSWORD", "")
        if enabled and not password:
            raise ConfigurationError(
                "SDN_PG_PASSWORD is required when SDN_DB_ENABLED is true"
            )
        return cls(
            enabled=enabled,
            host=values.get("SDN_PG_HOST", "127.0.0.1"),
            port=_integer(values, "SDN_PG_PORT", 5432, minimum=1, maximum=65535),
            database=values.get("SDN_PG_DB", "sdn_monitor"),
            user=values.get("SDN_PG_USER", "sdn_user"),
            password=password,
            connect_timeout_seconds=_integer(
                values, "SDN_PG_CONNECT_TIMEOUT", 5, minimum=1, maximum=60
            ),
        )


@dataclass(frozen=True)
class DetectionSettings:
    """Settings for the local HTTP inference service."""

    api_key: str = ""
    model_path: Optional[Path] = None
    model_sha256: str = ""
    max_batch_size: int = 500

    @classmethod
    def from_env(cls, source: Optional[Mapping[str, str]] = None) -> DetectionSettings:
        values = _env(source)
        raw_path = values.get("DDOS_MODEL_PATH", "").strip()
        checksum = values.get("DDOS_MODEL_SHA256", "").strip().lower()
        if checksum and not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ConfigurationError(
                "DDOS_MODEL_SHA256 must be 64 hexadecimal characters"
            )
        return cls(
            api_key=values.get("DDOS_API_KEY", ""),
            model_path=Path(raw_path) if raw_path else None,
            model_sha256=checksum,
            max_batch_size=_integer(
                values, "DDOS_MAX_BATCH_SIZE", 500, minimum=1, maximum=5000
            ),
        )


@dataclass(frozen=True)
class ControllerSettings:
    """Runtime settings for monitoring, inference, and mitigation."""

    poll_interval_seconds: float = 5.0
    inference_url: str = "http://127.0.0.1:8000/predict"
    inference_api_key: str = ""
    detection_threshold: float = 0.8
    mitigation_enabled: bool = False
    block_seconds: int = 300
    flow_idle_timeout_seconds: int = 60
    database_flush_rows: int = 100
    allowed_target_networks: Sequence[ipaddress.IPv4Network] = (
        ipaddress.IPv4Network("10.0.0.0/8"),
    )

    @classmethod
    def from_env(cls, source: Optional[Mapping[str, str]] = None) -> ControllerSettings:
        values = _env(source)
        return cls(
            poll_interval_seconds=_floating(
                values, "SDN_POLL_INTERVAL", 5.0, minimum=0.5, maximum=300.0
            ),
            inference_url=values.get(
                "SDN_DDOS_SERVICE_URL", "http://127.0.0.1:8000/predict"
            ),
            inference_api_key=values.get("SDN_DDOS_API_KEY", ""),
            detection_threshold=_floating(
                values, "SDN_DDOS_THRESHOLD", 0.8, minimum=0.0, maximum=1.0
            ),
            mitigation_enabled=_boolean(values, "SDN_MITIGATION_ENABLED", False),
            block_seconds=_integer(
                values, "SDN_BLOCK_SECONDS", 300, minimum=1, maximum=86400
            ),
            flow_idle_timeout_seconds=_integer(
                values, "SDN_FLOW_IDLE_TIMEOUT", 60, minimum=0, maximum=86400
            ),
            database_flush_rows=_integer(
                values, "SDN_DB_FLUSH_EVERY", 100, minimum=1, maximum=10000
            ),
            allowed_target_networks=_networks(
                values.get("SDN_ALLOWED_TARGET_CIDRS", "10.0.0.0/8")
            ),
        )


def validate_lab_target(
    target: str, allowed_networks: Sequence[ipaddress.IPv4Network]
) -> ipaddress.IPv4Address:
    """Return a validated private lab address or raise ConfigurationError."""

    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ConfigurationError("target must be a literal IPv4 address") from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise ConfigurationError("target must be an IPv4 address")
    if address.is_loopback or address.is_multicast or address.is_unspecified:
        raise ConfigurationError("target must be a usable Mininet host address")
    if not any(address in network for network in allowed_networks):
        raise ConfigurationError("target is outside SDN_ALLOWED_TARGET_CIDRS")
    return address
