"""Per-run detection settings: what the runner tells the detector and the controller.

An experiment may carry a `DetectionConfig`. At run start the runner

* pushes the detector-side part (mode, LLM, prompt, entropy tuning, response policy)
  to the detector service with `PUT /config`, and
* hands the controller-side part (window shape, sample budget, response limits) over
  as environment variables of the Ryu process it spawns.

An experiment without a `DetectionConfig` changes nothing: the detector keeps whatever
`scripts/detector.sh` or the service defaults said.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from typing import Any, Optional

import requests

from sdn_ddos.lab.contracts import DetectionConfig, EntropyParams, Experiment

DETECTOR_TIMEOUT = (1.0, 8.0)


def _flag(value: bool) -> str:
    return "true" if value else "false"


def entropy_features(entropy: EntropyParams) -> list[str]:
    """The distributions the entropy detector watches (the IPs plus what is on)."""

    features = ["src", "dst"]
    if entropy.watch_ports:
        features.append("dport")
    if entropy.watch_protocols:
        features.append("proto")
    if entropy.watch_pairs:
        features.append("pair")
    return features


def victim_addresses(topology: Any, experiment: Experiment) -> list[str]:
    """The victims' addresses as /32 networks, to protect them (see `ResponseParams`).

    A detector never names a protected host as an attacker and the response never acts
    on it. The victims are protected unless `protect_victims` is turned off.
    """

    detection = experiment.detection
    if detection is not None and not detection.response.protect_victims:
        return []
    addresses = {host.name: host.ip.split("/")[0] for host in topology.hosts}
    return [f"{addresses[name]}/32" for name in experiment.victims if name in addresses]


def protected_value(*groups: Sequence[str]) -> str:
    """`SDN_RESPONSE_PROTECTED`: the networks of every group, once each, in order."""

    return ",".join(dict.fromkeys(item for group in groups for item in group))


def controller_env(
    detection: DetectionConfig, protected_hosts: Sequence[str] = ()
) -> dict[str, str]:
    """Environment overrides for the Ryu controller of one run."""

    response = detection.response
    entropy = detection.entropy
    burst = response.rate_limit_burst or response.rate_limit_pps * 2
    return {
        "SDN_LLM_MAX_SAMPLES": str(detection.llm_max_samples),
        "SDN_POLL_INTERVAL": str(detection.poll_seconds),
        "SDN_DDOS_THRESHOLD": str(detection.threshold),
        "SDN_ENTROPY_WINDOW_SECONDS": str(entropy.window_seconds),
        "SDN_ENTROPY_WINDOW_MODE": entropy.window_mode,
        "SDN_ENTROPY_DEDUPE_SWITCHES": _flag(entropy.dedupe_switches),
        "SDN_ENTROPY_FEATURES": ",".join(entropy_features(entropy)),
        "SDN_RESPONSE_POLICY": response.policy,
        "SDN_RESPONSE_DRY_RUN": _flag(response.dry_run),
        "SDN_RATE_LIMIT_PPS": str(response.rate_limit_pps),
        "SDN_RATE_LIMIT_BURST": str(burst),
        "SDN_RATE_LIMIT_SECONDS": str(response.rate_limit_seconds),
        "SDN_RESPONSE_ESCALATE_AFTER": str(response.escalate_after_seconds),
        "SDN_BLOCK_SECONDS": str(response.block_seconds),
        "SDN_RESPONSE_MAX_ACTIVE": str(response.max_active),
        "SDN_RESPONSE_CONFIRM_HITS": str(response.confirm_hits),
        "SDN_RESPONSE_CONFIRM_SECONDS": str(response.confirm_seconds),
        "SDN_RESPONSE_PROTECTED": protected_value(response.protected, protected_hosts),
    }


def detector_update(detection: DetectionConfig) -> dict[str, Any]:
    """Body of `PUT /config` on the detector service."""

    entropy = detection.entropy
    update: dict[str, Any] = {
        "mode": detection.mode,
        "response": detection.response.policy,
        "dry_run": detection.response.dry_run,
        "entropy": {
            "k": entropy.k,
            "alpha": entropy.alpha,
            "warmup_windows": entropy.warmup_windows,
            "consecutive_windows": entropy.consecutive_windows,
            "min_total_rate": entropy.min_rate,
            "min_std": entropy.min_std,
            "candidate_share": entropy.candidate_share,
            "candidate_min_rate": entropy.candidate_min_rate,
            "update_hold": entropy.update_hold,
            "alpha_run": entropy.alpha_run,
            "measure": entropy.measure,
            "order": entropy.order,
            "center": entropy.center,
            "spread": entropy.spread,
            "history": entropy.history,
            "context": entropy.context,
            "features": entropy_features(entropy),
            "decide": list(entropy.decide),
            "margin": entropy.margin,
            "rate_threshold": entropy.rate_threshold,
        },
    }
    if detection.mode == "llm":
        update["model"] = detection.model
        update["prompt"] = detection.prompt
    return update


class DetectorClient:
    """Runner-side client of the detector service. Problems surface as ValueError so
    the API answers with a readable 409 instead of a generic 'runner unavailable'."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = session or requests.Session()

    @classmethod
    def from_env(
        cls, env: Optional[Mapping[str, str]] = None
    ) -> Optional["DetectorClient"]:
        source = os.environ if env is None else env
        url = source.get("SDN_DDOS_SERVICE_URL", "").strip()
        key = source.get("SDN_DDOS_API_KEY", "").strip()
        if not url or not key:
            return None
        return cls(url.rsplit("/", 1)[0], key)

    def _call(self, method: str, path: str, body: Any = None) -> Any:
        try:
            response = self.session.request(
                method,
                f"{self.base_url}{path}",
                json=body,
                headers={"X-Api-Key": self.api_key},
                timeout=DETECTOR_TIMEOUT,
            )
        except requests.RequestException as error:
            raise ValueError(
                "the detector service is not reachable; check that its container "
                f"is running ({error.__class__.__name__})"
            ) from error
        if response.status_code in (404, 405):
            raise ValueError(
                "this lab's detector service cannot be configured from the "
                "workspace; start the lab with scripts/lab_detector.sh"
            )
        if response.status_code in (401, 503):
            raise ValueError("the detector service rejected the lab's access key")
        if not response.ok:
            try:
                detail = response.json().get("detail")
            except ValueError:
                detail = None
            reason = detail or response.status_code
            raise ValueError(f"the detector service refused the settings: {reason}")
        return response.json()

    def config(self) -> dict[str, Any]:
        return dict(self._call("GET", "/config"))

    def models(self) -> list[str]:
        return [str(name) for name in self._call("GET", "/models").get("models", [])]

    def apply(self, detection: DetectionConfig) -> dict[str, Any]:
        return dict(self._call("PUT", "/config", detector_update(detection)))
