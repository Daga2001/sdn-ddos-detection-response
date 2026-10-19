"""Controller-side client for the detector service (Python 3.9, requests only).

`RemoteEntropy` mirrors EntropyDetector.observe() but runs the detection in the
detector container, keeping one adaptive state per run id. It never falls back
to another detector: a failed call raises and the caller skips that window.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Dict, Optional

import requests

from sdn_ddos.detection.entropy import EntropyResult, FlowObservation, Histogram


def fetch_remote_config(
    base_url: str, api_key: str, timeout: float = 3.0
) -> Optional[Dict[str, Any]]:
    """The detector's active {mode, model}, or None if it is not a detector service."""

    if not api_key:
        return None
    try:
        response = requests.get(
            f"{base_url}/config", headers={"X-Api-Key": api_key}, timeout=timeout
        )
        response.raise_for_status()
        config = response.json()
    except (requests.RequestException, ValueError):
        return None
    if not isinstance(config, dict) or config.get("mode") not in (
        "llm",
        "entropy",
        "off",
    ):
        return None
    return config


class RemoteEntropy:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        run_id: str,
        timeout: float = 5.0,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.base_url = base_url
        self.api_key = api_key
        self.run_id = run_id
        self.timeout = timeout
        self.session = session or requests.Session()
        self.consecutive_windows = 2

    def observe(
        self,
        scope: int,
        flows: Sequence[FlowObservation],
        extra: Optional[Mapping[str, Histogram]] = None,
    ) -> EntropyResult:
        payload: Dict[str, Any] = {
            "run_id": self.run_id,
            "scope": scope,
            "flows": [{"src": f.src, "dst": f.dst, "weight": f.weight} for f in flows],
        }
        for name, key in (("dport", "dports"), ("proto", "protos")):
            if extra and extra.get(name):
                payload[key] = [
                    {"weight": weight, "count": count} for weight, count in extra[name]
                ]
        response = self.session.post(
            f"{self.base_url}/entropy/observe",
            json=payload,
            headers={"X-Api-Key": self.api_key},
            timeout=self.timeout,
        )
        response.raise_for_status()
        body = response.json()
        details = body["details"]
        self.consecutive_windows = int(body["consecutive_windows"])
        return EntropyResult(
            dpid=scope,
            evaluated=bool(details["evaluated"]),
            reason=str(details["reason"]),
            h_src=details["h_src"],
            h_dst=details["h_dst"],
            src_lower=details["src_lower"],
            src_upper=details["src_upper"],
            dst_lower=details["dst_lower"],
            total_rate=float(details["total_rate"]),
            suspicious=bool(details["suspicious"]),
            confirmed=bool(body["confirmed"]),
            consecutive=int(body["consecutive"]),
            target_dst=body["target_dst"],
            candidates=tuple(body["candidates"]),
            signals=dict(details.get("signals") or {}),
            panel=dict(details.get("panel") or {}),
            top_src=tuple((str(n), float(w)) for n, w in details.get("top_src") or ()),
            top_dst=tuple((str(n), float(w)) for n, w in details.get("top_dst") or ()),
            measure=str(details.get("measure", "shannon")),
            center=str(details.get("center_kind", "ewma")),
            config=dict(details.get("config") or {}),
            note=str(details.get("note") or ""),
        )
