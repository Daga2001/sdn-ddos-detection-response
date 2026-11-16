"""What each detector decision costs, measured where the controller can see it.

The thesis compares detectors by how well they detect *and* by what each decision
costs. Two things are measured here, both inside the lab:

* the time the controller waits for each decision (the detector service round
  trip, the language-model call included), kept as running totals so a dropped
  telemetry event never removes a decision from them;
* the CPU time and memory of the detector service process, which reports them
  itself through ``GET /usage``, together with the CPU time its request threads
  spent deciding (so health checks and other requests are not charged to the
  decisions).

What a decision is depends on the detector: for the LLM it is one flow sample sent
to the model, for entropy it is one evaluated window of the whole network. LLM
verdicts served from the controller's cache cost no model call and are counted
apart as *reused*. GPU use on the computer that runs the language model is not
measured.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass
class DecisionCost:
    """Running totals of the decisions a detector made during one run."""

    decisions: int = 0
    reused: int = 0
    failed: int = 0
    milliseconds: float = 0.0

    def add(
        self,
        detector: str,
        decisions: int,
        elapsed_ms: float,
        *,
        reused: int = 0,
        failed: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Count one call to the detector; return its event, or None without a call.

        ``elapsed_ms`` is the time waited for the whole call; a failed call still
        took that time, so it is added to the totals and reported with no verdicts.
        """

        if decisions < 0 or reused < 0:
            raise ValueError("decision counts cannot be negative")
        self.reused += reused
        if decisions == 0:
            return None
        elapsed = max(0.0, float(elapsed_ms))
        self.decisions += decisions
        self.milliseconds += elapsed
        if failed:
            self.failed += decisions
        return {
            "detector": detector,
            "decisions": decisions,
            "reused": reused,
            "elapsed_ms": round(elapsed, 3),
            "ms_per_decision": round(elapsed / decisions, 3),
            "failed": failed,
        }

    def totals(self) -> Dict[str, Any]:
        return {
            "decisions_total": self.decisions,
            "decisions_reused_total": self.reused,
            "decisions_failed_total": self.failed,
            "decision_ms_total": round(self.milliseconds, 3),
        }


def usage_from(payload: Any) -> Optional[Dict[str, float]]:
    """The detector's ``/usage`` answer, or None when it is not a valid one."""

    if not isinstance(payload, dict):
        return None
    cpu = payload.get("cpu_seconds")
    rss = payload.get("rss_bytes")
    if isinstance(cpu, bool) or not isinstance(cpu, (int, float)):
        return None
    if isinstance(rss, bool) or not isinstance(rss, int):
        return None
    if not math.isfinite(cpu) or cpu < 0 or rss < 0:
        return None
    usage = {"cpu_seconds": float(cpu), "rss_bytes": float(rss)}
    decided = payload.get("decision_cpu_seconds")
    if (
        isinstance(decided, (int, float))
        and not isinstance(decided, bool)
        and math.isfinite(decided)
        and decided >= 0
    ):
        usage["decision_cpu_seconds"] = float(decided)
    return usage


def cpu_percent_since(
    previous: Optional[Tuple[float, float]], cpu_seconds: float, now: float
) -> Tuple[Optional[float], Tuple[float, float]]:
    """CPU use between two samples as a percent of one core, and the new sample.

    None for the first sample, when the clock did not move, or when the process
    restarted (its CPU time went down).
    """

    current = (cpu_seconds, now)
    if previous is None:
        return None, current
    used = cpu_seconds - previous[0]
    elapsed = now - previous[1]
    if elapsed <= 0 or used < 0:
        return None, current
    return round(used / elapsed * 100.0, 2), current
