"""Local access and internal runner configuration; no baked-in credentials."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LabSettings:
    access_token: str
    runner_token: str
    origin: str = "http://localhost:8080"
    runner_url: str = "http://runner:9001"
    static_dir: str = "web/dist"

    def __post_init__(self) -> None:
        if len(self.access_token) < 32 or len(self.runner_token) < 32:
            raise ValueError(
                "lab credentials must contain at least 32 characters; "
                "run make lab-setup"
            )

    @classmethod
    def from_env(cls) -> LabSettings:
        return cls(
            access_token=os.environ.get("SDN_LAB_TOKEN", ""),
            runner_token=os.environ.get("SDN_RUNNER_TOKEN", ""),
            origin=os.environ.get("SDN_LAB_ORIGIN", "http://localhost:8080"),
            runner_url=os.environ.get("SDN_RUNNER_URL", "http://runner:9001"),
            static_dir=os.environ.get("SDN_LAB_STATIC", str(Path("web/dist"))),
        )
