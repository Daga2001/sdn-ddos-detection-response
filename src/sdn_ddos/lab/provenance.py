"""What a run needs to be reproduced and to be counted: settings fingerprint and commit.

* `settings_fingerprint` is a SHA-256 of the detector settings that must stay frozen
  between calibration and held-out runs: the whole `DetectionConfig` (detector, model,
  prompt profile, thresholds, entropy tuning, response policy) and the forwarding
  choice. The attack (attackers, rate, duration) is the scenario, not a setting, and is
  left out. Two runs with the same fingerprint were judged with the same settings.
* `repository_commit` says which code ran. Inside the lab containers the repository's
  `.git` directory is mounted read-only (compose.lab.yaml); outside, `SDN_GIT_COMMIT`
  may name the commit.
"""

from __future__ import annotations

import hashlib
import json
import os
from importlib import metadata
from pathlib import Path
from typing import Any, Optional

from sdn_ddos.lab.contracts import DetectionConfig

FINGERPRINT_LENGTH = 16  # hex characters shown and exported; enough to tell runs apart


def settings_fingerprint(detection: Optional[DetectionConfig], forwarding: str) -> str:
    payload: dict[str, Any] = {
        "detection": detection.model_dump(mode="json") if detection else None,
        "forwarding": forwarding,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:FINGERPRINT_LENGTH]


def _read_ref(git_dir: Path, ref: str) -> Optional[str]:
    loose = git_dir / ref
    if loose.is_file():
        return loose.read_text(encoding="utf-8").strip() or None
    packed = git_dir / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="utf-8").splitlines():
            if line.endswith(f" {ref}") and not line.startswith(("#", "^")):
                return line.split(" ", 1)[0]
    return None


def repository_commit(env: Optional[dict[str, str]] = None) -> dict[str, str]:
    """`{"commit": ..., "branch": ...}`; "unknown" when neither source is available."""

    source = dict(os.environ) if env is None else env
    named = source.get("SDN_GIT_COMMIT", "").strip()
    if named:
        return {"commit": named, "branch": source.get("SDN_GIT_BRANCH", "").strip()}
    git_dir = Path(source.get("SDN_GIT_DIR", "/repo-git"))
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return {"commit": "unknown", "branch": ""}
    if head.startswith("ref: "):
        ref = head[5:].strip()
        try:
            commit = _read_ref(git_dir, ref)
        except OSError:
            commit = None
        branch = ref.rsplit("refs/heads/", 1)[-1]
        return {"commit": commit or "unknown", "branch": branch}
    return {"commit": head, "branch": ""}  # detached HEAD


def package_version(name: str) -> str:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return "not_installed"


def os_release(path: str = "/etc/os-release") -> str:
    """PRETTY_NAME of the operating system (e.g. "Ubuntu 22.04.5 LTS")."""

    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return "unknown"
    for line in lines:
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"') or "unknown"
    return "unknown"
