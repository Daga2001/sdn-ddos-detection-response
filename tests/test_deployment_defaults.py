import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def compose_workspace(tmp_path: Path) -> Path:
    if shutil.which("docker") is None:
        pytest.skip("Docker Compose CLI is needed to validate the deployment")
    version = subprocess.run(
        ["docker", "compose", "version"], capture_output=True, check=False
    )
    if version.returncode:
        pytest.skip("Docker Compose CLI is not installed")
    for name in ("compose.yaml", "compose.lab.yaml", "compose.detector.yaml"):
        shutil.copyfile(ROOT / name, tmp_path / name)
    shutil.copyfile(ROOT / ".env.example", tmp_path / ".env")
    (tmp_path / ".lab").mkdir()
    (tmp_path / ".lab/env").write_text(
        "SDN_LAB_TOKEN=test-lab-token\n"
        "SDN_RUNNER_TOKEN=test-runner-token\n"
        "SDN_LAB_INFERENCE_KEY=test-inference-key\n"
    )
    return tmp_path


def render_compose(workspace: Path) -> subprocess.CompletedProcess[str]:
    # Config rendering uses no daemon, containers, database, or real credentials.
    return subprocess.run(
        [
            "docker",
            "compose",
            "config",
            "--format",
            "json",
        ],
        cwd=workspace,
        env={
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("COMPOSE_", "SDN_", "DDOS_"))
        },
        capture_output=True,
        text=True,
        check=False,
    )


def test_default_compose_connects_the_lab_to_the_detector(
    compose_workspace: Path,
) -> None:
    result = render_compose(compose_workspace)
    assert result.returncode == 0, result.stderr
    config = json.loads(result.stdout)
    services = config["services"]
    assert set(services) == {"postgres", "web", "runner", "inference", "detector"}
    runner = services["runner"]
    assert (
        runner["environment"]["SDN_DDOS_SERVICE_URL"] == "http://detector:8000/predict"
    )
    assert runner["environment"]["SDN_RYU_MANAGER"] == "/usr/local/bin/ryu-modes"
    assert "detector" in runner["depends_on"]
    assert "control" in runner["networks"]
    assert "control" in services["detector"]["networks"]
    assert runner["environment"]["SDN_DDOS_API_KEY"] == "test-inference-key"
    assert services["detector"]["environment"]["DDOS_API_KEY"] == "test-inference-key"
    assert runner["environment"]["SDN_MITIGATION_ENABLED"] == "false"
    assert runner["environment"]["SDN_RESPONSE_DRY_RUN"] == "true"
    assert services["detector"]["environment"]["SDN_RESPONSE_DRY_RUN"] == "true"
    assert not services["detector"].get("ports")
    assert config["networks"]["control"]["internal"] is True
    assert config["name"] == "sdn-ddos-detection-response"
    assert services["web"]["environment"]["SDN_RUNNER_URL"] == (
        "http://lab-runner-control:9001"
    )
    assert runner["networks"]["control"]["aliases"] == ["lab-runner-control"]
    assert "lab-runner-control" not in runner["networks"]["default"].get("aliases", [])
    assert not config["networks"]["default"].get("external", False)
    assert config["volumes"]["sdn-postgres-data"]["name"] == (
        f"{ROOT.name}_sdn-postgres-data"
    )


def test_default_compose_requires_generated_credentials(
    compose_workspace: Path,
) -> None:
    (compose_workspace / ".lab/env").unlink()
    result = render_compose(compose_workspace)
    assert result.returncode != 0
    assert ".lab/env" in result.stderr


def test_lab_defaults_use_the_calibrated_prompt_and_keep_enforcement_opt_in() -> None:
    compose = (ROOT / "compose.detector.yaml").read_text()
    assert "${SDN_LLM_PROMPT:-lab}" in compose
    assert "SDN_LLM_PROMPT:-insdn" not in compose
    assert "${SDN_RESPONSE_DRY_RUN:-true}" in compose
    assert "SDN_RESPONSE_DRY_RUN:-false" not in compose
    env_example = (ROOT / ".env.example").read_text()
    assert re.search(r"^SDN_LLM_PROMPT=lab$", env_example, re.MULTILINE)
    assert re.search(r"^SDN_RESPONSE_DRY_RUN=true$", env_example, re.MULTILINE)


def test_fresh_databases_create_detection_decisions() -> None:
    schema = (ROOT / "database/schema.sql").read_text()
    migration = (ROOT / "database/migrations/001_detection_decisions.sql").read_text()
    for fragment in (
        "CREATE TABLE IF NOT EXISTS detection_decisions",
        "detector TEXT NOT NULL CHECK (detector IN ('llm', 'entropy'))",
        "latency_ms DOUBLE PRECISION",
        "idx_detection_decisions_detector_ts",
    ):
        assert fragment in schema, f"schema.sql lacks: {fragment}"
        assert fragment in migration, f"migration lacks: {fragment}"


def test_external_database_uses_the_same_project_without_starting_postgres(
    compose_workspace: Path,
) -> None:
    env = compose_workspace / ".env"
    env.write_text(
        env.read_text()
        .replace("COMPOSE_PROFILES=local-db", "COMPOSE_PROFILES=")
        .replace("SDN_LAB_DB_EXTERNAL=false", "SDN_LAB_DB_EXTERNAL=true")
    )
    result = render_compose(compose_workspace)
    assert result.returncode == 0, result.stderr
    config = json.loads(result.stdout)
    assert "postgres" not in config["services"]
    assert config["networks"]["default"]["external"] is True
    assert config["name"] == "sdn-ddos-detection-response"


@pytest.mark.parametrize("script", ["scripts/lab.sh", "scripts/lab_detector.sh"])
def test_retired_startup_commands_never_invoke_docker(script: str) -> None:
    result = subprocess.run(
        ["bash", str(ROOT / script), "up"], capture_output=True, text=True
    )
    assert result.returncode == 2
    assert "docker compose up" in result.stderr
