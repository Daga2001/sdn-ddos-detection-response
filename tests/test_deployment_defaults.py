import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
