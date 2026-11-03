-- One row per detector decision, so LLM and entropy can be compared on equal
-- terms (join with attack_windows by ts for ground truth). Safe to re-apply.

CREATE TABLE IF NOT EXISTS detection_decisions (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    detector TEXT NOT NULL CHECK (detector IN ('llm', 'entropy')),
    dpid BIGINT,
    verdict BOOLEAN NOT NULL,
    score DOUBLE PRECISION,
    latency_ms DOUBLE PRECISION,
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_detection_decisions_detector_ts
    ON detection_decisions (detector, ts);
