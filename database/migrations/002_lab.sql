-- GUI projects and experiment history. Apply explicitly to an existing database.
BEGIN;
CREATE TABLE IF NOT EXISTS lab_projects (
    id UUID PRIMARY KEY,
    topology JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS lab_runs (
    id UUID PRIMARY KEY,
    topology JSONB NOT NULL,
    settings JSONB,
    versions JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS lab_events (
    run_id UUID NOT NULL REFERENCES lab_runs(id),
    seq BIGINT NOT NULL CHECK (seq > 0),
    ts TIMESTAMPTZ NOT NULL,
    kind TEXT NOT NULL,
    data JSONB NOT NULL,
    PRIMARY KEY (run_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_lab_runs_started ON lab_runs (started_at);
ALTER TABLE flow_stats ADD COLUMN IF NOT EXISTS run_id UUID;
ALTER TABLE port_stats ADD COLUMN IF NOT EXISTS run_id UUID;
ALTER TABLE controller_stats ADD COLUMN IF NOT EXISTS run_id UUID;
ALTER TABLE attack_windows ADD COLUMN IF NOT EXISTS run_id UUID;
ALTER TABLE detection_events ADD COLUMN IF NOT EXISTS run_id UUID;
ALTER TABLE mitigation_events ADD COLUMN IF NOT EXISTS run_id UUID;
COMMIT;
