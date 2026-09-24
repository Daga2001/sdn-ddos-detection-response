-- Canonical PostgreSQL schema for SDN monitoring and experiment ground truth.
-- Safe to apply repeatedly in the isolated local lab database.

CREATE TABLE IF NOT EXISTS flow_stats (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    dpid BIGINT NOT NULL,
    table_id INTEGER,
    priority INTEGER NOT NULL,
    cookie BIGINT NOT NULL,
    eth_src TEXT,
    eth_dst TEXT,
    ipv4_src INET,
    ipv4_dst INET,
    ip_proto INTEGER,
    l4_src_port INTEGER,
    l4_dst_port INTEGER,
    packet_count BIGINT NOT NULL CHECK (packet_count >= 0),
    byte_count BIGINT NOT NULL CHECK (byte_count >= 0),
    duration_sec BIGINT NOT NULL CHECK (duration_sec >= 0),
    duration_nsec BIGINT NOT NULL CHECK (duration_nsec >= 0),
    pktrate DOUBLE PRECISION,
    byterate DOUBLE PRECISION,
    label INTEGER NOT NULL DEFAULT 0 CHECK (label IN (0, 1)),
    prob_ddos DOUBLE PRECISION CHECK (prob_ddos BETWEEN 0 AND 1)
);

CREATE TABLE IF NOT EXISTS port_stats (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    dpid BIGINT NOT NULL,
    port_no BIGINT NOT NULL,
    rx_packets BIGINT NOT NULL,
    tx_packets BIGINT NOT NULL,
    rx_bytes BIGINT NOT NULL,
    tx_bytes BIGINT NOT NULL,
    rx_dropped BIGINT NOT NULL,
    tx_dropped BIGINT NOT NULL,
    rx_errors BIGINT NOT NULL,
    tx_errors BIGINT NOT NULL,
    rx_byterate DOUBLE PRECISION,
    tx_byterate DOUBLE PRECISION
);

CREATE TABLE IF NOT EXISTS controller_stats (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    cpu_percent DOUBLE PRECISION NOT NULL CHECK (cpu_percent >= 0),
    rss_bytes BIGINT NOT NULL CHECK (rss_bytes >= 0)
);

CREATE TABLE IF NOT EXISTS attack_windows (
    id BIGSERIAL PRIMARY KEY,
    start_ts TIMESTAMPTZ NOT NULL,
    end_ts TIMESTAMPTZ NOT NULL,
    attack_type TEXT NOT NULL,
    target_ip INET NOT NULL,
    CHECK (end_ts >= start_ts)
);

CREATE TABLE IF NOT EXISTS detection_events (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    dpid BIGINT NOT NULL,
    ipv4_src INET,
    ipv4_dst INET,
    ip_proto INTEGER,
    l4_dst_port INTEGER,
    probability DOUBLE PRECISION NOT NULL CHECK (probability BETWEEN 0 AND 1),
    threshold DOUBLE PRECISION NOT NULL CHECK (threshold BETWEEN 0 AND 1),
    mitigation_enabled BOOLEAN NOT NULL
);

CREATE TABLE IF NOT EXISTS mitigation_events (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    ipv4_src INET NOT NULL,
    action TEXT NOT NULL,
    duration_seconds INTEGER NOT NULL CHECK (duration_seconds > 0),
    affected_switches INTEGER NOT NULL CHECK (affected_switches >= 0)
);

CREATE INDEX IF NOT EXISTS idx_flow_stats_ts ON flow_stats (ts);
CREATE INDEX IF NOT EXISTS idx_flow_stats_dpid ON flow_stats (dpid);
CREATE INDEX IF NOT EXISTS idx_flow_stats_ipv4_src ON flow_stats (ipv4_src);
CREATE INDEX IF NOT EXISTS idx_port_stats_ts ON port_stats (ts);
CREATE INDEX IF NOT EXISTS idx_port_stats_dpid_port ON port_stats (dpid, port_no);
CREATE INDEX IF NOT EXISTS idx_controller_stats_ts ON controller_stats (ts);
CREATE INDEX IF NOT EXISTS idx_detection_events_ts ON detection_events (ts);
CREATE INDEX IF NOT EXISTS idx_mitigation_events_ts ON mitigation_events (ts);
