# Troubleshooting

## Ryu fails during installation or startup

Use Python 3.9, install `setuptools<58`, and install `requirements/ryu-legacy.txt` with `--no-build-isolation`. Do not “fix” the problem by installing random Eventlet versions into a shared system Python. Record any working environment change in this guide.

## The inference service reports `not_ready`

Check that `DDOS_MODEL_PATH` points to a readable project-owned artifact, `DDOS_MODEL_SHA256` is exactly 64 hexadecimal characters and matches `sha256sum`, and `DDOS_API_KEY` is set. Do not bypass checksum verification.

## No rows appear in PostgreSQL

Check `SDN_DB_ENABLED=true`, the local container health check, and the exported `.env` variables. The controller intentionally uses `NullMetricsStore` when the database is disabled.

## Mininet cannot connect

Confirm the controller is listening on port 6653, the topology uses OpenFlow 1.3, and stale OVS state has been cleared with `sudo mn -c` inside the VM. Do not expose the controller port to an untrusted network.
