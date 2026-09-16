# Agent and contributor guide

This file is the canonical instruction source for coding agents. `AGENT.md`, `CLAUDE.md`, and `.github/copilot-instructions.md` point here.

## Mission and boundaries

This repository supports an undergraduate, reproducible SDN security experiment. Prefer small, testable changes that improve evidence quality, repeatability, and safety. It is not an authorization to scan or attack any network outside the isolated Mininet lab.

Never commit credentials, private keys, passphrases, database URLs, proxy lists, raw attack logs, packet captures, virtual environments, caches, or unverified model artifacts. Never add a command that targets a user-supplied public address or launches an unbounded flood. Keep mitigation disabled by default.

## Current architecture

- `src/sdn_ddos/controller/app.py` is a Ryu OpenFlow 1.3 learning switch. It polls flow/port statistics, calls the local inference API, records metrics, and can install temporary source-IP drop rules.
- `src/sdn_ddos/detection/api.py` exposes authenticated `GET /health` and `POST /predict`. Model loading requires an explicit path and SHA-256 checksum.
- `src/sdn_ddos/topology/enterprise.py` builds the implemented four-switch/nine-host Mininet topology. `topology/spec.py` is dependency-free and is the source for inventory tests.
- `src/sdn_ddos/experiments/attack_launcher.py` is a bounded SYN-rate generator for private Mininet addresses only.
- `src/sdn_ddos/storage.py` buffers PostgreSQL inserts. `NullMetricsStore` is used when `SDN_DB_ENABLED=false`.
- `database/schema.sql` is the canonical schema; do not reintroduce remote database defaults or hidden DDL migrations in application startup.

The proposal and implementation are intentionally tracked separately. Update `docs/current-vs-proposed.md` whenever behavior changes.

## Development workflow

1. Read the relevant architecture and experiment documentation before changing behavior.
2. Use `uv sync --group dev` and work from the repository root.
3. Add or update unit tests before changing security-sensitive behavior.
4. Run `make check`. Use a privileged Mininet smoke test only in the isolated VM.
5. Update README/docs, `.env.example`, and the model card when interfaces or experiment assumptions change.

## Interface rules

- Preserve the six-feature order in `sdn_ddos.controller.core.FEATURE_ORDER` unless the model contract and migration notes change together.
- Keep `/predict` authentication, bounded batches, strict input validation, and generic error messages.
- Validate every mitigation source against `SDN_ALLOWED_TARGET_CIDRS`; never bypass `BlockRegistry`.
- Use parameterized SQL and keep event timestamps in UTC.
- Do not load a pickle/joblib model before checksum verification.
- Keep subprocess calls argument-array based (`shell=False`); retain explicit duration, rate, and process cleanup.

## Testing expectations

Tests must cover happy paths and failure paths: invalid configuration, missing model, bad authentication, malformed predictions, counter resets, duplicate/unsafe blocks, unsafe targets, subprocess cleanup, and topology inventory. Tests must not send traffic, require root, or connect to a real database.

## Definition of done

A change is ready only when it has focused tests, updated documentation, no new secrets or generated artifacts, passing `make check`, and an accurate note in the current-status/roadmap documentation. Before merge, conduct the five-axis review described by the code-review-and-quality skill.
