# SDN DDoS Detection and Response

Undergraduate research by **Natan Gabriel Medina Corea**, supervised by **David Alberto Guzmán Ardila**, **Dr. Deisy Chaves Sanchez**, and **Dr. Maria Patricia Trujillo Uribe**.

The project investigates the following question:

> How can a Software-Defined Network efficiently detect and mitigate DDoS attacks against the controller while preserving business-service performance and keeping implementation costs low?

The approved project objective is to design and simulate a mechanism to detect and respond to DDoS attacks in SDN networks under business-like scenarios. This repository contains the working baseline: a Mininet topology, a Ryu/OpenFlow 1.3 controller, flow and port monitoring, an authenticated inference API, PostgreSQL metrics storage, and a bounded lab-only traffic generator.

## Important status note

This is an **alpha research baseline**, not a production defense and not the completed thesis mechanism. The current code uses a Random Forest-compatible inference contract and temporary source-IP drop rules. The proposal’s entropy confirmation, prompt-driven 3B LLM, persistent blacklist escalation, rate limiting, larger topologies, and complete evaluation suite are documented as roadmap work in [`docs/current-vs-proposed.md`](docs/current-vs-proposed.md).

## Safety

Run experiments only inside an isolated Mininet/VMware lab that you own or are explicitly authorized to test. The attack launcher refuses public targets, requires `--confirm-isolated-lab`, and has hard duration/rate limits. Never point it at an Internet, campus, corporate, or third-party address. See [`SECURITY.md`](SECURITY.md) and [`docs/experiments.md`](docs/experiments.md).

## Quick start

The normal development environment is Python 3.9+ with [`uv`](https://docs.astral.sh/uv/). Mininet, Open vSwitch, Ryu, `hping3`, and PostgreSQL are lab prerequisites; see [`docs/setup.md`](docs/setup.md).

```bash
cp .env.example .env
uv sync --group dev
docker compose up -d postgres
set -a; . .env; set +a
```

Start the inference service, controller, and topology in separate terminals as described in the setup guide. A model is intentionally not included. Until a project-owned model is supplied with a verified `DDOS_MODEL_SHA256`, the service reports `not_ready` and the controller safely continues in monitoring-only mode.

## Repository map

```text
src/sdn_ddos/
├── controller/       # Ryu app and testable controller logic
├── detection/        # FastAPI API and verified model loading
├── topology/         # Mininet topology and topology specification
├── experiments/      # bounded, authorized lab experiment launcher
└── storage.py        # PostgreSQL and no-op persistence implementations
database/schema.sql   # canonical metrics/event schema
config/topology.json  # human-readable topology inventory
tests/                # dependency-light unit tests
docs/                 # research, architecture, setup, and experiment guides
```

## Quality commands

```bash
make sync
make check
```

`make check` runs formatting, Ruff, mypy, unit tests, shell syntax checks, and topology JSON validation. The full Mininet/Open vSwitch smoke test is manual and must be run only in the isolated lab.

## Attribution and references

The implementation is released under Apache-2.0. Research references are listed in [`docs/references.md`](docs/references.md); copyrighted papers and local security reports are deliberately not redistributed here. See [`CITATION.cff`](CITATION.cff) for citation metadata.
