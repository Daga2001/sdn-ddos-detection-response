# SDN DDoS Detection and Response

Undergraduate research by **Natan Gabriel Medina Corea**, supervised by **David Alberto Guzmán Ardila**, **Dr. Deisy Chaves Sanchez**, and **Dr. Maria Patricia Trujillo Uribe**.

The project investigates the following question:

> How can a Software-Defined Network efficiently detect and mitigate DDoS attacks against the controller while preserving business-service performance and keeping implementation costs low?

The approved project objective is to design and simulate a mechanism to detect and respond to DDoS attacks in SDN networks under business-like scenarios. This repository contains the working baseline: a Mininet topology, a Ryu/OpenFlow 1.3 controller, flow and port monitoring, an authenticated inference API, PostgreSQL metrics storage, and a bounded lab-only traffic generator.

## Important status note

This is an **alpha research baseline**, not a production defense and not the completed thesis mechanism. The current code uses a Random Forest-compatible inference contract and temporary source-IP drop rules. The proposal’s entropy confirmation, prompt-driven 3B LLM, persistent blacklist escalation, rate limiting, larger topologies, and complete evaluation suite are documented as roadmap work in [`docs/current-vs-proposed.md`](docs/current-vs-proposed.md).

## Safety

Run experiments only inside an isolated Mininet lab that you own or are explicitly authorized to test. The attack launcher refuses public targets, requires `--confirm-isolated-lab`, and has hard duration/rate limits. Never point it at an Internet, campus, corporate, or third-party address. See [`SECURITY.md`](SECURITY.md) and [`docs/experiments.md`](docs/experiments.md).

## Quick start

Choose one way to run the lab. You do not need to follow both:

- **Browser GUI with Docker:** follow the section below to edit topologies, watch traffic and command output, and replay recorded experiments.
- **Manual VM/command-line setup:** use the [VM/CLI instructions](#manual-vmcommand-line-setup) if you want to start each component yourself.

## Optional graphical container workspace

**The GUI and Mininet lab run in Docker. You do not install Mininet, Ryu, Python libraries, or Node.js on your computer for this option.** Docker builds the application images and installs those dependencies inside them.

The [Docker Compose file](compose.lab.yaml) starts three containers together:

- **`web`:** the GUI and its backend, accessed in your browser at http://localhost:8080.
- **`runner`:** Mininet, Open vSwitch, Ryu, and the tools used for lab experiments.
- **`inference`:** the existing attack-detection API.

Your **existing PostgreSQL container stays separate**. The GUI stack connects to it; it does not replace it. The containers keep the current technologies rather than introducing a different network simulator.

### What your computer still needs

Use a dedicated, isolated Linux lab machine with local Docker Engine, Docker Compose, Bash, Make, and OpenSSL. Docker must run in its normal rootful mode, not rootless mode. This first version does not support Docker Desktop, macOS, Windows, or a remote Docker engine.

**A VM is not a runtime requirement on native Linux.** However, Docker containers share the host's Linux kernel. This runner needs the kernel's Open vSwitch networking support loaded on that host; that part is not provided by the container image. The command below enables that support, not a host installation of Mininet or Ryu.

Only the runner uses privileged Docker access so it can create virtual networks. The GUI and detection containers do not. Because that privilege gives the runner broad access to the host, do not run this stack on a production or shared machine, or expose the GUI to the Internet.

### First-time setup

Run these commands from the repository root, on the machine where Docker runs.

1. **Keep your existing database and configuration.** Keep your working `.env`; if it is missing, copy `.env.example` to `.env` and configure it. Its `SDN_PG_DB`, `SDN_PG_USER`, and `SDN_PG_PASSWORD` must match your running database. These defaults connect to the repository's existing database container:

   ```dotenv
   SDN_LAB_DB_NETWORK=sdn-ddos-detection-response_default
   SDN_LAB_PG_HOST=postgres
   ```

   For a different container, use its Docker network name and database network alias. Keep `SDN_PG_PORT` set to your database's host port; the lab containers use internal port 5432. If you have no database yet, follow the [database setup](docs/setup.md#database) first; you can skip that guide's manual Mininet/Ryu installation.

2. **Back up the database, then add the GUI's tables.** For the repository's database, run:

   ```bash
   docker compose exec -T postgres psql -U sdn_user -d sdn_monitor \
     -v ON_ERROR_STOP=1 < database/migrations/002_lab.sql
   ```

   Use your own database/user names if different. This migration adds storage for saved topologies and experiment history; it does not delete existing records. A fresh database created from the current `database/schema.sql` already has these tables. Startup does not apply migrations for you.

3. **Create login credentials and check the host:**

   ```bash
   make lab-setup
   make lab-doctor
   ```

   Setup creates private credentials in `.lab/env`; it keeps them if you run it again. Doctor only checks the environment. If it says Open vSwitch is not loaded, run the following **on the intended isolated lab host**, then repeat the check:

   ```bash
   sudo modprobe openvswitch
   make lab-doctor
   ```

   If that command reports a missing module, the host needs kernel support before this runner can start. Do not skip the check.

4. **Build and start the Docker containers:**

   ```bash
   make lab-up
   ```

   This is a Docker shortcut, not a command that installs the lab on your host. After checking the environment, it runs:

   ```bash
   docker compose --env-file .env --env-file .lab/env \
     -f compose.lab.yaml up --build -d
   ```

   You do not need to run both commands. Allow several minutes and several GB of disk space for the first build.

5. **Open http://localhost:8080 in your browser.** Open `.lab/env` locally and paste only the value of `SDN_LAB_TOKEN` into the login screen. Do not share or commit that file. Choose the small teaching topology and click **Observe** to start a network without launching an attack. You can then inspect devices, capture bounded packet headers, and import/export topologies.

A trained model is not included. You can use the editor and observe traffic without one, but actual model-based detection remains `not_ready` until you supply a verified model. Mitigation is off by default.

### Starting again, stopping, and troubleshooting

After the first-time setup, use `make lab-up` to start the workspace. If the host rebooted, you may need to load Open vSwitch again when the host check asks.

- `make lab-logs` shows the recent container logs if startup fails.
- **Stop lab** in the GUI stops the active network. Closing the browser does not stop an experiment.
- `make lab-down` stops and removes the GUI stack's containers, but leaves your separate PostgreSQL container and saved records in place.

See the [full GUI guide](docs/lab-workspace.md) for topology editing, bounded experiments, replay, and limitations.

### What has actually been tested?

The images have been built and the automated tests have passed. The full live-network check—starting Mininet, sending bounded lab traffic, and checking monitoring and cleanup—has **not** been completed. The repository requires that privileged smoke test in an isolated VM before live integration is considered verified. That is a testing policy, not a requirement to install a VM for the native Linux container deployment. See the [verification record](docs/lab-verification.md).

## Manual VM/command-line setup

This is the separate, non-GUI workflow. Skip it if you are using the Docker GUI above.

The development environment uses Python 3.9+ with [`uv`](https://docs.astral.sh/uv/). Mininet, Open vSwitch, Ryu, `hping3`, and PostgreSQL are lab prerequisites; see [`docs/setup.md`](docs/setup.md).

```bash
test -e .env || cp .env.example .env
uv sync --group dev
docker compose up -d postgres
set -a; . .env; set +a
```

Start the inference service, controller, and topology in separate terminals as described in the setup guide. Until a project-owned model is supplied with a verified `DDOS_MODEL_SHA256`, the service reports `not_ready` and the controller safely continues in monitoring-only mode.

## Repository map

```text
src/sdn_ddos/
├── controller/       # Ryu app and testable controller logic
├── detection/        # FastAPI API and verified model loading
├── topology/         # Mininet topology and topology specification
├── experiments/      # bounded, authorized lab experiment launcher
├── lab/              # GUI API, validated topology, isolated runner, replay store
└── storage.py        # PostgreSQL and no-op persistence implementations
database/schema.sql   # canonical metrics/event schema
web/                  # React/TypeScript topology and observation workspace
compose.lab.yaml      # optional lab stack; existing database is external
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
