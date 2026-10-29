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

After first-time setup, `docker compose up -d` uses [compose.yaml](compose.yaml)
to start the workspace and detector alongside the repository database. It reuses
[compose.lab.yaml](compose.lab.yaml) and [compose.detector.yaml](compose.detector.yaml):

- **`web`:** the GUI and its backend, accessed in your browser at http://localhost:8080.
- **`runner`:** Mininet, Open vSwitch, Ryu, and the tools used for lab experiments.
- **`inference`:** the existing attack-detection API.
- **`detector`:** the selectable LLM/entropy detection service, connected to the runner.
- **`postgres`:** the repository database, using its existing persistent volume.

For a separate PostgreSQL deployment, the explicit lab scripts remain available
as described below. Choose one Compose workflow; the default project and the
separate `sdn-lab` project both publish the workspace on port 8080.

### What your computer still needs

Use a dedicated, isolated Linux lab machine with local Docker Engine, Docker Compose 2.20.3 or newer (for `include`), Bash, Make, OpenSSL, and curl. Docker must run in its normal rootful mode, not rootless mode. This first version does not support Docker Desktop, macOS, Windows, or a remote Docker engine.

If Docker is not installed yet, install [Docker Engine](https://docs.docker.com/engine/install/) and the [Docker Compose plugin](https://docs.docker.com/compose/install/linux/) for your Linux distribution. Confirm both are available before continuing:

```bash
docker info
docker compose version
```

**A VM is not a runtime requirement on native Linux.** However, Docker containers share the host's Linux kernel. This runner needs the kernel's Open vSwitch networking support loaded on that host; that part is not provided by the container image. The command below enables that support, not a host installation of Mininet or Ryu.

Only the runner uses privileged Docker access so it can create virtual networks. The GUI and detection containers do not. Because that privilege gives the runner broad access to the host, do not run this stack on a production or shared machine, or expose the GUI to the Internet.

### First launch with the repository database

Run the following from the repository root. This is the shortest setup path when you use the PostgreSQL service in `compose.yaml` and its local-only example credentials. If its existing volume contains experiment records you care about, back it up before applying the migration.

```bash
# Preserve an existing configuration; create one only when it is missing.
test -f .env || cp .env.example .env

# Generate ignored local login credentials before any default Compose command.
# Re-running this keeps the existing credentials.
make lab-setup

# Start PostgreSQL, wait for it to be healthy, and add the GUI tables.
docker compose up -d --wait postgres
docker compose exec -T postgres psql -U sdn_user -d sdn_monitor \
  -v ON_ERROR_STOP=1 < database/migrations/002_lab.sql

# Load the host networking support required by the Mininet container.
# Run this only on the intended isolated lab machine.
sudo modprobe openvswitch
make lab-doctor

# Start the full workspace, including the detector (builds missing images).
docker compose up -d
```

The migration is additive and safe to repeat for the repository database. It is still necessary for a database volume created before the GUI tables were added. The first image build may take several minutes and several GB of disk space. Direct Compose commands do not run the host checks, so run `make lab-doctor` first as shown above.

Verify that the web service is ready:

```bash
curl -fsS http://localhost:8080/health
```

The expected response is `{"status":"ready"}`. Open **http://localhost:8080**, then print the login token locally and paste it into the login screen:

```bash
sed -n 's/^SDN_LAB_TOKEN=//p' .lab/env
```

Do not share the token or commit `.lab/env`. Choose the **small teaching topology** and click **Observe** to start Mininet without launching attack traffic.

### Using an existing or customized PostgreSQL container

Do not replace a working `.env` or database. Back up the database, then make sure these values describe the database from the two different connection points:

- `SDN_PG_DB`, `SDN_PG_USER`, and `SDN_PG_PASSWORD` match the database credentials.
- `SDN_PG_PORT` is the port published to the Linux host.
- `SDN_LAB_DB_NETWORK` is the database container's Docker network.
- `SDN_LAB_PG_HOST` is its alias on that Docker network; the lab containers always connect to its internal port `5432`.

The repository defaults are:

```dotenv
SDN_LAB_DB_NETWORK=sdn-ddos-detection-response_default
SDN_LAB_PG_HOST=postgres
```

Apply `database/migrations/002_lab.sql` explicitly with your database's container, user, and database names. Application startup never changes the schema automatically. After the migration, continue with `make lab-setup`, load `openvswitch`, run `make lab-doctor`, and then run `make lab-up` as shown above. See the [full GUI guide](docs/lab-workspace.md#start-with-your-existing-database) for the detailed database-network explanation.

A trained Random Forest model is not included; the baseline `inference` service
remains `not_ready` until you supply a verified model. The default Compose stack
connects the runner to `detector`, where you can choose **Entropy** without a model
artifact or **LLM** with a reachable Ollama server and installed model. Mitigation
is off by default. See [detection modes](docs/detection-modes.md).

### Starting again, stopping, and troubleshooting

After the first launch, use `docker compose up -d` to start the workspace and
detector. Use `docker compose up -d --build` after changing application code.
If the host rebooted, run `make lab-doctor` and load Open vSwitch if requested.

If the workspace is already running from `make lab-up` or `scripts/lab_detector.sh`,
stop any active run in the UI, then switch projects once:

```bash
bash scripts/lab_detector.sh down
docker compose up -d
```

The first command removes the old `sdn-lab` containers and leaves PostgreSQL and
its volume in place. Credentials in `.lab/env` are reused automatically. Refresh
the Detection tab after startup. For this default workflow, use the Detection tab
to choose the detector; `scripts/detector.sh` manages the separate `sdn-lab` project.

- `docker compose logs --tail 100 detector` shows recent detector logs.
- `docker compose ps` shows the services and their status.
- **Stop lab** in the GUI stops the active network. Closing the browser does not stop an experiment.
- `docker compose down` stops the default stack, including PostgreSQL; it retains the database volume. Do not add `-v` if you need the records.
- For the separate external-database workflow, keep using `make lab-up`, `make lab-logs`, and `make lab-down` (or `scripts/lab_detector.sh` for detection).

Common startup failures:

| Message or symptom | Resolution |
| --- | --- |
| `Open vSwitch is not loaded` | On the isolated lab host, run `sudo modprobe openvswitch`, then `make lab-doctor` again. If the module is unavailable, install kernel Open vSwitch support before continuing. |
| External database network does not exist | Start the repository database with `docker compose up -d postgres`, or correct `SDN_LAB_DB_NETWORK` for your existing container. |
| http://localhost:8080 does not respond | Run `docker compose logs --tail 100 web runner`. Also confirm the old `sdn-lab` project is stopped and port 8080 is available. |
| Detector reports `not_ready` | For LLM mode, check Ollama connectivity and the installed model, or select Entropy. The baseline `inference` service needs a verified model artifact. |

See the [full GUI guide](docs/lab-workspace.md) for topology editing, bounded experiments, replay, and limitations.

### What has actually been tested?

The images have been built and the automated tests have passed. The full live-network check—starting Mininet, sending bounded lab traffic, and checking monitoring and cleanup—has **not** been completed. The repository requires that privileged smoke test in an isolated VM before live integration is considered verified. That is a testing policy, not a requirement to install a VM for the native Linux container deployment. See the [verification record](docs/lab-verification.md).

## Manual VM/command-line setup

This is the separate, non-GUI workflow. Skip it if you are using the Docker GUI above.

The development environment uses Python 3.9+ with [`uv`](https://docs.astral.sh/uv/). Mininet, Open vSwitch, Ryu, `hping3`, and PostgreSQL are lab prerequisites; see [`docs/setup.md`](docs/setup.md).

```bash
test -e .env || cp .env.example .env
uv sync --group dev
make lab-setup  # credentials required when parsing the default Compose stack
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
