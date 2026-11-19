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

For a separate PostgreSQL deployment, select external-database mode in `.env`
as described below. Both database modes use this same Compose project and startup
command; the former `sdn-lab` startup wrappers are retired.

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
- Set `COMPOSE_PROFILES=` and `SDN_LAB_DB_EXTERNAL=true` to use an external database without starting the repository PostgreSQL service.
- `SDN_LAB_DB_NETWORK` is the database container's Docker network.
- `SDN_LAB_PG_HOST` is its alias on that Docker network; the lab containers always connect to its internal port `5432`.

The repository defaults are:

```dotenv
COMPOSE_PROFILES=local-db
SDN_LAB_DB_EXTERNAL=false
SDN_LAB_DB_NETWORK=sdn-ddos-detection-response_default
SDN_LAB_PG_HOST=postgres
```

Apply `database/migrations/002_lab.sql` explicitly with your database's container, user, and database names. Application startup never changes the schema automatically. After the migration, continue with `make lab-setup`, load `openvswitch`, run `make lab-doctor`, and then run `docker compose up` as shown above. See the [full GUI guide](docs/lab-workspace.md#start-with-your-existing-database) for the detailed database-network explanation.

A trained Random Forest model is not included; the baseline `inference` service
remains `not_ready` until you supply a verified model. The default Compose stack
connects the runner to `detector`, where you can choose **Entropy** without a model
artifact or **LLM** with a reachable Ollama server and installed model. Mitigation
is off by default. See [detection modes](docs/detection-modes.md).

### Starting again, stopping, and troubleshooting

After the first launch, use `docker compose up -d` to start the workspace and
detector. Use `docker compose up -d --build` after changing application code.
If the host rebooted, run `make lab-doctor` and load Open vSwitch if requested.

`docker compose up` is the only supported startup entry point. The root file pins
one project name and includes the detector. The former Make targets and lab
startup wrappers no longer launch a separate project. `scripts/detector.sh`
now manages the same detector as the GUI.

For existing configurations, add `COMPOSE_PROFILES=local-db` and
`SDN_LAB_DB_EXTERNAL=false` when using the repository PostgreSQL container. For
an external database, leave `COMPOSE_PROFILES` empty and set
`SDN_LAB_DB_EXTERNAL=true` with its network and host.

- `docker compose logs --tail 100 detector` shows recent detector logs.
- `docker compose ps` shows the services and their status.
- **Stop lab** stops the active network. Refreshing or closing the tab that started a GUI run, or locking its login session, also requests an immediate stop. Other viewing tabs do not own that run.
- The interface shows **Stopping** until process cleanup finishes. Silent browser/network failures require detection: native WebSocket ping/pong uses a one-second interval and two-second response timeout; a five-second runner lease covers loss of the web service. There is no extra grace period after detection.
- Bounded scripts that start experiments through the API without browser ownership keep their declared lifetimes. Replay never starts traffic.
- `docker compose down` stops the canonical stack and retains its volume. Never add `-v` when keeping experiment records. An external database is not managed by this stack.

**Migrating an already duplicated deployment:** stop each runner directly and
wait for its cleanup; a shared `runner` hostname can address the wrong one in
the old deployment. Remove only the obsolete `sdn-lab` containers and their
private networks, preserving the shared database and its volume. Rebuild the
canonical services with `docker compose up -d --build`. A database advisory lock
now prevents a second updated runner from opening the same database, and the
web service uses a runner address present only on its private control network.

Common startup failures:

| Message or symptom | Resolution |
| --- | --- |
| `Open vSwitch is not loaded` | On the isolated lab host, run `sudo modprobe openvswitch`, then `make lab-doctor` again. If the module is unavailable, install kernel Open vSwitch support before continuing. |
| External database network does not exist | Enable `COMPOSE_PROFILES=local-db` for the managed database, or set `SDN_LAB_DB_EXTERNAL=true` and correct `SDN_LAB_DB_NETWORK` for an external database. |
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

## Key design decisions

The decisions below shape what the experiments can and cannot show. Each one names the
reason and where the evidence or the standard is. Change one only together with its
entry here, its test, and the thesis report.

| # | Decision | Why | Evidence / source |
|---|---|---|---|
| 1 | Ryu, OpenFlow 1.3, Mininet and Open vSwitch | Open source, reproducible, real controller and switch code | `docs/decisions/0001`, `0002`; Lantz et al. 2010 |
| 2 | Two forwarding modes: per-port and port-free, chosen per run (no default) | Per-port rules expose control-plane saturation (SO1); port-free compares detectors on equal terms (SO3) | `src/sdn_ddos/controller/app.py`; report 3.3.3 |
| 3 | hping3 floods to port 8080 with the source port incremented per packet; every attacker floods every victim; rate is per attack flow | With per-port rules the victim's replies need a new rule per packet; bounded, non-spoofed traffic | `experiments/attack_launcher.py`, `lab/contracts.py` (`attack_plan`); hping3(8) |
| 4 | Three detectors behind one API: LLM, packet-rate rule, entropy; one at a time | The rule is the LLM prompt's own decision rule, so what the model adds can be measured (Arp et al. 2022) | `detection/service.py`, `detection/rule.py` |
| 5 | LLM: Llama 3.2 3B local, temperature 0, seed 42, verdict cache, threshold 0.8 fixed in advance | Deterministic, runs on consumer GPU; a threshold tuned on reported runs would be data snooping | `detection/llm_api.py` |
| 6 | Asynchronous judging, newest poll per switch replaces an unjudged one | Ryu is single-threaded; waiting for the LLM held up legitimate flows | report Appendix C |
| 7 | One response for every detector: block after 2 detections in 30 s, 300 s, servers protected, never permanent | Same design as Snort `detection_filter`, Suricata `threshold`, fail2ban; one detection blocked legitimate hosts in development | `lab/contracts.py` (`ResponseParams`); `docs/thesis-campaign.md` §6 |
| 8 | Ground truth from the experiment definition; main unit host per run | Detectors cannot grade themselves; units are never mixed | `web/src/results.ts` |
| 9 | Run purpose, settings fingerprint, commit and prompt hash recorded per run; only held-out runs reported | Separates tuning from evaluation (Arp et al. 2022) | `lab/provenance.py`, `scripts/compare_runs.py` |
| 10 | 10 runs per cell in randomized complete blocks | RFC 8456 §4.7; randomized blocks keep an interrupted campaign balanced (NIST/SEMATECH 5.3.3.2) | `scripts/campaign/lab_campaign.py --rounds` |
| 11 | Wilson intervals for proportions, Mann–Whitney U for comparisons | Small samples, no normality assumed (Wilson 1927; Brown et al. 2001) | `src/sdn_ddos/analysis/compare.py` |
| 12 | TC-1 emulates a hardware flow table of 1 500 rules (`flow_limit`, `overflow_policy=refuse`) | Open vSwitch keeps rules in RAM with no small limit; 1 500 is the HP ProCurve 5406zl table measured by Kuźniar et al. (PAM 2015) | `lab/runtime.py` (`flow_limit_command`) |
| 13 | Thesis campaign phases 180/120/120 s (TC-5: 300 s of attack), original entropy preset (5 s windows), polling interval chosen by a pilot (1 s), settings frozen after a calibration | The design run on 18–19 Nov 2026; entropy warm-up 16 × 5 s = 80 s plus margin; pilot rule stated before the pilot; freeze 2026-11-18T14:11:20Z (`fee8ae6`) | `scripts/campaign/scenarios.py`; `docs/thesis-campaign.md` §0 |
| 14 | Optional cloud LLM backend (OpenAI-compatible; OpenRouter primary, explicit-model fallback), Ollama stays the default and the only thesis backend | Lets the lab run without a local GPU; cloud runs use another model name, so they get another settings fingerprint and are never pooled with Ollama runs; their cost includes the internet round trip | `detection/llm_api.py` (`query_cloud_chain`); `docs/detection-modes.md` |
| 15 | A "not DDoS" LLM verdict is worth at most 0.5 probability of attack (`min(1 − confidence, 0.5)`) | Offline probe of the `lab` prompt: 343 of 503 flagged answers were `is_ddos=false, confidence=0.0`, which `1 − confidence` turned into 1.0; with the 0.8 threshold a negative verdict can no longer be flagged | `detection/llm_api.py` (`to_prediction`); `docs/detection-modes.md` |
| 16 | Protected hosts (the servers and the experiment's victims) are never named by any detector and take no LLM or rule samples | A victim's replies have the flood's rate; naming it would be a self-inflicted denial of service (seen with entropy in development); one test for detectors and response | `controller/response.py` (`is_protected`); `lab/contracts.py` (`protect_victims`) |
| 17 | With port-free forwarding, TCP/UDP flows reach the model with port 0 | Port-free rules match no layer-4 port, so those flows had no port and were dropped before the model while entropy counted them | `controller/core.py` (`build_model_sample`) |

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
