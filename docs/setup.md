# Reproducible setup

This guide covers the **manual VM/command-line workflow**. If you want the browser GUI with Mininet in Docker, follow the [Docker GUI startup instructions](../README.md#optional-graphical-container-workspace) instead. You do not need to install this guide's Mininet/Ryu packages or Python environments on the host for that option.

## Recommended environment

Use an isolated Ubuntu VM as described in the proposal (VMware or another local hypervisor). Give the VM enough CPU and RAM for Open vSwitch, Mininet, PostgreSQL, and the controller. Do not bridge experiment traffic to an uncontrolled physical interface.

Install system packages inside the VM:

```bash
sudo apt update
sudo apt install -y git curl build-essential openvswitch-switch mininet hping3 iperf3 postgresql-client
```

Install [`uv`](https://docs.astral.sh/uv/) and create the project environment:

```bash
uv sync --group dev
cp .env.example .env
set -a; . .env; set +a
```

The application supports Python 3.9 through the current supported Python versions. The legacy Ryu environment is specifically pinned to Python 3.9 because the published Ryu package has old Eventlet/setuptools assumptions:

```bash
python3.9 -m venv .venv-ryu
source .venv-ryu/bin/activate
python -m pip install --upgrade 'pip<24' 'setuptools==57.5.0' 'wheel==0.45.1' 'pbr==5.11.1'
python -m pip install --no-build-isolation -r requirements/ryu-legacy.txt
```

## Database

```bash
docker compose up -d postgres
docker compose exec -T postgres pg_isready -U sdn_user -d sdn_monitor
```

The compose service applies [`database/schema.sql`](../database/schema.sql) on first initialization. The example credentials are for the disposable local container only.

## Start order

Terminal 1, inference service:

```bash
set -a; . .env; set +a
scripts/run_inference.sh
```

Terminal 2, controller (with `.venv-ryu` active):

```bash
set -a; . .env; set +a
scripts/run_controller.sh
```

Terminal 3, topology:

```bash
set -a; . .env; set +a
sudo -E uv run sdn-ddos-topology
```

The first health response should be `not_ready` until a trusted project-owned model is supplied. Monitoring-only operation is expected with mitigation disabled.

## Model supply

Do not download or load an arbitrary pickle. Follow [`model-card-template.md`](model-card-template.md), place the approved artifact outside Git, calculate its SHA-256, and set `DDOS_MODEL_PATH` and `DDOS_MODEL_SHA256` in `.env`. The service must report `ready` before model-backed experiments begin.
