FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    UV_PYTHON_INSTALL_DIR=/opt/python SDN_LAB_RUNNER=1 PYTHONPATH=/app/src
COPY --from=ghcr.io/astral-sh/uv:0.8.22 /uv /usr/local/bin/uv
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates build-essential python3 python3-venv python3-dev \
    mininet openvswitch-switch iproute2 iputils-ping hping3 tshark curl \
    procps util-linux kmod && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY requirements/ryu-legacy.txt ./requirements/
# Runtime uses the distro interpreter to see the distro Mininet package.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv venv --python /usr/bin/python3 --system-site-packages /opt/lab && \
    uv export --frozen --no-dev --no-emit-project --output-file /tmp/runtime.txt >/dev/null && \
    uv pip install --python /opt/lab/bin/python -r /tmp/runtime.txt
RUN --mount=type=cache,target=/root/.cache/uv \
    uv python install 3.9 && uv venv --python 3.9 /opt/ryu && \
    uv pip install --python /opt/ryu/bin/python 'setuptools==57.5.0' 'wheel==0.45.1' 'pip==24.3.1' 'pbr==5.11.1' && \
    uv pip install --python /opt/ryu/bin/python --no-build-isolation \
      -r requirements/ryu-legacy.txt 'psutil==7.0.0' 'requests==2.32.5' 'psycopg2-binary==2.9.10'
COPY src/ ./src/
RUN /opt/ryu/bin/python -c 'from ryu.cmd.manager import main; import sdn_ddos.controller.app' && \
    /opt/lab/bin/python -c 'from mininet.net import Mininet; import sdn_ddos.lab.worker'
COPY containers/runner-entrypoint.sh /usr/local/bin/runner-entrypoint
ENTRYPOINT ["bash", "/usr/local/bin/runner-entrypoint"]
