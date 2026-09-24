FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:0.8.22 /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/
RUN uv sync --frozen --no-dev && useradd --uid 10001 --create-home lab
USER 10001:10001
CMD ["/app/.venv/bin/uvicorn", "sdn_ddos.detection.api:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
