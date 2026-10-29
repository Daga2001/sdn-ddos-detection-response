FROM node:24-bookworm-slim AS frontend
WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SDN_LAB_STATIC=/app/web/dist
WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:0.8.22 /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/
RUN uv sync --frozen --no-dev && useradd --uid 10001 --create-home lab
COPY --from=frontend /build/web/dist ./web/dist
USER 10001:10001
CMD ["/app/.venv/bin/uvicorn", "sdn_ddos.lab.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-access-log", "--ws", "websockets", "--ws-ping-interval", "1", "--ws-ping-timeout", "2", "--ws-max-size", "1024"]
