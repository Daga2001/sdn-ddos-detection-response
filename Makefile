.PHONY: sync format format-check lint type-check test check db-up db-down

sync:
	uv sync --group dev

format:
	uv run ruff format .
	uv run ruff check --fix .

format-check:
	uv run ruff format --check .

lint:
	uv run ruff check .

type-check:
	uv run mypy src/sdn_ddos

test:
	uv run pytest

check: format-check lint type-check test
	bash -n scripts/*.sh
	python -m json.tool config/topology.json >/dev/null

db-up:
	docker compose up -d postgres

db-down:
	docker compose down
