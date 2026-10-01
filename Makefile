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
	for script in scripts/*.sh containers/*.sh; do bash -n "$$script"; done
	python -m json.tool config/topology.json >/dev/null

db-up:
	docker compose up -d postgres

db-down:
	docker compose down

.PHONY: lab-setup lab-doctor lab-up lab-down lab-logs web-check
lab-setup:
	bash scripts/lab.sh setup
lab-doctor:
	bash scripts/lab.sh doctor
lab-up:
	bash scripts/lab.sh up
lab-down:
	bash scripts/lab.sh down
lab-logs:
	bash scripts/lab.sh logs
web-check:
	cd web && npm ci && npm run format-check && npm run build && npm test
