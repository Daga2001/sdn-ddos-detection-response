.PHONY: sync format format-check lint type-check test check

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

.PHONY: lab-setup lab-doctor web-check
lab-setup:
	bash scripts/lab.sh setup
lab-doctor:
	bash scripts/lab.sh doctor
web-check:
	cd web && npm ci && npm run format-check && npm run build && npm test
