.PHONY: lint format-check test check

lint:
	uv run --extra dev ruff check .

format-check:
	uv run --extra dev ruff format --check .

test:
	uv run --extra dev pytest -q

check: lint format-check test
