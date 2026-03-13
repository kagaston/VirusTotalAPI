[private]
default:
    @just --list --unsorted

sync:
    uv sync

format:
    uv run ruff format app/*/src/ app/*/tests/

lint:
    uv run ruff check --fix app/*/src/ app/*/tests/

typecheck:
    uv run basedpyright app/*/src/

test pkg="*":
    uv run pytest app/{{pkg}}/tests/ -v --tb=short

test-cov:
    uv run pytest app/*/tests/ --cov=app --cov-report=term-missing --tb=short

check:
    uv run nox

build:
    uv build

clean:
    rm -rf dist/ build/ .pytest_cache/ .basedpyright/
    find . -type d -name __pycache__ -exec rm -rf {} +

update:
    uv lock --upgrade

preflight: format lint typecheck test
