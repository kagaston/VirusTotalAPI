"""Nox sessions for CI validation."""

import nox

nox.options.default_venv_backend = "uv"

PYTHON_VERSION = "3.11"
PYPROJECT = nox.project.load_toml("pyproject.toml")
DEV_DEPS = nox.project.dependency_groups(PYPROJECT, "dev")


@nox.session(python=PYTHON_VERSION)
def format(session: nox.Session) -> None:
    """Check code formatting with ruff (no fixes)."""
    session.install(*DEV_DEPS)
    session.run("ruff", "format", "--check", "app/*/src/", "app/*/tests/")


@nox.session(python=PYTHON_VERSION)
def lint(session: nox.Session) -> None:
    """Lint the codebase using ruff (no fixes)."""
    session.install(*DEV_DEPS)
    session.run("ruff", "check", "app/*/src/", "app/*/tests/")


@nox.session(python=PYTHON_VERSION)
def typecheck(session: nox.Session) -> None:
    """Type check using basedpyright."""
    session.install(*DEV_DEPS)
    session.install(".")
    session.run("basedpyright", "app/*/src/")


@nox.session(python=PYTHON_VERSION)
def tests(session: nox.Session) -> None:
    """Run the test suite."""
    session.install(*DEV_DEPS)
    session.install(".")
    session.run("pytest", "app/*/tests/", *session.posargs)
