"""Tests for the CLI entry point."""

import pytest

from virustotal.cli import main


class TestCLI:
    def test_no_args_exits_with_error(self):
        with pytest.raises(SystemExit, match="1"):
            main([])

    def test_unknown_command_exits_with_error(self):
        with pytest.raises(SystemExit):
            main(["nonexistent"])
