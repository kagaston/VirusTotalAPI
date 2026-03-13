"""Tests for logger package: formatters, setup, rotating file, and get_logger."""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

import logger.config as _mod
from logger.config import (
    _DIM,
    _FUNC_COLOR,
    _LEVEL_COLORS,
    _NAME_COLOR,
    _RESET,
    _TIME_COLOR,
    ColorFormatter,
    JSONFormatter,
    PlainFormatter,
    ReadableFormatter,
    get_logger,
    setup_logging,
)


@pytest.fixture(autouse=True)
def _reset_logging():
    """Ensure every test starts with a clean logging state."""
    _mod._initialized = False
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.WARNING)
    yield
    _mod._initialized = False
    root.handlers.clear()
    root.setLevel(logging.WARNING)


def _make_record(
    level: int = logging.INFO,
    msg: str = "test message",
    name: str = "test",
) -> logging.LogRecord:
    return logging.LogRecord(
        name=name,
        level=level,
        pathname="test.py",
        lineno=42,
        msg=msg,
        args=(),
        exc_info=None,
        func="do_work",
    )


class TestColorFormatter:
    def test_output_contains_ansi_codes(self):
        fmt = ColorFormatter()
        out = fmt.format(_make_record())
        assert _RESET in out
        assert _NAME_COLOR in out
        assert _FUNC_COLOR in out
        assert _TIME_COLOR in out

    def test_level_colors_applied(self):
        fmt = ColorFormatter()
        for level_name, ansi in _LEVEL_COLORS.items():
            level = getattr(logging, level_name)
            out = fmt.format(_make_record(level=level, msg=f"at {level_name}"))
            assert ansi in out
            assert level_name in out

    def test_warning_message_is_tinted(self):
        fmt = ColorFormatter()
        out = fmt.format(_make_record(level=logging.WARNING, msg="danger"))
        assert _LEVEL_COLORS["WARNING"] in out.split("|")[-1]

    def test_info_message_not_tinted(self):
        fmt = ColorFormatter()
        out = fmt.format(_make_record(level=logging.INFO, msg="plain"))
        msg_part = out.split("|")[-1]
        assert _LEVEL_COLORS["INFO"] not in msg_part

    def test_funcname_and_lineno_present(self):
        fmt = ColorFormatter()
        out = fmt.format(_make_record())
        assert "do_work:42" in out

    def test_exception_rendered_dim(self):
        fmt = ColorFormatter()
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            exc = sys.exc_info()
        record = _make_record(level=logging.ERROR, msg="fail")
        record.exc_info = exc
        out = fmt.format(record)
        assert _DIM in out
        assert "RuntimeError" in out


class TestPlainFormatter:
    def test_no_ansi_codes(self):
        fmt = PlainFormatter()
        out = fmt.format(_make_record())
        assert "\033[" not in out

    def test_contains_level_and_message(self):
        fmt = PlainFormatter()
        out = fmt.format(_make_record(level=logging.WARNING, msg="watch out"))
        assert "WARNING" in out
        assert "watch out" in out

    def test_readable_formatter_is_alias(self):
        assert ReadableFormatter is PlainFormatter


class TestJSONFormatter:
    def test_format_produces_valid_json(self):
        fmt = JSONFormatter()
        out = fmt.format(_make_record())
        parsed = json.loads(out)
        assert parsed["level"] == "INFO"
        assert parsed["msg"] == "test message"
        assert "ts" in parsed

    def test_format_includes_exception(self):
        fmt = JSONFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            exc_info = sys.exc_info()
        record = _make_record(level=logging.ERROR, msg="fail")
        record.exc_info = exc_info
        parsed = json.loads(fmt.format(record))
        assert "exception" in parsed
        assert "ValueError" in parsed["exception"]


class TestSetupLogging:
    def test_returns_named_logger(self):
        log = setup_logging("myapp")
        assert log.name == "myapp"

    def test_default_app_name(self):
        log = setup_logging()
        assert log.name == "vt"

    def test_creates_console_handler(self):
        setup_logging()
        root = logging.getLogger()
        assert any(isinstance(h, logging.StreamHandler) for h in root.handlers)

    def test_json_format_via_env(self):
        with patch.dict(os.environ, {"LOG_FORMAT": "json"}):
            setup_logging()
        root = logging.getLogger()
        ch = root.handlers[0]
        assert isinstance(ch.formatter, JSONFormatter)

    def test_plain_format_via_env(self):
        with patch.dict(os.environ, {"LOG_FORMAT": "plain"}):
            setup_logging()
        root = logging.getLogger()
        ch = root.handlers[0]
        assert isinstance(ch.formatter, PlainFormatter)

    def test_verbose_sets_debug_level(self):
        setup_logging(verbose=True)
        root = logging.getLogger()
        ch = next(h for h in root.handlers if isinstance(h, logging.StreamHandler))
        assert ch.level == logging.DEBUG

    def test_noisy_loggers_suppressed(self):
        setup_logging()
        for name in ("urllib3", "httpx", "httpcore"):
            assert logging.getLogger(name).level == logging.WARNING

    def test_rotating_file_handler(self):
        with tempfile.TemporaryDirectory() as tmp:
            setup_logging("test_app", log_dir=tmp)
            root = logging.getLogger()
            from logging.handlers import RotatingFileHandler

            rfh = [h for h in root.handlers if isinstance(h, RotatingFileHandler)]
            assert len(rfh) == 1
            assert Path(rfh[0].baseFilename).name == "test_app.log"

    def test_no_console_when_disabled(self):
        setup_logging(console=False)
        root = logging.getLogger()
        stream_handlers = [
            h for h in root.handlers if isinstance(h, logging.StreamHandler) and not hasattr(h, "baseFilename")
        ]
        assert len(stream_handlers) == 0


class TestGetLogger:
    def test_returns_namespaced_logger(self):
        log = get_logger("client")
        assert log.name == "vt.client"

    def test_returns_logger_instance(self):
        log = get_logger("scanner")
        assert isinstance(log, logging.Logger)

    def test_different_names_return_different_loggers(self):
        a = get_logger("alpha")
        b = get_logger("bravo")
        assert a is not b
