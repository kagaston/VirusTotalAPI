"""Tests for settings package: config constants and defaults."""

from __future__ import annotations

import os


class TestConfigDefaults:
    def test_virustotal_base_url(self):
        from settings.config import VIRUSTOTAL_BASE_URL

        if not os.getenv("VIRUSTOTAL_BASE_URL"):
            assert VIRUSTOTAL_BASE_URL == "https://www.virustotal.com/api/v3"

    def test_request_timeout_default(self):
        from settings.config import REQUEST_TIMEOUT

        expected = 30
        if not os.getenv("VT_REQUEST_TIMEOUT"):
            assert expected == REQUEST_TIMEOUT

    def test_log_format_default(self):
        from settings.config import LOG_FORMAT

        if not os.getenv("LOG_FORMAT"):
            assert LOG_FORMAT == "color"

    def test_log_level_default(self):
        from settings.config import LOG_LEVEL

        if not os.getenv("LOG_LEVEL"):
            assert LOG_LEVEL == "INFO"

    def test_api_key_defaults_empty(self):
        from settings.config import VIRUSTOTAL_API_KEY

        if not os.getenv("VIRUSTOTAL_API_KEY"):
            assert VIRUSTOTAL_API_KEY == ""
