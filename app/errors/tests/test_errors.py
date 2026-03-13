"""Tests for errors package: exception hierarchy and handle_error dispatch."""

from __future__ import annotations

from errors.handler import (
    AuthenticationError,
    ConfigError,
    RateLimitError,
    ReportError,
    ScanError,
    VTError,
    handle_error,
)


class TestExceptionHierarchy:
    def test_vt_error_is_exception(self):
        assert issubclass(VTError, Exception)

    def test_scan_error_inherits(self):
        assert issubclass(ScanError, VTError)

    def test_report_error_inherits(self):
        assert issubclass(ReportError, VTError)

    def test_authentication_error_inherits(self):
        assert issubclass(AuthenticationError, VTError)

    def test_rate_limit_error_inherits(self):
        assert issubclass(RateLimitError, VTError)

    def test_config_error_inherits(self):
        assert issubclass(ConfigError, VTError)


class TestVTErrorResource:
    def test_message_preserved(self):
        exc = VTError("something broke")
        assert str(exc) == "something broke"

    def test_resource_kwarg_stored(self):
        exc = VTError("scan failed", resource="https://example.com")
        assert exc.resource == "https://example.com"

    def test_resource_defaults_to_none(self):
        exc = VTError("oops")
        assert exc.resource is None

    def test_subclass_preserves_resource(self):
        exc = ScanError("upload failed", resource="malware.exe")
        assert exc.resource == "malware.exe"
        assert str(exc) == "upload failed"


class TestHandleError:
    def test_rate_limit_error(self):
        exc = RateLimitError("quota exceeded")
        result = handle_error(exc)
        assert result.startswith("Rate limit exceeded:")
        assert "quota exceeded" in result

    def test_authentication_error(self):
        exc = AuthenticationError("invalid key")
        result = handle_error(exc)
        assert result.startswith("Authentication error:")
        assert "invalid key" in result

    def test_scan_error(self):
        exc = ScanError("file too large", resource="big.exe")
        result = handle_error(exc)
        assert result.startswith("Scan error:")
        assert "file too large" in result

    def test_report_error(self):
        exc = ReportError("not found", resource="8.8.8.8")
        result = handle_error(exc)
        assert result.startswith("Report error:")
        assert "not found" in result

    def test_config_error(self):
        exc = ConfigError("missing API key")
        result = handle_error(exc)
        assert result.startswith("Configuration error:")

    def test_unexpected_error_returns_generic(self):
        exc = RuntimeError("kaboom")
        result = handle_error(exc, context="domain_report")
        assert "unexpected error" in result.lower()
