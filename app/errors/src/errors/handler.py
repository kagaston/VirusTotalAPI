"""Custom exception hierarchy and global error handler for VirusTotal API."""

from __future__ import annotations

from logger.config import get_logger

log = get_logger("error_handler")


class VTError(Exception):
    """Base exception for VirusTotal API operations."""

    def __init__(self, message: str, *, resource: str | None = None) -> None:
        super().__init__(message)
        self.resource = resource


class ScanError(VTError):
    """Raised when a file or URL scan submission fails."""


class ReportError(VTError):
    """Raised when fetching an IP or domain report fails."""


class AuthenticationError(VTError):
    """Raised when the API key is missing, invalid, or revoked."""


class RateLimitError(VTError):
    """Raised when the API rate limit is exceeded."""


class ConfigError(VTError):
    """Raised when required configuration is missing or invalid."""


def handle_error(exc: Exception, *, context: str | None = None) -> str:
    """Log the error and return a user-facing message.

    Args:
        exc: The exception to handle.
        context: Optional context string for logging (e.g. endpoint, resource).

    Returns:
        A user-facing error message string.
    """
    if isinstance(exc, RateLimitError):
        log.warning("Rate limit exceeded: %s (resource=%s)", exc, getattr(exc, "resource", None))
        return f"Rate limit exceeded: {exc}"

    if isinstance(exc, AuthenticationError):
        log.error("Authentication error: %s", exc)
        return f"Authentication error: {exc}"

    if isinstance(exc, ScanError):
        log.error("Scan error: %s (resource=%s)", exc, getattr(exc, "resource", None))
        return f"Scan error: {exc}"

    if isinstance(exc, ReportError):
        log.error("Report error: %s (resource=%s)", exc, getattr(exc, "resource", None))
        return f"Report error: {exc}"

    if isinstance(exc, ConfigError):
        log.error("Configuration error: %s", exc)
        return f"Configuration error: {exc}"

    log.exception("Unexpected error (context=%s)", context)
    return "An unexpected error occurred."
