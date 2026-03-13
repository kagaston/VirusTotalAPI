"""VirusTotal API v3 client."""

from pathlib import Path
from typing import Any

import requests

from errors.handler import ReportError, ScanError
from logger.config import get_logger
from settings.config import REQUEST_TIMEOUT, VIRUSTOTAL_BASE_URL

log = get_logger("client")


class VirusTotalClient:
    """Client for the VirusTotal API v3.

    Provides methods for file scanning, URL scanning, IP address reports,
    and domain reports through the VirusTotal REST API.

    Attributes:
        BASE_URL: The base URL for the VirusTotal API.
    """

    BASE_URL = VIRUSTOTAL_BASE_URL

    def __init__(self, api_key: str) -> None:
        """Initialize the client with an API key.

        Args:
            api_key: Your VirusTotal API key.
        """
        self._api_key = api_key
        self._headers = {"x-apikey": api_key}

    def _request(
        self,
        method: str,
        endpoint: str,
        data: dict[str, str] | None = None,
        files: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send an HTTP request to the VirusTotal API.

        Args:
            method: The HTTP method (GET, POST, etc.).
            endpoint: The API endpoint path (e.g. "/files").
            data: Optional request payload.
            files: Optional files to upload.

        Returns:
            The parsed JSON response.

        Raises:
            requests.HTTPError: If the API returns a non-2xx status code.
        """
        url = f"{self.BASE_URL}{endpoint}"
        log.debug("%s %s", method, url)
        response = requests.request(method, url, headers=self._headers, data=data, files=files, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.json()

    def file_scan(self, file_path: str | Path) -> dict[str, Any]:
        """Submit a file for scanning.

        Args:
            file_path: Path to the file to scan.

        Returns:
            The scan submission response.

        Raises:
            ScanError: If the file scan submission fails.
        """
        try:
            with open(file_path, "rb") as f:
                return self._request("POST", "/files", files={"file": f})
        except requests.HTTPError as exc:
            raise ScanError(f"File scan failed: {exc}", resource=str(file_path)) from exc

    def url_scan(self, url: str) -> dict[str, Any]:
        """Submit a URL for scanning.

        Args:
            url: The URL to scan.

        Returns:
            The scan submission response.

        Raises:
            ScanError: If the URL scan submission fails.
        """
        try:
            return self._request("POST", "/urls", data={"url": url})
        except requests.HTTPError as exc:
            raise ScanError(f"URL scan failed: {exc}", resource=url) from exc

    def ip_report(self, ip_address: str) -> dict[str, Any]:
        """Retrieve an IP address report.

        Args:
            ip_address: The IP address to look up.

        Returns:
            The IP address analysis report.

        Raises:
            ReportError: If the report retrieval fails.
        """
        try:
            return self._request("GET", f"/ip_addresses/{ip_address}")
        except requests.HTTPError as exc:
            raise ReportError(f"IP report failed: {exc}", resource=ip_address) from exc

    def domain_report(self, domain: str) -> dict[str, Any]:
        """Retrieve a domain report.

        Args:
            domain: The domain name to look up.

        Returns:
            The domain analysis report.

        Raises:
            ReportError: If the report retrieval fails.
        """
        try:
            return self._request("GET", f"/domains/{domain}")
        except requests.HTTPError as exc:
            raise ReportError(f"Domain report failed: {exc}", resource=domain) from exc
