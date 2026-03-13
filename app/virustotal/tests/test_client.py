"""Tests for the VirusTotal API client."""

import responses

from virustotal.client import VirusTotalClient


class TestVirusTotalClient:
    @responses.activate
    def test_url_scan_sends_post_with_url(self, client: VirusTotalClient):
        responses.add(
            responses.POST,
            f"{VirusTotalClient.BASE_URL}/urls",
            json={"data": {"id": "scan-123"}},
            status=200,
        )

        result = client.url_scan("https://example.com")

        assert result == {"data": {"id": "scan-123"}}
        assert responses.calls[0].request.body == "url=https%3A%2F%2Fexample.com"

    @responses.activate
    def test_ip_report_sends_get(self, client: VirusTotalClient):
        responses.add(
            responses.GET,
            f"{VirusTotalClient.BASE_URL}/ip_addresses/8.8.8.8",
            json={"data": {"type": "ip_address", "id": "8.8.8.8"}},
            status=200,
        )

        result = client.ip_report("8.8.8.8")

        assert result["data"]["id"] == "8.8.8.8"

    @responses.activate
    def test_domain_report_sends_get(self, client: VirusTotalClient):
        responses.add(
            responses.GET,
            f"{VirusTotalClient.BASE_URL}/domains/example.com",
            json={"data": {"type": "domain", "id": "example.com"}},
            status=200,
        )

        result = client.domain_report("example.com")

        assert result["data"]["id"] == "example.com"

    @responses.activate
    def test_file_scan_sends_post_with_file(self, client: VirusTotalClient, tmp_path):
        responses.add(
            responses.POST,
            f"{VirusTotalClient.BASE_URL}/files",
            json={"data": {"id": "file-456"}},
            status=200,
        )
        test_file = tmp_path / "malware.txt"
        test_file.write_text("not actually malware")

        result = client.file_scan(test_file)

        assert result == {"data": {"id": "file-456"}}

    @responses.activate
    def test_request_includes_api_key_header(self, client: VirusTotalClient):
        responses.add(
            responses.GET,
            f"{VirusTotalClient.BASE_URL}/domains/test.com",
            json={"data": {}},
            status=200,
        )

        client.domain_report("test.com")

        assert responses.calls[0].request.headers["x-apikey"] == "test-api-key-000000"
