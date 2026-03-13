"""Shared test fixtures."""

import pytest

from virustotal.client import VirusTotalClient

FAKE_API_KEY = "test-api-key-000000"


@pytest.fixture
def client() -> VirusTotalClient:
    """Provide a VirusTotalClient with a fake API key."""
    return VirusTotalClient(FAKE_API_KEY)
