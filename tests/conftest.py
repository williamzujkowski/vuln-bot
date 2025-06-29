"""Pytest configuration and shared fixtures."""

from pathlib import Path

import pytest


@pytest.fixture
def temp_cache_dir(tmp_path: Path) -> Path:
    """Create a temporary cache directory for testing."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    return cache_dir


@pytest.fixture
def mock_api_response() -> dict:
    """Mock API response for testing."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "descriptions": [
                        {"lang": "en", "value": "Test vulnerability description"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
                        ]
                    },
                }
            }
        ]
    }
