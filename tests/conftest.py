"""Pytest configuration and shared fixtures."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def temp_cache_dir(tmp_path: Path) -> Path:
    """Create a temporary cache directory for testing."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    return cache_dir


@pytest.fixture
def temp_api_dir(tmp_path: Path) -> Path:
    """Create a temporary API directory for testing.

    Returns the parent API directory (e.g., /tmp/api), not the vulns subdirectory.
    The vulns/ subdirectory is created automatically.
    """
    api_dir = tmp_path / "api"
    (api_dir / "vulns").mkdir(parents=True)
    return api_dir


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Path:
    """Create a temporary output directory for testing."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    return output_dir


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


@pytest.fixture
def sample_cve_compliant() -> Dict[str, Any]:
    """Sample CVE that meets EPSS threshold (≥60%)."""
    return {
        "cveId": "CVE-2024-1234",
        "cve_id": "CVE-2024-1234",
        "title": "Critical SQL Injection Vulnerability",
        "description": "A critical SQL injection vulnerability affecting multiple products",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "epssScore": 0.85,  # 85% - compliant
        "epss_score": 0.85,
        "epssPercentile": 99.5,
        "published": "2024-10-20T00:00:00Z",
        "last_modified": "2024-10-23T00:00:00Z",
        "cwe": ["CWE-89"],
        "product": "ExampleDB",
        "vendor": "Example Corp",
        "references": [
            {"url": "https://example.com/security-advisory", "type": "advisory"}
        ],
    }


@pytest.fixture
def sample_cve_non_compliant() -> Dict[str, Any]:
    """Sample CVE that does NOT meet EPSS threshold (<60%)."""
    return {
        "cveId": "CVE-2024-5678",
        "cve_id": "CVE-2024-5678",
        "title": "Low Risk XSS Vulnerability",
        "description": "A low-risk XSS vulnerability",
        "severity": "HIGH",
        "cvss": 7.2,
        "epssScore": 0.45,  # 45% - non-compliant
        "epss_score": 0.45,
        "epssPercentile": 75.0,
        "published": "2024-10-15T00:00:00Z",
        "last_modified": "2024-10-20T00:00:00Z",
        "cwe": ["CWE-79"],
        "product": "ExampleApp",
        "vendor": "Example Inc",
        "references": [
            {"url": "https://example.com/advisory", "type": "advisory"}
        ],
    }


@pytest.fixture
def sample_cve_missing_epss() -> Dict[str, Any]:
    """Sample CVE with missing EPSS score."""
    return {
        "cveId": "CVE-2024-9999",
        "cve_id": "CVE-2024-9999",
        "title": "Vulnerability without EPSS data",
        "description": "A vulnerability missing EPSS enrichment",
        "severity": "HIGH",
        "cvss": 8.1,
        "published": "2024-10-01T00:00:00Z",
        "last_modified": "2024-10-05T00:00:00Z",
        "cwe": ["CWE-20"],
        "product": "ExampleService",
        "vendor": "Example LLC",
    }


@pytest.fixture
def sample_cve_cve50_format() -> Dict[str, Any]:
    """Sample CVE in CVE 5.0 format with nested EPSS data."""
    return {
        "cveId": "CVE-2025-0001",
        "cve_id": "CVE-2025-0001",
        "title": "CVE 5.0 Format Vulnerability",
        "description": "Vulnerability using CVE 5.0 schema",
        "severity": "CRITICAL",
        "cvss": 9.5,
        "containers": {
            "adp": [
                {
                    "enrichments": {
                        "epss": {
                            "score": 0.92,  # 92% - highly compliant
                            "percentile": 99.8,
                        }
                    }
                }
            ]
        },
        "published": "2025-01-01T00:00:00Z",
        "last_modified": "2025-01-05T00:00:00Z",
        "cwe": ["CWE-78"],
        "product": "FutureApp",
        "vendor": "Future Corp",
    }


@pytest.fixture
def sample_cve_list(
    sample_cve_compliant: Dict,
    sample_cve_non_compliant: Dict,
    sample_cve_missing_epss: Dict,
    sample_cve_cve50_format: Dict,
) -> List[Dict[str, Any]]:
    """List of sample CVEs for testing."""
    return [
        sample_cve_compliant,
        sample_cve_non_compliant,
        sample_cve_missing_epss,
        sample_cve_cve50_format,
    ]


@pytest.fixture
def mock_logger():
    """Mock logger for testing."""
    logger = MagicMock()
    logger.info = MagicMock()
    logger.warning = MagicMock()
    logger.error = MagicMock()
    logger.debug = MagicMock()
    return logger


@pytest.fixture
def mock_epss_api_response():
    """Mock EPSS API response."""
    return {
        "data": [
            {"cve": "CVE-2024-1234", "epss": "0.85000", "percentile": "0.99500"},
            {"cve": "CVE-2024-5678", "epss": "0.45000", "percentile": "0.75000"},
        ]
    }


@pytest.fixture
def mock_nvd_api_response():
    """Mock NVD API response."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "published": "2024-10-20T00:00:00.000",
                    "lastModified": "2024-10-23T00:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Critical SQL Injection Vulnerability",
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                }
                            }
                        ]
                    },
                }
            }
        ]
    }


@pytest.fixture
def mock_cisa_kev_response():
    """Mock CISA KEV API response."""
    return {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-1234",
                "vendorProject": "Example Corp",
                "product": "ExampleDB",
                "vulnerabilityName": "SQL Injection",
                "dateAdded": "2024-10-22",
                "shortDescription": "Critical SQL injection vulnerability",
                "requiredAction": "Apply updates immediately",
                "dueDate": "2024-11-05",
            }
        ]
    }
