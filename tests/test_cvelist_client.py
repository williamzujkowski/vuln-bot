"""Tests for CVEList client."""

from unittest.mock import Mock, patch

import pytest

from scripts.harvest.cvelist_client import CVEListClient
from scripts.models import SeverityLevel


class TestCVEListClient:
    """Test CVEListClient functionality."""

    @pytest.fixture
    def client(self, tmp_path, monkeypatch):
        """Create a CVEListClient instance."""
        monkeypatch.setenv("GITHUB_TOKEN", "test-token")
        return CVEListClient(
            cache_dir=tmp_path,
            use_github_api=True,
        )

    @pytest.fixture
    def sample_cve_v5(self):
        """Create a sample CVE v5.0 record."""
        return {
            "cveMetadata": {
                "cveId": "CVE-2025-0001",
                "datePublished": "2025-01-01T00:00:00.000Z",
                "dateUpdated": "2025-01-02T00:00:00.000Z",
            },
            "containers": {
                "cna": {
                    "title": "Test Vulnerability",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "A test vulnerability description",
                        }
                    ],
                    "affected": [
                        {
                            "vendor": "Test Vendor",
                            "product": "Test Product",
                            "versions": [
                                {
                                    "version": "1.0",
                                    "status": "affected",
                                }
                            ],
                        }
                    ],
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ],
                    "references": [
                        {
                            "url": "https://example.com/advisory",
                            "tags": ["vendor-advisory"],
                        }
                    ],
                }
            },
        }

    def test_initialization(self, client):
        """Test client initialization."""
        assert client.use_github_api is True
        assert (
            client.base_url
            == "https://raw.githubusercontent.com/CVEProject/cvelistV5/main"
        )
        # Check headers include token
        headers = client.get_headers()
        assert "Authorization" in headers
        assert headers["Authorization"] == "token test-token"

    def test_parse_cve_v5_record(self, client, sample_cve_v5):
        """Test parsing CVE v5 record."""
        vuln = client.parse_cve_v5_record(sample_cve_v5)

        assert vuln is not None
        assert vuln.cve_id == "CVE-2025-0001"
        assert vuln.title == "Test Vulnerability"
        assert vuln.description == "A test vulnerability description"
        assert vuln.severity == SeverityLevel.CRITICAL
        assert vuln.cvss_base_score == 9.8
        assert len(vuln.affected_vendors) == 1
        assert vuln.affected_vendors[0] == "test vendor"
        assert len(vuln.references) == 1

    def test_meets_severity_threshold(self, client, sample_cve_v5):
        """Test severity threshold checking."""
        # Sample CVE has CRITICAL severity, should meet HIGH threshold
        assert (
            client._meets_severity_threshold(sample_cve_v5, SeverityLevel.HIGH) is True
        )

        # Test with LOW severity CVE
        low_severity_cve = {
            "containers": {
                "cna": {
                    "metrics": [{"cvssV3_1": {"baseSeverity": "LOW", "baseScore": 3.5}}]
                }
            }
        }
        assert (
            client._meets_severity_threshold(low_severity_cve, SeverityLevel.HIGH)
            is False
        )
        assert (
            client._meets_severity_threshold(low_severity_cve, SeverityLevel.LOW)
            is True
        )

    def test_parse_cve_v5_record_missing_data(self, client):
        """Test parsing CVE record with missing data."""
        minimal_cve = {
            "cveMetadata": {
                "cveId": "CVE-2025-0002",
                "datePublished": "2025-01-01T00:00:00.000Z",
            },
            "containers": {
                "cna": {
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Minimal description",
                        }
                    ],
                }
            },
        }

        vuln = client.parse_cve_v5_record(minimal_cve)

        assert vuln is not None
        assert vuln.cve_id == "CVE-2025-0002"
        assert (
            vuln.title == "CVE-2025-0002: Minimal description..."
        )  # Falls back to CVE ID + description
        assert vuln.description == "Minimal description"
        assert vuln.severity == SeverityLevel.NONE
        assert vuln.cvss_base_score is None

    @patch("requests.get")
    def test_fetch_cves_for_year_github_api(self, mock_get, client):
        """Test fetching CVEs for a year using GitHub API."""
        # Mock GitHub API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "tree": [
                {"path": "2025/0xxx", "type": "tree"},
                {"path": "2025/1xxx", "type": "tree"},
            ]
        }
        mock_get.return_value = mock_response

        # Set temporary limits for testing
        client._temp_max_dirs = 2
        client._temp_max_files = 5

        vulnerabilities = []
        for vuln in client.fetch_cves_for_year(2025, min_severity=SeverityLevel.HIGH):
            vulnerabilities.append(vuln)
            if len(vulnerabilities) >= 5:
                break

        # Should have made at least one API call
        assert mock_get.called
