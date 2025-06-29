"""Extended tests for CVEListClient to improve coverage."""

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from scripts.harvest.cvelist_client import CVEListClient
from scripts.models import SeverityLevel


class TestCVEListClientExtended:
    """Extended test cases for CVEListClient."""

    @pytest.fixture
    def temp_repo_path(self, tmp_path):
        """Create temporary repository path."""
        repo_path = tmp_path / "cvelist"
        repo_path.mkdir()
        return repo_path

    @pytest.fixture
    def client(self, temp_repo_path):
        """Create CVEListClient instance."""
        return CVEListClient(
            local_repo_path=temp_repo_path,
            use_github_api=True,
            use_releases=False,
            cache_dir=temp_repo_path / "cache",
        )

    def test_get_headers(self, client):
        """Test header generation."""
        headers = client.get_headers()
        assert "User-Agent" in headers
        assert "Accept" in headers

    def test_initialization_options(self, temp_repo_path):
        """Test different initialization options."""
        # With GitHub API
        client1 = CVEListClient(use_github_api=True)
        assert client1.base_url == CVEListClient.GITHUB_RAW_URL

        # Without GitHub API
        client2 = CVEListClient(use_github_api=False)
        assert client2.base_url == ""

        # With local repo
        client3 = CVEListClient(local_repo_path=temp_repo_path)
        assert client3.local_repo_path == temp_repo_path

    def test_fetch_cve_from_api(self, client):
        """Test fetching CVE from API."""
        cve_id = "CVE-2024-1234"
        year = "2024"

        mock_response = {
            "cveMetadata": {
                "cveId": cve_id,
                "assignerOrgId": "test-org",
                "state": "PUBLISHED",
                "datePublished": "2024-01-01T00:00:00Z",
                "dateUpdated": "2024-01-02T00:00:00Z",
            },
            "containers": {
                "cna": {
                    "title": "Test vulnerability",
                    "descriptions": [{"lang": "en", "value": "Test description"}],
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        }
                    ],
                    "references": [{"url": "https://example.com/advisory"}],
                }
            },
        }

        with patch.object(client, "get", return_value=mock_response):
            result = client.fetch_cve_from_api(cve_id, year)
            assert result == mock_response

    def test_parse_cve_record(self, client):
        """Test parsing CVE record."""
        record = {
            "cveMetadata": {
                "cveId": "CVE-2024-1234",
                "state": "PUBLISHED",
                "datePublished": "2024-01-01T00:00:00Z",
                "dateUpdated": "2024-01-02T00:00:00Z",
            },
            "containers": {
                "cna": {
                    "title": "Test vulnerability",
                    "descriptions": [{"lang": "en", "value": "Test description"}],
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        }
                    ],
                    "affected": [{"vendor": "TestVendor", "product": "TestProduct"}],
                    "references": [{"url": "https://example.com/advisory"}],
                }
            },
        }

        vuln = client.parse_cve_record(record)

        assert vuln is not None
        assert vuln.cve_id == "CVE-2024-1234"
        assert vuln.title == "Test vulnerability"
        assert vuln.description == "Test description"
        assert vuln.severity == SeverityLevel.CRITICAL
        assert vuln.cvss_base_score == 9.8
        assert len(vuln.references) == 1
        assert vuln.references[0].url == "https://example.com/advisory"

    def test_parse_cvss_metrics(self, client):
        """Test parsing different CVSS versions."""
        # CVSS v3.1
        metrics_v31 = [
            {
                "cvssV3_1": {
                    "baseScore": 8.5,
                    "baseSeverity": "HIGH",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            }
        ]

        result = client.parse_cvss_metrics(metrics_v31)
        assert result["base_score"] == 8.5
        assert result["severity"] == SeverityLevel.HIGH

        # CVSS v3.0
        metrics_v30 = [
            {
                "cvssV3_0": {
                    "baseScore": 7.5,
                    "baseSeverity": "HIGH",
                    "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                }
            }
        ]

        result = client.parse_cvss_metrics(metrics_v30)
        assert result["base_score"] == 7.5

        # CVSS v2.0
        metrics_v20 = [
            {
                "cvssV2_0": {
                    "baseScore": 6.5,
                    "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                }
            }
        ]

        result = client.parse_cvss_metrics(metrics_v20)
        assert result["base_score"] == 6.5

        # No metrics
        result = client.parse_cvss_metrics([])
        assert result["base_score"] is None
        assert result["severity"] == SeverityLevel.MEDIUM

    def test_extract_affected_products(self, client):
        """Test extracting affected products."""
        affected = [
            {
                "vendor": "Vendor1",
                "product": "Product1",
                "versions": [
                    {"version": "1.0", "status": "affected"},
                    {"version": "1.1", "status": "affected"},
                ],
            },
            {"vendor": "Vendor2", "product": "Product2"},
        ]

        vendors = client.extract_affected_vendors(affected)
        assert "Vendor1" in vendors
        assert "Vendor2" in vendors

    def test_parse_references(self, client):
        """Test parsing references."""
        references = [
            {"url": "https://example.com/advisory"},
            {"url": "https://github.com/vendor/repo/security/advisories/GHSA-1234"},
            {
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
                "tags": ["official"],
            },
            {"name": "Reference without URL"},
        ]

        parsed = client.parse_references(references)
        assert len(parsed) == 3  # Only those with URLs
        assert parsed[0].url == "https://example.com/advisory"
        assert parsed[1].source == "github"
        assert "official" in parsed[2].tags

    def test_harvest_date_range(self, client):
        """Test harvesting by date range."""
        start_date = datetime.now() - timedelta(days=7)
        end_date = datetime.now()

        # Mock the directory listing and CVE fetching
        mock_listing = [
            {"name": "CVE-2024-0001.json", "type": "file"},
            {"name": "CVE-2024-0002.json", "type": "file"},
        ]

        mock_cve1 = {
            "cveMetadata": {
                "cveId": "CVE-2024-0001",
                "state": "PUBLISHED",
                "datePublished": (datetime.now() - timedelta(days=3)).isoformat() + "Z",
                "dateUpdated": (datetime.now() - timedelta(days=2)).isoformat() + "Z",
            },
            "containers": {
                "cna": {
                    "title": "Test CVE 1",
                    "descriptions": [{"lang": "en", "value": "Test description 1"}],
                }
            },
        }

        mock_cve2 = {
            "cveMetadata": {
                "cveId": "CVE-2024-0002",
                "state": "PUBLISHED",
                "datePublished": (datetime.now() - timedelta(days=10)).isoformat()
                + "Z",
                "dateUpdated": (datetime.now() - timedelta(days=9)).isoformat() + "Z",
            },
            "containers": {
                "cna": {
                    "title": "Test CVE 2",
                    "descriptions": [{"lang": "en", "value": "Test description 2"}],
                }
            },
        }

        with patch.object(
            client, "_fetch_directory_listing", return_value=mock_listing
        ), patch.object(client, "get", side_effect=[mock_cve1, mock_cve2]):
            vulns = list(client.harvest_date_range(start_date, end_date))

            # Should only include CVE-2024-0001 (within date range)
            assert len(vulns) == 1
            assert vulns[0].cve_id == "CVE-2024-0001"

    def test_handle_cisa_adp_container(self, client):
        """Test handling CISA ADP container."""
        record = {
            "cveMetadata": {
                "cveId": "CVE-2024-1234",
                "state": "PUBLISHED",
                "datePublished": "2024-01-01T00:00:00Z",
                "dateUpdated": "2024-01-02T00:00:00Z",
            },
            "containers": {
                "cna": {
                    "title": "Test vulnerability",
                    "descriptions": [{"lang": "en", "value": "Test description"}],
                },
                "adp": [
                    {
                        "providerMetadata": {
                            "orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0"  # CISA org ID
                        },
                        "title": "CISA-ADP: Known Exploited Vulnerability",
                        "cisaKnownExploited": True,
                        "cisaActionDue": "2024-01-15",
                    }
                ],
            },
        }

        vuln = client.parse_cve_record(record)
        assert vuln is not None
        assert vuln.cisa_kev is True
        assert vuln.cisa_kev_due_date is not None

    def test_error_handling(self, client):
        """Test error handling in CVE parsing."""
        # Invalid record
        invalid_record = {"invalid": "data"}
        vuln = client.parse_cve_record(invalid_record)
        assert vuln is None

        # Missing required fields
        incomplete_record = {
            "cveMetadata": {"cveId": "CVE-2024-1234"},
            "containers": {},
        }
        vuln = client.parse_cve_record(incomplete_record)
        assert vuln is None

    def test_rejected_cve_handling(self, client):
        """Test handling of rejected CVEs."""
        rejected_record = {
            "cveMetadata": {
                "cveId": "CVE-2024-9999",
                "state": "REJECTED",
                "datePublished": "2024-01-01T00:00:00Z",
            },
            "containers": {},
        }

        vuln = client.parse_cve_record(rejected_record)
        assert vuln is None
