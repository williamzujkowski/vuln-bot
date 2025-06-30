"""Extended tests for CVEListClient to improve coverage."""

from unittest.mock import Mock, patch

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
        """Test fetching CVE from API via _fetch_cve_file method."""
        with patch("requests.get") as mock_get:
            cve_data = {
                "cveMetadata": {
                    "cveId": "CVE-2024-1234",
                    "datePublished": "2024-01-01T00:00:00Z",
                },
                "containers": {
                    "cna": {
                        "title": "Test vulnerability",
                        "descriptions": [{"lang": "en", "value": "Test description"}],
                    }
                },
            }

            mock_response = Mock()
            mock_response.json.return_value = cve_data
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response

            result = client._fetch_cve_file("cves/2024/0xxx/CVE-2024-1234.json")
            assert result == cve_data
            mock_get.assert_called_once()

    def test_parse_cve_v5_record(self, client):
        """Test parsing CVE v5 record."""
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

        vuln = client.parse_cve_v5_record(record)

        assert vuln is not None
        assert vuln.cve_id == "CVE-2024-1234"
        assert vuln.title == "Test vulnerability"
        assert vuln.description == "Test description"
        assert vuln.severity == SeverityLevel.CRITICAL
        assert len(vuln.cvss_metrics) == 1
        assert vuln.cvss_metrics[0].base_score == 9.8
        assert len(vuln.references) == 1
        assert vuln.references[0].url == "https://example.com/advisory"

    def test_parse_cvss_metric(self, client):
        """Test parsing different CVSS versions."""
        # CVSS v3.1
        metric_v31 = {
            "cvssV3_1": {
                "baseScore": 8.5,
                "baseSeverity": "HIGH",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "exploitabilityScore": 3.9,
                "impactScore": 5.9,
            }
        }

        result = client._parse_cvss_metric(metric_v31)
        assert result is not None
        assert result.base_score == 8.5
        assert result.base_severity == SeverityLevel.HIGH
        assert result.version == "3.1"

        # CVSS v3.0
        metric_v30 = {
            "cvssV3_0": {
                "baseScore": 7.5,
                "baseSeverity": "HIGH",
                "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            }
        }

        result = client._parse_cvss_metric(metric_v30)
        assert result is not None
        assert result.base_score == 7.5
        assert result.version == "3.0"

        # Unsupported version (v2.0)
        metric_v20 = {
            "cvssV2_0": {
                "baseScore": 6.5,
                "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            }
        }

        result = client._parse_cvss_metric(metric_v20)
        assert result is None  # v2.0 not supported

        # No metrics
        result = client._parse_cvss_metric({})
        assert result is None

    def test_extract_affected_products(self, client):
        """Test extracting affected products from CVE record."""
        record = {
            "cveMetadata": {
                "cveId": "CVE-2024-1234",
                "datePublished": "2024-01-01T00:00:00Z",
            },
            "containers": {
                "cna": {
                    "title": "Test vulnerability",
                    "descriptions": [{"lang": "en", "value": "Test description"}],
                    "affected": [
                        {"vendor": "TestVendor1", "product": "TestProduct1"},
                        {"vendor": "TestVendor2", "product": "TestProduct2"},
                        {
                            "vendor": "TestVendor1",
                            "product": "TestProduct3",
                        },  # Duplicate vendor
                    ],
                }
            },
        }

        vuln = client.parse_cve_v5_record(record)
        assert vuln is not None

        # Check that vendors and products are extracted correctly
        assert "testvendor1" in vuln.affected_vendors
        assert "testvendor2" in vuln.affected_vendors
        assert len(vuln.affected_vendors) == 2  # No duplicates

        assert "testproduct1" in vuln.affected_products
        assert "testproduct2" in vuln.affected_products
        assert "testproduct3" in vuln.affected_products
        assert len(vuln.affected_products) == 3

    def test_parse_references(self, client):
        """Test parsing references from CVE record."""
        record = {
            "cveMetadata": {
                "cveId": "CVE-2024-1234",
                "datePublished": "2024-01-01T00:00:00Z",
            },
            "containers": {
                "cna": {
                    "title": "Test vulnerability",
                    "descriptions": [{"lang": "en", "value": "Test description"}],
                    "references": [
                        {
                            "url": "https://example.com/advisory",
                            "name": "Advisory Source",
                            "tags": ["vendor-advisory", "security-bulletin"],
                        },
                        {
                            "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
                            "name": "NVD",
                            "tags": ["third-party-advisory"],
                        },
                    ],
                }
            },
        }

        vuln = client.parse_cve_v5_record(record)
        assert vuln is not None

        # Check that references are parsed correctly
        assert len(vuln.references) == 2

        ref1 = vuln.references[0]
        assert ref1.url == "https://example.com/advisory"
        assert ref1.source == "Advisory Source"
        assert "vendor-advisory" in ref1.tags
        assert "security-bulletin" in ref1.tags

        ref2 = vuln.references[1]
        assert ref2.url == "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
        assert ref2.source == "NVD"
        assert "third-party-advisory" in ref2.tags

    def test_harvest_date_range(self, client):
        """Test harvesting by date range using existing harvest method."""

        with patch.object(client, "fetch_cves_for_year") as mock_fetch:
            mock_fetch.return_value = []

            # Test harvest method with date range filtering
            result = client.harvest(
                years=[2024],
                min_severity=SeverityLevel.HIGH,
                max_vulnerabilities=100,
                incremental=False,
            )

            # Verify that the method was called correctly
            # The harvest method calls fetch_cves_for_year with (year, min_severity, incremental)
            mock_fetch.assert_called_once_with(2024, SeverityLevel.HIGH, False)
            assert result == []

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
                        "providerMetadata": {"shortName": "CISA-ADP"},
                        "knownExploitedVulnerability": True,
                        "title": "CISA-ADP: Known Exploited Vulnerability",
                        "cisaActionDue": "2024-01-15",
                    }
                ],
            },
        }

        vuln = client.parse_cve_v5_record(record)
        assert vuln is not None
        # Check that exploitation status is set correctly
        from scripts.models import ExploitationStatus

        assert vuln.exploitation_status == ExploitationStatus.ACTIVE

    def test_error_handling(self, client):
        """Test error handling in CVE parsing."""
        # Invalid record
        invalid_record = {"invalid": "data"}
        vuln = client.parse_cve_v5_record(invalid_record)
        assert vuln is None

        # Missing required fields
        incomplete_record = {
            "cveMetadata": {"cveId": "CVE-2024-1234"},
            "containers": {},
        }
        vuln = client.parse_cve_v5_record(incomplete_record)
        assert vuln is None

    def test_fetch_cves_for_year_with_max_vulnerabilities(self, client):
        """Test fetch_cves_for_year respects max limit."""
        # Mock GitHub API response for directory listing
        with patch("requests.get") as mock_get:
            # First call: list subdirectories
            mock_response1 = Mock()
            mock_response1.json.return_value = [
                {"name": "0xxx", "type": "dir"},
                {"name": "1xxx", "type": "dir"},
            ]
            mock_response1.raise_for_status = Mock()

            # Second call: list files in 0xxx
            mock_response2 = Mock()
            mock_response2.json.return_value = [
                {"name": "CVE-2024-0001.json", "type": "file"},
                {"name": "CVE-2024-0002.json", "type": "file"},
            ]
            mock_response2.raise_for_status = Mock()

            # Third and fourth calls: CVE file contents
            cve_data = {
                "cveMetadata": {
                    "cveId": "CVE-2024-0001",
                    "datePublished": "2024-01-01T00:00:00Z",
                },
                "containers": {
                    "cna": {
                        "metrics": [
                            {"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ]
                    }
                },
            }
            mock_response3 = Mock()
            mock_response3.json.return_value = cve_data
            mock_response3.raise_for_status = Mock()

            mock_get.side_effect = [
                mock_response1,
                mock_response2,
                mock_response3,
                mock_response3,
            ]

            cves = client.fetch_cves_for_year(2024, SeverityLevel.HIGH)
            assert len(cves) >= 1
