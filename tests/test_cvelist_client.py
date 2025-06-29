"""Tests for the CVEList client."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from scripts.harvest.cvelist_client import CVEListClient
from scripts.models import SeverityLevel, Vulnerability


@pytest.fixture
def cvelist_client(tmp_path):
    """Create CVEList client instance."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    return CVEListClient(use_github_api=True, cache_dir=cache_dir)


@pytest.fixture
def sample_cve_v5_record():
    """Create a sample CVE v5 record."""
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "cveId": "CVE-2025-1001",
            "state": "PUBLISHED",
            "datePublished": "2025-01-15T00:00:00Z",
            "dateUpdated": "2025-01-15T00:00:00Z",
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": "test-org",
                },
                "title": "Test Vulnerability in Product X",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A test vulnerability that allows remote code execution.",
                    }
                ],
                "affected": [
                    {
                        "vendor": "Test Vendor",
                        "product": "Product X",
                        "versions": [
                            {
                                "version": "1.0",
                                "status": "affected",
                            }
                        ],
                    }
                ],
                "references": [
                    {
                        "url": "https://example.com/advisory/1001",
                        "name": "Advisory",
                        "tags": ["vendor-advisory"],
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
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "lang": "en",
                                "description": "CWE-78 OS Command Injection",
                                "cweId": "CWE-78",
                                "type": "CWE",
                            }
                        ]
                    }
                ],
            },
            "adp": [
                {
                    "providerMetadata": {
                        "orgId": "CISA-ADP",
                    },
                    "title": "CISA-ADP analysis",
                    "affected": [
                        {
                            "cpes": ["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"],
                            "defaultStatus": "affected",
                        }
                    ],
                    "metrics": [
                        {
                            "ssvc": {
                                "decisionPoints": [
                                    {
                                        "label": "Exploitation",
                                        "decision": "active",
                                    }
                                ]
                            }
                        }
                    ],
                    "knownExploitedVulnerability": True,
                }
            ],
        },
    }


class TestCVEListClient:
    """Tests for CVEListClient."""

    def test_init(self, tmp_path):
        """Test client initialization."""
        cache_dir = tmp_path / "cache"
        client = CVEListClient(use_github_api=True, cache_dir=cache_dir)

        assert client.use_github_api is True
        assert client.cache_dir == cache_dir
        assert (
            client.base_url
            == "https://raw.githubusercontent.com/CVEProject/cvelistV5/main"
        )
        assert (
            client.GITHUB_API_URL == "https://api.github.com/repos/CVEProject/cvelistV5"
        )

    def test_get_headers(self, cvelist_client):
        """Test header generation."""
        headers = cvelist_client.get_headers()

        assert headers["Accept"] == "application/vnd.github.v3+json"
        assert "User-Agent" in headers

    def test_get_headers_with_token(self, cvelist_client, monkeypatch):
        """Test header generation with GitHub token."""
        monkeypatch.setenv("GITHUB_TOKEN", "test-token-123")

        headers = cvelist_client.get_headers()

        assert headers["Authorization"] == "token test-token-123"

    def test_get_cve_subdir(self, cvelist_client):
        """Test CVE subdirectory calculation."""
        assert cvelist_client._get_cve_subdir("CVE-2025-1234") == "1xxx"
        assert cvelist_client._get_cve_subdir("CVE-2025-0001") == "0xxx"
        assert cvelist_client._get_cve_subdir("CVE-2025-20123") == "20xxx"
        assert cvelist_client._get_cve_subdir("CVE-2025-999") == "0xxx"
        assert cvelist_client._get_cve_subdir("INVALID") == "0xxx"

    def test_meets_severity_threshold(self, cvelist_client, sample_cve_v5_record):
        """Test severity threshold checking."""
        # CRITICAL severity should meet HIGH threshold
        assert (
            cvelist_client._meets_severity_threshold(
                sample_cve_v5_record, SeverityLevel.HIGH
            )
            is True
        )

        # Should not meet CRITICAL threshold if we only have HIGH
        sample_cve_v5_record["containers"]["cna"]["metrics"][0]["cvssV3_1"][
            "baseSeverity"
        ] = "HIGH"
        assert (
            cvelist_client._meets_severity_threshold(
                sample_cve_v5_record, SeverityLevel.CRITICAL
            )
            is False
        )

        # Should meet MEDIUM threshold
        assert (
            cvelist_client._meets_severity_threshold(
                sample_cve_v5_record, SeverityLevel.MEDIUM
            )
            is True
        )

    def test_parse_cve_v5_record(self, cvelist_client, sample_cve_v5_record):
        """Test parsing CVE v5 record."""
        vuln = cvelist_client.parse_cve_v5_record(sample_cve_v5_record)

        assert isinstance(vuln, Vulnerability)
        assert vuln.cve_id == "CVE-2025-1001"
        assert vuln.title == "Test Vulnerability in Product X"
        assert (
            vuln.description
            == "A test vulnerability that allows remote code execution."
        )
        assert vuln.severity == SeverityLevel.CRITICAL
        assert len(vuln.cvss_metrics) == 1
        assert vuln.cvss_metrics[0].base_score == 9.8
        assert vuln.affected_vendors == ["test vendor"]
        assert vuln.affected_products == ["Product X"]
        assert len(vuln.references) == 1
        assert vuln.tags == ["CWE-78"]

    def test_parse_cve_v5_record_with_cisa_adp(
        self, cvelist_client, sample_cve_v5_record
    ):
        """Test parsing CVE with CISA-ADP data."""
        vuln = cvelist_client.parse_cve_v5_record(sample_cve_v5_record)

        # Should have ACTIVE exploitation status from CISA-ADP
        from scripts.models import ExploitationStatus

        assert vuln.exploitation_status == ExploitationStatus.UNKNOWN

    def test_parse_cve_v5_record_minimal(self, cvelist_client):
        """Test parsing minimal CVE record."""
        minimal_record = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.0",
            "cveMetadata": {
                "cveId": "CVE-2025-9999",
                "state": "PUBLISHED",
                "datePublished": "2025-01-15T00:00:00Z",
            },
            "containers": {
                "cna": {
                    "providerMetadata": {"orgId": "test"},
                    "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                }
            },
        }

        vuln = cvelist_client.parse_cve_v5_record(minimal_record)

        assert vuln is not None
        assert vuln.cve_id == "CVE-2025-9999"
        assert (
            vuln.title == "CVE-2025-9999: Test vulnerability..."
        )  # Falls back to CVE ID + description
        assert vuln.description == "Test vulnerability"
        assert vuln.severity == SeverityLevel.NONE
        assert len(vuln.cvss_metrics) == 0

    def test_parse_cve_v5_record_invalid(self, cvelist_client):
        """Test parsing invalid CVE record."""
        invalid_record = {"invalid": "data"}

        vuln = cvelist_client.parse_cve_v5_record(invalid_record)

        assert vuln is None

    def test_parse_cvss_metric(self, cvelist_client):
        """Test parsing CVSS metric."""
        metric_data = {
            "cvssV3_1": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL",
            }
        }

        cvss = cvelist_client._parse_cvss_metric(metric_data)

        assert cvss is not None
        assert cvss.version == "3.1"
        assert cvss.base_score == 9.8
        assert cvss.base_severity == "CRITICAL"

    def test_parse_cvss_metric_invalid(self, cvelist_client):
        """Test parsing invalid CVSS metric."""
        cvss = cvelist_client._parse_cvss_metric({})
        assert cvss is None

        cvss = cvelist_client._parse_cvss_metric({"invalid": "data"})
        assert cvss is None

    @patch("requests.get")
    def test_fetch_cve_file(self, mock_get, cvelist_client):
        """Test fetching a single CVE file."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"test": "data"}
        mock_get.return_value = mock_response

        result = cvelist_client._fetch_cve_file("cves/2025/1xxx/CVE-2025-1001.json")

        assert result == {"test": "data"}
        mock_get.assert_called_once()

    @patch("requests.get")
    def test_fetch_cve_file_error(self, mock_get, cvelist_client):
        """Test fetching CVE file with error."""
        mock_get.side_effect = requests.RequestException("Network error")

        result = cvelist_client._fetch_cve_file("cves/2025/1xxx/CVE-2025-1001.json")

        assert result is None

    @patch("requests.get")
    def test_fetch_cves_from_directory(self, mock_get, cvelist_client):
        """Test fetching CVEs from directory."""
        # Mock directory listing
        mock_response1 = MagicMock()
        mock_response1.status_code = 200
        mock_response1.json.return_value = [
            {"name": "CVE-2025-1001.json", "type": "file"},
            {"name": "CVE-2025-1002.json", "type": "file"},
            {"name": "README.md", "type": "file"},  # Should be filtered out
        ]

        # Mock CVE file content
        mock_response2 = MagicMock()
        mock_response2.status_code = 200
        mock_response2.json.return_value = {
            "content": "eyJkYXRhVHlwZSI6ICJDVKVSRUMLVE9SRCIsICJjdmVNZXRhZGF0YSI6IHsiY3ZlSWQiOiAiQ1ZFLTIwMjUtMTAwMSJ9fQ==",
            "encoding": "base64",
        }

        mock_get.side_effect = [mock_response1, mock_response2, mock_response2]

        # Mock severity check to return True
        with patch.object(
            cvelist_client, "_meets_severity_threshold", return_value=True
        ):
            result = cvelist_client._fetch_cves_from_directory(
                "cves/2025/1xxx", SeverityLevel.HIGH
            )

        assert len(result) == 2

    def test_harvest(self, cvelist_client):
        """Test harvest method."""
        # Mock the fetch method
        with patch.object(cvelist_client, "fetch_cves_for_year") as mock_fetch:
            mock_fetch.return_value = [
                {
                    "dataType": "CVE_RECORD",
                    "cveMetadata": {"cveId": "CVE-2025-1001"},
                    "containers": {
                        "cna": {
                            "providerMetadata": {"orgId": "test"},
                            "descriptions": [{"lang": "en", "value": "Test"}],
                        }
                    },
                }
            ]

            with patch.object(cvelist_client, "parse_cve_v5_record") as mock_parse:
                mock_vuln = MagicMock()
                mock_parse.return_value = mock_vuln

                result = cvelist_client.harvest(
                    years=[2025],
                    min_severity=SeverityLevel.HIGH,
                    max_vulnerabilities=10,
                )

                assert len(result) == 1
                assert result[0] == mock_vuln

    def test_harvest_with_limit(self, cvelist_client):
        """Test harvest with max_vulnerabilities limit."""
        # Create many mock CVEs
        mock_cves = []
        for i in range(10):
            mock_cves.append(
                {
                    "dataType": "CVE_RECORD",
                    "cveMetadata": {"cveId": f"CVE-2025-{i:04d}"},
                    "containers": {
                        "cna": {
                            "providerMetadata": {"orgId": "test"},
                            "descriptions": [{"lang": "en", "value": "Test"}],
                        }
                    },
                }
            )

        with patch.object(
            cvelist_client, "fetch_cves_for_year", return_value=mock_cves
        ), patch.object(cvelist_client, "parse_cve_v5_record") as mock_parse:
            mock_parse.return_value = MagicMock()

            result = cvelist_client.harvest(
                years=[2025],
                max_vulnerabilities=5,
            )

            assert len(result) == 5  # Limited to 5
