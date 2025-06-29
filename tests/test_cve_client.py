"""Tests for CVE API client."""

import os
from unittest.mock import Mock, patch

import pytest

from scripts.harvest.cve_client import CVEClient
from scripts.models import SeverityLevel, Vulnerability


class TestCVEClient:
    """Test cases for CVE API client."""

    @pytest.fixture
    def client(self):
        """Create CVE client instance."""
        return CVEClient(api_key="test-api-key")

    @pytest.fixture
    def sample_cve_response(self):
        """Sample CVE API response."""
        return {
            "resultsPerPage": 2,
            "startIndex": 0,
            "totalResults": 2,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "sourceIdentifier": "nvd@nist.gov",
                        "published": "2024-01-01T00:00:00.000",
                        "lastModified": "2024-01-02T00:00:00.000",
                        "vulnStatus": "Analyzed",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "A critical vulnerability in test software",
                            }
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "source": "nvd@nist.gov",
                                    "type": "Primary",
                                    "cvssData": {
                                        "version": "3.1",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL",
                                    },
                                }
                            ]
                        },
                        "references": [
                            {
                                "url": "https://example.com/advisory",
                                "source": "nvd@nist.gov",
                            }
                        ],
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "operator": "OR",
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                                            }
                                        ],
                                    }
                                ]
                            }
                        ],
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2024-0002",
                        "sourceIdentifier": "nvd@nist.gov",
                        "published": "2024-01-01T00:00:00.000",
                        "lastModified": "2024-01-02T00:00:00.000",
                        "vulnStatus": "Analyzed",
                        "descriptions": [
                            {"lang": "en", "value": "Another test vulnerability"}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "source": "nvd@nist.gov",
                                    "type": "Primary",
                                    "cvssData": {
                                        "version": "3.1",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                                        "baseScore": 6.5,
                                        "baseSeverity": "MEDIUM",
                                    },
                                }
                            ]
                        },
                    }
                },
            ],
        }

    def test_init_with_api_key(self):
        """Test client initialization with API key."""
        client = CVEClient(api_key="test-key")
        assert client.api_key == "test-key"
        assert client.rate_limiter.calls == 30  # Higher limit with API key

    def test_init_without_api_key(self):
        """Test client initialization without API key."""
        with patch.dict(os.environ, {}, clear=True):
            client = CVEClient()
            assert client.api_key is None
            assert client.rate_limiter.calls == 5  # Lower limit without API key

    def test_init_with_env_api_key(self):
        """Test client initialization with environment variable API key."""
        with patch.dict(os.environ, {"CVE_API_KEY": "env-key"}):
            client = CVEClient()
            assert client.api_key == "env-key"

    def test_get_headers_with_api_key(self, client):
        """Test headers include API key when present."""
        headers = client.get_headers()
        assert "apiKey" in headers
        assert headers["apiKey"] == "test-api-key"

    def test_get_headers_without_api_key(self):
        """Test headers without API key."""
        client = CVEClient()
        client.api_key = None
        headers = client.get_headers()
        assert "apiKey" not in headers

    def test_fetch_recent_cves_success(self, client, sample_cve_response):
        """Test fetching recent CVEs successfully."""
        with patch.object(client, "get", return_value=sample_cve_response):
            raw_cves = client.fetch_recent_cves(days_back=7)

            assert len(raw_cves) == 2
            assert all(isinstance(v, dict) for v in raw_cves)
            assert raw_cves[0]["cve"]["id"] == "CVE-2024-0001"
            assert raw_cves[1]["cve"]["id"] == "CVE-2024-0002"

    def test_fetch_recent_cves_with_filters(self, client):
        """Test fetching CVEs with severity filter."""
        with patch.object(client, "get") as mock_get:
            mock_get.return_value = {"vulnerabilities": []}

            client.fetch_recent_cves(days_back=7, severity=SeverityLevel.CRITICAL)

            # Check API was called with correct parameters
            call_args = mock_get.call_args[1]["params"]
            assert "lastModStartDate" in call_args
            assert "lastModEndDate" in call_args
            assert call_args["cvssV3Severity"] == "CRITICAL"
            assert call_args["resultsPerPage"] == 2000

    def test_fetch_recent_cves_pagination(self, client):
        """Test pagination handling."""
        # First page response with 2000 results (max per page)
        page1 = {
            "resultsPerPage": 2000,
            "startIndex": 0,
            "totalResults": 3500,  # More than one page
            "vulnerabilities": [
                {"cve": {"id": f"CVE-2024-{i:04d}"}} for i in range(2000)
            ],
        }

        # Second page response
        page2 = {
            "resultsPerPage": 1500,
            "startIndex": 2000,
            "totalResults": 3500,
            "vulnerabilities": [
                {"cve": {"id": f"CVE-2024-{i:04d}"}} for i in range(2000, 3500)
            ],
        }

        with patch.object(client, "get", side_effect=[page1, page2]):
            raw_cves = client.fetch_recent_cves(days_back=7)

            # Should make 2 API calls
            assert client.get.call_count == 2
            # Should return all 3500 vulnerabilities
            assert len(raw_cves) == 3500

    def test_fetch_recent_cves_error_handling(self, client):
        """Test error handling in fetch_recent_cves."""
        with patch.object(client, "get", side_effect=Exception("API Error")):
            raw_cves = client.fetch_recent_cves()
            assert raw_cves == []  # Should return empty list on error

    def test_parse_cve_record_complete(self, client):
        """Test parsing complete CVE record."""
        cve_data = {
            "cve": {
                "id": "CVE-2024-0001",
                "sourceIdentifier": "nvd@nist.gov",
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-01-02T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "A critical vulnerability"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            },
                        }
                    ]
                },
                "references": [
                    {
                        "url": "https://example.com/advisory",
                        "source": "nvd@nist.gov",
                        "tags": ["Vendor Advisory"],
                    }
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                                        "matchCriteriaId": "12345",
                                    }
                                ],
                            }
                        ]
                    }
                ],
            }
        }

        vuln = client.parse_cve_record(cve_data)

        assert vuln.cve_id == "CVE-2024-0001"
        assert vuln.title == "CVE-2024-0001: A critical vulnerability..."
        assert vuln.description == "A critical vulnerability"
        assert vuln.severity == SeverityLevel.CRITICAL
        assert vuln.cvss_metrics[0].base_score == 9.8
        assert len(vuln.references) == 1
        assert vuln.references[0].url == "https://example.com/advisory"
        assert len(vuln.cpe_matches) == 1

    def test_parse_cve_record_minimal(self, client):
        """Test parsing CVE with minimal data."""
        cve_data = {
            "cve": {
                "id": "CVE-2024-0001",
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-01-02T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Minimal vulnerability"}],
            }
        }

        vuln = client.parse_cve_record(cve_data)

        assert vuln.cve_id == "CVE-2024-0001"
        assert vuln.description == "Minimal vulnerability"
        assert vuln.severity == SeverityLevel.NONE  # Default when no CVSS
        assert vuln.cvss_metrics == []
        assert vuln.references == []

    def test_parse_cve_record_invalid(self, client):
        """Test parsing invalid CVE record."""
        # Missing required fields
        assert client.parse_cve_record({}) is None
        assert client.parse_cve_record({"cve": {"id": "CVE-2024-0001"}}) is None

    def test_fetch_and_parse_recent_cves(self, client, sample_cve_response):
        """Test fetching and parsing recent CVEs."""
        with patch.object(
            client,
            "fetch_recent_cves",
            return_value=sample_cve_response["vulnerabilities"],
        ), patch.object(client, "parse_cve_record") as mock_parse:
            mock_parse.side_effect = [
                Mock(spec=Vulnerability, cve_id="CVE-2024-0001"),
                Mock(spec=Vulnerability, cve_id="CVE-2024-0002"),
            ]

            vulns = client.fetch_and_parse_recent_cves(days_back=7)

            assert len(vulns) == 2
            assert all(isinstance(v, Vulnerability) for v in vulns)
            assert vulns[0].cve_id == "CVE-2024-0001"
            assert vulns[1].cve_id == "CVE-2024-0002"

    def test_fetch_and_parse_recent_cves_with_filters(self, client):
        """Test fetching and parsing with severity filter."""
        with patch.object(client, "fetch_recent_cves", return_value=[]), patch.object(
            client, "parse_cve_record"
        ):
            vulns = client.fetch_and_parse_recent_cves(
                days_back=7, severity=SeverityLevel.CRITICAL
            )

            assert vulns == []
            client.fetch_recent_cves.assert_called_once_with(7, SeverityLevel.CRITICAL)

    def test_fetch_and_parse_recent_cves_parse_errors(self, client):
        """Test handling of parse errors."""
        raw_cves = [
            {"cve": {"id": "CVE-2024-0001"}},
            {"cve": {"id": "CVE-2024-0002"}},
            {"cve": {"id": "CVE-2024-0003"}},
        ]

        with patch.object(
            client, "fetch_recent_cves", return_value=raw_cves
        ), patch.object(client, "parse_cve_record") as mock_parse:
            # First and third parse successfully, second returns None
            mock_parse.side_effect = [
                Mock(spec=Vulnerability, cve_id="CVE-2024-0001"),
                None,  # Parse error
                Mock(spec=Vulnerability, cve_id="CVE-2024-0003"),
            ]

            vulns = client.fetch_and_parse_recent_cves()

            # Should only return successfully parsed vulns
            assert len(vulns) == 2
            assert vulns[0].cve_id == "CVE-2024-0001"
            assert vulns[1].cve_id == "CVE-2024-0003"

    def test_parse_cve_record_with_cvss_v2(self, client):
        """Test parsing CVE with CVSS v2 metrics."""
        cve_data = {
            "cve": {
                "id": "CVE-2024-0001",
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-01-02T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                "metrics": {
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                "baseScore": 9.5,
                            },
                        }
                    ]
                },
            }
        }

        vuln = client.parse_cve_record(cve_data)

        assert vuln is not None
        assert vuln.severity == SeverityLevel.CRITICAL  # 9.5 maps to CRITICAL
        assert vuln.cvss_metrics[0].base_score == 9.5
        assert vuln.cvss_metrics[0].version == "2.0"

    def test_parse_cve_record_with_multiple_cvss_versions(self, client):
        """Test parsing CVE with multiple CVSS versions."""
        cve_data = {
            "cve": {
                "id": "CVE-2024-0001",
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-01-02T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            },
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                "baseScore": 7.5,
                            },
                        }
                    ],
                },
            }
        }

        vuln = client.parse_cve_record(cve_data)

        assert vuln is not None
        assert vuln.severity == SeverityLevel.CRITICAL  # Uses highest severity
        assert len(vuln.cvss_metrics) == 2
        # v3.1 should be first
        assert vuln.cvss_metrics[0].version == "3.1"
        assert vuln.cvss_metrics[0].base_score == 9.8
        # v2 should be second
        assert vuln.cvss_metrics[1].version == "2.0"
        assert vuln.cvss_metrics[1].base_score == 7.5
