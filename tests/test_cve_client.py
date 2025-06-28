"""Tests for CVE API client."""

from unittest.mock import patch

from scripts.harvest.cve_client import CVEClient
from scripts.models import SeverityLevel


class TestCVEClient:
    """Test CVEClient functionality."""

    def test_initialization(self, tmp_path):
        """Test client initialization."""
        client = CVEClient(cache_dir=tmp_path, api_key="test-key")
        assert client.base_url == "https://services.nvd.nist.gov/rest/json/cves/2.0"
        assert client._api_key == "test-key"

    def test_initialization_no_api_key(self, tmp_path):
        """Test client initialization without API key."""
        client = CVEClient(cache_dir=tmp_path)
        assert client._api_key is None

    @patch.object(CVEClient, "_make_request")
    def test_fetch_recent_cves_success(self, mock_request, tmp_path):
        """Test fetching recent CVEs successfully."""
        mock_request.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-0001",
                        "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                        "published": "2023-01-01T00:00:00.000",
                        "lastModified": "2023-01-02T00:00:00.000",
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
                            {"url": "https://example.com/advisory", "tags": []}
                        ],
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                }
            ],
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
        }

        client = CVEClient(cache_dir=tmp_path)
        result = client.fetch_recent_cves(days_back=7)

        assert len(result) == 1
        assert result[0]["cve"]["id"] == "CVE-2023-0001"
        mock_request.assert_called_once()

    @patch.object(CVEClient, "_make_request")
    def test_fetch_recent_cves_pagination(self, mock_request, tmp_path):
        """Test fetching CVEs with pagination."""
        # First page
        mock_request.side_effect = [
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": f"CVE-2023-{i:04d}",
                            "descriptions": [{"lang": "en", "value": f"Vuln {i}"}],
                            "published": "2023-01-01T00:00:00.000",
                            "lastModified": "2023-01-02T00:00:00.000",
                        }
                    }
                    for i in range(2000)
                ],
                "resultsPerPage": 2000,
                "startIndex": 0,
                "totalResults": 3000,
            },
            # Second page
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": f"CVE-2023-{i:04d}",
                            "descriptions": [{"lang": "en", "value": f"Vuln {i}"}],
                            "published": "2023-01-01T00:00:00.000",
                            "lastModified": "2023-01-02T00:00:00.000",
                        }
                    }
                    for i in range(2000, 3000)
                ],
                "resultsPerPage": 1000,
                "startIndex": 2000,
                "totalResults": 3000,
            },
        ]

        client = CVEClient(cache_dir=tmp_path)
        result = client.fetch_recent_cves(days_back=7)

        assert len(result) == 3000
        assert mock_request.call_count == 2

    @patch.object(CVEClient, "_make_request")
    def test_fetch_recent_cves_empty_response(self, mock_request, tmp_path):
        """Test handling empty CVE response."""
        mock_request.return_value = {
            "vulnerabilities": [],
            "resultsPerPage": 0,
            "startIndex": 0,
            "totalResults": 0,
        }

        client = CVEClient(cache_dir=tmp_path)
        result = client.fetch_recent_cves(days_back=7)

        assert result == []

    @patch.object(CVEClient, "_make_request")
    def test_fetch_recent_cves_with_api_key(self, mock_request, tmp_path):
        """Test API key is included in headers."""
        mock_request.return_value = {
            "vulnerabilities": [],
            "resultsPerPage": 0,
            "startIndex": 0,
            "totalResults": 0,
        }

        client = CVEClient(cache_dir=tmp_path, api_key="test-key")
        client.fetch_recent_cves(days_back=7)

        # Check that API key header was passed
        _, kwargs = mock_request.call_args
        assert kwargs["headers"] == {"apiKey": "test-key"}

    def test_parse_vulnerabilities(self, tmp_path):
        """Test parsing CVE data into Vulnerability objects."""
        client = CVEClient(cache_dir=tmp_path)

        cve_data = [
            {
                "cve": {
                    "id": "CVE-2023-0001",
                    "descriptions": [
                        {"lang": "en", "value": "Test vulnerability description"}
                    ],
                    "published": "2023-01-01T00:00:00.000",
                    "lastModified": "2023-01-02T00:00:00.000",
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
                            "tags": ["Vendor Advisory"],
                        }
                    ],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:apache:commons:1.0:*:*:*:*:*:*:*",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]

        vulnerabilities = client.parse_vulnerabilities(cve_data)

        assert len(vulnerabilities) == 1
        vuln = vulnerabilities[0]
        assert vuln.cve_id == "CVE-2023-0001"
        assert vuln.title == "CVE-2023-0001"
        assert vuln.description == "Test vulnerability description"
        assert vuln.severity == SeverityLevel.CRITICAL
        assert vuln.cvss_metrics is not None
        assert vuln.cvss_metrics.base_score == 9.8
        assert (
            vuln.cvss_metrics.vector_string
            == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        assert len(vuln.references) == 1
        assert vuln.affected_vendors == ["apache"]

    def test_parse_vulnerabilities_no_cvss(self, tmp_path):
        """Test parsing CVE without CVSS metrics."""
        client = CVEClient(cache_dir=tmp_path)

        cve_data = [
            {
                "cve": {
                    "id": "CVE-2023-0002",
                    "descriptions": [{"lang": "en", "value": "No CVSS vulnerability"}],
                    "published": "2023-01-01T00:00:00.000",
                    "lastModified": "2023-01-02T00:00:00.000",
                    "metrics": {},
                    "references": [],
                }
            }
        ]

        vulnerabilities = client.parse_vulnerabilities(cve_data)

        assert len(vulnerabilities) == 1
        vuln = vulnerabilities[0]
        assert vuln.cve_id == "CVE-2023-0002"
        assert vuln.cvss_metrics is None
        assert vuln.severity == SeverityLevel.NONE

    def test_parse_vulnerabilities_multiple_descriptions(self, tmp_path):
        """Test parsing CVE with multiple language descriptions."""
        client = CVEClient(cache_dir=tmp_path)

        cve_data = [
            {
                "cve": {
                    "id": "CVE-2023-0003",
                    "descriptions": [
                        {"lang": "es", "value": "Descripción en español"},
                        {"lang": "en", "value": "English description"},
                        {"lang": "fr", "value": "Description française"},
                    ],
                    "published": "2023-01-01T00:00:00.000",
                    "lastModified": "2023-01-02T00:00:00.000",
                }
            }
        ]

        vulnerabilities = client.parse_vulnerabilities(cve_data)

        assert len(vulnerabilities) == 1
        # Should prefer English description
        assert vulnerabilities[0].description == "English description"

    def test_parse_vulnerabilities_no_english_description(self, tmp_path):
        """Test parsing CVE without English description."""
        client = CVEClient(cache_dir=tmp_path)

        cve_data = [
            {
                "cve": {
                    "id": "CVE-2023-0004",
                    "descriptions": [
                        {"lang": "es", "value": "Solo español"},
                    ],
                    "published": "2023-01-01T00:00:00.000",
                    "lastModified": "2023-01-02T00:00:00.000",
                }
            }
        ]

        vulnerabilities = client.parse_vulnerabilities(cve_data)

        assert len(vulnerabilities) == 1
        # Should fall back to first available description
        assert vulnerabilities[0].description == "Solo español"

    def test_parse_vulnerabilities_vendor_extraction(self, tmp_path):
        """Test extracting vendor information from CPE configurations."""
        client = CVEClient(cache_dir=tmp_path)

        cve_data = [
            {
                "cve": {
                    "id": "CVE-2023-0005",
                    "descriptions": [{"lang": "en", "value": "Multi-vendor vuln"}],
                    "published": "2023-01-01T00:00:00.000",
                    "lastModified": "2023-01-02T00:00:00.000",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*",
                                        },
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:adobe:reader:*:*:*:*:*:*:*:*",
                                        },
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]

        vulnerabilities = client.parse_vulnerabilities(cve_data)

        assert len(vulnerabilities) == 1
        vendors = vulnerabilities[0].affected_vendors
        assert "microsoft" in vendors
        assert "adobe" in vendors

    def test_parse_vulnerabilities_cvss_v2(self, tmp_path):
        """Test parsing CVE with CVSS v2 metrics."""
        client = CVEClient(cache_dir=tmp_path)

        cve_data = [
            {
                "cve": {
                    "id": "CVE-2023-0006",
                    "descriptions": [{"lang": "en", "value": "CVSS v2 vuln"}],
                    "published": "2023-01-01T00:00:00.000",
                    "lastModified": "2023-01-02T00:00:00.000",
                    "metrics": {
                        "cvssMetricV2": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                    "baseScore": 10.0,
                                },
                            }
                        ]
                    },
                }
            }
        ]

        vulnerabilities = client.parse_vulnerabilities(cve_data)

        assert len(vulnerabilities) == 1
        vuln = vulnerabilities[0]
        assert vuln.cvss_metrics.version == "2.0"
        assert vuln.cvss_metrics.base_score == 10.0
        assert vuln.severity == SeverityLevel.CRITICAL

    def test_parse_vulnerabilities_error_handling(self, tmp_path):
        """Test error handling in vulnerability parsing."""
        client = CVEClient(cache_dir=tmp_path)

        # Invalid date format
        cve_data = [
            {
                "cve": {
                    "id": "CVE-2023-0007",
                    "descriptions": [{"lang": "en", "value": "Invalid date"}],
                    "published": "invalid-date",
                    "lastModified": "2023-01-02T00:00:00.000",
                }
            }
        ]

        # Should skip invalid entries
        vulnerabilities = client.parse_vulnerabilities(cve_data)
        assert len(vulnerabilities) == 0

    @patch.object(CVEClient, "_make_request")
    def test_harvest_error_handling(self, mock_request, tmp_path):
        """Test error handling in harvest method."""
        mock_request.side_effect = Exception("API Error")

        client = CVEClient(cache_dir=tmp_path)
        with patch("scripts.harvest.cve_client.logger") as mock_logger:
            result = client.harvest(days_back=7)
            assert result == []
            mock_logger.error.assert_called_once()
