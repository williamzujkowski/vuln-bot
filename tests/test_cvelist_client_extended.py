"""Extended tests for CVEList client to improve coverage."""

from datetime import datetime
from unittest.mock import Mock, patch

import pytest
import requests

from scripts.harvest.cvelist_client import CVEListClient
from scripts.models import SeverityLevel


class TestCVEListClientExtended:
    """Extended test cases for CVEListClient."""

    @pytest.fixture
    def client(self, tmp_path):
        """Create CVEListClient instance."""
        return CVEListClient(cache_dir=tmp_path / "cache", github_token="test-token")

    def test_fetch_directory_listing(self, client):
        """Test fetching directory listing from GitHub API."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name": "CVE-2024-0001.json", "type": "file"},
            {"name": "CVE-2024-0002.json", "type": "file"},
            {"name": "README.md", "type": "file"},
        ]

        with patch.object(client.session, "get", return_value=mock_response):
            files = client._fetch_directory_listing("2024/0xxx")

            # Should only return CVE JSON files
            assert len(files) == 2
            assert all(f.startswith("CVE-") for f in files)

    def test_fetch_directory_listing_pagination(self, client):
        """Test handling of paginated directory listings."""
        # First page
        mock_response1 = Mock()
        mock_response1.status_code = 200
        mock_response1.json.return_value = [
            {"name": f"CVE-2024-{i:04d}.json", "type": "file"} for i in range(100)
        ]
        mock_response1.links = {"next": {"url": "https://api.github.com/next"}}

        # Second page
        mock_response2 = Mock()
        mock_response2.status_code = 200
        mock_response2.json.return_value = [
            {"name": f"CVE-2024-{i:04d}.json", "type": "file"} for i in range(100, 150)
        ]
        mock_response2.links = {}

        with patch.object(
            client.session, "get", side_effect=[mock_response1, mock_response2]
        ):
            files = client._fetch_directory_listing("2024/0xxx")

            assert len(files) == 150

    def test_fetch_directory_listing_error(self, client):
        """Test error handling in directory listing."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = requests.HTTPError("Not found")

        with patch.object(client.session, "get", return_value=mock_response):
            files = client._fetch_directory_listing("invalid/path")

            # Should return empty list on error
            assert files == []

    def test_harvest_year_directory(self, client):
        """Test harvesting a full year directory."""
        # Mock subdirectory listings
        subdirs = ["0xxx", "1xxx", "2xxx"]

        def mock_get(url, **kwargs):  # noqa: ARG001
            response = Mock()
            response.status_code = 200

            if url.endswith("/2024"):
                # Year directory listing
                response.json.return_value = [
                    {"name": subdir, "type": "dir"} for subdir in subdirs
                ]
            elif any(subdir in url for subdir in subdirs):
                # Subdirectory listing
                response.json.return_value = [
                    {"name": "CVE-2024-0001.json", "type": "file"}
                ]
            else:
                # CVE file content
                response.json.return_value = {
                    "cveMetadata": {"cveId": "CVE-2024-0001"},
                    "containers": {
                        "cna": {
                            "metrics": [
                                {
                                    "cvssV3_1": {
                                        "baseScore": 9.0,
                                        "baseSeverity": "CRITICAL",
                                    }
                                }
                            ]
                        }
                    },
                }

            response.links = {}
            return response

        with patch.object(client.session, "get", side_effect=mock_get):
            vulns = list(
                client._harvest_year_directory(2024, min_severity=SeverityLevel.HIGH)
            )

            # Should process vulnerabilities from all subdirectories
            assert len(vulns) > 0

    def test_parse_cisa_adp_container(self, client):
        """Test parsing CISA ADP container data."""
        cve_data = {
            "cveMetadata": {"cveId": "CVE-2024-0001"},
            "containers": {
                "cna": {
                    "metrics": [
                        {"cvssV3_1": {"baseScore": 8.0, "baseSeverity": "HIGH"}}
                    ]
                },
                "adp": [
                    {
                        "providerMetadata": {"shortName": "CISA-ADP"},
                        "metrics": [
                            {
                                "other": {
                                    "type": "ssvc",
                                    "content": {
                                        "exploitability": "active",
                                        "cisaKev": True,
                                    },
                                }
                            }
                        ],
                    }
                ],
            },
        }

        vuln = client._parse_cve_v5_record(cve_data)

        assert vuln is not None
        assert vuln.tags is not None
        assert "cisa-kev" in vuln.tags
        assert "active-exploitation" in vuln.tags

    def test_filter_by_date_range(self, client):
        """Test date range filtering."""
        # Create vulnerabilities with different dates
        recent_cve = {
            "cveMetadata": {
                "cveId": "CVE-2024-0001",
                "datePublished": datetime.now().isoformat(),
            },
            "containers": {
                "cna": {
                    "metrics": [
                        {"cvssV3_1": {"baseScore": 9.0, "baseSeverity": "CRITICAL"}}
                    ]
                }
            },
        }

        old_cve = {
            "cveMetadata": {
                "cveId": "CVE-2023-0001",
                "datePublished": "2023-01-01T00:00:00Z",
            },
            "containers": {
                "cna": {
                    "metrics": [
                        {"cvssV3_1": {"baseScore": 9.0, "baseSeverity": "CRITICAL"}}
                    ]
                }
            },
        }

        # Parse both
        recent_vuln = client._parse_cve_v5_record(recent_cve)
        old_vuln = client._parse_cve_v5_record(old_cve)

        assert recent_vuln is not None
        assert old_vuln is not None

        # Check dates
        assert recent_vuln.published.year == datetime.now().year
        assert old_vuln.published.year == 2023

    def test_batch_processing(self, client):
        """Test batch processing of CVE files."""
        cve_files = [f"CVE-2024-{i:04d}.json" for i in range(10)]

        def mock_get(url, **kwargs):  # noqa: ARG001
            response = Mock()
            response.status_code = 200

            # Extract CVE ID from URL
            cve_id = url.split("/")[-1].replace(".json", "")

            response.json.return_value = {
                "cveMetadata": {"cveId": cve_id},
                "containers": {
                    "cna": {
                        "metrics": [
                            {"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
                        ]
                    }
                },
            }

            return response

        with patch.object(client.session, "get", side_effect=mock_get):
            vulns = list(
                client._process_cve_batch(
                    cve_files, "2024/0xxx", min_severity=SeverityLevel.HIGH
                )
            )

            assert len(vulns) == 10
            assert all(v.severity == SeverityLevel.HIGH for v in vulns)

    def test_rate_limit_handling(self, client):
        """Test GitHub API rate limit handling."""
        # First request hits rate limit
        rate_limit_response = Mock()
        rate_limit_response.status_code = 403
        rate_limit_response.headers = {
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": str(int(datetime.now().timestamp()) + 60),
        }
        rate_limit_response.raise_for_status.side_effect = requests.HTTPError(
            "Rate limited"
        )

        # Second request succeeds
        success_response = Mock()
        success_response.status_code = 200
        success_response.json.return_value = []

        with patch.object(
            client.session, "get", side_effect=[rate_limit_response, success_response]
        ), patch("time.sleep"):  # Don't actually sleep in tests
            files = client._fetch_directory_listing("2024/0xxx")

            # Should retry after rate limit
            assert isinstance(files, list)
