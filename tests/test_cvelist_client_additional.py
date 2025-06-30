"""Additional tests for CVEListClient to improve coverage."""

import json
import zipfile
from datetime import datetime
from unittest.mock import Mock, patch

import pytest

from scripts.harvest.cvelist_client import CVEListClient
from scripts.models import SeverityLevel, Vulnerability


class TestCVEListClientAdditional:
    """Additional test cases for CVEListClient to improve coverage."""

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
            cache_dir=str(temp_repo_path / "cache"),
        )

    def test_ensure_local_repo_clones(self, client, temp_repo_path):
        """Test _ensure_local_repo clones repository if not exists."""
        # Remove the directory to simulate non-existing repo
        import shutil

        if temp_repo_path.exists():
            shutil.rmtree(temp_repo_path)

        with patch("scripts.harvest.cvelist_client.Repo.clone_from") as mock_clone:
            client._ensure_local_repo()

            # Should call Repo.clone_from
            mock_clone.assert_called_once_with(client.CLONE_URL, client.local_repo_path)

    def test_ensure_local_repo_pulls(self, client, temp_repo_path):
        """Test _ensure_local_repo pulls if repo exists."""
        # Create .git directory to simulate existing repo
        git_dir = temp_repo_path / ".git"
        git_dir.mkdir()

        # Mock the git operations
        mock_repo = Mock()
        mock_origin = Mock()
        mock_repo.remotes.origin = mock_origin

        with patch(
            "scripts.harvest.cvelist_client.Repo", return_value=mock_repo
        ) as mock_repo_class:
            client._ensure_local_repo()

            # Should create Repo object and pull
            mock_repo_class.assert_called_once_with(client.local_repo_path)
            mock_origin.pull.assert_called_once()

    def test_fetch_cves_from_directory(self, client):
        """Test _fetch_cves_from_directory."""
        # Mock the GitHub API response for directory listing
        mock_files = [
            {"name": "CVE-2024-1001.json", "type": "file"},
            {"name": "CVE-2024-1002.json", "type": "file"},
            {
                "name": "CVE-2024-1003.json",
                "type": "file",
            },  # Will be filtered out (LOW severity)
        ]

        # Create test CVE files
        cve1 = {
            "cveMetadata": {"cveId": "CVE-2024-1001", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "metrics": [
                        {"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                    ]
                }
            },
        }

        cve2 = {
            "cveMetadata": {"cveId": "CVE-2024-1002", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "metrics": [
                        {"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
                    ]
                }
            },
        }

        cve3 = {
            "cveMetadata": {"cveId": "CVE-2024-1003", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "metrics": [{"cvssV3_1": {"baseScore": 3.5, "baseSeverity": "LOW"}}]
                }
            },
        }

        with patch("requests.get") as mock_get:
            # Mock directory listing response
            dir_response = Mock()
            dir_response.json.return_value = mock_files
            dir_response.raise_for_status = Mock()

            # Mock individual file responses
            file_response1 = Mock()
            file_response1.json.return_value = cve1
            file_response1.raise_for_status = Mock()

            file_response2 = Mock()
            file_response2.json.return_value = cve2
            file_response2.raise_for_status = Mock()

            file_response3 = Mock()
            file_response3.json.return_value = cve3
            file_response3.raise_for_status = Mock()

            # Set up the mock to return different responses
            mock_get.side_effect = [
                dir_response,
                file_response1,
                file_response2,
                file_response3,
            ]

            # _fetch_cves_from_directory returns raw CVE data that meets severity threshold
            cve_records = client._fetch_cves_from_directory(
                "cves/2024/1xxx", min_severity=SeverityLevel.HIGH, incremental=False
            )

            # Should return only HIGH and CRITICAL CVEs
            assert len(cve_records) == 2
            assert cve_records[0]["cveMetadata"]["cveId"] == "CVE-2024-1001"
            assert cve_records[1]["cveMetadata"]["cveId"] == "CVE-2024-1002"

    def test_fetch_cves_from_directory_local_repo(self, client, temp_repo_path):
        """Test _fetch_cves_from_directory using local repository."""
        # Set client to use local repo instead of API
        client.use_github_api = False

        year_dir = temp_repo_path / "cves" / "2024" / "1xxx"
        year_dir.mkdir(parents=True)

        # Create test CVE files
        cve1 = {
            "cveMetadata": {"cveId": "CVE-2024-1001", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "metrics": [
                        {"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                    ]
                }
            },
        }
        (year_dir / "CVE-2024-1001.json").write_text(json.dumps(cve1))

        # This should use the local repo path
        cve_records = client._fetch_cves_from_directory(
            "cves/2024/1xxx", min_severity=SeverityLevel.HIGH, incremental=False
        )

        assert len(cve_records) == 1

    def test_fetch_cve_file_success(self, client):
        """Test _fetch_cve_file successfully reads file from GitHub."""
        cve_data = {"cveMetadata": {"cveId": "CVE-2024-1234"}}

        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.json.return_value = cve_data
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response

            result = client._fetch_cve_file("cves/2024/1xxx/CVE-2024-1234.json")
            assert result == cve_data

    def test_fetch_cve_file_error(self, client):
        """Test _fetch_cve_file handles request errors."""
        with patch("requests.get") as mock_get:
            mock_get.side_effect = Exception("Network error")

            result = client._fetch_cve_file("cves/2024/1xxx/CVE-2024-1234.json")
            assert result is None

    def test_fetch_cve_file_not_found(self, client):
        """Test _fetch_cve_file handles 404 errors."""
        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.raise_for_status.side_effect = Exception("404 Not Found")
            mock_get.return_value = mock_response

            result = client._fetch_cve_file("cves/2024/1xxx/CVE-2024-9999.json")
            assert result is None

    def test_should_skip_cve_no_cache(self, client):
        """Test _should_skip_cve without cache manager."""
        client.cache_manager = None
        result = client._should_skip_cve(
            "CVE-2024-0001", "cves/2024/0xxx/CVE-2024-0001.json"
        )
        assert result is False

    def test_should_skip_cve_with_cache(self, client):
        """Test _should_skip_cve with cached vulnerability."""
        from datetime import timezone

        # Mock cache manager
        mock_cache = Mock()
        cached_vuln = Mock(spec=Vulnerability)
        # Use timezone-aware datetime
        cached_vuln.last_modified_date = datetime(2024, 1, 2, tzinfo=timezone.utc)
        mock_cache.get_vulnerability.return_value = cached_vuln
        client.cache_manager = mock_cache

        # Mock GitHub API response with older date
        with patch("requests.get") as mock_get:
            mock_response = Mock()
            # This base64 encodes: {"cveMetadata": {"dateUpdated": "2024-01-01T00:00:00Z"}}
            mock_response.json.return_value = {
                "content": "eyJjdmVNZXRhZGF0YSI6IHsiZGF0ZVVwZGF0ZWQiOiAiMjAyNC0wMS0wMVQwMDowMDowMFoifX0=",
                "encoding": "base64",
            }
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response

            result = client._should_skip_cve(
                "CVE-2024-0001", "cves/2024/0xxx/CVE-2024-0001.json"
            )
            assert result is True

    def test_fetch_cves_from_releases(self, client):
        """Test _fetch_cves_from_releases."""
        mock_release = {
            "tag_name": "v5.0-2024.01.01",
            "published_at": "2024-01-01T00:00:00Z",
            "assets": [
                {
                    "name": "all_CVEs_at_midnight.json.zip",
                    "browser_download_url": "https://example.com/midnight.zip",
                    "size": 1024 * 1024,
                }
            ],
        }

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

        with patch("requests.get") as mock_get:
            # Mock release API response
            release_response = Mock()
            release_response.json.return_value = mock_release
            release_response.raise_for_status = Mock()

            # Return release response for first call
            mock_get.return_value = release_response

            with patch.object(client, "_download_and_process_zip") as mock_download:
                mock_download.return_value = [cve_data]

                cves = client._fetch_cves_from_releases(
                    year=2024, min_severity=SeverityLevel.HIGH, incremental=False
                )

                assert len(cves) == 1
                mock_download.assert_called_once()

    def test_process_midnight_file(self, client):
        """Test _process_midnight_file."""
        mock_release = {
            "assets": [
                {
                    "name": "all_CVEs_at_midnight_utc.json.zip",
                    "browser_download_url": "https://example.com/midnight.zip",
                    "size": 1024 * 1024,
                }
            ]
        }

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

        with patch.object(client, "_download_and_process_zip") as mock_download:
            mock_download.return_value = [cve_data]

            cves = client._process_midnight_file(
                mock_release,
                year=2024,
                min_severity=SeverityLevel.LOW,
                incremental=False,
            )

            assert len(cves) == 1
            mock_download.assert_called_once()

    def test_process_delta_files(self, client):
        """Test _process_delta_files."""
        mock_release = {
            "assets": [
                {
                    "name": "delta_CVEs_2024-01-01.json.zip",
                    "browser_download_url": "https://example.com/delta1.zip",
                    "size": 1024,
                },
                {
                    "name": "delta_CVEs_2024-01-02.json.zip",
                    "browser_download_url": "https://example.com/delta2.zip",
                    "size": 1024,
                },
            ]
        }

        cve_data = {
            "cveMetadata": {
                "cveId": "CVE-2024-0001",
                "datePublished": "2024-01-01T00:00:00Z",
            },
            "containers": {
                "cna": {
                    "metrics": [
                        {"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
                    ]
                }
            },
        }

        with patch.object(client, "_download_and_process_zip") as mock_download:
            mock_download.return_value = [cve_data]

            cves = client._process_delta_files(
                mock_release, year=2024, min_severity=SeverityLevel.LOW
            )

            assert len(cves) == 2  # Two delta files processed
            assert mock_download.call_count == 2

    def test_download_and_process_zip(self, client, tmp_path):
        """Test _download_and_process_zip."""
        # Create a test zip file with nested structure
        zip_path = tmp_path / "test.zip"
        inner_zip_path = tmp_path / "cves.zip"

        # Create inner zip with CVE files
        with zipfile.ZipFile(inner_zip_path, "w") as inner_zf:
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
            inner_zf.writestr("cves/2024/0xxx/CVE-2024-0001.json", json.dumps(cve_data))

        # Create outer zip containing inner zip
        with zipfile.ZipFile(zip_path, "w") as outer_zf:
            outer_zf.write(inner_zip_path, "cves.zip")

        mock_asset = {
            "name": "test.zip",
            "browser_download_url": "https://example.com/test.zip",
            "size": 1024,
        }

        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.iter_content = lambda _: [zip_path.read_bytes()]
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response

            cves = client._download_and_process_zip(
                mock_asset, year=2024, min_severity=SeverityLevel.LOW, incremental=False
            )

            assert len(cves) == 1

    def test_process_zip_contents(self, client, tmp_path):
        """Test _process_zip_contents."""
        # Create a zip file with CVE files for testing
        zip_path = tmp_path / "test.zip"

        with zipfile.ZipFile(zip_path, "w") as zf:
            # Add CVE files for year 2024
            cve1_data = {
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
            zf.writestr("cves/2024/0xxx/CVE-2024-0001.json", json.dumps(cve1_data))

            # Add a LOW severity CVE that should be filtered out
            cve2_data = {
                "cveMetadata": {
                    "cveId": "CVE-2024-0002",
                    "datePublished": "2024-01-01T00:00:00Z",
                },
                "containers": {
                    "cna": {
                        "metrics": [
                            {"cvssV3_1": {"baseScore": 3.0, "baseSeverity": "LOW"}}
                        ]
                    }
                },
            }
            zf.writestr("cves/2024/0xxx/CVE-2024-0002.json", json.dumps(cve2_data))

        mock_asset = {"name": "test.zip"}

        with zipfile.ZipFile(zip_path, "r") as zf:
            cves = client._process_zip_contents(
                zf,
                mock_asset,
                year=2024,
                min_severity=SeverityLevel.HIGH,
                incremental=False,
            )

            # Should only return the CRITICAL severity CVE
            assert len(cves) == 1
            assert cves[0]["cveMetadata"]["cveId"] == "CVE-2024-0001"

    def test_should_skip_cve_in_zip(self, client, tmp_path):
        """Test _should_skip_cve_in_zip."""
        # Create a test zip file
        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            cve_data = {
                "cveMetadata": {
                    "cveId": "CVE-2024-0001",
                    "dateUpdated": "2024-01-02T00:00:00Z",
                }
            }
            zf.writestr("CVE-2024-0001.json", json.dumps(cve_data))

        # Test without cache manager
        client.cache_manager = None
        with zipfile.ZipFile(zip_path, "r") as zf:
            result = client._should_skip_cve_in_zip(
                "CVE-2024-0001", zf, "CVE-2024-0001.json"
            )
            assert result is False

        # Test with cache manager and older cached version
        mock_cache = Mock()
        cached_vuln = Mock()
        cached_vuln.last_modified_date = datetime(2024, 1, 1)
        mock_cache.get_vulnerability.return_value = cached_vuln
        client.cache_manager = mock_cache

        with zipfile.ZipFile(zip_path, "r") as zf:
            result = client._should_skip_cve_in_zip(
                "CVE-2024-0001", zf, "CVE-2024-0001.json"
            )
            assert result is False  # Should not skip because update is newer

    def test_parse_cvss_metric_v31(self, client):
        """Test _parse_cvss_metric for CVSS v3.1."""
        metric_data = {
            "cvssV3_1": {
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "exploitabilityScore": 3.9,
                "impactScore": 5.9,
            }
        }

        cvss_metric = client._parse_cvss_metric(metric_data)

        assert cvss_metric is not None
        assert cvss_metric.version == "3.1"
        assert cvss_metric.base_score == 9.8
        assert cvss_metric.base_severity == SeverityLevel.CRITICAL

    def test_parse_cvss_metric_v30(self, client):
        """Test _parse_cvss_metric for CVSS v3.0."""
        metric_data = {
            "cvssV3_0": {
                "baseScore": 7.5,
                "baseSeverity": "HIGH",
                "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            }
        }

        cvss_metric = client._parse_cvss_metric(metric_data)

        assert cvss_metric is not None
        assert cvss_metric.version == "3.0"
        assert cvss_metric.base_score == 7.5

    def test_parse_cvss_metric_none(self, client):
        """Test _parse_cvss_metric with unsupported version."""
        metric_data = {
            "cvssV2_0": {
                "baseScore": 10.0,
                "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
            }
        }

        cvss_metric = client._parse_cvss_metric(metric_data)

        # Should return None for unsupported CVSS versions
        assert cvss_metric is None

    def test_harvest_from_local_repo(self, client, temp_repo_path):
        """Test harvest using local repository."""
        # Set client to use local repo
        client.use_github_api = False

        # Create test CVE structure
        year_dir = temp_repo_path / "cves" / "2024" / "1xxx"
        year_dir.mkdir(parents=True)

        cve_data = {
            "cveMetadata": {
                "cveId": "CVE-2024-1001",
                "datePublished": "2024-01-01T00:00:00Z",
            },
            "containers": {
                "cna": {
                    "title": "Test CVE",
                    "descriptions": [{"lang": "en", "value": "Test description"}],
                    "metrics": [
                        {"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
                    ],
                }
            },
        }
        (year_dir / "CVE-2024-1001.json").write_text(json.dumps(cve_data))

        with patch.object(client, "_ensure_local_repo"):
            vulnerabilities = client.harvest(
                years=[2024], min_severity=SeverityLevel.LOW, max_vulnerabilities=10
            )

            assert len(vulnerabilities) == 1
            assert vulnerabilities[0].cve_id == "CVE-2024-1001"

    def test_harvest_from_releases(self, client):
        """Test harvest using releases."""
        client.use_releases = True

        cve_data = {
            "cveMetadata": {
                "cveId": "CVE-2024-1001",
                "datePublished": "2024-01-01T00:00:00Z",
            },
            "containers": {
                "cna": {
                    "title": "Test CVE",
                    "descriptions": [{"lang": "en", "value": "Test description"}],
                    "metrics": [
                        {"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                    ],
                }
            },
        }

        with patch.object(client, "_fetch_cves_from_releases") as mock_fetch:
            mock_fetch.return_value = [cve_data]

            vulnerabilities = client.harvest(
                years=[2024], min_severity=SeverityLevel.HIGH, max_vulnerabilities=10
            )

            assert len(vulnerabilities) == 1
            assert vulnerabilities[0].cve_id == "CVE-2024-1001"
            mock_fetch.assert_called_once_with(2024, SeverityLevel.HIGH, False)

    def test_get_cve_subdir(self, client):
        """Test _get_cve_subdir."""
        assert client._get_cve_subdir("CVE-2024-1234") == "1xxx"
        assert client._get_cve_subdir("CVE-2024-12345") == "12xxx"
        assert client._get_cve_subdir("CVE-2024-123") == "0xxx"
        assert client._get_cve_subdir("CVE-2024-1") == "0xxx"
