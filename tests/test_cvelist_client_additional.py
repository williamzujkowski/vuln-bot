"""Additional tests for CVEListClient to improve coverage."""

import json
import zipfile
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

    def test_ensure_local_repo_clones(self, client):
        """Test _ensure_local_repo clones repository if not exists."""
        # Mock Path to simulate non-existing repo
        with patch.object(client.local_repo_path, "exists", return_value=False), patch(
            "scripts.harvest.cvelist_client.subprocess.run"
        ) as mock_run:
            mock_run.return_value = Mock(returncode=0)
            client._ensure_local_repo()

            # Should call git clone
            mock_run.assert_called()
            assert "git" in mock_run.call_args[0][0][0]
            assert "clone" in mock_run.call_args[0][0]

    def test_ensure_local_repo_pulls(self, client, temp_repo_path):
        """Test _ensure_local_repo pulls if repo exists."""
        # Create .git directory to simulate existing repo
        git_dir = temp_repo_path / ".git"
        git_dir.mkdir()

        with patch("scripts.harvest.cvelist_client.subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0)
            client._ensure_local_repo()

            # Should call git pull
            assert mock_run.call_count == 2  # fetch and pull

    def test_fetch_cves_from_directory(self, client, temp_repo_path):
        """Test _fetch_cves_from_directory."""
        # Create test directory structure
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

        (year_dir / "CVE-2024-1001.json").write_text(json.dumps(cve1))
        (year_dir / "CVE-2024-1002.json").write_text(json.dumps(cve2))

        with patch.object(client, "parse_cve_v5_record") as mock_parse:
            mock_parse.side_effect = [
                Mock(spec=Vulnerability, severity=SeverityLevel.CRITICAL),
                Mock(spec=Vulnerability, severity=SeverityLevel.HIGH),
            ]

            vulnerabilities = client._fetch_cves_from_directory(
                str(year_dir), min_severity=SeverityLevel.HIGH, max_vulnerabilities=10
            )

            assert len(vulnerabilities) == 2
            assert mock_parse.call_count == 2

    def test_fetch_cves_from_directory_with_limit(self, client, temp_repo_path):
        """Test _fetch_cves_from_directory respects limit."""
        year_dir = temp_repo_path / "cves" / "2024" / "1xxx"
        year_dir.mkdir(parents=True)

        # Create 5 test CVE files
        for i in range(5):
            cve = {
                "cveMetadata": {"cveId": f"CVE-2024-100{i}", "state": "PUBLISHED"},
                "containers": {"cna": {}},
            }
            (year_dir / f"CVE-2024-100{i}.json").write_text(json.dumps(cve))

        with patch.object(client, "parse_cve_v5_record") as mock_parse:
            mock_parse.return_value = Mock(
                spec=Vulnerability, severity=SeverityLevel.HIGH
            )

            # Fetch with limit of 3
            vulnerabilities = client._fetch_cves_from_directory(
                str(year_dir), min_severity=SeverityLevel.LOW, max_vulnerabilities=3
            )

            assert len(vulnerabilities) == 3

    def test_fetch_cve_file_success(self, client, temp_repo_path):
        """Test _fetch_cve_file successfully reads file."""
        cve_file = temp_repo_path / "test.json"
        cve_data = {"cveMetadata": {"cveId": "CVE-2024-1234"}}
        cve_file.write_text(json.dumps(cve_data))

        result = client._fetch_cve_file(str(cve_file))
        assert result == cve_data

    def test_fetch_cve_file_invalid_json(self, client, temp_repo_path):
        """Test _fetch_cve_file handles invalid JSON."""
        cve_file = temp_repo_path / "invalid.json"
        cve_file.write_text("not valid json")

        result = client._fetch_cve_file(str(cve_file))
        assert result is None

    def test_fetch_cve_file_not_found(self, client):
        """Test _fetch_cve_file handles missing file."""
        result = client._fetch_cve_file("/nonexistent/file.json")
        assert result is None

    def test_should_skip_cve_reserved(self, client):
        """Test _should_skip_cve skips RESERVED CVEs."""
        assert client._should_skip_cve(
            "CVE-2024-0001", "/path/CVE-2024-0001-RESERVED.json"
        )

    def test_should_skip_cve_reject(self, client):
        """Test _should_skip_cve skips REJECT CVEs."""
        assert client._should_skip_cve(
            "CVE-2024-0001", "/path/CVE-2024-0001-REJECT.json"
        )

    def test_should_skip_cve_normal(self, client):
        """Test _should_skip_cve doesn't skip normal CVEs."""
        assert not client._should_skip_cve("CVE-2024-0001", "/path/CVE-2024-0001.json")

    def test_fetch_cves_from_releases(self, client):
        """Test _fetch_cves_from_releases."""
        mock_release = {
            "tag_name": "v5.0-2024.01.01",
            "published_at": "2024-01-01T00:00:00Z",
            "assets": [
                {
                    "name": "midnight-v5.json.zip",
                    "browser_download_url": "https://example.com/midnight.zip",
                }
            ],
        }

        with patch.object(client, "get", return_value=[mock_release]), patch.object(
            client, "_download_and_process_zip"
        ) as mock_download:
            mock_download.return_value = [Mock(spec=Vulnerability)]

            vulnerabilities = client._fetch_cves_from_releases(
                days_back=7, min_severity=SeverityLevel.HIGH, max_vulnerabilities=10
            )

            assert len(vulnerabilities) == 1
            mock_download.assert_called_once()

    def test_process_midnight_file(self, client, tmp_path):
        """Test _process_midnight_file."""
        # Create a midnight file with CVE entries
        midnight_data = {
            "cves": [
                {
                    "cveMetadata": {"cveId": "CVE-2024-0001", "state": "PUBLISHED"},
                    "containers": {"cna": {}},
                },
                {
                    "cveMetadata": {"cveId": "CVE-2024-0002", "state": "PUBLISHED"},
                    "containers": {"cna": {}},
                },
            ]
        }

        midnight_file = tmp_path / "midnight.json"
        midnight_file.write_text(json.dumps(midnight_data))

        with patch.object(client, "parse_cve_v5_record") as mock_parse:
            mock_parse.side_effect = [
                Mock(spec=Vulnerability),
                Mock(spec=Vulnerability),
            ]

            vulnerabilities = client._process_midnight_file(
                str(midnight_file),
                min_severity=SeverityLevel.LOW,
                max_vulnerabilities=10,
            )

            assert len(vulnerabilities) == 2

    def test_process_delta_files(self, client, tmp_path):
        """Test _process_delta_files."""
        # Create delta files
        delta1_data = {
            "new": [
                {
                    "cveMetadata": {"cveId": "CVE-2024-0001", "state": "PUBLISHED"},
                    "containers": {"cna": {}},
                }
            ],
            "updated": [
                {
                    "cveMetadata": {"cveId": "CVE-2024-0002", "state": "PUBLISHED"},
                    "containers": {"cna": {}},
                }
            ],
        }

        delta1_file = tmp_path / "delta_20240101.json"
        delta1_file.write_text(json.dumps(delta1_data))

        with patch.object(client, "parse_cve_v5_record") as mock_parse:
            mock_parse.side_effect = [
                Mock(spec=Vulnerability),
                Mock(spec=Vulnerability),
            ]

            vulnerabilities = client._process_delta_files(
                [str(delta1_file)],
                min_severity=SeverityLevel.LOW,
                max_vulnerabilities=10,
            )

            assert len(vulnerabilities) == 2

    def test_download_and_process_zip(self, client, tmp_path):
        """Test _download_and_process_zip."""
        # Create a test zip file
        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            # Add a midnight file
            midnight_data = {
                "cves": [
                    {
                        "cveMetadata": {"cveId": "CVE-2024-0001", "state": "PUBLISHED"},
                        "containers": {"cna": {}},
                    }
                ]
            }
            zf.writestr("midnight-v5.json", json.dumps(midnight_data))

            # Add a delta file
            delta_data = {
                "new": [
                    {
                        "cveMetadata": {"cveId": "CVE-2024-0002", "state": "PUBLISHED"},
                        "containers": {"cna": {}},
                    }
                ]
            }
            zf.writestr("delta_20240101.json", json.dumps(delta_data))

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value.read.return_value = (
                zip_path.read_bytes()
            )

            with patch.object(client, "parse_cve_v5_record") as mock_parse:
                mock_parse.side_effect = [
                    Mock(spec=Vulnerability),
                    Mock(spec=Vulnerability),
                ]

                vulnerabilities = client._download_and_process_zip(
                    "https://example.com/test.zip",
                    str(tmp_path / "extract"),
                    min_severity=SeverityLevel.LOW,
                    max_vulnerabilities=10,
                )

                assert len(vulnerabilities) == 2

    def test_process_zip_contents_midnight_only(self, client, tmp_path):
        """Test _process_zip_contents with midnight file only."""
        extract_dir = tmp_path / "extract"
        extract_dir.mkdir()

        # Create midnight file
        midnight_file = extract_dir / "midnight-v5.json"
        midnight_data = {"cves": []}
        midnight_file.write_text(json.dumps(midnight_data))

        with patch.object(client, "_process_midnight_file") as mock_process:
            mock_process.return_value = []

            client._process_zip_contents(
                str(extract_dir), min_severity=SeverityLevel.LOW, max_vulnerabilities=10
            )

            mock_process.assert_called_once()

    def test_process_zip_contents_with_deltas(self, client, tmp_path):
        """Test _process_zip_contents with delta files."""
        extract_dir = tmp_path / "extract"
        extract_dir.mkdir()

        # Create delta files
        for i in range(3):
            delta_file = extract_dir / f"delta_2024010{i}.json"
            delta_file.write_text(json.dumps({"new": [], "updated": []}))

        with patch.object(client, "_process_delta_files") as mock_process:
            mock_process.return_value = []

            client._process_zip_contents(
                str(extract_dir), min_severity=SeverityLevel.LOW, max_vulnerabilities=10
            )

            mock_process.assert_called_once()
            # Should process all 3 delta files
            assert len(mock_process.call_args[0][0]) == 3

    def test_should_skip_cve_in_zip(self, client):
        """Test _should_skip_cve_in_zip."""
        # Should skip REJECTED
        assert client._should_skip_cve_in_zip({"cveMetadata": {"state": "REJECTED"}})

        # Should skip without containers
        assert client._should_skip_cve_in_zip({"cveMetadata": {"state": "PUBLISHED"}})

        # Should not skip valid CVE
        assert not client._should_skip_cve_in_zip(
            {"cveMetadata": {"state": "PUBLISHED"}, "containers": {"cna": {}}}
        )

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

    def test_parse_cvss_metric_v2(self, client):
        """Test _parse_cvss_metric for CVSS v2.0."""
        metric_data = {
            "cvssV2_0": {
                "baseScore": 10.0,
                "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
            }
        }

        cvss_metric = client._parse_cvss_metric(metric_data)

        assert cvss_metric is not None
        assert cvss_metric.version == "2.0"
        assert cvss_metric.base_score == 10.0
        assert (
            cvss_metric.base_severity == SeverityLevel.CRITICAL
        )  # 10.0 maps to CRITICAL

    def test_harvest_from_local_repo(self, client, temp_repo_path):
        """Test harvest using local repository."""
        # Create test CVE structure
        year_dir = temp_repo_path / "cves" / "2024" / "1xxx"
        year_dir.mkdir(parents=True)

        cve_data = {
            "cveMetadata": {"cveId": "CVE-2024-1001", "state": "PUBLISHED"},
            "containers": {"cna": {}},
        }
        (year_dir / "CVE-2024-1001.json").write_text(json.dumps(cve_data))

        with patch.object(client, "_ensure_local_repo"), patch.object(
            client, "parse_cve_v5_record"
        ) as mock_parse:
            mock_parse.return_value = Mock(spec=Vulnerability)

            vulnerabilities = client.harvest(
                days_back=7, min_severity=SeverityLevel.LOW, limit=10
            )

            assert len(vulnerabilities) == 1

    def test_harvest_from_releases(self, client):
        """Test harvest using releases."""
        client.use_releases = True

        with patch.object(client, "_fetch_cves_from_releases") as mock_fetch:
            mock_fetch.return_value = [Mock(spec=Vulnerability)]

            vulnerabilities = client.harvest(
                days_back=7, min_severity=SeverityLevel.HIGH, limit=10
            )

            assert len(vulnerabilities) == 1
            mock_fetch.assert_called_once()

    def test_get_cve_subdir(self, client):
        """Test _get_cve_subdir."""
        assert client._get_cve_subdir("CVE-2024-1234") == "1xxx"
        assert client._get_cve_subdir("CVE-2024-12345") == "12xxx"
        assert client._get_cve_subdir("CVE-2024-123") == "0xxx"
        assert client._get_cve_subdir("CVE-2024-1") == "0xxx"
