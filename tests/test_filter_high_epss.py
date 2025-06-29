"""Tests for filter_high_epss module."""

import json
from unittest.mock import patch

import pytest

from scripts.filter_high_epss import filter_high_epss_vulns, organize_into_subfolders


class TestFilterHighEPSS:
    """Test cases for filtering high EPSS vulnerabilities."""

    @pytest.fixture
    def sample_vulnerability_data(self):
        """Create sample vulnerability data for testing."""
        return {
            "vulnerabilities": [
                {
                    "cveId": "CVE-2024-0001",
                    "epssScore": 85.5,
                    "severity": "CRITICAL",
                    "publishedDate": "2024-01-01T00:00:00Z",
                },
                {
                    "cveId": "CVE-2024-0002",
                    "epssScore": 70.0,
                    "severity": "HIGH",
                    "publishedDate": "2024-01-02T00:00:00Z",
                },
                {
                    "cveId": "CVE-2024-0003",
                    "epssScore": 65.5,
                    "severity": "HIGH",
                    "publishedDate": "2024-01-03T00:00:00Z",
                },
                {
                    "cveId": "CVE-2024-0004",
                    "epssScore": 50.0,
                    "severity": "MEDIUM",
                    "publishedDate": "2024-01-04T00:00:00Z",
                },
                {
                    "cveId": "CVE-2025-0001",
                    "epssScore": 90.0,
                    "severity": "CRITICAL",
                    "publishedDate": "2025-01-01T00:00:00Z",
                },
                {
                    "cveId": "CVE-2025-0002",
                    "epssScore": None,  # No EPSS score
                    "severity": "HIGH",
                    "publishedDate": "2025-01-02T00:00:00Z",
                },
            ],
            "count": 6,
            "generated": "2024-01-01T00:00:00Z",
        }

    def test_filter_high_epss_vulns_success(self, tmp_path, sample_vulnerability_data):
        """Test successful filtering of high EPSS vulnerabilities."""
        # Create source and target directories
        src_dir = tmp_path / "src" / "api" / "vulns"
        src_dir.mkdir(parents=True)
        public_dir = tmp_path / "public" / "api" / "vulns"

        # Write source data
        source_file = src_dir / "index.json"
        source_file.write_text(json.dumps(sample_vulnerability_data))

        # Patch paths
        with patch("scripts.filter_high_epss.source_index", str(source_file)), patch(
            "scripts.filter_high_epss.target_index", str(public_dir / "index.json")
        ), patch("os.makedirs") as mock_makedirs:
            filter_high_epss_vulns()

            # Check output directory was created
            mock_makedirs.assert_called_once_with("public/api/vulns", exist_ok=True)

            # Read filtered data
            target_file = public_dir / "index.json"
            assert target_file.exists()

            with open(target_file) as f:
                filtered_data = json.load(f)

            # Check filtering results - should have 3 vulns with EPSS >= 70
            assert filtered_data["count"] == 3
            assert len(filtered_data["vulnerabilities"]) == 3

            # Check correct vulns were kept
            cve_ids = [v["cveId"] for v in filtered_data["vulnerabilities"]]
            assert "CVE-2024-0001" in cve_ids  # 85.5%
            assert "CVE-2024-0002" in cve_ids  # 70.0%
            assert "CVE-2025-0001" in cve_ids  # 90.0%

            # These should be filtered out
            assert "CVE-2024-0003" not in cve_ids  # 65.5%
            assert "CVE-2024-0004" not in cve_ids  # 50.0%
            assert "CVE-2025-0002" not in cve_ids  # None

    def test_filter_high_epss_vulns_no_source_file(self):
        """Test handling when source file doesn't exist."""
        with patch("os.path.exists", return_value=False), patch(
            "builtins.print"
        ) as mock_print:
            filter_high_epss_vulns()

            # Should print error message
            mock_print.assert_called_with(
                "Error: src/api/vulns/index.json not found. Run generate-briefing first."
            )

    def test_filter_high_epss_vulns_with_backup(
        self, tmp_path, sample_vulnerability_data
    ):
        """Test backup creation when target file exists."""
        # Create directories
        src_dir = tmp_path / "src" / "api" / "vulns"
        src_dir.mkdir(parents=True)
        public_dir = tmp_path / "public" / "api" / "vulns"
        public_dir.mkdir(parents=True)

        # Write source data
        source_file = src_dir / "index.json"
        source_file.write_text(json.dumps(sample_vulnerability_data))

        # Create existing target file
        target_file = public_dir / "index.json"
        existing_data = {"existing": "data"}
        target_file.write_text(json.dumps(existing_data))

        # Patch paths
        with patch("scripts.filter_high_epss.source_index", str(source_file)), patch(
            "scripts.filter_high_epss.target_index", str(target_file)
        ):
            filter_high_epss_vulns()

            # Check backup was created
            backup_file = public_dir / "index.json.backup"
            assert backup_file.exists()

            with open(backup_file) as f:
                backup_data = json.load(f)
            assert backup_data == existing_data

    def test_organize_into_subfolders(self, tmp_path):
        """Test organizing vulnerabilities into batched subfolders."""
        # Create base directory
        base_dir = tmp_path / "public" / "api" / "vulns"
        base_dir.mkdir(parents=True)

        # Create a large list of vulnerabilities
        vulns = []
        for i in range(2500):  # More than 1000 to trigger subfolder creation
            vulns.append(
                {"cveId": f"CVE-2024-{i:04d}", "epssScore": 75.0, "severity": "HIGH"}
            )

        organize_into_subfolders(vulns, str(base_dir))

        # Check batch directories were created
        assert (base_dir / "batch_001").exists()
        assert (base_dir / "batch_002").exists()
        assert (base_dir / "batch_003").exists()

        # Check batch index files
        batch1_index = base_dir / "batch_001" / "index.json"
        assert batch1_index.exists()

        with open(batch1_index) as f:
            batch1_data = json.load(f)
        assert batch1_data["count"] == 1000
        assert batch1_data["batch"] == 1

        # Check master index
        master_index = base_dir / "batches.json"
        assert master_index.exists()

    def test_organize_into_subfolders_small_set(self, tmp_path):
        """Test organizing with fewer than 1000 vulnerabilities."""
        base_dir = tmp_path / "public" / "api" / "vulns"
        base_dir.mkdir(parents=True)

        # Create a small list (less than 1000)
        vulns = []
        for i in range(500):
            vulns.append(
                {"cveId": f"CVE-2024-{i:04d}", "epssScore": 75.0, "severity": "HIGH"}
            )

        organize_into_subfolders(vulns, str(base_dir))

        # Should create only one batch
        assert (base_dir / "batch_001").exists()
        assert not (base_dir / "batch_002").exists()

        # Check the batch has all 500 items
        batch1_index = base_dir / "batch_001" / "index.json"
        with open(batch1_index) as f:
            batch1_data = json.load(f)
        assert batch1_data["count"] == 500

    def test_filter_calls_organize_for_large_dataset(self, tmp_path):
        """Test that filter_high_epss_vulns calls organize_into_subfolders for large datasets."""
        # Create source with > 1000 high EPSS vulns
        src_dir = tmp_path / "src" / "api" / "vulns"
        src_dir.mkdir(parents=True)
        public_dir = tmp_path / "public" / "api" / "vulns"

        # Create test data with > 1000 high EPSS vulns
        vulns = []
        for i in range(1500):
            vulns.append(
                {
                    "cveId": f"CVE-2024-{i:04d}",
                    "epssScore": 75.0 + (i % 20),  # All above 70%
                    "severity": "HIGH" if i % 2 else "CRITICAL",
                }
            )

        source_data = {
            "vulnerabilities": vulns,
            "count": len(vulns),
            "generated": "2024-01-01T00:00:00Z",
        }

        source_file = src_dir / "index.json"
        source_file.write_text(json.dumps(source_data))

        with patch("scripts.filter_high_epss.source_index", str(source_file)), patch(
            "scripts.filter_high_epss.target_index", str(public_dir / "index.json")
        ), patch("scripts.filter_high_epss.organize_into_subfolders") as mock_organize:
            filter_high_epss_vulns()

            # Should call organize_into_subfolders since we have > 1000 vulns
            mock_organize.assert_called_once()

    def test_organize_into_subfolders_custom_batch_size(self, tmp_path):
        """Test organizing with custom batch size."""
        base_dir = tmp_path / "public" / "api" / "vulns"
        base_dir.mkdir(parents=True)

        # Create 300 vulnerabilities
        vulns = []
        for i in range(300):
            vulns.append(
                {
                    "cveId": f"CVE-2024-{i:04d}",
                    "epssScore": 80.0,
                    "severity": "CRITICAL",
                }
            )

        # Use custom batch size of 100
        organize_into_subfolders(vulns, str(base_dir), items_per_folder=100)

        # Should create 3 batches of 100 each
        assert (base_dir / "batch_001").exists()
        assert (base_dir / "batch_002").exists()
        assert (base_dir / "batch_003").exists()
        assert not (base_dir / "batch_004").exists()

        # Check master index
        with open(base_dir / "batches.json") as f:
            master = json.load(f)
        assert master["total_batches"] == 3
        assert master["items_per_batch"] == 100

    def test_main_execution(self, tmp_path, sample_vulnerability_data):
        """Test main execution."""
        # Create source file
        src_dir = tmp_path / "src" / "api" / "vulns"
        src_dir.mkdir(parents=True)
        source_file = src_dir / "index.json"
        source_file.write_text(json.dumps(sample_vulnerability_data))

        # Patch paths
        with patch("scripts.filter_high_epss.source_index", str(source_file)), patch(
            "scripts.filter_high_epss.target_index",
            str(tmp_path / "public" / "api" / "vulns" / "index.json"),
        ), patch("sys.argv", ["filter_high_epss.py"]):
            from scripts.filter_high_epss import main

            main()
