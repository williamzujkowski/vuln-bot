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

    @patch("os.path.exists")
    @patch("os.makedirs")
    def test_filter_high_epss_vulns_success(
        self, mock_makedirs, mock_exists, sample_vulnerability_data, capsys
    ):
        """Test successful filtering of high EPSS vulnerabilities."""
        # Set up the test environment
        mock_exists.return_value = True

        # Variables to capture written data
        written_data = {}

        # Create a custom mock_open that handles reading and writing
        def mock_open_func(filename, mode="r"):
            if "r" in mode:
                # Reading the source file
                from io import BytesIO, StringIO

                if "b" in mode:
                    return BytesIO(json.dumps(sample_vulnerability_data).encode())
                return StringIO(json.dumps(sample_vulnerability_data))
            elif "w" in mode:
                # Writing to target file
                from io import BytesIO, StringIO

                if "b" in mode:

                    class MockBytesWriter(BytesIO):
                        def __init__(self, filename):
                            super().__init__()
                            self.filename = filename

                        def __exit__(self, *args):
                            written_data[self.filename] = self.getvalue().decode()
                            return False

                    return MockBytesWriter(filename)
                else:

                    class MockFileWriter(StringIO):
                        def __init__(self, filename):
                            super().__init__()
                            self.filename = filename

                        def __exit__(self, *args):
                            written_data[self.filename] = self.getvalue()
                            return False

                    return MockFileWriter(filename)

        with patch("builtins.open", side_effect=mock_open_func):
            # Run the function
            filter_high_epss_vulns()

        # Check output directory was created
        mock_makedirs.assert_called_once_with("public/api/vulns", exist_ok=True)

        # Parse the written data
        assert "public/api/vulns/index.json" in written_data
        filtered_data = json.loads(written_data["public/api/vulns/index.json"])

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

        # Check console output
        captured = capsys.readouterr()
        assert "Total vulnerabilities: 6" in captured.out
        assert "High EPSS vulnerabilities (>= 70%): 3" in captured.out

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

    @patch("shutil.copy")
    @patch("os.makedirs")
    @patch("os.path.exists")
    def test_filter_high_epss_vulns_with_backup(
        self, mock_exists, mock_copy, sample_vulnerability_data
    ):
        """Test backup creation when target file exists."""
        # First call checks source file, second checks if target exists
        mock_exists.side_effect = [True, True]

        # Variables to capture written data
        written_data = {}

        # Create a custom mock_open that handles reading and writing
        def mock_open_func(filename, mode="r"):
            if "r" in mode:
                # Reading the source file
                from io import BytesIO, StringIO

                if "b" in mode:
                    return BytesIO(json.dumps(sample_vulnerability_data).encode())
                return StringIO(json.dumps(sample_vulnerability_data))
            elif "w" in mode:
                # Writing to target file
                from io import BytesIO, StringIO

                if "b" in mode:

                    class MockBytesWriter(BytesIO):
                        def __init__(self, filename):
                            super().__init__()
                            self.filename = filename

                        def __exit__(self, *args):
                            written_data[self.filename] = self.getvalue().decode()
                            return False

                    return MockBytesWriter(filename)
                else:

                    class MockFileWriter(StringIO):
                        def __init__(self, filename):
                            super().__init__()
                            self.filename = filename

                        def __exit__(self, *args):
                            written_data[self.filename] = self.getvalue()
                            return False

                    return MockFileWriter(filename)

        with patch("builtins.open", side_effect=mock_open_func):
            # Run the function
            filter_high_epss_vulns()

        # Check backup was created
        mock_copy.assert_called_once_with(
            "public/api/vulns/index.json", "public/api/vulns/index.json.backup"
        )

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

    @patch("scripts.filter_high_epss.organize_into_subfolders")
    @patch("os.makedirs")
    @patch("os.path.exists")
    def test_filter_calls_organize_for_large_dataset(self, mock_exists, mock_organize):
        """Test that filter_high_epss_vulns calls organize_into_subfolders for large datasets."""
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

        mock_exists.return_value = True

        # Variables to capture written data
        written_data = {}

        # Create a custom mock_open that handles reading and writing
        def mock_open_func(filename, mode="r"):
            if "r" in mode:
                # Reading the source file
                from io import BytesIO, StringIO

                if "b" in mode:
                    return BytesIO(json.dumps(source_data).encode())
                return StringIO(json.dumps(source_data))
            elif "w" in mode:
                # Writing to target file
                from io import BytesIO, StringIO

                if "b" in mode:

                    class MockBytesWriter(BytesIO):
                        def __init__(self, filename):
                            super().__init__()
                            self.filename = filename

                        def __exit__(self, *args):
                            written_data[self.filename] = self.getvalue().decode()
                            return False

                    return MockBytesWriter(filename)
                else:

                    class MockFileWriter(StringIO):
                        def __init__(self, filename):
                            super().__init__()
                            self.filename = filename

                        def __exit__(self, *args):
                            written_data[self.filename] = self.getvalue()
                            return False

                    return MockFileWriter(filename)

        with patch("builtins.open", side_effect=mock_open_func):
            # Run the function
            filter_high_epss_vulns()

        # Should call organize_into_subfolders since we have > 1000 vulns
        mock_organize.assert_called_once()
        # Check it was called with correct arguments
        call_args = mock_organize.call_args[0]
        assert len(call_args[0]) == 1500  # All vulns have EPSS >= 70
        assert call_args[1] == "public/api/vulns"

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

    @patch("os.makedirs")
    @patch("os.path.exists")
    def test_main_execution(self, mock_exists, sample_vulnerability_data, capsys):
        """Test main execution."""
        # Test the module's __main__ execution
        import runpy
        import sys

        # Save original argv
        original_argv = sys.argv

        mock_exists.return_value = True

        # Variables to capture written data
        written_data = {}

        # Create a custom mock_open that handles reading and writing
        def mock_open_func(filename, mode="r"):
            if "r" in mode:
                # Reading the source file
                from io import BytesIO, StringIO

                if "b" in mode:
                    return BytesIO(json.dumps(sample_vulnerability_data).encode())
                return StringIO(json.dumps(sample_vulnerability_data))
            elif "w" in mode:
                # Writing to target file
                from io import BytesIO, StringIO

                if "b" in mode:

                    class MockBytesWriter(BytesIO):
                        def __init__(self, filename):
                            super().__init__()
                            self.filename = filename

                        def __exit__(self, *args):
                            written_data[self.filename] = self.getvalue().decode()
                            return False

                    return MockBytesWriter(filename)
                else:

                    class MockFileWriter(StringIO):
                        def __init__(self, filename):
                            super().__init__()
                            self.filename = filename

                        def __exit__(self, *args):
                            written_data[self.filename] = self.getvalue()
                            return False

                    return MockFileWriter(filename)

        try:
            # Set up argv for the script
            sys.argv = ["filter_high_epss.py"]

            with patch("builtins.open", side_effect=mock_open_func):
                # Run the module as __main__
                runpy.run_module("scripts.filter_high_epss", run_name="__main__")

            # Verify filtering happened
            assert "public/api/vulns/index.json" in written_data

            # Check console output
            captured = capsys.readouterr()
            assert "Total vulnerabilities:" in captured.out
            assert "High EPSS vulnerabilities" in captured.out
        finally:
            # Restore argv
            sys.argv = original_argv
