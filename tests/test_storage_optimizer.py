"""Tests for the storage optimizer module."""

import json

import pytest

from scripts.storage_optimizer import (
    create_client_viewer,
    optimize_vulnerability_storage,
)


@pytest.fixture
def sample_vuln_files(tmp_path):
    """Create sample vulnerability index file."""
    source_dir = tmp_path / "source"
    source_dir.mkdir()

    # Create sample vulnerability data
    vulns = [
        {
            "cveId": "CVE-2024-0001",
            "description": "Critical vulnerability",
            "severity": "CRITICAL",
            "publishedDate": "2024-01-01T00:00:00Z",
            "cvssBaseScore": 9.8,
            "epssScore": 0.95,
        },
        {
            "cveId": "CVE-2024-0002",
            "description": "High vulnerability",
            "severity": "HIGH",
            "publishedDate": "2024-01-02T00:00:00Z",
            "cvssBaseScore": 8.5,
            "epssScore": 0.85,
        },
        {
            "cveId": "CVE-2025-0001",
            "description": "Critical vulnerability",
            "severity": "CRITICAL",
            "publishedDate": "2025-01-01T00:00:00Z",
            "cvssBaseScore": 9.5,
            "epssScore": 0.90,
        },
    ]

    # Create index.json file
    index_data = {
        "vulnerabilities": vulns,
        "count": len(vulns),
        "generated": "2024-01-01T00:00:00Z",
    }

    index_file = source_dir / "index.json"
    with open(index_file, "w") as f:
        json.dump(index_data, f)

    return source_dir


@pytest.fixture
def output_dir(tmp_path):
    """Create output directory."""
    output = tmp_path / "output"
    output.mkdir()
    return output


class TestStorageOptimizer:
    """Test cases for storage optimizer."""

    def test_optimize_vulnerability_storage_severity_year(
        self, sample_vuln_files, output_dir
    ):
        """Test optimization with severity-year strategy."""
        optimize_vulnerability_storage(sample_vuln_files, output_dir, "severity-year")

        # Check chunk files were created
        chunk_files = list(output_dir.glob("vulns-*.json"))
        assert len(chunk_files) >= 2  # At least 2024 and 2025 files

        # Check chunk index exists
        index_file = output_dir / "chunk-index.json"
        assert index_file.exists()

        # Verify index content
        with open(index_file) as f:
            index = json.load(f)
            assert "chunks" in index
            assert "strategy" in index
            assert "total_count" in index
            assert index["total_count"] == 3
            assert index["strategy"] == "severity-year"

        # Verify chunk contents
        for chunk_file in chunk_files:
            with open(chunk_file) as f:
                data = json.load(f)
                assert "vulnerabilities" in data
                assert "count" in data
                assert "chunk" in data
                assert isinstance(data["vulnerabilities"], list)

    def test_optimize_vulnerability_storage_size_chunks(
        self, sample_vuln_files, output_dir
    ):
        """Test optimization with size-chunks strategy."""
        optimize_vulnerability_storage(sample_vuln_files, output_dir, "size-chunks")

        # Check chunk files
        chunk_files = list(output_dir.glob("vulns-*.json"))

        # Should have chunk files
        assert len(chunk_files) >= 1

        # Verify chunk files have proper naming
        for chunk_file in chunk_files:
            assert "chunk" in chunk_file.name

    def test_optimize_vulnerability_storage_single_file(
        self, sample_vuln_files, output_dir
    ):
        """Test optimization with single-file strategy."""
        optimize_vulnerability_storage(sample_vuln_files, output_dir, "single-file")

        # Should create single complete file
        complete_file = output_dir / "vulns-complete.json"
        assert complete_file.exists()

        with open(complete_file) as f:
            data = json.load(f)
            assert len(data["vulnerabilities"]) == 3
            assert data["storage_strategy"] == "single-file"
            assert data["includes_full_details"] is True

    def test_empty_source_directory(self, tmp_path, output_dir):
        """Test with empty source directory."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        # Create empty index.json
        index_file = empty_dir / "index.json"
        with open(index_file, "w") as f:
            json.dump({"vulnerabilities": [], "count": 0}, f)

        optimize_vulnerability_storage(empty_dir, output_dir, "severity-year")

        # Should still create index
        chunk_index_file = output_dir / "chunk-index.json"
        assert chunk_index_file.exists()

        with open(chunk_index_file) as f:
            index = json.load(f)
            assert index["total_count"] == 0

    def test_missing_index_file(self, tmp_path, output_dir, capsys):
        """Test handling of missing index.json file."""
        source_dir = tmp_path / "no_index"
        source_dir.mkdir()

        # Try to optimize without index.json
        optimize_vulnerability_storage(source_dir, output_dir, "severity-year")

        # Should print error message
        captured = capsys.readouterr()
        assert "Error:" in captured.out
        assert "index.json not found" in captured.out

    def test_create_client_viewer(self):
        """Test client viewer JavaScript generation."""
        viewer_code = create_client_viewer()

        # Check it contains expected elements
        assert "class VulnerabilityViewer" in viewer_code
        assert "show(vulnerability)" in viewer_code
        assert "close()" in viewer_code
        assert "copyToClipboard()" in viewer_code
        assert "download()" in viewer_code

        # Check it's valid JavaScript (basic syntax check)
        assert viewer_code.count("{") == viewer_code.count("}")
        assert viewer_code.count("(") == viewer_code.count(")")
        assert viewer_code.count("[") == viewer_code.count("]")

    def test_performance_with_many_files(self, tmp_path, output_dir):
        """Test performance with many vulnerability files."""
        source_dir = tmp_path / "many"
        source_dir.mkdir()

        # Create 100 vulnerabilities in index
        vulns = []
        for i in range(100):
            year = 2024 if i < 50 else 2025
            severity = "CRITICAL" if i % 2 == 0 else "HIGH"

            vuln = {
                "cveId": f"CVE-{year}-{i:04d}",
                "severity": severity,
                "publishedDate": f"{year}-01-01T00:00:00Z",
                "cvssBaseScore": 7.0 + (i % 3),
            }
            vulns.append(vuln)

        # Create index.json
        index_data = {"vulnerabilities": vulns, "count": len(vulns)}
        with open(source_dir / "index.json", "w") as f:
            json.dump(index_data, f)

        import time

        start = time.time()
        optimize_vulnerability_storage(source_dir, output_dir, "severity-year")
        duration = time.time() - start

        # Should complete quickly
        assert duration < 2.0  # 2 seconds for 100 files

        # Verify all files were processed
        index_file = output_dir / "chunk-index.json"
        with open(index_file) as f:
            index = json.load(f)
            assert index["total_count"] == 100

    def test_invalid_strategy(self, sample_vuln_files, output_dir, capsys):
        """Test handling of invalid strategy."""
        optimize_vulnerability_storage(
            sample_vuln_files, output_dir, "invalid-strategy"
        )

        # Should print error message
        captured = capsys.readouterr()
        assert "Unknown strategy: invalid-strategy" in captured.out

    def test_viewer_file_generation(self, sample_vuln_files, output_dir):
        """Test that viewer JavaScript file is generated."""
        # Run as main to test viewer generation
        import subprocess

        subprocess.run(
            [
                "python",
                "-m",
                "scripts.storage_optimizer",
                str(sample_vuln_files),
                str(output_dir),
            ],
            capture_output=True,
            text=True,
        )

        # Check viewer file was created
        viewer_file = output_dir / "vulnerability-viewer.js"
        assert viewer_file.exists()

        # Check it contains expected content
        viewer_content = viewer_file.read_text()
        assert "class VulnerabilityViewer" in viewer_content
