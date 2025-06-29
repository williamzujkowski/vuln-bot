"""Tests for the storage optimizer module."""

import json

import pytest

from scripts.storage_optimizer import (
    create_client_viewer,
    optimize_vulnerability_storage,
)


@pytest.fixture
def sample_vuln_files(tmp_path):
    """Create sample individual vulnerability JSON files."""
    source_dir = tmp_path / "source"
    source_dir.mkdir()

    # Create sample vulnerability files
    vulns = [
        {
            "cve_id": "CVE-2024-0001",
            "description": "Critical vulnerability",
            "severity": "CRITICAL",
            "published": "2024-01-01T00:00:00Z",
            "cvss_base_score": 9.8,
            "epss_score": 0.95,
        },
        {
            "cve_id": "CVE-2024-0002",
            "description": "High vulnerability",
            "severity": "HIGH",
            "published": "2024-01-02T00:00:00Z",
            "cvss_base_score": 8.5,
            "epss_score": 0.85,
        },
        {
            "cve_id": "CVE-2025-0001",
            "description": "Critical vulnerability",
            "severity": "CRITICAL",
            "published": "2025-01-01T00:00:00Z",
            "cvss_base_score": 9.5,
            "epss_score": 0.90,
        },
    ]

    for vuln in vulns:
        file_path = source_dir / f"{vuln['cve_id']}.json"
        with open(file_path, "w") as f:
            json.dump(vuln, f)

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
            assert "metadata" in index
            assert index["metadata"]["total_vulnerabilities"] == 3
            assert index["metadata"]["storage_strategy"] == "severity-year"

        # Verify chunk contents
        for chunk_file in chunk_files:
            with open(chunk_file) as f:
                data = json.load(f)
                assert "vulnerabilities" in data
                assert "metadata" in data
                assert isinstance(data["vulnerabilities"], list)

    def test_optimize_vulnerability_storage_year_only(
        self, sample_vuln_files, output_dir
    ):
        """Test optimization with year-only strategy."""
        optimize_vulnerability_storage(sample_vuln_files, output_dir, "year-only")

        # Check chunk files
        chunk_files = list(output_dir.glob("vulns-*.json"))

        # Should have files for 2024 and 2025
        years = set()
        for chunk_file in chunk_files:
            if "-all" not in chunk_file.name:  # Skip the all file
                year = chunk_file.stem.split("-")[1]
                years.add(year)

        assert "2024" in years
        assert "2025" in years

    def test_optimize_vulnerability_storage_all(self, sample_vuln_files, output_dir):
        """Test optimization with all-in-one strategy."""
        optimize_vulnerability_storage(sample_vuln_files, output_dir, "all")

        # Should create single file
        all_file = output_dir / "vulns-all.json"
        assert all_file.exists()

        with open(all_file) as f:
            data = json.load(f)
            assert len(data["vulnerabilities"]) == 3

    def test_empty_source_directory(self, tmp_path, output_dir):
        """Test with empty source directory."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        optimize_vulnerability_storage(empty_dir, output_dir, "severity-year")

        # Should still create index
        index_file = output_dir / "chunk-index.json"
        assert index_file.exists()

        with open(index_file) as f:
            index = json.load(f)
            assert index["metadata"]["total_vulnerabilities"] == 0

    def test_invalid_json_handling(self, tmp_path, output_dir):
        """Test handling of invalid JSON files."""
        source_dir = tmp_path / "invalid"
        source_dir.mkdir()

        # Create valid JSON
        valid_file = source_dir / "CVE-2024-0001.json"
        with open(valid_file, "w") as f:
            json.dump({"cve_id": "CVE-2024-0001", "severity": "HIGH"}, f)

        # Create invalid JSON
        invalid_file = source_dir / "CVE-2024-0002.json"
        with open(invalid_file, "w") as f:
            f.write("{ invalid json }")

        # Should process valid files and skip invalid ones
        optimize_vulnerability_storage(source_dir, output_dir, "severity-year")

        index_file = output_dir / "chunk-index.json"
        with open(index_file) as f:
            index = json.load(f)
            # Should only process the valid file
            assert index["metadata"]["total_vulnerabilities"] == 1

    def test_create_client_viewer(self):
        """Test client viewer JavaScript generation."""
        viewer_code = create_client_viewer()

        # Check it contains expected elements
        assert "class VulnerabilityChunkLoader" in viewer_code
        assert "async loadChunkIndex()" in viewer_code
        assert "async loadChunk(filename)" in viewer_code
        assert "async loadAllVulnerabilities()" in viewer_code
        assert "filterVulnerabilities(filters)" in viewer_code

        # Check it's valid JavaScript (basic syntax check)
        assert viewer_code.count("{") == viewer_code.count("}")
        assert viewer_code.count("(") == viewer_code.count(")")
        assert viewer_code.count("[") == viewer_code.count("]")

    def test_performance_with_many_files(self, tmp_path, output_dir):
        """Test performance with many vulnerability files."""
        source_dir = tmp_path / "many"
        source_dir.mkdir()

        # Create 100 vulnerability files
        for i in range(100):
            year = 2024 if i < 50 else 2025
            severity = "CRITICAL" if i % 2 == 0 else "HIGH"

            vuln = {
                "cve_id": f"CVE-{year}-{i:04d}",
                "severity": severity,
                "published": f"{year}-01-01T00:00:00Z",
                "cvss_base_score": 7.0 + (i % 3),
            }

            file_path = source_dir / f"{vuln['cve_id']}.json"
            with open(file_path, "w") as f:
                json.dump(vuln, f)

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
            assert index["metadata"]["total_vulnerabilities"] == 100

    def test_mixed_file_types(self, tmp_path, output_dir):
        """Test handling of non-JSON files in source directory."""
        source_dir = tmp_path / "mixed"
        source_dir.mkdir()

        # Create JSON file
        json_file = source_dir / "CVE-2024-0001.json"
        with open(json_file, "w") as f:
            json.dump({"cve_id": "CVE-2024-0001", "severity": "HIGH"}, f)

        # Create non-JSON files
        (source_dir / "README.md").write_text("# README")
        (source_dir / "test.txt").write_text("test")

        optimize_vulnerability_storage(source_dir, output_dir, "severity-year")

        # Should only process JSON files
        index_file = output_dir / "chunk-index.json"
        with open(index_file) as f:
            index = json.load(f)
            assert index["metadata"]["total_vulnerabilities"] == 1

    def test_missing_required_fields(self, tmp_path, output_dir):
        """Test handling of vulnerabilities missing required fields."""
        source_dir = tmp_path / "missing_fields"
        source_dir.mkdir()

        # Create files with missing fields
        vulns = [
            {"cve_id": "CVE-2024-0001"},  # Missing severity
            {"severity": "HIGH"},  # Missing cve_id
            {"cve_id": "CVE-2024-0002", "severity": "CRITICAL"},  # Valid
        ]

        for i, vuln in enumerate(vulns):
            file_path = source_dir / f"vuln_{i}.json"
            with open(file_path, "w") as f:
                json.dump(vuln, f)

        optimize_vulnerability_storage(source_dir, output_dir, "severity-year")

        # Should process only valid vulnerabilities
        index_file = output_dir / "chunk-index.json"
        with open(index_file) as f:
            index = json.load(f)
            # Only the valid vulnerability should be processed
            assert index["metadata"]["total_vulnerabilities"] == 1
