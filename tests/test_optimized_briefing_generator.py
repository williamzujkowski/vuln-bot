"""Tests for the optimized briefing generator that uses chunked storage."""

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from scripts.models import SeverityLevel, Vulnerability, VulnerabilityBatch
from scripts.processing.optimized_briefing_generator import OptimizedBriefingGenerator


@pytest.fixture
def sample_vulnerabilities():
    """Create sample vulnerabilities for testing."""
    vuln1 = Vulnerability(
        cve_id="CVE-2024-1234",
        description="Critical vulnerability in system A",
        severity=SeverityLevel.CRITICAL,
        published=datetime.now() - timedelta(days=1),
        last_modified=datetime.now(),
        cvss_base_score=9.5,
        epss_score=0.85,
        affected_vendors=["Vendor A"],
        references=["https://example.com/advisory1"],
        risk_score=85.0,
        tags=["infrastructure", "critical"],
    )

    vuln2 = Vulnerability(
        cve_id="CVE-2024-5678",
        description="High severity vulnerability in system B",
        severity=SeverityLevel.HIGH,
        published=datetime.now() - timedelta(days=2),
        last_modified=datetime.now() - timedelta(days=1),
        cvss_base_score=8.5,
        epss_score=0.75,
        affected_vendors=["Vendor B"],
        references=["https://example.com/advisory2"],
        risk_score=75.0,
        tags=["application", "high"],
    )

    vuln3 = Vulnerability(
        cve_id="CVE-2025-9999",
        description="Critical vulnerability in system C",
        severity=SeverityLevel.CRITICAL,
        published=datetime.now() - timedelta(days=3),
        last_modified=datetime.now() - timedelta(days=2),
        cvss_base_score=9.8,
        epss_score=0.95,
        affected_vendors=["Vendor C"],
        references=["https://example.com/advisory3"],
        risk_score=95.0,
        tags=["infrastructure", "critical"],
    )

    return [vuln1, vuln2, vuln3]


@pytest.fixture
def temp_output_dir(tmp_path):
    """Create a temporary output directory."""
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    return output_dir


class TestOptimizedBriefingGenerator:
    """Test cases for OptimizedBriefingGenerator."""

    def test_init(self, temp_output_dir):
        """Test generator initialization."""
        generator = OptimizedBriefingGenerator(output_dir=temp_output_dir)
        assert generator.output_dir == temp_output_dir
        assert generator.logger is not None
        assert generator.storage_strategy == "severity-year"  # default strategy

    def test_generate_all_with_severity_year_strategy(
        self, temp_output_dir, sample_vulnerabilities
    ):
        """Test generation with severity-year chunking strategy."""
        batch = VulnerabilityBatch(vulnerabilities=sample_vulnerabilities)
        generator = OptimizedBriefingGenerator(output_dir=temp_output_dir)

        # Generate all outputs
        result = generator.generate_all(batch)

        # Check that outputs were created
        assert "chunks" in result
        assert isinstance(result["chunks"], list)

        # Check that API directory was created
        json_dir = temp_output_dir / "api" / "vulns"
        assert json_dir.exists()

        # Check chunk files exist
        chunk_files = list(json_dir.glob("vulns-*.json"))
        assert len(chunk_files) > 0

        # Check chunk index was created
        chunk_index = json_dir / "chunk-index.json"
        assert chunk_index.exists()

        # Verify chunk index content
        with open(chunk_index) as f:
            index_data = json.load(f)
            assert "chunks" in index_data
            assert "metadata" in index_data
            assert index_data["metadata"]["total_vulnerabilities"] == 3

    def test_generate_severity_year_chunks(
        self, temp_output_dir, sample_vulnerabilities
    ):
        """Test severity-year chunking method."""
        batch = VulnerabilityBatch(vulnerabilities=sample_vulnerabilities)
        generator = OptimizedBriefingGenerator(output_dir=temp_output_dir)

        # Call the private method directly
        chunks = generator._generate_severity_year_chunks(batch)

        # Verify chunks were created
        assert isinstance(chunks, list)
        assert len(chunks) > 0

        # Check files were created
        json_dir = temp_output_dir / "api" / "vulns"
        assert json_dir.exists()

        # Verify content structure
        for chunk_file in json_dir.glob("vulns-*.json"):
            with open(chunk_file) as f:
                data = json.load(f)
                assert "vulnerabilities" in data
                assert "metadata" in data
                assert isinstance(data["vulnerabilities"], list)

    def test_generate_single_file(self, temp_output_dir, sample_vulnerabilities):
        """Test single file generation fallback."""
        batch = VulnerabilityBatch(vulnerabilities=sample_vulnerabilities)
        generator = OptimizedBriefingGenerator(
            output_dir=temp_output_dir, storage_strategy="single"
        )

        # Call the single file generation method
        filepath = generator._generate_single_file(batch)

        # Check file was created
        assert Path(filepath).exists()
        assert "all-vulnerabilities" in Path(filepath).name

        # Verify content
        with open(filepath) as f:
            data = json.load(f)
            assert "vulnerabilities" in data
            assert len(data["vulnerabilities"]) == 3
            assert "metadata" in data

    def test_empty_batch_handling(self, temp_output_dir):
        """Test handling of empty vulnerability batch."""
        batch = VulnerabilityBatch(vulnerabilities=[])
        generator = OptimizedBriefingGenerator(output_dir=temp_output_dir)

        result = generator.generate_all(batch)

        # Should still create structure
        assert "chunks" in result

        # Check chunk index exists but shows 0 vulnerabilities
        json_dir = temp_output_dir / "api" / "vulns"
        chunk_index = json_dir / "chunk-index.json"

        if chunk_index.exists():
            with open(chunk_index) as f:
                index_data = json.load(f)
                assert index_data["metadata"]["total_vulnerabilities"] == 0

    def test_large_batch_performance(self, temp_output_dir):
        """Test performance with a large batch of vulnerabilities."""
        # Create 100 vulnerabilities
        vulnerabilities = []
        for i in range(100):
            year = 2024 if i % 2 == 0 else 2025
            severity = SeverityLevel.CRITICAL if i % 3 == 0 else SeverityLevel.HIGH

            vuln = Vulnerability(
                cve_id=f"CVE-{year}-{i:04d}",
                description=f"Test vulnerability {i}",
                severity=severity,
                published=datetime.now() - timedelta(days=i),
                last_modified=datetime.now(),
                cvss_base_score=7.0 + (i % 3),
                epss_score=0.7 + (i % 30) / 100,
                affected_vendors=[f"Vendor{i % 10}"],
                references=[f"https://example.com/advisory{i}"],
                risk_score=70.0 + (i % 30),
            )
            vulnerabilities.append(vuln)

        batch = VulnerabilityBatch(vulnerabilities=vulnerabilities)
        generator = OptimizedBriefingGenerator(output_dir=temp_output_dir)

        import time

        start = time.time()
        result = generator.generate_all(batch)
        duration = time.time() - start

        # Should complete in reasonable time
        assert duration < 10.0  # 10 seconds for 100 vulnerabilities

        # Verify all vulnerabilities were stored
        assert "chunks" in result

    def test_json_serialization_edge_cases(self, temp_output_dir):
        """Test JSON serialization with edge cases."""
        # Create vulnerability with datetime objects and special characters
        vuln = Vulnerability(
            cve_id="CVE-2024-EDGE",
            description="Test with special chars: ñ, 中文, emoji 🔒",
            severity=SeverityLevel.CRITICAL,
            published=datetime.now(),
            last_modified=datetime.now(),
            cvss_base_score=9.0,
            epss_score=0.9,
            affected_vendors=["Vendor-A", "Vendor/B", "Vendor\\C"],
            references=["https://example.com/test?param=value&other=123"],
            risk_score=90.0,
            tags=["tag-with-dash", "tag_with_underscore", "tag.with.dot"],
        )

        batch = VulnerabilityBatch(vulnerabilities=[vuln])
        generator = OptimizedBriefingGenerator(output_dir=temp_output_dir)

        generator.generate_all(batch)

        # Verify the file can be read back and contains proper data
        json_dir = temp_output_dir / "api" / "vulns"
        chunk_files = list(json_dir.glob("vulns-*.json"))
        assert len(chunk_files) > 0

        with open(chunk_files[0]) as f:
            data = json.load(f)
            loaded_vuln = data["vulnerabilities"][0]
            assert loaded_vuln["cve_id"] == "CVE-2024-EDGE"
            assert "ñ" in loaded_vuln["description"]
            assert "中文" in loaded_vuln["description"]
            assert "🔒" in loaded_vuln["description"]

    def test_different_storage_strategies(
        self, temp_output_dir, sample_vulnerabilities
    ):
        """Test different storage strategies."""
        batch = VulnerabilityBatch(vulnerabilities=sample_vulnerabilities)

        # Test size-based strategy
        generator = OptimizedBriefingGenerator(
            output_dir=temp_output_dir, storage_strategy="size"
        )
        result = generator.generate_all(batch)
        assert "chunks" in result

        # Clean up for next test
        import shutil

        if (temp_output_dir / "api").exists():
            shutil.rmtree(temp_output_dir / "api")

        # Test single file strategy
        generator = OptimizedBriefingGenerator(
            output_dir=temp_output_dir, storage_strategy="single"
        )
        result = generator.generate_all(batch)
        assert "chunks" in result
