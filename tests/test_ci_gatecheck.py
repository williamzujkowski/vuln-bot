"""
Comprehensive tests for CI/CD gatecheck validation.

Tests all critical validation checks including:
- CVE count threshold validation (prevents 15,000+ CVE issue)
- EPSS threshold compliance validation
- Chunk file consistency checks
- API structure validation
- Data freshness validation
- Stale data pattern detection
"""

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from scripts.ci_gatecheck import CIGatecheck


class TestCIGatecheck:
    """Test suite for CIGatecheck class."""

    def test_init(self):
        """Test CIGatecheck initialization."""
        gatecheck = CIGatecheck()
        assert gatecheck.errors == []
        assert gatecheck.warnings == []
        assert gatecheck.metrics == {}

    def test_add_error(self):
        """Test adding errors to gatecheck."""
        gatecheck = CIGatecheck()
        gatecheck.add_error("Test error", "Error details")

        assert len(gatecheck.errors) == 1
        assert gatecheck.errors[0]["message"] == "Test error"
        assert gatecheck.errors[0]["details"] == "Error details"

    def test_add_warning(self):
        """Test adding warnings to gatecheck."""
        gatecheck = CIGatecheck()
        gatecheck.add_warning("Test warning", "Warning details")

        assert len(gatecheck.warnings) == 1
        assert gatecheck.warnings[0]["message"] == "Test warning"
        assert gatecheck.warnings[0]["details"] == "Warning details"

    def test_generate_report_passed(self):
        """Test report generation for passed validation."""
        gatecheck = CIGatecheck()
        gatecheck.metrics["total_cves"] = 298

        report = gatecheck.generate_report()

        assert report["status"] == "PASSED"
        assert report["summary"]["total_errors"] == 0
        assert report["summary"]["critical_checks_passed"] is True
        assert "timestamp" in report

    def test_generate_report_failed(self):
        """Test report generation for failed validation."""
        gatecheck = CIGatecheck()
        gatecheck.add_error("Critical error")

        report = gatecheck.generate_report()

        assert report["status"] == "FAILED"
        assert report["summary"]["total_errors"] == 1
        assert report["summary"]["critical_checks_passed"] is False


class TestCVECountValidation:
    """Test suite for CVE count threshold validation."""

    def test_validate_cve_count_within_bounds(self, temp_api_dir):
        """Test validation passes when CVE count is within expected bounds."""
        # Create index.json with 298 CVEs (baseline)
        index_file = temp_api_dir / "vulns" / "index.json"
        index_data = {"vulnerabilities": [{"cveId": f"CVE-2024-{i:04d}"} for i in range(298)]}
        index_file.write_text(json.dumps(index_data))

        gatecheck = CIGatecheck()
        result = gatecheck.validate_cve_count_threshold(
            temp_api_dir,
            max_count=1000,
            expected_count=298,
            min_baseline=298
        )

        assert result is True
        assert len(gatecheck.errors) == 0
        assert gatecheck.metrics["total_cves"] == 298

    def test_validate_cve_count_exceeds_max(self, temp_api_dir):
        """Test validation fails when CVE count exceeds maximum (15,000+ issue)."""
        # Create index.json with 1500 CVEs (exceeds max)
        index_file = temp_api_dir / "vulns" / "index.json"
        index_data = {"vulnerabilities": [{"cveId": f"CVE-2024-{i:05d}"} for i in range(1500)]}
        index_file.write_text(json.dumps(index_data))

        gatecheck = CIGatecheck()
        result = gatecheck.validate_cve_count_threshold(
            temp_api_dir,
            max_count=1000,
            expected_count=298,
            min_baseline=298
        )

        assert result is False
        assert len(gatecheck.errors) == 1
        assert "Excessive CVE count detected" in gatecheck.errors[0]["message"]
        assert gatecheck.metrics["total_cves"] == 1500

    def test_validate_cve_count_below_baseline(self, temp_api_dir):
        """Test validation fails when CVE count drops below minimum baseline."""
        # Create index.json with 250 CVEs (below 298 baseline)
        index_file = temp_api_dir / "vulns" / "index.json"
        index_data = {"vulnerabilities": [{"cveId": f"CVE-2024-{i:04d}"} for i in range(250)]}
        index_file.write_text(json.dumps(index_data))

        gatecheck = CIGatecheck()
        result = gatecheck.validate_cve_count_threshold(
            temp_api_dir,
            max_count=1000,
            expected_count=298,
            min_baseline=298
        )

        assert result is False
        assert len(gatecheck.errors) == 1
        assert "CVE count regression detected" in gatecheck.errors[0]["message"]

    def test_validate_cve_count_higher_than_expected_warning(self, temp_api_dir):
        """Test warning generated when count is higher than expected but within tolerance."""
        # Create index.json with 450 CVEs (higher than max_acceptable=447, within max=1000)
        # max_acceptable = expected_count * (1 + tolerance) = 298 * 1.5 = 447
        index_file = temp_api_dir / "vulns" / "index.json"
        index_data = {"vulnerabilities": [{"cveId": f"CVE-2024-{i:04d}"} for i in range(450)]}
        index_file.write_text(json.dumps(index_data))

        gatecheck = CIGatecheck()
        result = gatecheck.validate_cve_count_threshold(
            temp_api_dir,
            max_count=1000,
            expected_count=298,
            min_baseline=298
        )

        assert result is True  # Still passes (below max_count)
        assert len(gatecheck.warnings) == 1
        assert "higher than expected" in gatecheck.warnings[0]["message"]

    def test_validate_cve_count_missing_index(self, temp_api_dir):
        """Test validation when index.json is missing."""
        gatecheck = CIGatecheck()
        result = gatecheck.validate_cve_count_threshold(
            temp_api_dir,
            max_count=1000,
            expected_count=298,
            min_baseline=298
        )

        # Should fail baseline check (0 < 298)
        assert result is False
        assert gatecheck.metrics["total_cves"] == 0


class TestEPSSThresholdValidation:
    """Test suite for EPSS threshold compliance validation."""

    def test_validate_epss_all_compliant(self, temp_api_dir, sample_cve_compliant):
        """Test validation passes when all CVEs meet EPSS threshold."""
        # Create index.json with compliant CVEs (EPSS ≥60%)
        index_file = temp_api_dir / "vulns" / "index.json"
        index_data = {
            "vulnerabilities": [
                {**sample_cve_compliant, "cveId": f"CVE-2024-{i:04d}", "epssScore": 85.5}
                for i in range(10)
            ]
        }
        index_file.write_text(json.dumps(index_data))

        gatecheck = CIGatecheck()
        result = gatecheck.validate_epss_threshold_compliance(temp_api_dir, min_epss=0.6)

        assert result is True
        assert len(gatecheck.errors) == 0
        assert gatecheck.metrics["total_checked_epss"] == 10

    def test_validate_epss_some_violations(self, temp_api_dir):
        """Test validation fails when some CVEs violate EPSS threshold."""
        # Create index.json with mixed EPSS scores
        index_file = temp_api_dir / "vulns" / "index.json"
        index_data = {
            "vulnerabilities": [
                {"cveId": "CVE-2024-0001", "epssScore": 85.5, "severity": "CRITICAL"},  # Compliant
                {"cveId": "CVE-2024-0002", "epssScore": 45.2, "severity": "HIGH"},  # Violation
                {"cveId": "CVE-2024-0003", "epssScore": 92.1, "severity": "CRITICAL"},  # Compliant
                {"cveId": "CVE-2024-0004", "epssScore": 35.8, "severity": "HIGH"},  # Violation
            ]
        }
        index_file.write_text(json.dumps(index_data))

        gatecheck = CIGatecheck()
        result = gatecheck.validate_epss_threshold_compliance(temp_api_dir, min_epss=0.6)

        assert result is False
        assert len(gatecheck.errors) == 1
        assert "EPSS threshold violations found" in gatecheck.errors[0]["message"]
        assert gatecheck.metrics["epss_violations"] == 2

    def test_validate_epss_chunk_files_cve50_format(self, temp_api_dir, sample_cve_cve50_format):
        """Test validation handles CVE 5.0 format in chunk files."""
        # Create chunk file with CVE 5.0 format
        chunk_file = temp_api_dir / "vulns" / "vulns-2024-CRITICAL.json"
        chunk_data = {
            "vulnerabilities": [
                {
                    **sample_cve_cve50_format,
                    "cveId": f"CVE-2024-{i:04d}",
                    "containers": {
                        "adp": [{
                            "enrichments": {
                                "epss": {"score": 0.75}  # 75% - compliant
                            }
                        }]
                    }
                }
                for i in range(5)
            ]
        }
        chunk_file.write_text(json.dumps(chunk_data))

        # Empty index file
        index_file = temp_api_dir / "vulns" / "index.json"
        index_file.write_text(json.dumps({"vulnerabilities": []}))

        gatecheck = CIGatecheck()
        result = gatecheck.validate_epss_threshold_compliance(temp_api_dir, min_epss=0.6)

        assert result is True
        assert len(gatecheck.errors) == 0

    def test_validate_epss_chunk_files_legacy_format(self, temp_api_dir):
        """Test validation handles legacy epss.score format in chunk files."""
        # Create chunk file with legacy format
        chunk_file = temp_api_dir / "vulns" / "vulns-2024-HIGH.json"
        chunk_data = {
            "vulnerabilities": [
                {
                    "cveId": f"CVE-2024-{i:04d}",
                    "epss": {"score": 0.82}  # 82% - compliant
                }
                for i in range(5)
            ]
        }
        chunk_file.write_text(json.dumps(chunk_data))

        # Empty index file
        index_file = temp_api_dir / "vulns" / "index.json"
        index_file.write_text(json.dumps({"vulnerabilities": []}))

        gatecheck = CIGatecheck()
        result = gatecheck.validate_epss_threshold_compliance(temp_api_dir, min_epss=0.6)

        assert result is True
        assert len(gatecheck.errors) == 0


class TestChunkFileValidation:
    """Test suite for chunk file consistency validation."""

    def test_validate_chunk_consistency_normal(self, temp_api_dir):
        """Test chunk file validation with normal-sized chunks."""
        # Create chunk index
        chunk_index_file = temp_api_dir / "vulns" / "chunk-index.json"
        chunk_index = {
            "chunks": [
                {"file": "vulns-2024-CRITICAL.json", "count": 150},
                {"file": "vulns-2024-HIGH.json", "count": 148}
            ]
        }
        chunk_index_file.write_text(json.dumps(chunk_index))

        # Create chunk files
        for chunk in chunk_index["chunks"]:
            chunk_file = temp_api_dir / "vulns" / chunk["file"]
            chunk_data = {
                "vulnerabilities": [
                    {"cveId": f"CVE-2024-{i:05d}"}
                    for i in range(chunk["count"])
                ]
            }
            chunk_file.write_text(json.dumps(chunk_data))

        gatecheck = CIGatecheck()
        result = gatecheck.validate_chunk_file_consistency(temp_api_dir)

        assert result is True
        assert gatecheck.metrics["total_in_chunks"] == 298
        assert gatecheck.metrics["oversized_chunks"] == 0

    def test_validate_chunk_consistency_oversized(self, temp_api_dir):
        """Test chunk file validation detects oversized chunks (stale data indicator)."""
        # Create chunk index with oversized chunk
        chunk_index_file = temp_api_dir / "vulns" / "chunk-index.json"
        chunk_index = {
            "chunks": [
                {"file": "vulns-2024-CRITICAL.json", "count": 1500}  # Oversized!
            ]
        }
        chunk_index_file.write_text(json.dumps(chunk_index))

        # Create oversized chunk file
        chunk_file = temp_api_dir / "vulns" / "vulns-2024-CRITICAL.json"
        chunk_data = {
            "vulnerabilities": [{"cveId": f"CVE-2024-{i:05d}"} for i in range(1500)]
        }
        chunk_file.write_text(json.dumps(chunk_data))

        gatecheck = CIGatecheck()
        result = gatecheck.validate_chunk_file_consistency(temp_api_dir)

        assert result is False
        assert len(gatecheck.errors) == 1
        assert "Oversized chunks detected" in gatecheck.errors[0]["message"]

    def test_validate_chunk_consistency_missing_file(self, temp_api_dir):
        """Test chunk file validation detects missing chunk files."""
        # Create chunk index referencing non-existent file
        chunk_index_file = temp_api_dir / "vulns" / "chunk-index.json"
        chunk_index = {
            "chunks": [
                {"file": "vulns-2024-CRITICAL.json", "count": 150},
                {"file": "vulns-2024-MISSING.json", "count": 100}  # Missing!
            ]
        }
        chunk_index_file.write_text(json.dumps(chunk_index))

        # Create only first chunk file
        chunk_file = temp_api_dir / "vulns" / "vulns-2024-CRITICAL.json"
        chunk_data = {"vulnerabilities": [{"cveId": f"CVE-2024-{i:05d}"} for i in range(150)]}
        chunk_file.write_text(json.dumps(chunk_data))

        gatecheck = CIGatecheck()
        result = gatecheck.validate_chunk_file_consistency(temp_api_dir)

        assert len(gatecheck.errors) == 1
        assert "Chunk file missing" in gatecheck.errors[0]["message"]

    def test_validate_chunk_consistency_missing_index(self, temp_api_dir):
        """Test chunk file validation handles missing chunk-index.json."""
        gatecheck = CIGatecheck()
        result = gatecheck.validate_chunk_file_consistency(temp_api_dir)

        # Should return True with warning, not error
        assert result is True
        assert len(gatecheck.warnings) == 1
        assert "Chunk index file not found" in gatecheck.warnings[0]["message"]


class TestAPIStructureValidation:
    """Test suite for API structure validation."""

    def test_validate_api_structure_complete(self, temp_api_dir):
        """Test API structure validation when all required files exist."""
        # Create required files
        (temp_api_dir / "vulns" / "index.json").write_text(json.dumps({"vulnerabilities": []}))
        (temp_api_dir / "vulns" / "chunk-index.json").write_text(json.dumps({"chunks": []}))

        gatecheck = CIGatecheck()
        result = gatecheck.validate_api_structure(temp_api_dir)

        assert result is True
        assert len(gatecheck.errors) == 0

    def test_validate_api_structure_missing_files(self, temp_api_dir):
        """Test API structure validation when required files are missing."""
        # Don't create any files
        gatecheck = CIGatecheck()
        result = gatecheck.validate_api_structure(temp_api_dir)

        assert result is False
        assert len(gatecheck.errors) == 1
        assert "Required API files missing" in gatecheck.errors[0]["message"]


class TestDataFreshnessValidation:
    """Test suite for data freshness validation."""

    def test_validate_data_freshness_current(self, temp_api_dir):
        """Test validation passes when data is fresh."""
        # Create index.json with current timestamp
        index_file = temp_api_dir / "vulns" / "index.json"
        index_file.write_text(json.dumps({"vulnerabilities": []}))

        gatecheck = CIGatecheck()
        result = gatecheck.validate_data_freshness(temp_api_dir, max_age_hours=8)

        assert result is True
        assert len(gatecheck.errors) == 0
        assert gatecheck.metrics["data_age_hours"] < 1  # Just created

    def test_validate_data_freshness_stale(self, temp_api_dir):
        """Test validation fails when data is stale."""
        # Create index.json
        index_file = temp_api_dir / "vulns" / "index.json"
        index_file.write_text(json.dumps({"vulnerabilities": []}))

        # Modify file timestamp to 10 hours ago
        old_time = (datetime.now() - timedelta(hours=10)).timestamp()
        index_file.touch()
        import os
        os.utime(index_file, (old_time, old_time))

        gatecheck = CIGatecheck()
        result = gatecheck.validate_data_freshness(temp_api_dir, max_age_hours=8)

        assert len(gatecheck.errors) == 1
        assert "Data is stale" in gatecheck.errors[0]["message"]

    def test_validate_data_freshness_missing_file(self, temp_api_dir):
        """Test validation when index.json is missing."""
        gatecheck = CIGatecheck()
        result = gatecheck.validate_data_freshness(temp_api_dir, max_age_hours=8)

        assert result is False
        assert len(gatecheck.errors) == 1
        assert "Index file missing" in gatecheck.errors[0]["message"]


class TestStaleDataPatternDetection:
    """Test suite for stale data pattern detection."""

    def test_check_stale_patterns_none(self, temp_api_dir):
        """Test no stale patterns detected in clean data."""
        # Create only valid chunk files (2024-2025)
        (temp_api_dir / "vulns" / "vulns-2024-CRITICAL.json").write_text(json.dumps({"vulnerabilities": []}))
        (temp_api_dir / "vulns" / "vulns-2025-HIGH.json").write_text(json.dumps({"vulnerabilities": []}))

        gatecheck = CIGatecheck()
        result = gatecheck.check_for_known_stale_patterns(temp_api_dir)

        assert result is True
        assert len(gatecheck.errors) == 0
        assert gatecheck.metrics["stale_indicators"] == 0

    def test_check_stale_patterns_old_year_chunks(self, temp_api_dir):
        """Test detection of old year chunk files (2020-2023)."""
        # Create old year chunk files
        (temp_api_dir / "vulns" / "vulns-2020-CRITICAL.json").write_text(json.dumps({"vulnerabilities": []}))
        (temp_api_dir / "vulns" / "vulns-2022-HIGH.json").write_text(json.dumps({"vulnerabilities": []}))

        gatecheck = CIGatecheck()
        result = gatecheck.check_for_known_stale_patterns(temp_api_dir)

        assert result is False
        assert len(gatecheck.errors) == 1
        assert "Stale data patterns detected" in gatecheck.errors[0]["message"]
        assert gatecheck.metrics["stale_indicators"] == 2

    def test_check_stale_patterns_low_severity_chunks(self, temp_api_dir):
        """Test detection of LOW severity chunk files (shouldn't exist with ≥60% EPSS)."""
        # Create LOW severity chunk file
        (temp_api_dir / "vulns" / "vulns-2024-LOW.json").write_text(json.dumps({"vulnerabilities": []}))

        gatecheck = CIGatecheck()
        result = gatecheck.check_for_known_stale_patterns(temp_api_dir)

        assert result is False
        assert len(gatecheck.errors) == 1
        assert "Stale data patterns detected" in gatecheck.errors[0]["message"]
