"""Tests for data quality configuration and validation."""

from datetime import datetime, timedelta, timezone

import pytest

from scripts.models import (
    CPEMatch,
    CVSSMetric,
    EPSSScore,
    Reference,
    SeverityLevel,
    Vulnerability,
)
from scripts.quality import DataQualityConfig, DataQualityValidator


class TestDataQualityConfig:
    """Test data quality configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = DataQualityConfig()

        assert config.min_severity == "HIGH"
        assert config.min_epss_score == 0.0
        assert config.max_epss_score == 1.0
        assert config.min_year == 2024
        assert config.max_year == 2025
        assert len(config.required_fields) > 0
        assert "cve_id" in config.required_fields

    def test_config_from_dict(self):
        """Test creating configuration from dictionary."""
        config_dict = {
            "min_severity": "CRITICAL",
            "min_epss_score": 0.8,
            "allowed_severities": ["CRITICAL", "HIGH"],
            "priority_vendors": ["Microsoft", "Google"],
        }

        config = DataQualityConfig.from_dict(config_dict)

        assert config.min_severity == "CRITICAL"
        assert config.min_epss_score == 0.8
        assert config.allowed_severities == {"CRITICAL", "HIGH"}
        assert "Microsoft" in config.priority_vendors

    def test_config_to_dict(self):
        """Test converting configuration to dictionary."""
        config = DataQualityConfig()
        config_dict = config.to_dict()

        assert isinstance(config_dict, dict)
        assert config_dict["min_severity"] == "HIGH"
        assert isinstance(config_dict["allowed_severities"], list)
        assert set(config_dict["allowed_severities"]) == config.allowed_severities

    def test_config_validation(self):
        """Test configuration validation."""
        # Valid config
        config = DataQualityConfig()
        errors = config.validate()
        assert len(errors) == 0

        # Invalid severity
        config.min_severity = "INVALID"
        errors = config.validate()
        assert len(errors) > 0
        assert any("min_severity" in e for e in errors)

        # Invalid score ranges
        config = DataQualityConfig()
        config.min_cvss_score = 11.0
        errors = config.validate()
        assert any("cvss_score" in e for e in errors)

        config = DataQualityConfig()
        config.min_epss_score = 1.5
        errors = config.validate()
        assert any("epss_score" in e for e in errors)

        # Invalid quality weights
        config = DataQualityConfig()
        config.quality_score_weights = {"has_cvss": 0.5, "has_epss": 0.3}  # Sum != 1.0
        errors = config.validate()
        assert any("quality_score_weights" in e for e in errors)


class TestDataQualityValidator:
    """Test data quality validator."""

    @pytest.fixture
    def sample_vulnerability(self):
        """Create a sample vulnerability for testing."""
        return Vulnerability(
            cve_id="CVE-2024-12345",
            title="Test Vulnerability",
            description="This is a test vulnerability with sufficient description text to pass validation",
            severity=SeverityLevel.HIGH,
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=8.5,
                    base_severity=SeverityLevel.HIGH,
                )
            ],
            epss_score=EPSSScore(
                score=0.75,  # 75% as decimal
                percentile=90.0,
                date=datetime.now(timezone.utc),
            ),
            published_date=datetime.now(timezone.utc) - timedelta(days=5),
            last_modified_date=datetime.now(timezone.utc),
            affected_vendors=["Microsoft"],
            affected_products=["Windows"],
            references=[
                Reference(url="https://example.com/advisory", tags=["Vendor Advisory"])
            ],
            tags=["remote", "code-execution"],
            risk_score=85,
            cpe_matches=[
                CPEMatch(
                    cpe23_uri="cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
                    vulnerable=True,
                )
            ],
        )

    def test_validate_valid_vulnerability(self, sample_vulnerability):
        """Test validation of a valid vulnerability."""
        validator = DataQualityValidator()
        is_valid, errors, quality_scores = validator.validate_vulnerability(
            sample_vulnerability
        )

        assert is_valid is True
        assert len(errors) == 0
        assert quality_scores["has_cvss"] == 1.0
        assert quality_scores["has_epss"] == 1.0
        assert quality_scores["has_title"] == 1.0
        assert quality_scores["description_quality"] == 1.0

    def test_validate_invalid_cve_id(self, sample_vulnerability):
        """Test validation with invalid CVE ID."""
        validator = DataQualityValidator()
        sample_vulnerability.cve_id = "INVALID-ID"

        is_valid, errors, quality_scores = validator.validate_vulnerability(
            sample_vulnerability
        )

        assert is_valid is False
        assert any("CVE ID format" in e for e in errors)
        assert quality_scores["valid_cve_id"] == 0.0

    def test_validate_missing_required_fields(self):
        """Test validation with missing required fields."""
        validator = DataQualityValidator()
        # Create a vulnerability with minimum required Pydantic fields but missing quality requirements
        vuln = Vulnerability(
            cve_id="CVE-2024-12345",
            title="",  # Empty title
            description="",  # Empty description
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(timezone.utc),
            last_modified_date=datetime.now(timezone.utc),
        )

        is_valid, errors, quality_scores = validator.validate_vulnerability(vuln)

        # Should fail because title and description are empty even though they exist
        assert is_valid is False
        assert len(errors) > 0

    def test_validate_score_ranges(self, sample_vulnerability):
        """Test validation of score ranges."""
        validator = DataQualityValidator()

        # Invalid CVSS score
        sample_vulnerability.cvss_metrics[0].base_score = 15.0
        is_valid, errors, _ = validator.validate_vulnerability(sample_vulnerability)
        assert is_valid is False
        assert any("CVSS score" in e and "outside valid range" in e for e in errors)

        # Invalid EPSS score (score > 1.0)
        sample_vulnerability.cvss_metrics[0].base_score = 8.5
        sample_vulnerability.epss_score.score = 1.5
        is_valid, errors, _ = validator.validate_vulnerability(sample_vulnerability)
        assert is_valid is False
        assert any("EPSS score" in e and "outside valid range" in e for e in errors)

    def test_validate_text_length(self, sample_vulnerability):
        """Test validation of text field lengths."""
        validator = DataQualityValidator()

        # Title too long
        sample_vulnerability.title = "A" * 600
        is_valid, errors, quality_scores = validator.validate_vulnerability(
            sample_vulnerability
        )

        # Should still be valid but with warning (warnings don't fail validation)
        assert is_valid is True

    def test_validate_date_range(self, sample_vulnerability):
        """Test validation of date ranges."""
        validator = DataQualityValidator()

        # Year outside range
        sample_vulnerability.published_date = datetime(2020, 1, 1, tzinfo=timezone.utc)
        is_valid, errors, _ = validator.validate_vulnerability(sample_vulnerability)

        assert is_valid is False
        assert any("outside allowed range" in e for e in errors)

        # Future date
        sample_vulnerability.published_date = datetime.now(timezone.utc) + timedelta(
            days=30
        )
        is_valid, errors, _ = validator.validate_vulnerability(sample_vulnerability)

        assert is_valid is False
        assert any("future" in e for e in errors)

    def test_calculate_quality_score(self, sample_vulnerability):
        """Test quality score calculation."""
        validator = DataQualityValidator()
        _, _, quality_scores = validator.validate_vulnerability(sample_vulnerability)

        score = validator.calculate_quality_score(sample_vulnerability, quality_scores)

        assert 0.0 <= score <= 1.0
        assert score > 0.5  # Should be high for a well-formed vulnerability

    def test_filter_vulnerabilities(self, sample_vulnerability):
        """Test filtering vulnerabilities."""
        validator = DataQualityValidator()

        # Create variations
        vuln_high = sample_vulnerability

        vuln_medium = Vulnerability(
            cve_id="CVE-2024-22222",
            title="Medium severity",
            description="Medium severity vulnerability with sufficient description",
            severity=SeverityLevel.MEDIUM,
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                    base_score=5.0,
                    base_severity=SeverityLevel.MEDIUM,
                )
            ],
            published_date=datetime.now(timezone.utc),
            last_modified_date=datetime.now(timezone.utc),
        )

        vuln_low_epss = Vulnerability(
            cve_id="CVE-2024-33333",
            title="Low EPSS",
            description="High severity but low EPSS score vulnerability description",
            severity=SeverityLevel.HIGH,
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=8.0,
                    base_severity=SeverityLevel.HIGH,
                )
            ],
            epss_score=EPSSScore(
                score=0.1,  # 10% as decimal, below default threshold
                percentile=20.0,
                date=datetime.now(timezone.utc),
            ),
            published_date=datetime.now(timezone.utc),
            last_modified_date=datetime.now(timezone.utc),
        )

        vulnerabilities = [vuln_high, vuln_medium, vuln_low_epss]

        # Update config to use 0.6 EPSS threshold like in production
        validator.config.min_epss_score = 0.6

        # Filter with updated config (min_severity=HIGH, min_epss=0.6)
        filtered, stats = validator.filter_vulnerabilities(vulnerabilities)

        assert stats["total"] == 3
        assert stats["passed"] == 1  # Only vuln_high should pass
        assert stats["below_severity"] == 1  # vuln_medium should be filtered
        assert stats["below_epss"] == 1  # vuln_low_epss should be filtered

    def test_check_data_completeness(self, sample_vulnerability):
        """Test data completeness checking."""
        validator = DataQualityValidator()

        # Create vulnerabilities with varying completeness
        complete_vuln = sample_vulnerability

        incomplete_vuln = Vulnerability(
            cve_id="CVE-2024-44444",
            title="Incomplete",
            description="Incomplete vulnerability",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(timezone.utc),
            last_modified_date=datetime.now(timezone.utc),
            # Missing CVSS, EPSS, references, etc.
        )

        vulnerabilities = [complete_vuln, incomplete_vuln]
        completeness = validator.check_data_completeness(vulnerabilities)

        assert "has_cvss" in completeness
        assert "has_epss" in completeness
        assert "has_references" in completeness

        # Should be 50% for fields that only complete_vuln has
        assert completeness["has_cvss"] == 50.0
        assert completeness["has_epss"] == 50.0
        assert completeness["has_references"] == 50.0

    def test_quality_report(self, sample_vulnerability):
        """Test comprehensive quality report generation."""
        validator = DataQualityValidator()

        vulnerabilities = [
            sample_vulnerability,
            Vulnerability(
                cve_id="CVE-2024-55555",
                title="Low quality",
                description="Short",  # Too short
                severity=SeverityLevel.MEDIUM,  # Below threshold
                published_date=datetime.now(timezone.utc),
                last_modified_date=datetime.now(timezone.utc),
            ),
        ]

        report = validator.get_quality_report(vulnerabilities)

        assert "summary" in report
        assert "filter_statistics" in report
        assert "data_completeness" in report
        assert "quality_issues" in report
        assert "recommendations" in report

        assert report["summary"]["total_processed"] == 2
        assert report["filter_statistics"]["total"] == 2
        assert isinstance(report["recommendations"], list)

    def test_blocked_vendors_products(self):
        """Test filtering of blocked vendors and products."""
        config = DataQualityConfig(
            blocked_vendors={"BadVendor"},
            blocked_products={"BadProduct"},
        )
        validator = DataQualityValidator(config)

        vuln = Vulnerability(
            cve_id="CVE-2024-66666",
            title="Blocked vendor",
            description="Vulnerability in blocked vendor product with sufficient text",
            severity=SeverityLevel.HIGH,
            affected_vendors=["BadVendor"],
            affected_products=["BadProduct"],
            published_date=datetime.now(timezone.utc),
            last_modified_date=datetime.now(timezone.utc),
        )

        is_valid, errors, _ = validator.validate_vulnerability(vuln)

        assert is_valid is False
        assert any("blocked vendors" in e for e in errors)
        assert any("blocked products" in e for e in errors)

    def test_custom_epss_threshold(self):
        """Test custom EPSS threshold in quality config."""
        config = DataQualityConfig(min_epss_score=0.8)  # 80% threshold
        validator = DataQualityValidator(config)

        vuln = Vulnerability(
            cve_id="CVE-2024-77777",
            title="Medium EPSS",
            description="Vulnerability with medium EPSS score and sufficient description",
            severity=SeverityLevel.HIGH,
            epss_score=EPSSScore(
                score=0.7,  # 70% as decimal < 80% threshold
                percentile=85.0,
                date=datetime.now(timezone.utc),
            ),
            published_date=datetime.now(timezone.utc),
            last_modified_date=datetime.now(timezone.utc),
        )

        filtered, stats = validator.filter_vulnerabilities([vuln])

        assert stats["total"] == 1
        assert stats["below_epss"] == 1
        assert stats["passed"] == 0
