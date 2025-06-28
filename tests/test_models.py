"""Unit tests for vulnerability data models."""

from datetime import datetime, timedelta

import pytest

from scripts.models import (
    CVSSMetric,
    EPSSScore,
    SeverityLevel,
    Vulnerability,
    VulnerabilityBatch,
)


class TestCVSSMetric:
    """Test CVSSMetric model."""

    def test_cvss_metric_creation(self):
        """Test creating a CVSS metric."""
        metric = CVSSMetric(
            version="3.1",
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_score=9.8,
            base_severity=SeverityLevel.CRITICAL,
            exploitability_score=3.9,
            impact_score=5.9,
        )

        assert metric.version == "3.1"
        assert metric.base_score == 9.8
        assert metric.base_severity == SeverityLevel.CRITICAL

    def test_cvss_metric_validation(self):
        """Test CVSS metric validation."""
        with pytest.raises(ValueError):
            # Score out of range
            CVSSMetric(
                version="3.1",
                vector_string="CVSS:3.1/AV:N",
                base_score=11.0,  # Invalid
                base_severity=SeverityLevel.HIGH,
            )


class TestEPSSScore:
    """Test EPSSScore model."""

    def test_epss_score_creation(self):
        """Test creating an EPSS score."""
        score = EPSSScore(
            score=0.12345,
            percentile=85.6789,
            date=datetime.utcnow(),
        )

        # Should be rounded to 4 decimal places
        assert score.score == 0.1235
        assert score.percentile == 85.6789

    def test_epss_score_validation(self):
        """Test EPSS score validation."""
        with pytest.raises(ValueError):
            # Score out of range
            EPSSScore(
                score=1.5,  # Invalid
                percentile=50.0,
                date=datetime.utcnow(),
            )


class TestVulnerability:
    """Test Vulnerability model."""

    @pytest.fixture
    def sample_vulnerability(self):
        """Create a sample vulnerability."""
        return Vulnerability(
            cve_id="CVE-2024-0001",
            title="Test Vulnerability",
            description="A test vulnerability description",
            published_date=datetime.utcnow() - timedelta(days=5),
            last_modified_date=datetime.utcnow(),
            severity=SeverityLevel.HIGH,
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=9.8,
                    base_severity=SeverityLevel.CRITICAL,
                )
            ],
            risk_score=85,
        )

    def test_vulnerability_creation(self, sample_vulnerability):
        """Test creating a vulnerability."""
        assert sample_vulnerability.cve_id == "CVE-2024-0001"
        assert sample_vulnerability.severity == SeverityLevel.HIGH
        assert sample_vulnerability.risk_score == 85

    def test_cve_id_validation(self):
        """Test CVE ID validation."""
        with pytest.raises(ValueError):
            Vulnerability(
                cve_id="INVALID-ID",  # Invalid format
                title="Test",
                description="Test",
                published_date=datetime.utcnow(),
                last_modified_date=datetime.utcnow(),
                severity=SeverityLevel.MEDIUM,
            )

    def test_cvss_base_score_property(self, sample_vulnerability):
        """Test CVSS base score property."""
        assert sample_vulnerability.cvss_base_score == 9.8

        # Test with no metrics
        vuln = Vulnerability(
            cve_id="CVE-2024-0002",
            title="Test",
            description="Test",
            published_date=datetime.utcnow(),
            last_modified_date=datetime.utcnow(),
            severity=SeverityLevel.LOW,
        )
        assert vuln.cvss_base_score is None

    def test_epss_probability_property(self, sample_vulnerability):
        """Test EPSS probability property."""
        # No EPSS score
        assert sample_vulnerability.epss_probability is None

        # With EPSS score
        sample_vulnerability.epss_score = EPSSScore(
            score=0.456,
            percentile=90.0,
            date=datetime.utcnow(),
        )
        assert sample_vulnerability.epss_probability == 45.6

    def test_to_summary_dict(self, sample_vulnerability):
        """Test converting to summary dictionary."""
        summary = sample_vulnerability.to_summary_dict()

        assert summary["cveId"] == "CVE-2024-0001"
        assert summary["severity"] == "HIGH"
        assert summary["riskScore"] == 85
        assert summary["cvssScore"] == 9.8
        assert "publishedDate" in summary

    def test_to_detail_dict(self, sample_vulnerability):
        """Test converting to detail dictionary."""
        detail = sample_vulnerability.to_detail_dict()

        assert detail["cveId"] == "CVE-2024-0001"
        assert detail["description"] == "A test vulnerability description"
        assert len(detail["cvssMetrics"]) == 1
        assert detail["cvssMetrics"][0]["baseScore"] == 9.8


class TestVulnerabilityBatch:
    """Test VulnerabilityBatch model."""

    @pytest.fixture
    def sample_batch(self):
        """Create a sample batch."""
        vulns = [
            Vulnerability(
                cve_id=f"CVE-2024-{i:04d}",
                title=f"Test Vuln {i}",
                description=f"Description {i}",
                published_date=datetime.utcnow(),
                last_modified_date=datetime.utcnow(),
                severity=SeverityLevel.HIGH if i % 2 == 0 else SeverityLevel.MEDIUM,
                risk_score=90 - (i * 10),
            )
            for i in range(5)
        ]

        return VulnerabilityBatch(vulnerabilities=vulns)

    def test_batch_count(self, sample_batch):
        """Test batch count property."""
        assert sample_batch.count == 5

    def test_filter_by_severity(self, sample_batch):
        """Test filtering by severity."""
        high_vulns = sample_batch.filter_by_severity(SeverityLevel.HIGH)
        assert len(high_vulns) == 3  # 0, 2, 4 are HIGH

        medium_vulns = sample_batch.filter_by_severity(SeverityLevel.MEDIUM)
        assert len(medium_vulns) == 5  # All are MEDIUM or higher

    def test_filter_by_risk_score(self, sample_batch):
        """Test filtering by risk score."""
        high_risk = sample_batch.filter_by_risk_score(70)
        assert len(high_risk) == 3  # Scores: 90, 80, 70

        all_vulns = sample_batch.filter_by_risk_score(0)
        assert len(all_vulns) == 5

    def test_sort_by_risk(self, sample_batch):
        """Test sorting by risk."""
        sorted_vulns = sample_batch.sort_by_risk()

        # Should be in descending order
        scores = [v.risk_score for v in sorted_vulns]
        assert scores == [90, 80, 70, 60, 50]
