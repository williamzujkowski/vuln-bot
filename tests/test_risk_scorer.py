"""Tests for risk scorer module."""

from datetime import datetime, timedelta, timezone

import pytest

from scripts.models import CVSSMetric, EPSSScore, SeverityLevel, Vulnerability
from scripts.processing.risk_scorer import RiskScorer


class TestRiskScorer:
    """Test cases for RiskScorer."""

    @pytest.fixture
    def scorer(self):
        """Create risk scorer instance."""
        return RiskScorer()

    @pytest.fixture
    def high_risk_vuln(self):
        """Create high risk vulnerability."""
        return Vulnerability(
            cve_id="CVE-2024-0001",
            title="Critical RCE vulnerability",
            description="Critical remote code execution in popular software",
            severity=SeverityLevel.CRITICAL,
            published_date=datetime.now(timezone.utc) - timedelta(days=1),
            last_modified_date=datetime.now(timezone.utc),
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=9.8,
                    base_severity=SeverityLevel.CRITICAL,
                )
            ],
            epss_score=EPSSScore(
                score=0.95, percentile=99.0, date=datetime.now(timezone.utc)
            ),
            tags=["infrastructure", "rce", "KEV"],
            affected_products=["windows", "linux"],
        )

    @pytest.fixture
    def low_risk_vuln(self):
        """Create low risk vulnerability."""
        return Vulnerability(
            cve_id="CVE-2024-0002",
            title="Low severity issue",
            description="Minor issue with limited impact",
            severity=SeverityLevel.LOW,
            published_date=datetime.now(timezone.utc) - timedelta(days=365),
            last_modified_date=datetime.now(timezone.utc) - timedelta(days=300),
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
                    base_score=2.0,
                    base_severity=SeverityLevel.LOW,
                )
            ],
            epss_score=EPSSScore(
                score=0.001, percentile=10.0, date=datetime.now(timezone.utc)
            ),
            tags=[],
            affected_products=["unknown-product"],
        )

    def test_calculate_risk_score_high(self, scorer, high_risk_vuln):
        """Test risk score for high risk vulnerability."""
        score = scorer.calculate_risk_score(high_risk_vuln)

        assert score >= 70  # Should be very high
        assert score <= 100

    def test_calculate_risk_score_low(self, scorer, low_risk_vuln):
        """Test risk score for low risk vulnerability."""
        score = scorer.calculate_risk_score(low_risk_vuln)

        assert score < 30  # Should be low
        assert score >= 0

    def test_score_ranges(self, scorer):
        """Test score ranges for different vulnerability types."""
        # Critical vulnerability with high EPSS
        critical_vuln = Vulnerability(
            cve_id="CVE-2024-0001",
            title="Critical",
            description="Critical",
            severity=SeverityLevel.CRITICAL,
            published_date=datetime.now(timezone.utc),
            last_modified_date=datetime.now(timezone.utc),
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=10.0,
                    base_severity=SeverityLevel.CRITICAL,
                )
            ],
            epss_score=EPSSScore(score=0.99, percentile=100.0, date=datetime.now()),
        )
        score = scorer.calculate_risk_score(critical_vuln)
        assert score >= 65  # Should be very high

        # Low severity with low EPSS
        low_vuln = Vulnerability(
            cve_id="CVE-2024-0002",
            title="Low",
            description="Low",
            severity=SeverityLevel.LOW,
            published_date=datetime.now(timezone.utc) - timedelta(days=365),
            last_modified_date=datetime.now(timezone.utc),
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
                    base_score=1.0,
                    base_severity=SeverityLevel.LOW,
                )
            ],
            epss_score=EPSSScore(score=0.0001, percentile=1.0, date=datetime.now()),
        )
        score = scorer.calculate_risk_score(low_vuln)
        assert score < 20  # Should be very low

    def test_score_edge_cases(self, scorer):
        """Test edge cases."""
        # Vulnerability with no scores
        vuln = Vulnerability(
            cve_id="CVE-2024-0003",
            title="Test",
            description="Test",
            severity=SeverityLevel.MEDIUM,
            published_date=datetime.now(timezone.utc),
            last_modified_date=datetime.now(timezone.utc),
        )

        score = scorer.calculate_risk_score(vuln)
        assert score >= 0
        assert score <= 100

        # Vulnerability with partial data
        vuln.epss_score = EPSSScore(score=0.5, percentile=50.0, date=datetime.now())
        score = scorer.calculate_risk_score(vuln)
        assert score > 0
