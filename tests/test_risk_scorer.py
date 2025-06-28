"""Unit tests for risk scoring algorithm."""

import pytest
from datetime import datetime, timedelta

from scripts.models import (
    CVSSMetric,
    EPSSScore,
    ExploitationStatus,
    SeverityLevel,
    Vulnerability,
)
from scripts.processing.risk_scorer import RiskScorer


class TestRiskScorer:
    """Test RiskScorer functionality."""
    
    @pytest.fixture
    def scorer(self):
        """Create a risk scorer instance."""
        return RiskScorer()
    
    @pytest.fixture
    def base_vulnerability(self):
        """Create a base vulnerability for testing."""
        return Vulnerability(
            cve_id="CVE-2024-0001",
            title="Test Vulnerability",
            description="Test description",
            published_date=datetime.utcnow() - timedelta(days=30),
            last_modified_date=datetime.utcnow(),
            severity=SeverityLevel.HIGH,
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=7.5,
                    base_severity=SeverityLevel.HIGH,
                )
            ],
        )
    
    def test_basic_risk_score(self, scorer, base_vulnerability):
        """Test basic risk score calculation."""
        score = scorer.calculate_risk_score(base_vulnerability)
        
        # Should be reasonable for a HIGH severity vuln
        assert 40 <= score <= 80
    
    def test_cvss_component(self, scorer, base_vulnerability):
        """Test CVSS score component."""
        # Low CVSS
        base_vulnerability.cvss_metrics[0].base_score = 3.0
        low_score = scorer.calculate_risk_score(base_vulnerability)
        
        # High CVSS
        base_vulnerability.cvss_metrics[0].base_score = 9.5
        high_score = scorer.calculate_risk_score(base_vulnerability)
        
        assert high_score > low_score
    
    def test_epss_component(self, scorer, base_vulnerability):
        """Test EPSS score component."""
        # Without EPSS
        no_epss_score = scorer.calculate_risk_score(base_vulnerability)
        
        # With high EPSS
        base_vulnerability.epss_score = EPSSScore(
            score=0.95,
            percentile=99.0,
            date=datetime.utcnow(),
        )
        high_epss_score = scorer.calculate_risk_score(base_vulnerability)
        
        assert high_epss_score > no_epss_score
    
    def test_exploitation_status_component(self, scorer, base_vulnerability):
        """Test exploitation status component."""
        scores = {}
        
        for status in ExploitationStatus:
            base_vulnerability.exploitation_status = status
            scores[status] = scorer.calculate_risk_score(base_vulnerability)
        
        # Active exploitation should score highest
        assert scores[ExploitationStatus.ACTIVE] > scores[ExploitationStatus.UNKNOWN]
        assert scores[ExploitationStatus.WEAPONIZED] > scores[ExploitationStatus.NONE]
    
    def test_age_component(self, scorer):
        """Test age component of risk score."""
        # Very new vulnerability (1 day old)
        new_vuln = Vulnerability(
            cve_id="CVE-2024-0001",
            title="New Vuln",
            description="Test",
            published_date=datetime.utcnow() - timedelta(days=1),
            last_modified_date=datetime.utcnow(),
            severity=SeverityLevel.MEDIUM,
        )
        new_score = scorer.calculate_risk_score(new_vuln)
        
        # Old vulnerability (1 year old)
        old_vuln = Vulnerability(
            cve_id="CVE-2023-0001",
            title="Old Vuln",
            description="Test",
            published_date=datetime.utcnow() - timedelta(days=365),
            last_modified_date=datetime.utcnow(),
            severity=SeverityLevel.MEDIUM,
        )
        old_score = scorer.calculate_risk_score(old_vuln)
        
        assert new_score > old_score
    
    def test_vendor_impact_component(self, scorer, base_vulnerability):
        """Test vendor impact component."""
        # No vendors
        base_vulnerability.affected_vendors = []
        no_vendor_score = scorer.calculate_risk_score(base_vulnerability)
        
        # High impact vendor
        base_vulnerability.affected_vendors = ["microsoft", "apache"]
        high_impact_score = scorer.calculate_risk_score(base_vulnerability)
        
        # Low impact vendor
        base_vulnerability.affected_vendors = ["unknown-vendor"]
        low_impact_score = scorer.calculate_risk_score(base_vulnerability)
        
        assert high_impact_score > low_impact_score
        assert high_impact_score > no_vendor_score
    
    def test_attack_vector_component(self, scorer, base_vulnerability):
        """Test attack vector component."""
        scores = {}
        
        for vector in ["N", "A", "L", "P"]:
            base_vulnerability.attack_vector = vector
            scores[vector] = scorer.calculate_risk_score(base_vulnerability)
        
        # Network attacks should score highest
        assert scores["N"] > scores["L"]
        assert scores["A"] > scores["P"]
    
    def test_infrastructure_tags_bonus(self, scorer, base_vulnerability):
        """Test infrastructure tags bonus."""
        # No tags
        base_vulnerability.tags = []
        no_tags_score = scorer.calculate_risk_score(base_vulnerability)
        
        # Infrastructure tags
        base_vulnerability.tags = ["remote", "authentication", "rce"]
        infra_tags_score = scorer.calculate_risk_score(base_vulnerability)
        
        assert infra_tags_score > no_tags_score
    
    def test_score_bounds(self, scorer):
        """Test that scores stay within 0-100 bounds."""
        # Minimal risk vulnerability
        min_vuln = Vulnerability(
            cve_id="CVE-2024-0001",
            title="Min Risk",
            description="Test",
            published_date=datetime.utcnow() - timedelta(days=365),
            last_modified_date=datetime.utcnow(),
            severity=SeverityLevel.NONE,
            exploitation_status=ExploitationStatus.NONE,
            attack_vector="P",
            requires_user_interaction=True,
            requires_privileges="H",
        )
        min_score = scorer.calculate_risk_score(min_vuln)
        
        # Maximum risk vulnerability
        max_vuln = Vulnerability(
            cve_id="CVE-2024-0002",
            title="Max Risk",
            description="Test",
            published_date=datetime.utcnow() - timedelta(days=1),
            last_modified_date=datetime.utcnow(),
            severity=SeverityLevel.CRITICAL,
            exploitation_status=ExploitationStatus.ACTIVE,
            attack_vector="N",
            requires_user_interaction=False,
            requires_privileges="N",
            affected_vendors=["microsoft", "apache", "nginx"],
            tags=["remote", "rce", "authentication"],
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    base_score=10.0,
                    base_severity=SeverityLevel.CRITICAL,
                )
            ],
            epss_score=EPSSScore(
                score=0.99,
                percentile=99.9,
                date=datetime.utcnow(),
            ),
        )
        max_score = scorer.calculate_risk_score(max_vuln)
        
        assert 0 <= min_score <= 100
        assert 0 <= max_score <= 100
        assert max_score > min_score
    
    def test_get_risk_factors(self, scorer, base_vulnerability):
        """Test getting human-readable risk factors."""
        base_vulnerability.severity = SeverityLevel.CRITICAL
        base_vulnerability.epss_score = EPSSScore(
            score=0.75,
            percentile=95.0,
            date=datetime.utcnow(),
        )
        base_vulnerability.exploitation_status = ExploitationStatus.ACTIVE
        base_vulnerability.published_date = datetime.utcnow() - timedelta(days=3)
        base_vulnerability.affected_vendors = ["Microsoft"]
        base_vulnerability.attack_vector = "N"
        base_vulnerability.requires_user_interaction = False
        
        factors = scorer.get_risk_factors(base_vulnerability)
        
        assert "severity" in factors
        assert "CRITICAL" in factors["severity"]
        assert "epss" in factors
        assert "75.0%" in factors["epss"]
        assert "exploitation" in factors
        assert "age" in factors
        assert "within last week" in factors["age"]