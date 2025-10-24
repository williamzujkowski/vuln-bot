"""Comprehensive tests for risk scoring algorithm."""

from datetime import datetime, timezone

from scripts.models import (
    CVSSMetric,
    EPSSScore,
    ExploitationStatus,
    SeverityLevel,
    SSVCData,
    Vulnerability,
)
from scripts.processing.risk_scorer import RiskScorer

# Test constants
TEST_DATE = datetime(2025, 1, 1, tzinfo=timezone.utc)
RECENT_DATE = datetime.now(timezone.utc)


class TestRiskScorerSSVCMode:
    """Test suite for SSVC-enhanced risk scoring."""

    def test_maximum_score_with_ssvc(self):
        """Test maximum risk score (100) with full SSVC data."""
        scorer = RiskScorer()

        vuln = Vulnerability(
            cve_id="CVE-2025-9999",
            title="Maximum Risk Vulnerability",
            description="Test vulnerability with maximum risk",
            severity=SeverityLevel.CRITICAL,
            published_date=TEST_DATE,
            last_modified_date=TEST_DATE,
            # Maximum SSVC scores
            ssvc_data=SSVCData(
                exploitation="active",  # 100 * 0.30 = 30 points
                automatable="yes",  # 100 * 0.15 = 15 points
                technical_impact="total",  # 100 * 0.15 = 15 points
                priority_tier="ACT",
                compact_notation="A/Y/T",
                ssvc_score=60,  # Maximum SSVC score
            ),
            # Maximum CVSS
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=10.0,  # (10/10)*100 * 0.15 = 15 points
                    base_severity=SeverityLevel.CRITICAL,
                )
            ],
            # Maximum EPSS
            epss_score=EPSSScore(
                score=1.0,
                percentile=100.0,
                date=TEST_DATE,  # 100 * 0.10 = 10 points
            ),
            # Maximum KEV/Attack vector
            exploitation_status=ExploitationStatus.ACTIVE,  # 100 * 0.10 = 10 points
            attack_vector="N",  # 100 * 0.05 = 5 points
        )

        score = scorer.calculate_risk_score(vuln)

        # Total: 30 + 15 + 15 + 15 + 10 + 10 + 5 = 100
        assert score == 100

    def test_ssvc_act_priority(self):
        """Test ACT priority tier vulnerability."""
        scorer = RiskScorer()

        vuln = Vulnerability(
            cve_id="CVE-2025-9998",
            title="ACT Priority Vulnerability",
            description="Critical vulnerability requiring immediate action",
            severity=SeverityLevel.CRITICAL,
            published_date=TEST_DATE,
            last_modified_date=TEST_DATE,
            ssvc_data=SSVCData(
                exploitation="active",
                automatable="yes",
                technical_impact="total",
                priority_tier="ACT",
                compact_notation="A/Y/T",
                ssvc_score=60,  # Maximum SSVC score
            ),
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=9.8,
                    base_severity=SeverityLevel.CRITICAL,
                )
            ],
            epss_score=EPSSScore(score=0.95, percentile=99.5, date=TEST_DATE),
            exploitation_status=ExploitationStatus.ACTIVE,
            attack_vector="N",
        )

        score = scorer.calculate_risk_score(vuln)

        # ACT priority should have very high score (>90)
        assert score >= 90


class TestRiskScorerFallbackMode:
    """Test suite for fallback mode (without SSVC data)."""

    def test_fallback_with_active_exploitation(self):
        """Test fallback scoring with active exploitation."""
        scorer = RiskScorer()

        vuln = Vulnerability(
            cve_id="CVE-2025-9001",
            title="Fallback Active Exploitation",
            description="Vulnerability without SSVC data but active exploitation",
            severity=SeverityLevel.CRITICAL,
            published_date=TEST_DATE,
            last_modified_date=TEST_DATE,
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=9.0,
                    base_severity=SeverityLevel.CRITICAL,
                )
            ],
            epss_score=EPSSScore(score=0.85, percentile=95.0, date=TEST_DATE),
            exploitation_status=ExploitationStatus.ACTIVE,
            attack_vector="N",
        )

        score = scorer.calculate_risk_score(vuln)

        # Should get high score even without SSVC (fallback mode)
        assert score >= 65


class TestRiskScorerBatchScoring:
    """Test suite for batch scoring functionality."""

    def test_score_batch_multiple_vulns(self):
        """Test batch scoring with multiple vulnerabilities."""
        scorer = RiskScorer()

        vulns = [
            Vulnerability(
                cve_id=f"CVE-2025-{i:04d}",
                title=f"Test Vuln {i}",
                description="Test",
                severity=SeverityLevel.HIGH,
                published_date=TEST_DATE,
                last_modified_date=TEST_DATE,
                cvss_metrics=[
                    CVSSMetric(
                        version="3.1",
                        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        base_score=6.0 + (i * 0.5),  # 6.0, 6.5, 7.0, 7.5, 8.0
                        base_severity=SeverityLevel.HIGH,
                    )
                ],
                epss_score=EPSSScore(
                    score=0.5 + i * 0.1, percentile=50.0, date=TEST_DATE
                ),
                exploitation_status=ExploitationStatus.POC,
                attack_vector="N",
            )
            for i in range(5)
        ]

        scorer.score_batch(vulns)

        # All vulnerabilities should have risk_score set
        for vuln in vulns:
            assert hasattr(vuln, "risk_score")
            assert 0 <= vuln.risk_score <= 100


class TestRiskScorerEdgeCases:
    """Test suite for edge cases and missing data scenarios."""

    def test_missing_epss_score(self):
        """Test scoring with missing EPSS data."""
        scorer = RiskScorer()

        vuln = Vulnerability(
            cve_id="CVE-2025-9002",
            title="Vulnerability without EPSS",
            description="Test missing EPSS",
            severity=SeverityLevel.CRITICAL,
            published_date=TEST_DATE,
            last_modified_date=TEST_DATE,
            ssvc_data=SSVCData(
                exploitation="active",
                automatable="yes",
                technical_impact="total",
                priority_tier="ACT",
                compact_notation="A/Y/T",
                ssvc_score=60,
            ),
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=9.8,
                    base_severity=SeverityLevel.CRITICAL,
                )
            ],
            exploitation_status=ExploitationStatus.ACTIVE,
            attack_vector="N",
        )

        score = scorer.calculate_risk_score(vuln)

        # Should still get high score from SSVC + CVSS + KEV
        assert score >= 85

    def test_missing_cvss_metrics(self):
        """Test scoring with missing CVSS data."""
        scorer = RiskScorer()

        vuln = Vulnerability(
            cve_id="CVE-2025-9003",
            title="Vulnerability without CVSS",
            description="Test missing CVSS",
            severity=SeverityLevel.CRITICAL,
            published_date=TEST_DATE,
            last_modified_date=TEST_DATE,
            ssvc_data=SSVCData(
                exploitation="active",
                automatable="yes",
                technical_impact="total",
                priority_tier="ACT",
                compact_notation="A/Y/T",
                ssvc_score=60,
            ),
            epss_score=EPSSScore(score=0.95, percentile=99.5, date=TEST_DATE),
            exploitation_status=ExploitationStatus.ACTIVE,
            attack_vector="N",
        )

        score = scorer.calculate_risk_score(vuln)

        # Should still score high from SSVC + EPSS + KEV
        assert score >= 80

    def test_ssvc_attend_priority(self):
        """Test ATTEND priority tier vulnerability."""
        scorer = RiskScorer()

        vuln = Vulnerability(
            cve_id="CVE-2025-9004",
            title="ATTEND Priority Vulnerability",
            description="Vulnerability requiring scheduled remediation",
            severity=SeverityLevel.HIGH,
            published_date=TEST_DATE,
            last_modified_date=TEST_DATE,
            ssvc_data=SSVCData(
                exploitation="poc",
                automatable="yes",
                technical_impact="partial",
                priority_tier="ATTEND",
                compact_notation="P/Y/P",
                ssvc_score=30,
            ),
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                    base_score=7.5,
                    base_severity=SeverityLevel.HIGH,
                )
            ],
            epss_score=EPSSScore(score=0.65, percentile=85.0, date=TEST_DATE),
            exploitation_status=ExploitationStatus.POC,
            attack_vector="N",
        )

        score = scorer.calculate_risk_score(vuln)

        # ATTEND priority should have medium-high score (60-80 range)
        assert 60 <= score <= 80

    def test_ssvc_track_priority(self):
        """Test TRACK priority tier vulnerability."""
        scorer = RiskScorer()

        vuln = Vulnerability(
            cve_id="CVE-2025-9005",
            title="TRACK Priority Vulnerability",
            description="Vulnerability for monitoring only",
            severity=SeverityLevel.HIGH,
            published_date=TEST_DATE,
            last_modified_date=TEST_DATE,
            ssvc_data=SSVCData(
                exploitation="none",
                automatable="no",
                technical_impact="partial",
                priority_tier="TRACK",
                compact_notation="N/N/P",
                ssvc_score=0,
            ),
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N",
                    base_score=3.5,
                    base_severity=SeverityLevel.LOW,
                )
            ],
            epss_score=EPSSScore(score=0.15, percentile=30.0, date=TEST_DATE),
            exploitation_status=ExploitationStatus.NONE,
            attack_vector="L",
        )

        score = scorer.calculate_risk_score(vuln)

        # TRACK priority should have lower score (<40)
        assert score < 40

    def test_poc_exploitation_status(self):
        """Test vulnerability with PoC exploitation."""
        scorer = RiskScorer()

        vuln = Vulnerability(
            cve_id="CVE-2025-9006",
            title="PoC Available Vulnerability",
            description="Vulnerability with proof-of-concept exploit",
            severity=SeverityLevel.HIGH,
            published_date=TEST_DATE,
            last_modified_date=TEST_DATE,
            ssvc_data=SSVCData(
                exploitation="poc",
                automatable="yes",
                technical_impact="total",
                priority_tier="ATTEND",
                compact_notation="P/Y/T",
                ssvc_score=45,
            ),
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=8.5,
                    base_severity=SeverityLevel.HIGH,
                )
            ],
            epss_score=EPSSScore(score=0.75, percentile=90.0, date=TEST_DATE),
            exploitation_status=ExploitationStatus.POC,
            attack_vector="N",
        )

        score = scorer.calculate_risk_score(vuln)

        # PoC should score lower than active exploitation
        assert 65 <= score <= 85

    def test_local_attack_vector(self):
        """Test vulnerability with local attack vector."""
        scorer = RiskScorer()

        vuln = Vulnerability(
            cve_id="CVE-2025-9007",
            title="Local Attack Vector Vulnerability",
            description="Requires local access",
            severity=SeverityLevel.HIGH,
            published_date=TEST_DATE,
            last_modified_date=TEST_DATE,
            ssvc_data=SSVCData(
                exploitation="active",
                automatable="no",
                technical_impact="total",
                priority_tier="ATTEND",
                compact_notation="A/N/T",
                ssvc_score=45,
            ),
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    base_score=7.8,
                    base_severity=SeverityLevel.HIGH,
                )
            ],
            epss_score=EPSSScore(score=0.65, percentile=85.0, date=TEST_DATE),
            exploitation_status=ExploitationStatus.ACTIVE,
            attack_vector="L",
        )

        score = scorer.calculate_risk_score(vuln)

        # Local attack vector should score lower than network
        assert score < 85

    def test_physical_attack_vector(self):
        """Test vulnerability with physical attack vector."""
        scorer = RiskScorer()

        vuln = Vulnerability(
            cve_id="CVE-2025-9008",
            title="Physical Attack Vector Vulnerability",
            description="Requires physical access",
            severity=SeverityLevel.MEDIUM,
            published_date=TEST_DATE,
            last_modified_date=TEST_DATE,
            ssvc_data=SSVCData(
                exploitation="none",
                automatable="no",
                technical_impact="partial",
                priority_tier="TRACK",
                compact_notation="N/N/P",
                ssvc_score=0,
            ),
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=6.8,
                    base_severity=SeverityLevel.MEDIUM,
                )
            ],
            epss_score=EPSSScore(score=0.05, percentile=10.0, date=TEST_DATE),
            exploitation_status=ExploitationStatus.NONE,
            attack_vector="P",
        )

        score = scorer.calculate_risk_score(vuln)

        # Physical attack vector should have lowest score
        assert score < 30

    def test_minimum_score(self):
        """Test vulnerability with minimal risk factors."""
        scorer = RiskScorer()

        vuln = Vulnerability(
            cve_id="CVE-2025-9009",
            title="Minimum Risk Vulnerability",
            description="Low risk vulnerability",
            severity=SeverityLevel.LOW,
            published_date=TEST_DATE,
            last_modified_date=TEST_DATE,
            ssvc_data=SSVCData(
                exploitation="none",
                automatable="no",
                technical_impact="partial",
                priority_tier="TRACK",
                compact_notation="N/N/P",
                ssvc_score=0,
            ),
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N",
                    base_score=2.0,
                    base_severity=SeverityLevel.LOW,
                )
            ],
            epss_score=EPSSScore(score=0.01, percentile=5.0, date=TEST_DATE),
            exploitation_status=ExploitationStatus.NONE,
            attack_vector="L",
        )

        score = scorer.calculate_risk_score(vuln)

        # Minimum risk should score very low
        assert score < 20

    def test_no_ssvc_no_epss_no_kev(self):
        """Test vulnerability with only CVSS data."""
        scorer = RiskScorer()

        vuln = Vulnerability(
            cve_id="CVE-2025-9010",
            title="Basic Vulnerability",
            description="Only CVSS data available",
            severity=SeverityLevel.HIGH,
            published_date=TEST_DATE,
            last_modified_date=TEST_DATE,
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=8.5,
                    base_severity=SeverityLevel.HIGH,
                )
            ],
            attack_vector="N",
        )

        score = scorer.calculate_risk_score(vuln)

        # Should still calculate a reasonable score from CVSS alone
        assert 25 <= score <= 50
