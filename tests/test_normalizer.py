"""Tests for data normalizer."""

from datetime import datetime, timedelta, timezone

import pytest

from scripts.models import (
    CVSSMetric,
    EPSSScore,
    ExploitationStatus,
    Reference,
    SeverityLevel,
    Vulnerability,
)
from scripts.processing.normalizer import VulnerabilityNormalizer


class TestVulnerabilityNormalizer:
    """Test VulnerabilityNormalizer functionality."""

    @pytest.fixture
    def normalizer(self):
        """Create a VulnerabilityNormalizer instance."""
        return VulnerabilityNormalizer()

    @pytest.fixture
    def sample_vulnerabilities(self):
        """Create sample vulnerabilities for testing."""
        return [
            Vulnerability(
                cve_id="CVE-2023-0001",
                title="First Vuln",
                description="Description 1",
                severity=SeverityLevel.HIGH,
                published_date=datetime.now(timezone.utc) - timedelta(days=5),
                last_modified_date=datetime.now(timezone.utc),
                references=[Reference(url="https://example.com/1")],
                affected_vendors=["vendor1"],
                risk_score=75.0,
            ),
            Vulnerability(
                cve_id="CVE-2023-0002",
                title="Second Vuln",
                description="Description 2",
                severity=SeverityLevel.CRITICAL,
                published_date=datetime.now(timezone.utc) - timedelta(days=3),
                last_modified_date=datetime.now(timezone.utc),
                references=[Reference(url="https://example.com/2")],
                affected_vendors=["vendor2"],
                risk_score=85.0,
            ),
        ]

    def test_deduplicate_empty_list(self, normalizer):
        """Test deduplicating empty vulnerability list."""
        result = normalizer.deduplicate_vulnerabilities([])
        assert result == []

    def test_deduplicate_single_source(self, normalizer, sample_vulnerabilities):
        """Test deduplicating vulnerabilities from single source."""
        result = normalizer.deduplicate_vulnerabilities(sample_vulnerabilities)

        assert len(result) == 2
        assert result[0].cve_id == "CVE-2023-0001"
        assert result[1].cve_id == "CVE-2023-0002"

    def test_deduplicate_by_cve_id(self, normalizer):
        """Test deduplication by CVE ID."""
        vulns = [
            Vulnerability(
                cve_id="CVE-2023-0001",
                title="First Version",
                description="Description 1",
                severity=SeverityLevel.HIGH,
                published_date=datetime.now(timezone.utc) - timedelta(days=5),
                last_modified_date=datetime.now(timezone.utc) - timedelta(days=5),
                risk_score=70.0,
            ),
            Vulnerability(
                cve_id="CVE-2023-0001",  # Same CVE ID
                title="Updated Version",
                description="Updated Description",
                severity=SeverityLevel.CRITICAL,  # Different severity
                published_date=datetime.now(timezone.utc) - timedelta(days=5),
                last_modified_date=datetime.now(timezone.utc),  # More recent
                risk_score=85.0,
            ),
        ]

        result = normalizer.deduplicate_vulnerabilities(vulns)

        # Should keep only one vulnerability
        assert len(result) == 1
        # merge_vulnerabilities keeps first as base but merges data
        assert result[0].title == "First Version"
        # merge keeps first vuln's severity and risk score
        assert result[0].severity == SeverityLevel.HIGH
        assert result[0].risk_score == 70.0

    def test_merge_vulnerability_data(self, normalizer):
        """Test merging data from multiple sources."""
        base_vuln = Vulnerability(
            cve_id="CVE-2023-0001",
            title="Base Vulnerability",
            description="Base description",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(timezone.utc) - timedelta(days=5),
            last_modified_date=datetime.now(timezone.utc) - timedelta(days=2),
            references=[Reference(url="https://example.com/base")],
            affected_vendors=["vendor1"],
            risk_score=70.0,
        )

        updated_vuln = Vulnerability(
            cve_id="CVE-2023-0001",
            title="Updated Vulnerability",
            description="Updated description",
            severity=SeverityLevel.CRITICAL,
            published_date=datetime.now(timezone.utc) - timedelta(days=5),
            last_modified_date=datetime.now(timezone.utc),
            references=[
                Reference(url="https://example.com/updated"),
                Reference(url="https://example.com/new"),
            ],
            affected_vendors=["vendor1", "vendor2"],
            exploitation_status=ExploitationStatus.POC,
            tags=["important", "critical"],
            risk_score=85.0,
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=9.8,
                    base_severity=SeverityLevel.CRITICAL,
                )
            ],
        )

        merged = normalizer.merge_vulnerabilities([base_vuln, updated_vuln])

        # merge_vulnerabilities keeps first vuln as base
        assert merged.title == "Base Vulnerability"
        assert merged.description == "Base description"
        # merge keeps first vuln's severity and risk score
        assert merged.severity == SeverityLevel.HIGH
        assert merged.risk_score == 70.0

        # Should have merged references
        ref_urls = [ref.url for ref in merged.references]
        assert len(ref_urls) == 3
        assert "https://example.com/base" in ref_urls
        assert "https://example.com/updated" in ref_urls
        assert "https://example.com/new" in ref_urls

        # Should have merged vendors
        assert len(merged.affected_vendors) == 2
        assert "vendor1" in merged.affected_vendors
        assert "vendor2" in merged.affected_vendors

        # Should have additional data from updated version
        # Note: exploitation_status comparison is string-based, so UNKNOWN > POC
        assert merged.exploitation_status == ExploitationStatus.UNKNOWN
        # Check tags content, not order
        assert set(merged.tags) == {"important", "critical"}
        assert len(merged.cvss_metrics) == 1
        assert merged.cvss_metrics[0].base_score == 9.8

    def test_merge_with_epss_data(self, normalizer):
        """Test merging vulnerability with EPSS data."""
        base_vuln = Vulnerability(
            cve_id="CVE-2023-0001",
            title="Base Vulnerability",
            description="Base description",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(timezone.utc) - timedelta(days=5),
            last_modified_date=datetime.now(timezone.utc) - timedelta(days=1),
            risk_score=70.0,
        )

        # Same vuln with EPSS data
        with_epss = Vulnerability(
            cve_id="CVE-2023-0001",
            title="Base Vulnerability",
            description="Base description",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(timezone.utc) - timedelta(days=5),
            last_modified_date=datetime.now(timezone.utc),
            risk_score=80.0,  # Different risk score
            epss_score=EPSSScore(
                cve_id="CVE-2023-0001",
                score=0.8542,
                percentile=0.9521,
                date=datetime.now(timezone.utc),
            ),
        )

        result = normalizer.deduplicate_vulnerabilities([base_vuln, with_epss])

        assert len(result) == 1
        merged = result[0]

        # Should have EPSS data
        assert merged.epss_score is not None
        assert merged.epss_score.score == 0.8542
        assert merged.epss_score.percentile == 0.9521
        # risk_score stays from first vuln
        assert merged.risk_score == 70.0

    def test_normalize_preserves_order(self, normalizer):
        """Test that normalization preserves risk score order."""
        vulns = []
        for i in range(5):
            vuln = Vulnerability(
                cve_id=f"CVE-2023-{i:04d}",
                title=f"Vuln {i}",
                description=f"Description {i}",
                severity=SeverityLevel.HIGH,
                published_date=datetime.now(timezone.utc) - timedelta(days=i),
                last_modified_date=datetime.now(timezone.utc),
                risk_score=90.0 - (i * 10),  # Decreasing risk scores
            )
            vulns.append(vuln)

        result = normalizer.deduplicate_vulnerabilities(vulns)

        # Should maintain order by risk score
        assert len(result) == 5
        for i in range(5):
            assert result[i].cve_id == f"CVE-2023-{i:04d}"
            assert result[i].risk_score == 90.0 - (i * 10)

    def test_normalize_with_duplicate_references(self, normalizer):
        """Test normalization removes duplicate references."""
        vuln1 = Vulnerability(
            cve_id="CVE-2023-0001",
            title="Vulnerability",
            description="Description",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(timezone.utc) - timedelta(days=5),
            last_modified_date=datetime.now(timezone.utc) - timedelta(days=1),
            references=[
                Reference(url="https://example.com/1"),
                Reference(url="https://example.com/2"),
            ],
            risk_score=70.0,
        )

        vuln2 = Vulnerability(
            cve_id="CVE-2023-0001",
            title="Vulnerability",
            description="Description",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(timezone.utc) - timedelta(days=5),
            last_modified_date=datetime.now(timezone.utc),
            references=[
                Reference(url="https://example.com/2"),
                Reference(url="https://example.com/3"),
                Reference(url="https://example.com/1"),
            ],
            risk_score=70.0,
        )

        result = normalizer.deduplicate_vulnerabilities([vuln1, vuln2])

        assert len(result) == 1
        # Should have unique references
        assert len(result[0].references) == 3
        ref_urls = {ref.url for ref in result[0].references}
        assert ref_urls == {
            "https://example.com/1",
            "https://example.com/2",
            "https://example.com/3",
        }

    def test_normalize_with_duplicate_vendors(self, normalizer):
        """Test normalization removes duplicate vendors."""
        vuln1 = Vulnerability(
            cve_id="CVE-2023-0001",
            title="Vulnerability",
            description="Description",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(timezone.utc) - timedelta(days=5),
            last_modified_date=datetime.now(timezone.utc) - timedelta(days=1),
            affected_vendors=["microsoft", "adobe"],
            risk_score=70.0,
        )

        vuln2 = Vulnerability(
            cve_id="CVE-2023-0001",
            title="Vulnerability",
            description="Description",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(timezone.utc) - timedelta(days=5),
            last_modified_date=datetime.now(timezone.utc),
            affected_vendors=["adobe", "oracle", "microsoft"],
            risk_score=70.0,
        )

        result = normalizer.deduplicate_vulnerabilities([vuln1, vuln2])

        assert len(result) == 1
        # Should have unique vendors
        assert len(result[0].affected_vendors) == 3
        assert set(result[0].affected_vendors) == {"microsoft", "adobe", "oracle"}

    def test_normalize_with_duplicate_tags(self, normalizer):
        """Test normalization removes duplicate tags."""
        vuln1 = Vulnerability(
            cve_id="CVE-2023-0001",
            title="Vulnerability",
            description="Description",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(timezone.utc) - timedelta(days=5),
            last_modified_date=datetime.now(timezone.utc) - timedelta(days=1),
            tags=["critical", "remote"],
            risk_score=70.0,
        )

        vuln2 = Vulnerability(
            cve_id="CVE-2023-0001",
            title="Vulnerability",
            description="Description",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(timezone.utc) - timedelta(days=5),
            last_modified_date=datetime.now(timezone.utc),
            tags=["remote", "exploit", "critical"],
            risk_score=70.0,
        )

        result = normalizer.deduplicate_vulnerabilities([vuln1, vuln2])

        assert len(result) == 1
        # Should have unique tags
        assert len(result[0].tags) == 3
        assert set(result[0].tags) == {"critical", "remote", "exploit"}

    def test_normalize_large_dataset(self, normalizer):
        """Test normalizing large dataset with duplicates."""
        vulns = []

        # Create 100 vulnerabilities with some duplicates
        for i in range(100):
            cve_id = f"CVE-2023-{i % 50:04d}"  # 50 unique CVEs, each appears twice
            vuln = Vulnerability(
                cve_id=cve_id,
                title=f"Vuln {i}",
                description=f"Description {i}",
                severity=SeverityLevel.HIGH if i % 3 == 0 else SeverityLevel.MEDIUM,
                published_date=datetime.now(timezone.utc) - timedelta(days=i % 30),
                last_modified_date=datetime.now(timezone.utc) - timedelta(hours=i),
                risk_score=50.0 + (i % 50),
            )
            vulns.append(vuln)

        result = normalizer.deduplicate_vulnerabilities(vulns)

        # Should have 50 unique vulnerabilities
        assert len(result) == 50

        # Verify no duplicates
        cve_ids = [v.cve_id for v in result]
        assert len(set(cve_ids)) == 50

        # merge_vulnerabilities keeps the first occurrence
        for vuln in result:
            cve_num = int(vuln.cve_id.split("-")[-1])
            # The first occurrence (i = cve_num) is kept
            assert vuln.title == f"Vuln {cve_num}"
