"""Tests for data normalizer."""

from datetime import datetime, timedelta

import pytest

from scripts.models import (
    CVSSMetric,
    EPSSScore,
    ExploitationStatus,
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
                published_date=datetime.now(datetime.UTC) - timedelta(days=5),
                last_modified_date=datetime.now(datetime.UTC),
                references=["https://example.com/1"],
                affected_vendors=["vendor1"],
                risk_score=75.0,
            ),
            Vulnerability(
                cve_id="CVE-2023-0002",
                title="Second Vuln",
                description="Description 2",
                severity=SeverityLevel.CRITICAL,
                published_date=datetime.now(datetime.UTC) - timedelta(days=3),
                last_modified_date=datetime.now(datetime.UTC),
                references=["https://example.com/2"],
                affected_vendors=["vendor2"],
                risk_score=85.0,
            ),
        ]

    def test_normalize_empty_list(self, normalizer):
        """Test normalizing empty vulnerability list."""
        result = normalizer.normalize([])
        assert result == []

    def test_normalize_single_source(self, normalizer, sample_vulnerabilities):
        """Test normalizing vulnerabilities from single source."""
        result = normalizer.normalize(sample_vulnerabilities)

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
                published_date=datetime.now(datetime.UTC) - timedelta(days=5),
                last_modified_date=datetime.now(datetime.UTC) - timedelta(days=5),
                risk_score=70.0,
            ),
            Vulnerability(
                cve_id="CVE-2023-0001",  # Same CVE ID
                title="Updated Version",
                description="Updated Description",
                severity=SeverityLevel.CRITICAL,  # Different severity
                published_date=datetime.now(datetime.UTC) - timedelta(days=5),
                last_modified_date=datetime.now(datetime.UTC),  # More recent
                risk_score=85.0,
            ),
        ]

        result = normalizer.normalize(vulns)

        # Should keep only one vulnerability
        assert len(result) == 1
        # Should keep the more recently modified one
        assert result[0].title == "Updated Version"
        assert result[0].severity == SeverityLevel.CRITICAL
        assert result[0].risk_score == 85.0

    def test_merge_vulnerability_data(self, normalizer):
        """Test merging data from multiple sources."""
        base_vuln = Vulnerability(
            cve_id="CVE-2023-0001",
            title="Base Vulnerability",
            description="Base description",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(datetime.UTC) - timedelta(days=5),
            last_modified_date=datetime.now(datetime.UTC) - timedelta(days=2),
            references=["https://example.com/base"],
            affected_vendors=["vendor1"],
            risk_score=70.0,
        )

        updated_vuln = Vulnerability(
            cve_id="CVE-2023-0001",
            title="Updated Vulnerability",
            description="Updated description",
            severity=SeverityLevel.CRITICAL,
            published_date=datetime.now(datetime.UTC) - timedelta(days=5),
            last_modified_date=datetime.now(datetime.UTC),
            references=["https://example.com/updated", "https://example.com/new"],
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

        result = normalizer.normalize([base_vuln, updated_vuln])

        assert len(result) == 1
        merged = result[0]

        # Should use data from more recent version
        assert merged.title == "Updated Vulnerability"
        assert merged.description == "Updated description"
        assert merged.severity == SeverityLevel.CRITICAL
        assert merged.risk_score == 85.0

        # Should have merged references
        assert len(merged.references) == 3
        assert "https://example.com/base" in merged.references
        assert "https://example.com/updated" in merged.references
        assert "https://example.com/new" in merged.references

        # Should have merged vendors
        assert len(merged.affected_vendors) == 2
        assert "vendor1" in merged.affected_vendors
        assert "vendor2" in merged.affected_vendors

        # Should have additional data from updated version
        assert merged.exploitation_status == ExploitationStatus.POC
        assert merged.tags == ["important", "critical"]
        assert len(merged.cvss_metrics) == 1
        assert merged.cvss_metrics[0].base_score == 9.8

    def test_merge_with_epss_data(self, normalizer):
        """Test merging vulnerability with EPSS data."""
        base_vuln = Vulnerability(
            cve_id="CVE-2023-0001",
            title="Base Vulnerability",
            description="Base description",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(datetime.UTC) - timedelta(days=5),
            last_modified_date=datetime.now(datetime.UTC) - timedelta(days=1),
            risk_score=70.0,
        )

        # Same vuln with EPSS data
        with_epss = Vulnerability(
            cve_id="CVE-2023-0001",
            title="Base Vulnerability",
            description="Base description",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(datetime.UTC) - timedelta(days=5),
            last_modified_date=datetime.now(datetime.UTC),
            risk_score=80.0,  # Different risk score
            epss_score=EPSSScore(
                cve_id="CVE-2023-0001",
                score=0.8542,
                percentile=0.9521,
                date=datetime.now(datetime.UTC),
            ),
        )

        result = normalizer.normalize([base_vuln, with_epss])

        assert len(result) == 1
        merged = result[0]

        # Should have EPSS data
        assert merged.epss_score is not None
        assert merged.epss_score.score == 0.8542
        assert merged.epss_score.percentile == 0.9521
        assert merged.risk_score == 80.0

    def test_normalize_preserves_order(self, normalizer):
        """Test that normalization preserves risk score order."""
        vulns = []
        for i in range(5):
            vuln = Vulnerability(
                cve_id=f"CVE-2023-{i:04d}",
                title=f"Vuln {i}",
                description=f"Description {i}",
                severity=SeverityLevel.HIGH,
                published_date=datetime.now(datetime.UTC) - timedelta(days=i),
                last_modified_date=datetime.now(datetime.UTC),
                risk_score=90.0 - (i * 10),  # Decreasing risk scores
            )
            vulns.append(vuln)

        result = normalizer.normalize(vulns)

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
            published_date=datetime.now(datetime.UTC) - timedelta(days=5),
            last_modified_date=datetime.now(datetime.UTC) - timedelta(days=1),
            references=["https://example.com/1", "https://example.com/2"],
            risk_score=70.0,
        )

        vuln2 = Vulnerability(
            cve_id="CVE-2023-0001",
            title="Vulnerability",
            description="Description",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(datetime.UTC) - timedelta(days=5),
            last_modified_date=datetime.now(datetime.UTC),
            references=[
                "https://example.com/2",
                "https://example.com/3",
                "https://example.com/1",
            ],
            risk_score=70.0,
        )

        result = normalizer.normalize([vuln1, vuln2])

        assert len(result) == 1
        # Should have unique references
        assert len(result[0].references) == 3
        assert set(result[0].references) == {
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
            published_date=datetime.now(datetime.UTC) - timedelta(days=5),
            last_modified_date=datetime.now(datetime.UTC) - timedelta(days=1),
            affected_vendors=["microsoft", "adobe"],
            risk_score=70.0,
        )

        vuln2 = Vulnerability(
            cve_id="CVE-2023-0001",
            title="Vulnerability",
            description="Description",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(datetime.UTC) - timedelta(days=5),
            last_modified_date=datetime.now(datetime.UTC),
            affected_vendors=["adobe", "oracle", "microsoft"],
            risk_score=70.0,
        )

        result = normalizer.normalize([vuln1, vuln2])

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
            published_date=datetime.now(datetime.UTC) - timedelta(days=5),
            last_modified_date=datetime.now(datetime.UTC) - timedelta(days=1),
            tags=["critical", "remote"],
            risk_score=70.0,
        )

        vuln2 = Vulnerability(
            cve_id="CVE-2023-0001",
            title="Vulnerability",
            description="Description",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(datetime.UTC) - timedelta(days=5),
            last_modified_date=datetime.now(datetime.UTC),
            tags=["remote", "exploit", "critical"],
            risk_score=70.0,
        )

        result = normalizer.normalize([vuln1, vuln2])

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
                published_date=datetime.now(datetime.UTC) - timedelta(days=i % 30),
                last_modified_date=datetime.now(datetime.UTC) - timedelta(hours=i),
                risk_score=50.0 + (i % 50),
            )
            vulns.append(vuln)

        result = normalizer.normalize(vulns)

        # Should have 50 unique vulnerabilities
        assert len(result) == 50

        # Verify no duplicates
        cve_ids = [v.cve_id for v in result]
        assert len(set(cve_ids)) == 50

        # Should keep the more recent versions
        for vuln in result:
            cve_num = int(vuln.cve_id.split("-")[-1])
            # The second occurrence (i = 50+cve_num) has more recent modification time
            expected_hours_ago = 50 + cve_num
            assert vuln.title == f"Vuln {expected_hours_ago}"
