"""Extended tests for the normalizer module to improve coverage."""

from datetime import datetime

import pytest

from scripts.models import (ExploitationStatus, Reference, SeverityLevel,
                            Vulnerability)
from scripts.processing.normalizer import VulnerabilityNormalizer


class TestVulnerabilityNormalizerExtended:
    """Extended test cases for VulnerabilityNormalizer."""

    @pytest.fixture
    def normalizer(self):
        """Create a normalizer instance."""
        return VulnerabilityNormalizer()

    def test_normalize_cve_id(self, normalizer):
        """Test CVE ID normalization."""
        # Valid CVE IDs
        assert normalizer.normalize_cve_id("CVE-2024-1234") == "CVE-2024-1234"
        assert normalizer.normalize_cve_id("cve-2024-1234") == "CVE-2024-1234"
        assert normalizer.normalize_cve_id("CVE-2024-1234 ") == "CVE-2024-1234"
        assert (
            normalizer.normalize_cve_id("Found CVE-2024-1234 in system")
            == "CVE-2024-1234"
        )

        # Invalid CVE IDs
        assert normalizer.normalize_cve_id("CVE-24-1234") is None
        assert normalizer.normalize_cve_id("CVE-2024") is None
        assert normalizer.normalize_cve_id("NOT-A-CVE") is None
        assert normalizer.normalize_cve_id("") is None

    def test_detect_exploitation_status(self, normalizer):
        """Test exploitation status detection."""
        # Active exploitation
        assert (
            normalizer.detect_exploitation_status(
                "This vulnerability is being actively exploited in the wild"
            )
            == ExploitationStatus.ACTIVE
        )
        assert (
            normalizer.detect_exploitation_status("Observed in the wild attacks")
            == ExploitationStatus.ACTIVE
        )

        # Weaponized
        assert (
            normalizer.detect_exploitation_status("Weaponized exploit available")
            == ExploitationStatus.WEAPONIZED
        )
        assert (
            normalizer.detect_exploitation_status(
                "This has been turned into an exploit kit"
            )
            == ExploitationStatus.WEAPONIZED
        )

        # POC
        assert (
            normalizer.detect_exploitation_status("POC exploit published")
            == ExploitationStatus.POC
        )
        assert (
            normalizer.detect_exploitation_status(
                "Proof of concept available on GitHub"
            )
            == ExploitationStatus.POC
        )

        # Unknown
        assert (
            normalizer.detect_exploitation_status("Regular vulnerability description")
            == ExploitationStatus.UNKNOWN
        )

    def test_normalize_severity(self, normalizer):
        """Test severity normalization from various formats."""
        # String severities
        assert normalizer.normalize_severity("critical") == SeverityLevel.CRITICAL
        assert normalizer.normalize_severity("CRITICAL") == SeverityLevel.CRITICAL
        assert normalizer.normalize_severity("high") == SeverityLevel.HIGH
        assert normalizer.normalize_severity("medium") == SeverityLevel.MEDIUM
        assert normalizer.normalize_severity("low") == SeverityLevel.LOW
        assert normalizer.normalize_severity("none") == SeverityLevel.NONE

        # Numeric string severities
        assert normalizer.normalize_severity("9.5") == SeverityLevel.CRITICAL
        assert normalizer.normalize_severity("7.5") == SeverityLevel.HIGH
        assert normalizer.normalize_severity("5.0") == SeverityLevel.MEDIUM
        assert normalizer.normalize_severity("2.0") == SeverityLevel.LOW
        assert normalizer.normalize_severity("0.0") == SeverityLevel.NONE

        # Numeric severities
        assert normalizer.normalize_severity(10.0) == SeverityLevel.CRITICAL
        assert normalizer.normalize_severity(8.0) == SeverityLevel.HIGH
        assert normalizer.normalize_severity(5.5) == SeverityLevel.MEDIUM
        assert normalizer.normalize_severity(1.0) == SeverityLevel.LOW
        assert normalizer.normalize_severity(0.0) == SeverityLevel.NONE

        # Edge cases
        assert normalizer.normalize_severity("unknown") == SeverityLevel.MEDIUM
        assert normalizer.normalize_severity(None) == SeverityLevel.MEDIUM
        assert normalizer.normalize_severity("not-a-number") == SeverityLevel.MEDIUM

    def test_extract_tags(self, normalizer):
        """Test tag extraction from text."""
        # Authentication tags
        text = "Critical authentication bypass vulnerability"
        tags = normalizer.extract_tags(text)
        assert "authentication" in tags
        assert "bypass" in tags

        # RCE tags
        text = "Remote code execution vulnerability allowing privilege escalation"
        tags = normalizer.extract_tags(text)
        assert "remote" in tags
        assert "rce" in tags
        assert "privilege_escalation" in tags

        # Injection tags
        text = "XSS inject vulnerability in database server"
        tags = normalizer.extract_tags(text)
        assert "injection" in tags

        # Memory corruption tags
        text = "Buffer overflow vulnerability causing denial of service"
        tags = normalizer.extract_tags(text)
        assert "memory" in tags
        assert "dos" in tags

    def test_parse_date(self, normalizer):
        """Test date parsing from various formats."""
        # ISO format
        date = normalizer.parse_date("2024-01-15T10:30:00Z")
        assert date.year == 2024
        assert date.month == 1
        assert date.day == 15

        # RFC format
        date = normalizer.parse_date("Mon, 15 Jan 2024 10:30:00 GMT")
        assert date.year == 2024
        assert date.month == 1
        assert date.day == 15

        # Date only
        date = normalizer.parse_date("2024-01-15")
        assert date.year == 2024
        assert date.month == 1
        assert date.day == 15

        # Already datetime
        now = datetime.now()
        assert normalizer.parse_date(now) == now

        # Invalid dates
        assert normalizer.parse_date("not-a-date") is None
        assert normalizer.parse_date("") is None
        assert normalizer.parse_date(None) is None

    def test_merge_vulnerabilities(self, normalizer):
        """Test merging multiple vulnerability records."""
        now = datetime.now()

        vuln1 = Vulnerability(
            cve_id="CVE-2024-0001",
            title="CVE-2024-0001: Test vulnerability 1",
            description="Test vulnerability 1",
            severity=SeverityLevel.HIGH,
            published_date=now,
            last_modified_date=now,
            references=[Reference(url="https://example.com/advisory1")],
            affected_vendors=["Vendor1"],
            tags=["tag1"],
        )

        vuln2 = Vulnerability(
            cve_id="CVE-2024-0001",  # Same CVE
            title="CVE-2024-0001: Test vulnerability 1 duplicate",
            description="Test vulnerability 1 duplicate",
            severity=SeverityLevel.HIGH,
            published_date=now,
            last_modified_date=now,
            references=[Reference(url="https://example.com/advisory2")],
            affected_vendors=["Vendor2"],
            tags=["tag2"],
            exploitation_status=ExploitationStatus.ACTIVE,
        )

        merged = normalizer.merge_vulnerabilities([vuln1, vuln2])

        # Should merge references
        assert len(merged.references) == 2
        assert any(r.url == "https://example.com/advisory1" for r in merged.references)
        assert any(r.url == "https://example.com/advisory2" for r in merged.references)

        # Should merge vendors
        assert set(merged.affected_vendors) == {"Vendor1", "Vendor2"}

        # Should merge tags
        assert set(merged.tags) == {"tag1", "tag2"}

        # Should use highest exploitation status
        assert merged.exploitation_status == ExploitationStatus.ACTIVE

    def test_deduplicate_vulnerabilities(self, normalizer):
        """Test vulnerability deduplication."""
        now = datetime.now()

        vulns = [
            Vulnerability(
                cve_id="CVE-2024-0001",
                title="CVE-2024-0001: Test vulnerability 1",
                description="Test vulnerability 1",
                severity=SeverityLevel.HIGH,
                published_date=now,
                last_modified_date=now,
                references=[Reference(url="https://example.com/advisory1")],
            ),
            Vulnerability(
                cve_id="CVE-2024-0001",  # Duplicate
                title="CVE-2024-0001: Test vulnerability 1 duplicate",
                description="Test vulnerability 1 duplicate",
                severity=SeverityLevel.HIGH,
                published_date=now,
                last_modified_date=now,
                references=[Reference(url="https://example.com/advisory2")],
            ),
            Vulnerability(
                cve_id="CVE-2024-0002",
                title="CVE-2024-0002: Test vulnerability 2",
                description="Test vulnerability 2",
                severity=SeverityLevel.MEDIUM,
                published_date=now,
                last_modified_date=now,
            ),
        ]

        deduplicated = normalizer.deduplicate_vulnerabilities(vulns)

        # Should deduplicate
        assert len(deduplicated) == 2

        # Should merge references from duplicates
        vuln1 = next(v for v in deduplicated if v.cve_id == "CVE-2024-0001")
        assert len(vuln1.references) == 2

    def test_normalize_github_advisory(self, normalizer):
        """Test GitHub advisory normalization."""
        advisory = {
            "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
            "identifiers": [{"type": "CVE", "value": "CVE-2024-1234"}],
            "published_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-01-16T10:30:00Z",
            "severity": "critical",
            "summary": "Critical RCE vulnerability in test package",
            "description": "A critical remote code execution vulnerability was found.",
            "html_url": "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx",
            "vulnerabilities": [
                {"package": {"ecosystem": "npm", "name": "test-package"}}
            ],
            "references": [{"url": "https://example.com/advisory"}],
        }

        vuln = normalizer.normalize_github_advisory(advisory)

        assert vuln is not None
        assert vuln.cve_id == "CVE-2024-1234"
        assert vuln.severity == SeverityLevel.CRITICAL
        assert "rce" in vuln.tags
        assert "npm" in vuln.affected_vendors
        assert "test-package" in vuln.affected_products
        assert len(vuln.references) >= 2  # GitHub URL + advisory reference
