"""Extended tests for the normalizer module to improve coverage."""

from datetime import datetime

import pytest

from scripts.models import (
    ExploitationStatus,
    SeverityLevel,
    Vulnerability,
    VulnerabilityBatch,
)
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
            normalizer.detect_exploitation_status("Observed in-the-wild attacks")
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
                "Proof-of-concept available on GitHub"
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
        # Infrastructure tags
        text = "Critical vulnerability in cloud infrastructure affecting AWS services"
        tags = normalizer.extract_tags(text)
        assert "infrastructure" in tags
        assert "cloud" in tags

        # Web application tags
        text = "XSS vulnerability in web application allowing remote code execution"
        tags = normalizer.extract_tags(text)
        assert "web" in tags
        assert "rce" in tags

        # Database tags
        text = "SQL injection vulnerability in database server"
        tags = normalizer.extract_tags(text)
        assert "database" in tags

        # Multiple tags
        text = "Critical infrastructure vulnerability with RCE in cloud database"
        tags = normalizer.extract_tags(text)
        assert len(tags) >= 3
        assert "infrastructure" in tags
        assert "cloud" in tags
        assert "database" in tags
        assert "rce" in tags

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

    def test_extract_product_info(self, normalizer):
        """Test product information extraction."""
        # From references
        refs = [
            "https://github.com/apache/struts/security/advisories/GHSA-1234",
            "https://www.microsoft.com/security/blog/CVE-2024-1234",
            "https://ubuntu.com/security/CVE-2024-1234",
        ]
        vendors, products = normalizer.extract_product_info(refs)
        assert "apache" in vendors
        assert "microsoft" in vendors
        assert "ubuntu" in vendors

        # From descriptions
        desc = "A vulnerability in Cisco IOS XE Software could allow an attacker..."
        vendors, products = normalizer.extract_product_info([desc])
        assert "cisco" in vendors

        # Common products
        desc = "MySQL database server vulnerability affecting versions 5.7 and 8.0"
        vendors, products = normalizer.extract_product_info([desc])
        assert "mysql" in products

    def test_deduplicate_list(self, normalizer):
        """Test list deduplication while preserving order."""
        # Simple deduplication
        items = ["a", "b", "a", "c", "b"]
        result = normalizer.deduplicate_list(items)
        assert result == ["a", "b", "c"]

        # Case-insensitive deduplication
        items = ["Apple", "apple", "APPLE", "banana"]
        result = normalizer.deduplicate_list(items, case_sensitive=False)
        assert len(result) == 2
        assert "banana" in result

        # Empty list
        assert normalizer.deduplicate_list([]) == []

    def test_enrich_vulnerability(self, normalizer):
        """Test vulnerability enrichment."""
        vuln = Vulnerability(
            cve_id="CVE-2024-1234",
            description="Critical RCE vulnerability in cloud infrastructure",
            severity=SeverityLevel.CRITICAL,
            published=datetime.now(),
            last_modified=datetime.now(),
        )

        enriched = normalizer.enrich_vulnerability(vuln)

        # Should add tags
        assert len(enriched.tags) > 0
        assert "infrastructure" in enriched.tags
        assert "cloud" in enriched.tags
        assert "rce" in enriched.tags

        # Should detect exploitation status
        vuln_exploited = vuln.copy()
        vuln_exploited.description = "Actively exploited vulnerability in the wild"
        enriched = normalizer.enrich_vulnerability(vuln_exploited)
        assert enriched.exploitation_status == ExploitationStatus.ACTIVE

    def test_normalize_batch(self, normalizer):
        """Test batch normalization."""
        vulns = [
            Vulnerability(
                cve_id="CVE-2024-0001",
                description="Test vulnerability 1",
                severity=SeverityLevel.HIGH,
                published=datetime.now(),
                last_modified=datetime.now(),
                references=["https://example.com/advisory1"],
            ),
            Vulnerability(
                cve_id="CVE-2024-0001",  # Duplicate
                description="Test vulnerability 1 duplicate",
                severity=SeverityLevel.HIGH,
                published=datetime.now(),
                last_modified=datetime.now(),
                references=["https://example.com/advisory2"],
            ),
            Vulnerability(
                cve_id="CVE-2024-0002",
                description="Test vulnerability 2",
                severity=SeverityLevel.MEDIUM,
                published=datetime.now(),
                last_modified=datetime.now(),
            ),
        ]

        batch = VulnerabilityBatch(vulnerabilities=vulns)
        normalized = normalizer.normalize_batch(batch)

        # Should deduplicate
        assert normalized.count == 2

        # Should merge references from duplicates
        vuln1 = next(
            v for v in normalized.vulnerabilities if v.cve_id == "CVE-2024-0001"
        )
        assert len(vuln1.references) == 2

    def test_calculate_confidence_score(self, normalizer):
        """Test confidence score calculation."""
        # High confidence - all fields present
        vuln = Vulnerability(
            cve_id="CVE-2024-1234",
            description="Detailed description of the vulnerability",
            severity=SeverityLevel.CRITICAL,
            published=datetime.now(),
            last_modified=datetime.now(),
            cvss_base_score=9.8,
            epss_score=0.95,
            affected_vendors=["Vendor1", "Vendor2"],
            references=["https://example.com/1", "https://example.com/2"],
            tags=["tag1", "tag2", "tag3"],
        )
        score = normalizer.calculate_confidence_score(vuln)
        assert score > 0.8

        # Low confidence - minimal fields
        vuln_minimal = Vulnerability(
            cve_id="CVE-2024-1234",
            description="Brief",
            severity=SeverityLevel.MEDIUM,
            published=datetime.now(),
            last_modified=datetime.now(),
        )
        score = normalizer.calculate_confidence_score(vuln_minimal)
        assert score < 0.5

    def test_is_high_quality(self, normalizer):
        """Test vulnerability quality check."""
        # High quality
        vuln = Vulnerability(
            cve_id="CVE-2024-1234",
            description="A comprehensive description of the vulnerability with detailed technical information",
            severity=SeverityLevel.CRITICAL,
            published=datetime.now(),
            last_modified=datetime.now(),
            cvss_base_score=9.8,
            epss_score=0.95,
            affected_vendors=["Vendor1"],
            references=["https://example.com/advisory"],
        )
        assert normalizer.is_high_quality(vuln) is True

        # Low quality - short description
        vuln.description = "Brief"
        assert normalizer.is_high_quality(vuln) is False

    def test_clean_description(self, normalizer):
        """Test description cleaning."""
        # Remove HTML tags
        desc = (
            "This is a <b>vulnerability</b> with <script>alert('xss')</script> content"
        )
        cleaned = normalizer.clean_description(desc)
        assert "<b>" not in cleaned
        assert "<script>" not in cleaned

        # Normalize whitespace
        desc = "This    has     multiple    spaces\n\nand newlines"
        cleaned = normalizer.clean_description(desc)
        assert "  " not in cleaned

        # Trim length
        desc = "x" * 10000
        cleaned = normalizer.clean_description(desc)
        assert len(cleaned) <= 5000
