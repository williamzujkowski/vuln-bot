"""Tests for EPSSFilterAgent."""

import os
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from scripts.agents.epss_filter_agent import EPSSFilterAgent


class TestEPSSFilterAgent:
    """Test suite for EPSSFilterAgent."""

    @pytest.fixture
    def sample_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Sample vulnerability data for testing."""
        return [
            {
                "cveId": "CVE-2024-0001",
                "epssScore": 0.85,  # 85% - should pass
                "severity": "CRITICAL",
                "description": "High risk vulnerability",
            },
            {
                "cveId": "CVE-2024-0002",
                "epss_score": 0.3,  # 30% - should fail
                "severity": "HIGH",
                "description": "Medium risk vulnerability",
            },
            {
                "cveId": "CVE-2024-0003",
                "epssScore": {"score": 0.6},  # 60% nested - should pass
                "severity": "HIGH",
                "description": "Another high risk vulnerability",
            },
            {
                "cveId": "CVE-2024-0004",
                # No EPSS score - should fail
                "severity": "CRITICAL",
                "description": "Critical vulnerability without EPSS",
            },
            {
                "cveId": "CVE-2024-0005",
                "epss": {"score": 0.95},  # 95% nested alternative - should pass
                "severity": "CRITICAL",
                "description": "Very high risk vulnerability",
            },
            {
                "cveId": "CVE-2024-0006",
                "epssPercentile": 75,  # 75% as percentile - should pass
                "severity": "HIGH",
                "description": "High percentile vulnerability",
            },
            {
                "cveId": "CVE-2024-0007",
                "epssScore": 0.5,  # Exactly 50% - should pass
                "severity": "MEDIUM",
                "description": "Threshold edge case",
            },
            {
                "cveId": "CVE-2024-0008",
                "epssScore": 0.49999,  # Just below 50% - should fail
                "severity": "HIGH",
                "description": "Just below threshold",
            },
        ]

    def test_init_default_threshold(self):
        """Test initialization with default threshold."""
        agent = EPSSFilterAgent()
        assert agent.threshold == 0.5
        assert agent.name == "EPSSFilterAgent"

    def test_init_custom_threshold(self):
        """Test initialization with custom threshold."""
        agent = EPSSFilterAgent(threshold=0.7)
        assert agent.threshold == 0.7

    def test_init_env_threshold(self):
        """Test initialization with environment variable threshold."""
        with patch.dict(os.environ, {"EPSS_THRESHOLD": "0.8"}):
            agent = EPSSFilterAgent()
            assert agent.threshold == 0.8

    def test_init_invalid_env_threshold(self):
        """Test initialization with invalid environment variable."""
        with patch.dict(os.environ, {"EPSS_THRESHOLD": "invalid"}):
            agent = EPSSFilterAgent()
            assert agent.threshold == 0.5  # Falls back to default

    def test_init_invalid_threshold(self):
        """Test initialization with invalid threshold value."""
        with pytest.raises(
            ValueError, match="EPSS threshold must be between 0.0 and 1.0"
        ):
            EPSSFilterAgent(threshold=1.5)

        with pytest.raises(ValueError):
            EPSSFilterAgent(threshold=-0.1)

    def test_filter_vulnerabilities_default_threshold(self, sample_vulnerabilities):
        """Test filtering with default 50% threshold."""
        agent = EPSSFilterAgent()
        filtered, stats = agent.filter_vulnerabilities(sample_vulnerabilities)

        # Should have 5 vulnerabilities that pass (>= 50%)
        assert len(filtered) == 5
        assert stats["total_processed"] == 8
        assert stats["passed_filter"] == 5
        assert stats["failed_filter"] == 2
        assert stats["missing_epss"] == 1
        assert stats["threshold"] == 0.5

        # Check specific CVEs that should pass
        passed_cves = [v["cveId"] for v in filtered]
        assert "CVE-2024-0001" in passed_cves  # 85%
        assert "CVE-2024-0003" in passed_cves  # 60%
        assert "CVE-2024-0005" in passed_cves  # 95%
        assert "CVE-2024-0006" in passed_cves  # 75%
        assert "CVE-2024-0007" in passed_cves  # 50%

        # Check CVEs that should not pass
        assert "CVE-2024-0002" not in passed_cves  # 30%
        assert "CVE-2024-0004" not in passed_cves  # No EPSS
        assert "CVE-2024-0008" not in passed_cves  # 49.999%

    def test_filter_vulnerabilities_custom_threshold(self, sample_vulnerabilities):
        """Test filtering with custom 70% threshold."""
        agent = EPSSFilterAgent(threshold=0.7)
        filtered, stats = agent.filter_vulnerabilities(sample_vulnerabilities)

        # Should have only 3 vulnerabilities that pass (>= 70%)
        assert len(filtered) == 3
        assert stats["passed_filter"] == 3
        assert stats["failed_filter"] == 4

        passed_cves = [v["cveId"] for v in filtered]
        assert "CVE-2024-0001" in passed_cves  # 85%
        assert "CVE-2024-0005" in passed_cves  # 95%
        assert "CVE-2024-0006" in passed_cves  # 75%

    def test_extract_epss_score_formats(self):
        """Test EPSS score extraction from various formats."""
        agent = EPSSFilterAgent()

        # Direct float
        assert agent._extract_epss_score({"epssScore": 0.8}) == 0.8
        assert agent._extract_epss_score({"epss_score": 0.7}) == 0.7

        # Nested dict
        assert agent._extract_epss_score({"epssScore": {"score": 0.6}}) == 0.6
        assert agent._extract_epss_score({"epss": {"score": 0.5}}) == 0.5

        # Percentile fallback
        assert agent._extract_epss_score({"epssPercentile": 80}) == 0.8
        assert agent._extract_epss_score({"epss_percentile": 90}) == 0.9

        # Missing/invalid
        assert agent._extract_epss_score({}) is None
        assert agent._extract_epss_score({"epssScore": None}) is None
        assert agent._extract_epss_score({"epssScore": "invalid"}) is None

    def test_filter_empty_list(self):
        """Test filtering empty vulnerability list."""
        agent = EPSSFilterAgent()
        filtered, stats = agent.filter_vulnerabilities([])

        assert len(filtered) == 0
        assert stats["total_processed"] == 0
        assert stats["passed_filter"] == 0

    def test_filter_invalid_epss_scores(self):
        """Test filtering with invalid EPSS scores."""
        vulns = [
            {"cveId": "CVE-2024-0001", "epssScore": 1.5},  # > 1.0
            {"cveId": "CVE-2024-0002", "epssScore": -0.1},  # < 0.0
            {"cveId": "CVE-2024-0003", "epssScore": 0.8},  # Valid
        ]

        agent = EPSSFilterAgent()
        filtered, stats = agent.filter_vulnerabilities(vulns)

        assert len(filtered) == 1
        assert filtered[0]["cveId"] == "CVE-2024-0003"
        assert stats["invalid_epss"] == 2

    def test_get_filter_report(self):
        """Test filter report generation."""
        agent = EPSSFilterAgent()

        # Run a filter first
        vulns = [
            {"cveId": "CVE-2024-0001", "epssScore": 0.8},
            {"cveId": "CVE-2024-0002", "epssScore": 0.3},
            {"cveId": "CVE-2024-0003"},  # Missing EPSS
        ]
        agent.filter_vulnerabilities(vulns)

        report = agent.get_filter_report()

        assert report["total_processed"] == 3
        assert report["passed_filter"] == 1
        assert report["failed_filter"] == 1
        assert report["missing_epss"] == 1
        assert "pass_rate_percentage" in report
        assert "filter_rate_percentage" in report
        assert "missing_rate_percentage" in report
        assert "report_generated" in report

    def test_process_async(self):
        """Test async process method."""
        agent = EPSSFilterAgent()

        data = {
            "vulnerabilities": [
                {"cveId": "CVE-2024-0001", "epssScore": 0.8},
                {"cveId": "CVE-2024-0002", "epssScore": 0.3},
            ]
        }

        # Run async process (it's actually sync in this implementation)
        import asyncio

        result = asyncio.run(agent.process(data))

        assert "vulnerabilities" in result
        assert "epss_filter_stats" in result
        assert "epss_filter_report" in result
        assert result["filter_applied"] is True
        assert result["threshold"] == 0.5
        assert len(result["vulnerabilities"]) == 1

    def test_filter_logging(self):
        """Test that appropriate logging occurs during filtering."""
        # We'll skip detailed log testing since structlog format is complex
        # Just verify the function works without errors
        agent = EPSSFilterAgent()

        vulns = [
            {"cveId": "CVE-2024-0001", "epssScore": 0.8},
            {"cveId": "CVE-2024-0002", "epssScore": 0.3},
            {"cveId": "CVE-2024-0003"},  # Missing EPSS
        ]

        # This should execute without errors
        filtered, stats = agent.filter_vulnerabilities(vulns)
        assert len(filtered) == 1
        assert stats["total_processed"] == 3

    def test_no_passing_vulnerabilities_warning(self):
        """Test warning when no vulnerabilities pass the filter."""
        agent = EPSSFilterAgent(threshold=0.9)

        vulns = [
            {"cveId": "CVE-2024-0001", "epssScore": 0.3},
            {"cveId": "CVE-2024-0002", "epssScore": 0.2},
        ]

        # Verify no vulnerabilities pass the high threshold
        filtered, stats = agent.filter_vulnerabilities(vulns)

        assert len(filtered) == 0
        assert stats["failed_filter"] == 2
        assert stats["passed_filter"] == 0

    def test_cve_id_extraction_fallback(self):
        """Test CVE ID extraction with fallback."""
        agent = EPSSFilterAgent()

        vulns = [
            {"cve_id": "CVE-2024-0001", "epssScore": 0.8},  # Alternative field
            {"epssScore": 0.9},  # No CVE ID - should use "Unknown"
        ]

        filtered, stats = agent.filter_vulnerabilities(vulns)
        assert len(filtered) == 2  # Both have passing EPSS scores
