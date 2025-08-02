#!/usr/bin/env python3
"""
Regression tests for EPSS threshold enforcement.
Ensures the 60% threshold is correctly applied across the pipeline.
"""

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from scripts.agents.epss_filter_agent import EPSSFilterAgent
from scripts.harvest.orchestrator import HarvestOrchestrator
from scripts.models import SeverityLevel, Vulnerability


class TestEPSSThresholdRegression:
    """Regression tests for EPSS threshold filtering."""

    def test_epss_filter_agent_default_threshold(self):
        """Test that EPSSFilterAgent defaults to 60% threshold."""
        agent = EPSSFilterAgent()
        assert agent.threshold == 0.6
        assert agent.DEFAULT_THRESHOLD == 0.6

    def test_epss_filter_agent_custom_threshold(self):
        """Test that EPSSFilterAgent accepts custom thresholds."""
        agent = EPSSFilterAgent(threshold=0.7)
        assert agent.threshold == 0.7

    def test_epss_filter_agent_env_threshold(self):
        """Test that EPSSFilterAgent respects EPSS_THRESHOLD environment variable."""
        with patch.dict(os.environ, {"EPSS_THRESHOLD": "0.8"}):
            agent = EPSSFilterAgent()
            assert agent.threshold == 0.8

    def test_epss_filter_agent_invalid_env_threshold(self):
        """Test that EPSSFilterAgent falls back to default on invalid env var."""
        with patch.dict(os.environ, {"EPSS_THRESHOLD": "invalid"}):
            agent = EPSSFilterAgent()
            assert agent.threshold == 0.6  # Should fall back to default

    def test_epss_filter_boundary_conditions(self):
        """Test EPSS filtering at exact threshold boundaries."""
        agent = EPSSFilterAgent(threshold=0.6)
        
        test_vulns = [
            {"cveId": "CVE-2024-0001", "epssScore": 0.59},  # Below threshold
            {"cveId": "CVE-2024-0002", "epssScore": 0.6},   # At threshold
            {"cveId": "CVE-2024-0003", "epssScore": 0.61},  # Above threshold
            {"cveId": "CVE-2024-0004", "epssScore": 1.0},   # Maximum
            {"cveId": "CVE-2024-0005", "epssScore": None},  # Missing EPSS
        ]
        
        filtered, stats = agent.filter_vulnerabilities(test_vulns)
        
        # Only CVEs with EPSS >= 0.6 should pass
        assert len(filtered) == 3
        assert {v["cveId"] for v in filtered} == {
            "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004"
        }
        
        # Check statistics
        assert stats["total_processed"] == 5
        assert stats["passed_filter"] == 3
        assert stats["failed_filter"] == 1
        assert stats["missing_epss"] == 1
        assert stats["threshold"] == 0.6

    def test_epss_filter_different_score_formats(self):
        """Test EPSS filtering with different score formats."""
        agent = EPSSFilterAgent(threshold=0.6)
        
        test_vulns = [
            # Direct score
            {"cveId": "CVE-2024-0001", "epssScore": 0.7},
            # Nested object
            {"cveId": "CVE-2024-0002", "epssScore": {"score": 0.8}},
            # EPSS object
            {"cveId": "CVE-2024-0003", "epss": {"score": 0.9}},
            # Percentile fallback
            {"cveId": "CVE-2024-0004", "epssPercentile": 70.0},  # 70% -> 0.7
            # Below threshold via percentile
            {"cveId": "CVE-2024-0005", "epssPercentile": 50.0},  # 50% -> 0.5
        ]
        
        filtered, stats = agent.filter_vulnerabilities(test_vulns)
        
        # CVE-0005 should be filtered out (50% -> 0.5 < 0.6)
        assert len(filtered) == 4
        filtered_ids = {v["cveId"] for v in filtered}
        assert "CVE-2024-0005" not in filtered_ids
        
        assert stats["passed_filter"] == 4
        assert stats["failed_filter"] == 1

    def test_orchestrator_default_epss_threshold(self):
        """Test that HarvestOrchestrator defaults to 60% EPSS threshold."""
        with tempfile.TemporaryDirectory() as temp_dir:
            orchestrator = HarvestOrchestrator(cache_dir=Path(temp_dir))
            
            # Check that the orchestrator's EPSS filter agent has correct threshold
            assert orchestrator.epss_filter_agent.threshold == 0.6

    def test_orchestrator_custom_epss_threshold(self):
        """Test that HarvestOrchestrator accepts custom EPSS thresholds."""
        with tempfile.TemporaryDirectory() as temp_dir:
            orchestrator = HarvestOrchestrator(cache_dir=Path(temp_dir))
            
            # Mock the harvest process to avoid actual network calls
            with patch.object(orchestrator, 'harvest_cve_data', return_value=[]):
                with patch.object(orchestrator, 'harvest_nvd_data', return_value=[]):
                    with patch.object(orchestrator, 'harvest_github_advisory_data', return_value=[]):
                        with patch.object(orchestrator, 'enrich_with_epss'):
                            # Test custom threshold
                            batch = orchestrator.harvest_all_sources(
                                years=[2024],
                                min_epss_score=0.8
                            )
                            
                            # Verify the threshold was updated
                            assert orchestrator.epss_filter_agent.threshold == 0.8

    def test_vulnerability_model_epss_properties(self):
        """Test that Vulnerability model correctly handles EPSS data."""
        # Create a vulnerability with EPSS data
        vuln = Vulnerability(
            cve_id="CVE-2024-0001",
            title="Test Vulnerability",
            description="Test description",
            published_date=datetime.now(timezone.utc),
            last_modified_date=datetime.now(timezone.utc),
            severity=SeverityLevel.HIGH,
            epss_score=None
        )
        
        # Test without EPSS score
        assert vuln.epss_probability is None
        
        # Add EPSS score
        from scripts.models import EPSSScore
        vuln.epss_score = EPSSScore(
            score=0.75,
            percentile=85.0,
            date=datetime.now(timezone.utc)
        )
        
        # Test with EPSS score
        assert vuln.epss_probability == 75.0  # 0.75 * 100

    def test_epss_filter_invalid_scores(self):
        """Test EPSS filtering handles invalid scores correctly."""
        agent = EPSSFilterAgent(threshold=0.6)
        
        test_vulns = [
            {"cveId": "CVE-2024-0001", "epssScore": -0.1},   # Invalid (negative)
            {"cveId": "CVE-2024-0002", "epssScore": 1.1},    # Invalid (> 1.0)
            {"cveId": "CVE-2024-0003", "epssScore": "abc"},  # Invalid (string)
            {"cveId": "CVE-2024-0004", "epssScore": 0.7},    # Valid
        ]
        
        filtered, stats = agent.filter_vulnerabilities(test_vulns)
        
        # Only the valid score should pass
        assert len(filtered) == 1
        assert filtered[0]["cveId"] == "CVE-2024-0004"
        
        # Check invalid score tracking
        assert stats["invalid_epss"] == 2  # -0.1 and 1.1
        assert stats["passed_filter"] == 1

    def test_epss_filter_empty_input(self):
        """Test EPSS filtering with empty input."""
        agent = EPSSFilterAgent(threshold=0.6)
        
        filtered, stats = agent.filter_vulnerabilities([])
        
        assert len(filtered) == 0
        assert stats["total_processed"] == 0
        assert stats["passed_filter"] == 0
        assert stats["failed_filter"] == 0
        assert stats["missing_epss"] == 0

    def test_epss_filter_report_generation(self):
        """Test EPSS filter report generation."""
        agent = EPSSFilterAgent(threshold=0.6)
        
        test_vulns = [
            {"cveId": "CVE-2024-0001", "epssScore": 0.7},
            {"cveId": "CVE-2024-0002", "epssScore": 0.5},
        ]
        
        agent.filter_vulnerabilities(test_vulns)
        report = agent.get_filter_report()
        
        assert report["total_processed"] == 2
        assert report["passed_filter"] == 1
        assert report["failed_filter"] == 1
        assert report["pass_rate_percentage"] == "50.0%"
        assert report["filter_rate_percentage"] == "50.0%"
        assert "report_generated" in report

    @pytest.mark.asyncio
    async def test_epss_filter_async_processing(self):
        """Test EPSS filter async processing method."""
        agent = EPSSFilterAgent(threshold=0.6)
        
        test_data = {
            "vulnerabilities": [
                {"cveId": "CVE-2024-0001", "epssScore": 0.7},
                {"cveId": "CVE-2024-0002", "epssScore": 0.5},
            ]
        }
        
        result = await agent.process(test_data)
        
        assert len(result["vulnerabilities"]) == 1
        assert result["vulnerabilities"][0]["cveId"] == "CVE-2024-0001"
        assert result["filter_applied"] is True
        assert result["threshold"] == 0.6
        assert "epss_filter_stats" in result
        assert "epss_filter_report" in result


class TestEPSSThresholdIntegration:
    """Integration tests for EPSS threshold across the full pipeline."""

    def test_cli_default_epss_threshold(self):
        """Test that CLI defaults to 60% EPSS threshold."""
        from scripts.main import harvest
        
        # Check that the click command default is 0.6
        assert harvest.params[3].default == 0.6  # min-epss parameter

    def test_workflow_epss_threshold(self):
        """Test that GitHub workflow uses 60% EPSS threshold."""
        workflow_file = Path(__file__).parent.parent / ".github/workflows/scheduled-harvest.yml"
        
        if workflow_file.exists():
            content = workflow_file.read_text()
            assert "--min-epss 0.6" in content

    def test_frontend_default_epss_threshold(self):
        """Test that frontend defaults to 60% EPSS threshold."""
        # Test TypeScript dashboard
        ts_file = Path(__file__).parent.parent / "src/assets/ts/dashboard.ts"
        if ts_file.exists():
            content = ts_file.read_text()
            assert "epssMin: 60" in content

        # Test JavaScript dashboard
        js_file = Path(__file__).parent.parent / "src/assets/js/dashboard-enhanced.js"
        if js_file.exists():
            content = js_file.read_text()
            assert "epssMin: 60" in content

    def test_documentation_consistency(self):
        """Test that documentation consistently mentions 60% threshold."""
        docs_to_check = [
            Path(__file__).parent.parent / "README.md",
            Path(__file__).parent.parent / "CLAUDE.md",
        ]
        
        for doc_file in docs_to_check:
            if doc_file.exists():
                content = doc_file.read_text()
                # Should contain 60% references
                assert "≥ 60%" in content or ">= 60%" in content
                # Should not contain old 50% references
                assert "≥ 50%" not in content and ">= 50%" not in content


class TestEPSSDataValidation:
    """Tests for EPSS data validation and quality checks."""

    def test_epss_score_range_validation(self):
        """Test that EPSS scores are validated to be in range [0.0, 1.0]."""
        agent = EPSSFilterAgent()
        
        # Test edge cases
        test_cases = [
            (0.0, True),    # Minimum valid
            (0.5, True),    # Mid-range
            (1.0, True),    # Maximum valid
            (-0.1, False),  # Below minimum
            (1.1, False),   # Above maximum
            (None, False),  # Missing
        ]
        
        for score, should_be_valid in test_cases:
            test_vulns = [{"cveId": "CVE-2024-0001", "epssScore": score}]
            filtered, stats = agent.filter_vulnerabilities(test_vulns)
            
            if should_be_valid and score >= agent.threshold:
                assert len(filtered) == 1
            else:
                assert len(filtered) == 0

    def test_epss_data_types(self):
        """Test EPSS filtering with various data types."""
        agent = EPSSFilterAgent(threshold=0.6)
        
        test_vulns = [
            {"cveId": "CVE-2024-0001", "epssScore": 0.7},      # float
            {"cveId": "CVE-2024-0002", "epssScore": "0.8"},    # string
            {"cveId": "CVE-2024-0003", "epssScore": 70},       # int (invalid)
            {"cveId": "CVE-2024-0004", "epssScore": []},       # list (invalid)
        ]
        
        filtered, stats = agent.filter_vulnerabilities(test_vulns)
        
        # Should handle type conversion for valid string
        expected_passed = 2  # 0.7 and "0.8" (converted to float)
        assert len(filtered) == expected_passed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])