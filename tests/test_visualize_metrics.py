"""Tests for the metrics visualization module."""

from unittest.mock import Mock, patch

import pytest

from scripts.visualize_metrics import (
    format_duration,
    generate_github_summary,
    print_harvest_summary,
)


class TestVisualizeMetrics:
    """Test cases for metrics visualization."""

    @pytest.fixture
    def sample_summary(self):
        """Create a sample harvest summary."""
        return {
            "harvest_id": "test-harvest-001",
            "status": "completed",
            "duration_seconds": 125.5,
            "start_time": "2024-01-01T10:00:00Z",
            "end_time": "2024-01-01T10:02:05Z",
            "total_vulnerabilities": 150,
            "risk_distribution": {"critical": 25, "high": 50, "medium": 50, "low": 25},
            "statistics": {
                "avg_risk_score": 75.5,
                "min_risk_score": 10,
                "max_risk_score": 95,
                "avg_cvss_score": 7.5,
                "avg_epss_score": 45.0,
                "kev_count": 10,
                "ssvc_count": 5,
            },
            "errors": {},
            "metadata": {
                "years": [2024],
                "min_epss_score": 0.6,
                "min_severity": "HIGH",
            },
        }

    def test_format_duration(self):
        """Test duration formatting."""
        # Seconds
        assert format_duration(45.5) == "45.5 seconds"

        # Minutes
        assert format_duration(125.5) == "2.1 minutes"

        # Hours
        assert format_duration(3700) == "1.0 hours"
        assert format_duration(7200) == "2.0 hours"

    def test_print_harvest_summary(self, sample_summary, capsys):
        """Test harvest summary printing."""
        print_harvest_summary(sample_summary)

        captured = capsys.readouterr()
        output = captured.out

        # Check key elements
        assert "VULNERABILITY HARVEST METRICS SUMMARY" in output
        assert "Harvest ID: test-harvest-001" in output
        assert "Status: completed" in output
        assert "Duration: 2.1 minutes" in output
        assert "Total Vulnerabilities Found: 150" in output

        # Check risk distribution
        assert "Risk Distribution:" in output
        assert "Critical" in output
        assert "High" in output
        assert "Medium" in output
        assert "Low" in output

        # Check statistics
        assert "Average Risk Score: 75.5" in output
        assert "Average CVSS Score: 7.5" in output
        assert "Average EPSS Score: 45.0%" in output
        assert "KEV Vulnerabilities: 10" in output

    def test_generate_github_summary(self, sample_summary):
        """Test GitHub summary generation."""
        summary_md = generate_github_summary(sample_summary)

        # Check markdown formatting
        assert "## 📊 Vulnerability Harvest Metrics" in summary_md
        assert "✅ **Status:** completed" in summary_md
        assert "⏱️ **Duration:** 2.1 minutes" in summary_md
        assert "🔢 **Total Vulnerabilities:** 150" in summary_md

        # Check risk distribution table
        assert "### Risk Distribution" in summary_md
        assert "| Risk Level | Count | Percentage |" in summary_md
        assert "| Critical | 25 | 16.7% |" in summary_md

        # Check statistics section
        assert "### Key Statistics" in summary_md
        assert "**Average Risk Score:** 75.5/100" in summary_md
        assert "**Average CVSS Score:** 7.5/10" in summary_md
        assert "**Average EPSS Score:** 45.0%" in summary_md

    def test_main_function_with_metrics_db(self, tmp_path, sample_summary, capsys):
        """Test main function with metrics database."""
        # Create a temporary metrics database
        db_path = tmp_path / "metrics.db"

        # Mock MetricsCollector
        with patch("scripts.visualize_metrics.MetricsCollector") as MockCollector:
            mock_collector = Mock()
            mock_collector.get_recent_harvests.return_value = [sample_summary]
            MockCollector.return_value = mock_collector

            # Test with text output
            with patch(
                "sys.argv",
                ["visualize_metrics.py", "--db-path", str(db_path), "--format", "text"],
            ):
                from scripts.visualize_metrics import main

                main()

            captured = capsys.readouterr()
            assert "VULNERABILITY HARVEST METRICS SUMMARY" in captured.out

    def test_main_function_github_format(self, tmp_path, sample_summary, capsys):
        """Test main function with GitHub format."""
        db_path = tmp_path / "metrics.db"

        with patch("scripts.visualize_metrics.MetricsCollector") as MockCollector:
            mock_collector = Mock()
            mock_collector.get_recent_harvests.return_value = [sample_summary]
            MockCollector.return_value = mock_collector

            # Test with github output
            with patch(
                "sys.argv",
                [
                    "visualize_metrics.py",
                    "--db-path",
                    str(db_path),
                    "--format",
                    "github",
                ],
            ):
                from scripts.visualize_metrics import main

                main()

            # Check that GitHub summary was written
            captured = capsys.readouterr()
            output = captured.out
            assert "## 📊 Vulnerability Harvest Metrics" in output

    def test_empty_summary_handling(self, capsys):
        """Test handling of empty harvest summary."""
        empty_summary = {
            "harvest_id": "empty-001",
            "status": "failure",
            "duration_seconds": 0,
            "start_time": "2024-01-01T10:00:00Z",
            "end_time": "2024-01-01T10:00:00Z",
            "total_vulnerabilities": 0,
            "risk_distribution": {},
            "statistics": {
                "avg_risk_score": 0,
                "min_risk_score": 0,
                "max_risk_score": 0,
                "avg_cvss_score": 0,
                "avg_epss_score": 0,
                "kev_count": 0,
                "ssvc_count": 0,
            },
            "errors": {
                "Connection failed": 1,
                "API timeout": 2,
            },
            "metadata": {},
        }

        print_harvest_summary(empty_summary)

        captured = capsys.readouterr()
        assert "Status: failure" in captured.out
        assert "Total Vulnerabilities Found: 0" in captured.out
        assert "Connection failed: 1" in captured.out
        assert "API timeout: 2" in captured.out

    def test_partial_success_summary(self):
        """Test summary with partial success status."""
        partial_summary = {
            "harvest_id": "partial-001",
            "status": "partial_success",
            "duration_seconds": 300,
            "start_time": "2024-01-01T10:00:00Z",
            "end_time": "2024-01-01T10:05:00Z",
            "total_vulnerabilities": 75,
            "risk_distribution": {"critical": 10, "high": 30, "medium": 25, "low": 10},
            "statistics": {
                "avg_risk_score": 65.0,
                "min_risk_score": 20,
                "max_risk_score": 90,
                "avg_cvss_score": 6.5,
                "avg_epss_score": 30.0,
                "kev_count": 5,
                "ssvc_count": 3,
            },
            "errors": {
                "Some API calls failed": 5,
            },
            "metadata": {},
        }

        github_summary = generate_github_summary(partial_summary)
        assert "❌ **Status:** partial_success" in github_summary
        assert "Some API calls failed: 5" in github_summary

    def test_large_numbers_formatting(self):
        """Test formatting of large numbers in summary."""
        large_summary = {
            "harvest_id": "large-001",
            "status": "completed",
            "duration_seconds": 3600,
            "start_time": "2024-01-01T10:00:00Z",
            "end_time": "2024-01-01T11:00:00Z",
            "total_vulnerabilities": 10000,
            "risk_distribution": {
                "critical": 2500,
                "high": 3500,
                "medium": 3000,
                "low": 1000,
            },
            "statistics": {
                "avg_risk_score": 72.5,
                "min_risk_score": 5,
                "max_risk_score": 100,
                "avg_cvss_score": 7.2,
                "avg_epss_score": 55.0,
                "kev_count": 500,
                "ssvc_count": 250,
            },
            "errors": {},
            "metadata": {},
        }

        github_summary = generate_github_summary(large_summary)
        assert "10000" in github_summary
        assert "1.0 hours" in github_summary
        assert "25.0%" in github_summary  # Critical percentage
