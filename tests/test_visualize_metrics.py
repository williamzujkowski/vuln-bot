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
            "status": "success",
            "duration_seconds": 125.5,
            "start_time": "2024-01-01T10:00:00Z",
            "end_time": "2024-01-01T10:02:05Z",
            "total_vulnerabilities": 150,
            "risk_distribution": {"critical": 25, "high": 50, "medium": 50, "low": 25},
            "statistics": {
                "average_risk_score": 75.5,
                "critical_count": 25,
                "has_epss_count": 100,
                "has_cisa_kev": 10,
            },
            "performance": {
                "total_duration": 125.5,
                "api_calls": 200,
                "cache_hits": 150,
                "cache_hit_rate": 0.75,
            },
            "errors": [],
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
        assert "Status: success" in output
        assert "Duration: 2.1 minutes" in output
        assert "Total Vulnerabilities Found: 150" in output

        # Check risk distribution
        assert "Risk Distribution:" in output
        assert "Critical:" in output
        assert "High:" in output
        assert "Medium:" in output
        assert "Low:" in output

    def test_generate_github_summary(self, sample_summary):
        """Test GitHub summary generation."""
        summary_md = generate_github_summary(sample_summary)

        # Check markdown formatting
        assert "## 📊 Vulnerability Harvest Summary" in summary_md
        assert "**Harvest ID:** `test-harvest-001`" in summary_md
        assert "**Status:** ✅ success" in summary_md
        assert "**Duration:** 2.1 minutes" in summary_md

        # Check statistics section
        assert "### 📈 Statistics" in summary_md
        assert "Average Risk Score" in summary_md
        assert "75.5" in summary_md

        # Check performance section
        assert "### ⚡ Performance" in summary_md
        assert "API Calls" in summary_md
        assert "Cache Hit Rate" in summary_md
        assert "75.0%" in summary_md

    def test_main_function_with_metrics_db(self, tmp_path, sample_summary, capsys):
        """Test main function with metrics database."""
        # Create a temporary metrics database
        db_path = tmp_path / "metrics.db"

        # Mock MetricsCollector
        with patch("scripts.visualize_metrics.MetricsCollector") as MockCollector:
            mock_collector = Mock()
            mock_collector.get_harvest_summary.return_value = sample_summary
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

    def test_main_function_github_format(self, tmp_path, sample_summary):
        """Test main function with GitHub format."""
        db_path = tmp_path / "metrics.db"

        with patch("scripts.visualize_metrics.MetricsCollector") as MockCollector:
            mock_collector = Mock()
            mock_collector.get_harvest_summary.return_value = sample_summary
            MockCollector.return_value = mock_collector

            # Capture output
            with patch("sys.stdout.write") as mock_write:
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
                output = "".join(call.args[0] for call in mock_write.call_args_list)
                assert "## 📊 Vulnerability Harvest Summary" in output

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
                "average_risk_score": 0,
                "critical_count": 0,
                "has_epss_count": 0,
                "has_cisa_kev": 0,
            },
            "performance": {
                "total_duration": 0,
                "api_calls": 0,
                "cache_hits": 0,
                "cache_hit_rate": 0,
            },
            "errors": ["Connection failed", "API timeout"],
        }

        print_harvest_summary(empty_summary)

        captured = capsys.readouterr()
        assert "Status: failure" in captured.out
        assert "Total Vulnerabilities Found: 0" in captured.out
        assert "Connection failed" in captured.out

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
                "average_risk_score": 65.0,
                "critical_count": 10,
                "has_epss_count": 50,
                "has_cisa_kev": 5,
            },
            "performance": {
                "total_duration": 300,
                "api_calls": 100,
                "cache_hits": 25,
                "cache_hit_rate": 0.25,
            },
            "errors": ["Some API calls failed"],
        }

        github_summary = generate_github_summary(partial_summary)
        assert "⚠️ partial_success" in github_summary
        assert "Some API calls failed" in github_summary

    def test_large_numbers_formatting(self):
        """Test formatting of large numbers in summary."""
        large_summary = {
            "harvest_id": "large-001",
            "status": "success",
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
                "average_risk_score": 72.5,
                "critical_count": 2500,
                "has_epss_count": 8000,
                "has_cisa_kev": 500,
            },
            "performance": {
                "total_duration": 3600,
                "api_calls": 5000,
                "cache_hits": 4000,
                "cache_hit_rate": 0.8,
            },
            "errors": [],
        }

        github_summary = generate_github_summary(large_summary)
        assert "10000" in github_summary
        assert "1.0 hours" in github_summary
        assert "80.0%" in github_summary  # cache hit rate
