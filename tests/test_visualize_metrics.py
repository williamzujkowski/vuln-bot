"""Tests for the metrics visualization module."""

import json
import sqlite3

# Import the module functions we need to test
import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestVisualizeMetrics:
    """Test cases for metrics visualization."""

    @pytest.fixture
    def temp_db(self, tmp_path):
        """Create temporary metrics database with test data."""
        db_path = tmp_path / "test_metrics.db"

        # Create tables
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # Create schema (matching metrics.py structure)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS harvest_runs (
                harvest_id TEXT PRIMARY KEY,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                status TEXT,
                total_vulnerabilities INTEGER,
                high_priority_count INTEGER,
                error_count INTEGER
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS harvest_metrics (
                metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
                harvest_id TEXT,
                metric_type TEXT,
                metric_name TEXT,
                metric_value REAL,
                recorded_at TIMESTAMP,
                FOREIGN KEY (harvest_id) REFERENCES harvest_runs(harvest_id)
            )
        """)

        # Insert test data
        now = datetime.now()
        harvest_id = "test-harvest-001"

        cursor.execute(
            """
            INSERT INTO harvest_runs VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                harvest_id,
                now - timedelta(minutes=5),
                now,
                "success",
                150,  # total vulnerabilities
                25,  # high priority
                2,  # errors
            ),
        )

        # Add some metrics
        metrics = [
            ("api_response_time", "github_api", 1.234),
            ("api_response_time", "epss_api", 0.567),
            ("cache_hit_rate", "overall", 0.85),
            ("processing_time", "enrichment", 45.6),
            ("vulnerabilities_processed", "total", 150),
        ]

        for metric_type, metric_name, value in metrics:
            cursor.execute(
                """
                INSERT INTO harvest_metrics (harvest_id, metric_type, metric_name, metric_value, recorded_at)
                VALUES (?, ?, ?, ?, ?)
            """,
                (harvest_id, metric_type, metric_name, value, now),
            )

        conn.commit()
        conn.close()

        return db_path

    def test_format_text_output(self, temp_db):
        """Test text format output."""
        from scripts.visualize_metrics import format_metrics

        metrics = format_metrics(str(temp_db), format_type="text")

        # Check output contains expected elements
        assert "Harvest Run Summary" in metrics
        assert "test-harvest-001" in metrics
        assert "Total Vulnerabilities: 150" in metrics
        assert "High Priority Count: 25" in metrics
        assert "Status: success" in metrics

    def test_format_github_output(self, temp_db):
        """Test GitHub markdown format output."""
        from scripts.visualize_metrics import format_metrics

        metrics = format_metrics(str(temp_db), format_type="github")

        # Check markdown formatting
        assert "##" in metrics  # Headers
        assert "|" in metrics  # Table formatting
        assert "✅" in metrics  # Success emoji
        assert "📊" in metrics  # Chart emoji

    def test_format_json_output(self, temp_db):
        """Test JSON format output."""
        from scripts.visualize_metrics import format_metrics

        metrics_json = format_metrics(str(temp_db), format_type="json")

        # Should be valid JSON
        metrics = json.loads(metrics_json)

        # Check structure
        assert "harvest_runs" in metrics
        assert "metrics" in metrics
        assert len(metrics["harvest_runs"]) > 0
        assert metrics["harvest_runs"][0]["harvest_id"] == "test-harvest-001"

    def test_get_recent_harvests(self, temp_db):
        """Test retrieving recent harvest runs."""
        from scripts.visualize_metrics import get_recent_harvests

        # Add more harvest runs
        conn = sqlite3.connect(str(temp_db))
        cursor = conn.cursor()

        now = datetime.now()
        for i in range(5):
            harvest_id = f"test-harvest-{i:03d}"
            cursor.execute(
                """
                INSERT INTO harvest_runs VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    harvest_id,
                    now - timedelta(hours=i * 4),
                    now - timedelta(hours=i * 4, minutes=-5),
                    "success" if i % 2 == 0 else "partial",
                    100 + i * 10,
                    20 + i,
                    i,
                ),
            )

        conn.commit()
        conn.close()

        # Get recent harvests
        recent = get_recent_harvests(str(temp_db), limit=3)

        assert len(recent) == 3
        # Should be ordered by most recent first
        assert recent[0]["harvest_id"] == "test-harvest-000"

    def test_calculate_statistics(self, temp_db):
        """Test statistical calculations."""
        from scripts.visualize_metrics import calculate_statistics

        stats = calculate_statistics(str(temp_db))

        # Check calculated stats
        assert "average_vulnerabilities" in stats
        assert "success_rate" in stats
        assert "average_duration" in stats
        assert stats["average_vulnerabilities"] == 150.0
        assert stats["success_rate"] == 1.0  # 100% success

    def test_export_metrics(self, temp_db, tmp_path):
        """Test metrics export functionality."""
        from scripts.visualize_metrics import export_metrics

        export_path = tmp_path / "metrics_export.json"

        export_metrics(str(temp_db), str(export_path))

        # Check file was created
        assert export_path.exists()

        # Verify content
        with open(export_path) as f:
            exported = json.load(f)
            assert "harvest_runs" in exported
            assert "metrics" in exported
            assert "statistics" in exported

    def test_empty_database(self, tmp_path):
        """Test handling of empty database."""
        from scripts.visualize_metrics import format_metrics

        # Create empty database
        empty_db = tmp_path / "empty.db"
        conn = sqlite3.connect(str(empty_db))
        cursor = conn.cursor()

        # Create tables but no data
        cursor.execute("""
            CREATE TABLE harvest_runs (
                harvest_id TEXT PRIMARY KEY,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                status TEXT,
                total_vulnerabilities INTEGER,
                high_priority_count INTEGER,
                error_count INTEGER
            )
        """)
        conn.commit()
        conn.close()

        # Should handle gracefully
        metrics = format_metrics(str(empty_db), format_type="text")
        assert "No harvest data available" in metrics

    def test_missing_database(self, tmp_path):
        """Test handling of missing database file."""
        from scripts.visualize_metrics import format_metrics

        missing_db = tmp_path / "missing.db"

        # Should handle gracefully
        metrics = format_metrics(str(missing_db), format_type="text")
        assert "Error" in metrics or "No data" in metrics

    def test_main_function(self, temp_db, capsys):
        """Test main function with different arguments."""
        from scripts.visualize_metrics import main

        # Test with text format
        with patch(
            "sys.argv",
            ["visualize_metrics.py", "--db-path", str(temp_db), "--format", "text"],
        ):
            main()

        captured = capsys.readouterr()
        assert "Harvest Run Summary" in captured.out

    def test_recent_summary(self, temp_db):
        """Test recent harvests summary."""
        from scripts.visualize_metrics import format_recent_summary

        summary = format_recent_summary(str(temp_db), recent=5)

        # Should show summary of recent runs
        assert "Recent Harvest Runs" in summary
        assert "test-harvest-001" in summary
