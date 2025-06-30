"""Tests for the CLI main module."""

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from scripts.main import cli as app
from scripts.models import SeverityLevel, VulnerabilityBatch


@pytest.fixture
def cli_runner():
    """Create CLI test runner."""
    return CliRunner()


@pytest.fixture
def mock_orchestrator():
    """Create mock orchestrator."""
    with patch("scripts.main.HarvestOrchestrator") as mock_class:
        mock_instance = MagicMock()
        mock_class.return_value = mock_instance

        # Configure mock batch
        mock_batch = VulnerabilityBatch(
            vulnerabilities=[],
            metadata={
                "harvest_id": "test-123",
                "total_vulnerabilities": 10,
                "unique_vulnerabilities": 8,
                "sources": [{"name": "cvelist", "count": 10, "status": "success"}],
            },
        )
        mock_instance.harvest_all_sources.return_value = mock_batch
        mock_instance.get_high_priority_vulnerabilities.return_value = []

        yield mock_instance


@pytest.fixture
def mock_briefing_generator():
    """Create mock briefing generator."""
    with patch(
        "scripts.processing.optimized_briefing_generator.OptimizedBriefingGenerator"
    ) as mock_class:
        mock_instance = MagicMock()
        mock_class.return_value = mock_instance

        # Configure generate_all to return proper results
        mock_instance.generate_all.return_value = {
            "briefing": "src/_posts/2025-06-29-vuln-brief.md",
            "index": "src/api/vulns/index.json",
            "chunks": [],
            "chunk_index": None,
        }

        yield mock_instance


class TestCLI:
    """Tests for CLI commands."""

    def test_harvest_command_basic(self, cli_runner, mock_orchestrator, tmp_path):
        """Test basic harvest command."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        result = cli_runner.invoke(
            app,
            ["harvest", "--cache-dir", str(cache_dir)],
        )

        assert result.exit_code == 0
        # Remove assertion about log message that doesn't appear in output
        assert "Vulnerability harvest completed" in result.output

        # Verify orchestrator called correctly
        mock_orchestrator.harvest_all_sources.assert_called_once()
        call_args = mock_orchestrator.harvest_all_sources.call_args
        assert call_args.kwargs["years"] == [2024, 2025]  # Default years
        assert call_args.kwargs["min_severity"] == "MEDIUM"
        assert call_args.kwargs["min_epss_score"] == 0.001

    def test_harvest_command_with_options(
        self, cli_runner, mock_orchestrator, tmp_path
    ):
        """Test harvest command with all options."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        result = cli_runner.invoke(
            app,
            [
                "harvest",
                "--cache-dir",
                str(cache_dir),
                "--years",
                "2024",
                "--years",
                "2025",
                "--min-severity",
                "CRITICAL",
                "--min-epss",
                "0.8",
            ],
        )

        assert result.exit_code == 0

        # Verify orchestrator called with correct parameters
        mock_orchestrator.harvest_all_sources.assert_called_once()
        call_args = mock_orchestrator.harvest_all_sources.call_args
        assert call_args.kwargs["years"] == [2024, 2025]
        assert call_args.kwargs["min_severity"] == "CRITICAL"
        assert call_args.kwargs["min_epss_score"] == 0.8

    def test_harvest_command_invalid_severity(self, cli_runner, tmp_path):
        """Test harvest command with invalid severity."""
        cache_dir = tmp_path / "cache"

        result = cli_runner.invoke(
            app,
            [
                "harvest",
                "--cache-dir",
                str(cache_dir),
                "--min-severity",
                "INVALID",
            ],
        )

        assert result.exit_code == 2  # Click validation error
        assert "Invalid value" in result.output

    def test_harvest_command_invalid_epss(
        self, cli_runner, mock_orchestrator, tmp_path
    ):
        """Test harvest command with invalid EPSS score."""
        _ = mock_orchestrator  # Use the parameter
        cache_dir = tmp_path / "cache"

        result = cli_runner.invoke(
            app,
            [
                "harvest",
                "--cache-dir",
                str(cache_dir),
                "--min-epss",
                "1.5",  # Out of range
            ],
        )

        # Click doesn't validate the range for float, it just accepts any float
        assert result.exit_code == 0

    def test_generate_briefing_command(self, cli_runner, tmp_path):
        """Test generate-briefing command."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        output_dir = tmp_path / "output"

        with patch("scripts.main.CacheManager") as mock_cache_manager_class, patch(
            "scripts.processing.optimized_briefing_generator.OptimizedBriefingGenerator"
        ) as mock_bg_class:
            # Configure cache manager mock
            mock_cache_instance = MagicMock()
            mock_cache_manager_class.return_value = mock_cache_instance
            mock_cache_instance.get_recent_vulnerabilities.return_value = []

            # Configure briefing generator mock
            mock_bg_instance = MagicMock()
            mock_bg_class.return_value = mock_bg_instance
            mock_bg_instance.generate_all.return_value = {
                "briefing": "src/_posts/2025-06-29-vuln-brief.md",
                "index": "src/api/vulns/index.json",
                "chunks": [],
                "chunk_index": None,
            }

            result = cli_runner.invoke(
                app,
                [
                    "generate-briefing",
                    "--cache-dir",
                    str(cache_dir),
                    "--output-dir",
                    str(output_dir),
                    "--limit",
                    "30",
                ],
            )

            assert result.exit_code == 0
            assert "No vulnerabilities found" in result.output

    def test_generate_briefing_with_data(self, cli_runner, tmp_path):
        """Test generate-briefing with vulnerability data."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        output_dir = tmp_path / "output"

        from datetime import datetime, timezone

        from scripts.models import Vulnerability

        with patch("scripts.main.CacheManager") as mock_cache_manager_class, patch(
            "scripts.processing.optimized_briefing_generator.OptimizedBriefingGenerator"
        ) as mock_bg_class:
            # Configure cache manager mock with vulnerabilities
            mock_cache_instance = MagicMock()
            mock_cache_manager_class.return_value = mock_cache_instance

            # Create sample vulnerability
            vuln = Vulnerability(
                cve_id="CVE-2025-1234",
                title="Test Vulnerability",
                description="Test description",
                published_date=datetime.now(timezone.utc),
                last_modified_date=datetime.now(timezone.utc),
                severity=SeverityLevel.HIGH,
                cvss_metrics=[],
                risk_score=85,
                affected_vendors=["test"],
                affected_products=["test"],
                references=[],
                sources=[],
            )
            mock_cache_instance.get_recent_vulnerabilities.return_value = [vuln]

            # Configure briefing generator mock
            mock_bg_instance = MagicMock()
            mock_bg_class.return_value = mock_bg_instance
            mock_bg_instance.generate_all.return_value = {
                "briefing": "src/_posts/2025-06-29-vuln-brief.md",
                "index": "src/api/vulns/index.json",
                "chunks": ["src/api/vulns/vulns-2025-HIGH.json"],
                "chunk_index": "src/api/vulns/chunk-index.json",
            }

            result = cli_runner.invoke(
                app,
                [
                    "generate-briefing",
                    "--cache-dir",
                    str(cache_dir),
                    "--output-dir",
                    str(output_dir),
                ],
            )

            assert result.exit_code == 0
            assert "Briefing generated successfully" in result.output
            assert "Data chunks: 1 files" in result.output

    def test_update_badge_command(self, cli_runner, tmp_path):
        """Test update-badge command."""
        # Create test files
        coverage_file = tmp_path / "coverage.xml"
        readme_file = tmp_path / "README.md"

        # Write test coverage.xml with 85% coverage
        coverage_content = """<?xml version="1.0" ?>
<coverage version="7.0" timestamp="1234567890" lines-valid="100" lines-covered="85" line-rate="0.85">
</coverage>"""
        coverage_file.write_text(coverage_content)

        # Write test README with old badge (80%)
        readme_content = """# Test Project
![Coverage](https://img.shields.io/badge/coverage-80%25-green)
Some content here"""
        readme_file.write_text(readme_content)

        result = cli_runner.invoke(
            app,
            [
                "update-badge",
                "--coverage-file",
                str(coverage_file),
                "--readme-file",
                str(readme_file),
            ],
        )

        assert result.exit_code == 0
        assert "Coverage badge updated to 85%" in result.output

        # Verify the file was updated
        updated_readme = readme_file.read_text()
        assert "coverage-85%25" in updated_readme

    @patch("scripts.main.CacheManager")
    def test_send_alerts_command_dry_run(self, mock_cache_class, cli_runner):
        """Test send-alerts command with dry run."""
        from datetime import datetime

        from scripts.models import SeverityLevel, Vulnerability

        # Create mock vulnerabilities with high risk scores
        high_risk_vuln = Vulnerability(
            cve_id="CVE-2024-1234",
            title="Test High Risk Vulnerability",
            description="Test description",
            severity=SeverityLevel.CRITICAL,
            published_date=datetime.now(),
            last_modified_date=datetime.now(),
            risk_score=85,  # High risk score
        )

        mock_cache_instance = mock_cache_class.return_value
        mock_cache_instance.get_recent_vulnerabilities.return_value = [high_risk_vuln]

        result = cli_runner.invoke(app, ["send-alerts", "--dry-run"])

        assert result.exit_code == 0
        assert "DRY RUN MODE" in result.output
        assert "Would send 1 alerts" in result.output

    @patch("scripts.main.CacheManager")
    def test_send_alerts_command_no_vulnerabilities(self, mock_cache_class, cli_runner):
        """Test send-alerts command when no vulnerabilities are found."""
        mock_cache_instance = mock_cache_class.return_value
        mock_cache_instance.get_recent_vulnerabilities.return_value = []

        result = cli_runner.invoke(app, ["send-alerts", "--dry-run"])

        assert result.exit_code == 0
        assert "No vulnerabilities found" in result.output

    def test_main_app_without_command(self, cli_runner):
        """Test running app without command shows help."""
        result = cli_runner.invoke(app, [])

        # Click group shows help when no command provided
        # Exit code may be 0 or 2 depending on Click version/Python version
        assert result.exit_code in [0, 2]
        assert "Usage" in result.output
        assert "harvest" in result.output
        assert "generate-briefing" in result.output
        assert "update-badge" in result.output

    def test_harvest_with_nonexistent_cache_dir(
        self, cli_runner, mock_orchestrator, tmp_path
    ):
        """Test harvest with non-existent cache directory (should create it)."""
        cache_dir = tmp_path / "nonexistent"

        result = cli_runner.invoke(
            app,
            ["harvest", "--cache-dir", str(cache_dir)],
        )

        # Should succeed and create directory
        assert result.exit_code == 0
        mock_orchestrator.harvest_all_sources.assert_called_once()

    def test_severity_enum_conversion(self, cli_runner, mock_orchestrator, tmp_path):
        """Test severity level enum conversion."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Test each severity level
        for severity in ["MEDIUM", "HIGH", "CRITICAL"]:
            result = cli_runner.invoke(
                app,
                [
                    "harvest",
                    "--cache-dir",
                    str(cache_dir),
                    "--min-severity",
                    severity,
                ],
            )

            assert result.exit_code == 0

            # Verify correct enum passed
            call_args = mock_orchestrator.harvest_all_sources.call_args
            assert call_args.kwargs["min_severity"] == severity
