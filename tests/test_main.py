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
        mock_instance.harvest_all.return_value = mock_batch

        yield mock_instance


@pytest.fixture
def mock_briefing_generator():
    """Create mock briefing generator."""
    with patch("scripts.main.BriefingGenerator") as mock_class:
        mock_instance = MagicMock()
        mock_class.return_value = mock_instance
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
        assert "Starting vulnerability harvest" in result.output
        assert "Harvest complete" in result.output

        # Verify orchestrator called correctly
        mock_orchestrator.harvest_all.assert_called_once()
        call_args = mock_orchestrator.harvest_all.call_args
        assert call_args.kwargs["sources"] == ["all"]
        assert call_args.kwargs["years"] == [2025]  # Current year
        assert call_args.kwargs["min_severity"] == SeverityLevel.HIGH
        assert call_args.kwargs["min_epss_score"] == 0.0

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
                "--sources",
                "cvelist",
                "--sources",
                "epss",
                "--years",
                "2024",
                "--years",
                "2025",
                "--min-severity",
                "CRITICAL",
                "--min-epss",
                "0.8",
                "--verbose",
            ],
        )

        assert result.exit_code == 0

        # Verify orchestrator called with correct parameters
        mock_orchestrator.harvest_all.assert_called_once()
        call_args = mock_orchestrator.harvest_all.call_args
        assert call_args.kwargs["sources"] == ["cvelist", "epss"]
        assert call_args.kwargs["years"] == [2024, 2025]
        assert call_args.kwargs["min_severity"] == SeverityLevel.CRITICAL
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

        assert result.exit_code != 0
        assert "Invalid value" in result.output

    def test_harvest_command_invalid_epss(self, cli_runner, tmp_path):
        """Test harvest command with invalid EPSS score."""
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

        assert result.exit_code != 0

    def test_generate_briefing_command(
        self, cli_runner, mock_orchestrator, mock_briefing_generator, tmp_path
    ):
        """Test generate-briefing command."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        output_dir = tmp_path / "output"

        # Configure mocks
        mock_batch = VulnerabilityBatch(vulnerabilities=[], metadata={})
        mock_orchestrator.get_recent_vulnerabilities.return_value = mock_batch

        result = cli_runner.invoke(
            app,
            [
                "generate-briefing",
                "--cache-dir",
                str(cache_dir),
                "--output-dir",
                str(output_dir),
                "--days",
                "3",
            ],
        )

        assert result.exit_code == 0
        assert "Generating vulnerability briefing" in result.output
        assert "Briefing generation complete" in result.output

        # Verify methods called
        mock_orchestrator.get_recent_vulnerabilities.assert_called_once_with(days=3)
        mock_briefing_generator.generate_daily_briefing.assert_called_once_with(
            mock_batch
        )
        mock_briefing_generator.generate_api_files.assert_called_once_with(mock_batch)

    def test_generate_briefing_no_data(
        self, cli_runner, mock_orchestrator, mock_briefing_generator, tmp_path
    ):  # noqa: ARG002
        """Test generate-briefing with no vulnerability data."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Configure mock to return None
        mock_orchestrator.get_recent_vulnerabilities.return_value = None

        result = cli_runner.invoke(
            app,
            [
                "generate-briefing",
                "--cache-dir",
                str(cache_dir),
            ],
        )

        assert result.exit_code == 0
        assert "No vulnerability data found" in result.output

    def test_check_command(self, cli_runner):
        """Test check command."""
        result = cli_runner.invoke(app, ["check"])

        assert result.exit_code == 0
        assert "System Check" in result.output
        assert "Python version" in result.output
        assert "Available commands" in result.output

    def test_check_command_verbose(self, cli_runner):
        """Test check command with verbose flag."""
        result = cli_runner.invoke(app, ["check", "--verbose"])

        assert result.exit_code == 0
        assert "System Check" in result.output

    def test_main_app_without_command(self, cli_runner):
        """Test running app without command shows help."""
        result = cli_runner.invoke(app, [])

        assert result.exit_code == 0
        assert "Usage:" in result.output
        assert "harvest" in result.output
        assert "generate-briefing" in result.output
        assert "check" in result.output

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
        mock_orchestrator.harvest_all.assert_called_once()

    def test_severity_enum_conversion(self, cli_runner, mock_orchestrator, tmp_path):
        """Test severity level enum conversion."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Test each severity level
        for severity in ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
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
            call_args = mock_orchestrator.harvest_all.call_args
            assert call_args.kwargs["min_severity"] == SeverityLevel[severity]
