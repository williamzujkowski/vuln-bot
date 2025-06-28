"""Simple tests for the CLI main module to improve coverage."""

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from scripts.main import cli


@pytest.fixture
def cli_runner():
    """Create CLI test runner."""
    return CliRunner()


class TestMainCLI:
    """Tests for main CLI."""

    def test_cli_help(self, cli_runner):
        """Test CLI help command."""
        result = cli_runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Morning Vuln Briefing" in result.output
        assert "harvest" in result.output
        assert "generate-briefing" in result.output

    @patch("scripts.main.HarvestOrchestrator")
    def test_harvest_dry_run(self, mock_orchestrator_class, cli_runner, tmp_path):
        """Test harvest command in dry-run mode."""
        cache_dir = tmp_path / "cache"

        result = cli_runner.invoke(
            cli,
            ["harvest", "--cache-dir", str(cache_dir), "--dry-run"],
        )

        assert result.exit_code == 0
        assert "Running in dry-run mode" in result.output
        # Should not create orchestrator in dry-run
        mock_orchestrator_class.assert_not_called()

    @patch("scripts.main.HarvestOrchestrator")
    @patch("scripts.main.CacheManager")
    def test_generate_briefing_no_data(
        self, mock_cache_class, mock_orchestrator_class, cli_runner, tmp_path
    ):  # noqa: ARG002
        """Test generate-briefing when no data available."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Configure mock to return None (no data)
        mock_cache_instance = MagicMock()
        mock_cache_instance.get_latest_batch.return_value = None
        mock_cache_class.return_value = mock_cache_instance

        result = cli_runner.invoke(
            cli,
            ["generate-briefing", "--cache-dir", str(cache_dir)],
        )

        assert result.exit_code == 0
        assert "No vulnerability data found" in result.output
