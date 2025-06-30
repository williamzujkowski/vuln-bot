"""Tests for badge update functionality."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from scripts.main import cli


class TestBadgeUpdate:
    """Test the badge update functionality."""

    @pytest.fixture
    def sample_coverage_xml(self) -> str:
        """Sample coverage XML content."""
        return """<?xml version="1.0" ?>
<coverage version="7.9.1" timestamp="1751249873976" lines-valid="2301" lines-covered="2031" line-rate="0.8827" branches-covered="0" branches-valid="0" branch-rate="0" complexity="0">
    <sources>
        <source>/home/runner/work/vuln-bot/vuln-bot/scripts</source>
    </sources>
</coverage>"""

    @pytest.fixture
    def sample_readme(self) -> str:
        """Sample README content with coverage badge."""
        return """# Vuln-Bot

![Coverage](https://img.shields.io/badge/coverage-88%25-green)
![CI](https://github.com/williamzujkowski/vuln-bot/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

A vulnerability intelligence platform."""

    def test_update_badge_success(self, sample_coverage_xml, sample_readme):
        """Test successful badge update."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            # Create test files
            coverage_file = Path("coverage.xml")
            readme_file = Path("README.md")

            coverage_file.write_text(sample_coverage_xml)
            readme_file.write_text(sample_readme)

            # Run the command
            result = runner.invoke(
                cli,
                [
                    "update-badge",
                    "--coverage-file",
                    "coverage.xml",
                    "--readme-file",
                    "README.md",
                ],
            )

            assert result.exit_code == 0
            assert "Coverage badge already shows 88%" in result.output

            # Check that README wasn't changed (already correct)
            assert readme_file.read_text() == sample_readme

    def test_update_badge_with_change(self, sample_coverage_xml):
        """Test badge update when coverage changes."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            # Create test files with different coverage
            coverage_file = Path("coverage.xml")
            readme_file = Path("README.md")

            # Modify coverage to 95%
            modified_coverage = sample_coverage_xml.replace(
                'line-rate="0.8827"', 'line-rate="0.95"'
            )
            coverage_file.write_text(modified_coverage)

            # README with old coverage
            readme_content = """# Vuln-Bot

![Coverage](https://img.shields.io/badge/coverage-88%25-green)
![CI](https://github.com/williamzujkowski/vuln-bot/actions/workflows/ci.yml/badge.svg)

A vulnerability intelligence platform."""
            readme_file.write_text(readme_content)

            # Run the command
            result = runner.invoke(
                cli,
                [
                    "update-badge",
                    "--coverage-file",
                    "coverage.xml",
                    "--readme-file",
                    "README.md",
                ],
            )

            assert result.exit_code == 0
            assert "Coverage badge updated to 95%" in result.output
            assert "color: brightgreen" in result.output

            # Check that README was updated
            updated_readme = readme_file.read_text()
            assert "coverage-95%25-brightgreen" in updated_readme
            assert "coverage-88%25-green" not in updated_readme

    def test_update_badge_dry_run(self, sample_coverage_xml):
        """Test dry run mode."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            # Create test files
            coverage_file = Path("coverage.xml")
            readme_file = Path("README.md")

            # Modify coverage to 75%
            modified_coverage = sample_coverage_xml.replace(
                'line-rate="0.8827"', 'line-rate="0.75"'
            )
            coverage_file.write_text(modified_coverage)

            readme_content = """# Vuln-Bot

![Coverage](https://img.shields.io/badge/coverage-88%25-green)
![CI](https://github.com/williamzujkowski/vuln-bot/actions/workflows/ci.yml/badge.svg)"""
            readme_file.write_text(readme_content)

            # Run the command in dry-run mode
            result = runner.invoke(
                cli,
                [
                    "update-badge",
                    "--coverage-file",
                    "coverage.xml",
                    "--readme-file",
                    "README.md",
                    "--dry-run",
                ],
            )

            assert result.exit_code == 0
            assert "DRY RUN MODE" in result.output
            assert (
                "Current: ![Coverage](https://img.shields.io/badge/coverage-88%25-green)"
                in result.output
            )
            assert (
                "New:     ![Coverage](https://img.shields.io/badge/coverage-75%25-yellowgreen)"
                in result.output
            )
            assert "Coverage: 75% (color: yellowgreen)" in result.output

            # Verify README wasn't changed
            assert readme_file.read_text() == readme_content

    def test_update_badge_missing_badge(self, sample_coverage_xml):
        """Test when coverage badge is not found in README."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            # Create test files
            coverage_file = Path("coverage.xml")
            readme_file = Path("README.md")

            coverage_file.write_text(sample_coverage_xml)
            readme_file.write_text("# Vuln-Bot\n\nNo badge here.")

            # Run the command
            result = runner.invoke(
                cli,
                [
                    "update-badge",
                    "--coverage-file",
                    "coverage.xml",
                    "--readme-file",
                    "README.md",
                ],
            )

            assert result.exit_code == 0
            assert "Coverage badge not found in README" in result.output

    def test_update_badge_invalid_xml(self):
        """Test with invalid coverage XML."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            # Create test files
            coverage_file = Path("coverage.xml")
            readme_file = Path("README.md")

            coverage_file.write_text("Invalid XML content")
            readme_file.write_text("# Vuln-Bot")

            # Run the command
            result = runner.invoke(
                cli,
                [
                    "update-badge",
                    "--coverage-file",
                    "coverage.xml",
                    "--readme-file",
                    "README.md",
                ],
            )

            assert result.exit_code == 1
            assert "Failed to parse coverage XML" in result.output

    def test_update_badge_color_thresholds(self, sample_readme):
        """Test different coverage percentages produce correct colors."""
        runner = CliRunner()

        test_cases = [
            (0.95, "95", "brightgreen"),
            (0.85, "85", "green"),
            (0.75, "75", "yellowgreen"),
            (0.65, "65", "yellow"),
            (0.55, "55", "orange"),
            (0.45, "45", "red"),
        ]

        for line_rate, percentage, expected_color in test_cases:
            with runner.isolated_filesystem():
                coverage_file = Path("coverage.xml")
                readme_file = Path("README.md")

                coverage_xml = f'''<?xml version="1.0" ?>
<coverage line-rate="{line_rate}" branch-rate="0" complexity="0">
    <sources><source>/scripts</source></sources>
</coverage>'''

                coverage_file.write_text(coverage_xml)
                readme_file.write_text(sample_readme)

                result = runner.invoke(
                    cli,
                    [
                        "update-badge",
                        "--coverage-file",
                        "coverage.xml",
                        "--readme-file",
                        "README.md",
                    ],
                )

                assert result.exit_code == 0
                if percentage != "88":  # 88% is already in sample_readme
                    assert f"Coverage badge updated to {percentage}%" in result.output
                    assert f"color: {expected_color}" in result.output
