"""Tests for badge generation module."""

from unittest.mock import patch

import pytest


class TestGenerateBadge:
    """Test cases for badge generation."""

    @pytest.fixture
    def temp_readme(self, tmp_path):
        """Create temporary README file."""
        readme = tmp_path / "README.md"
        readme.write_text("""# Test Project

![Coverage](https://img.shields.io/badge/coverage-50%25-yellow.svg)

Some other content here.
""")
        return readme

    def test_update_coverage_badge(self, temp_readme):
        """Test updating coverage badge in README."""
        from scripts.generate_badge import update_coverage_badge

        # Update to 85% coverage
        update_coverage_badge(str(temp_readme), 85.5)

        # Check updated content
        content = temp_readme.read_text()
        assert "coverage-85.5%25" in content
        assert "brightgreen" in content  # Color for high coverage

    def test_get_badge_color(self):
        """Test badge color selection based on coverage."""
        from scripts.generate_badge import get_badge_color

        assert get_badge_color(95) == "brightgreen"
        assert get_badge_color(85) == "green"
        assert get_badge_color(75) == "yellowgreen"
        assert get_badge_color(65) == "yellow"
        assert get_badge_color(55) == "orange"
        assert get_badge_color(45) == "red"

    def test_create_badge_url(self):
        """Test badge URL creation."""
        from scripts.generate_badge import create_badge_url

        url = create_badge_url(82.5, "green")

        assert "shields.io" in url
        assert "coverage-82.5%25" in url
        assert "color=green" in url

    def test_main_function(self, temp_readme, capsys):
        """Test main function."""
        from scripts.generate_badge import main

        with patch("sys.argv", ["generate_badge.py", str(temp_readme), "75.0"]):
            main()

        # Check file was updated
        content = temp_readme.read_text()
        assert "coverage-75%25" in content

        # Check output
        captured = capsys.readouterr()
        assert "Updated coverage badge" in captured.out

    def test_missing_readme(self, tmp_path):
        """Test handling of missing README file."""
        from scripts.generate_badge import update_coverage_badge

        missing_file = tmp_path / "missing.md"

        # Should handle gracefully
        with pytest.raises(FileNotFoundError):
            update_coverage_badge(str(missing_file), 80)

    def test_no_existing_badge(self, tmp_path):
        """Test adding badge when none exists."""
        from scripts.generate_badge import update_coverage_badge

        readme = tmp_path / "README.md"
        readme.write_text("""# Test Project

No badge here yet.
""")

        # Should add badge after title
        update_coverage_badge(str(readme), 90)

        content = readme.read_text()
        assert "![Coverage]" in content
        assert "coverage-90%25" in content

    def test_multiple_badges(self, tmp_path):
        """Test updating when multiple badges exist."""
        from scripts.generate_badge import update_coverage_badge

        readme = tmp_path / "README.md"
        readme.write_text("""# Test Project

![Build](https://img.shields.io/badge/build-passing-green.svg)
![Coverage](https://img.shields.io/badge/coverage-60%25-yellow.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

Content here.
""")

        update_coverage_badge(str(readme), 95)

        content = readme.read_text()
        # Should only update coverage badge
        assert "build-passing" in content
        assert "coverage-95%25" in content
        assert "license-MIT" in content
