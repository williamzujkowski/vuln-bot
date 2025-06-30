"""Tests for badge generation module."""

from unittest.mock import MagicMock, patch

import pytest


class TestGenerateBadge:
    """Test cases for badge generation."""

    @pytest.fixture
    def temp_readme(self, tmp_path):
        """Create temporary README file."""
        readme = tmp_path / "README.md"
        readme.write_text("""# Test Project

![Coverage](https://img.shields.io/badge/coverage-50%25-yellow)

Some other content here.
""")
        return readme

    def test_update_readme_badge(self, temp_readme, monkeypatch):
        """Test updating coverage badge in README."""
        from scripts.generate_badge import update_readme_badge

        # Change to temp directory
        monkeypatch.chdir(temp_readme.parent)

        # Update to 85% coverage
        result = update_readme_badge(85.5)

        assert result is True

        # Check updated content
        content = temp_readme.read_text()
        assert "coverage-86%25-green" in content  # Should round to 86%

    def test_get_badge_color(self):
        """Test badge color selection based on coverage."""
        from scripts.generate_badge import get_badge_color

        assert get_badge_color(95) == "green"
        assert get_badge_color(85) == "green"
        assert get_badge_color(80) == "green"
        assert get_badge_color(75) == "yellow"
        assert get_badge_color(65) == "yellow"
        assert get_badge_color(60) == "yellow"
        assert get_badge_color(55) == "orange"
        assert get_badge_color(45) == "orange"
        assert get_badge_color(40) == "orange"
        assert get_badge_color(35) == "red"
        assert get_badge_color(25) == "red"

    def test_get_coverage_percentage_from_json(self, tmp_path, monkeypatch):
        """Test getting coverage from coverage.json."""
        from scripts.generate_badge import get_coverage_percentage

        monkeypatch.chdir(tmp_path)

        # Create coverage.json
        coverage_json = tmp_path / "coverage.json"
        coverage_json.write_text('{"totals": {"percent_covered": 75.5}}')

        result = get_coverage_percentage()
        assert result == 75.5

    def test_get_coverage_percentage_from_xml(self, tmp_path, monkeypatch):
        """Test getting coverage from coverage.xml."""
        from scripts.generate_badge import get_coverage_percentage

        monkeypatch.chdir(tmp_path)

        # Create coverage.xml
        coverage_xml = tmp_path / "coverage.xml"
        coverage_xml.write_text(
            '<?xml version="1.0" ?><coverage line-rate="0.825"></coverage>'
        )

        result = get_coverage_percentage()
        assert result == 82.5

    def test_get_coverage_percentage_fallback(self, tmp_path, monkeypatch):
        """Test fallback when coverage module is available."""
        from scripts.generate_badge import get_coverage_percentage

        monkeypatch.chdir(tmp_path)

        # Mock the coverage module at import level
        mock_coverage_module = MagicMock()
        mock_cov_instance = MagicMock()
        mock_cov_instance.report.return_value = 77.3
        mock_coverage_module.Coverage.return_value = mock_cov_instance

        with patch.dict("sys.modules", {"coverage": mock_coverage_module}):
            result = get_coverage_percentage()
            assert result == 77.3

    def test_get_coverage_percentage_none(self, tmp_path, monkeypatch):
        """Test when no coverage data is found."""
        from scripts.generate_badge import get_coverage_percentage

        monkeypatch.chdir(tmp_path)

        result = get_coverage_percentage()
        assert result is None

    def test_main_function_success(self, temp_readme, monkeypatch, capsys):
        """Test main function with successful update."""
        from scripts.generate_badge import main

        monkeypatch.chdir(temp_readme.parent)

        # Create coverage.json
        coverage_json = temp_readme.parent / "coverage.json"
        coverage_json.write_text('{"totals": {"percent_covered": 75.0}}')

        result = main()
        assert result == 0

        # Check file was updated
        content = temp_readme.read_text()
        assert "coverage-75%25-yellow" in content

        # Check output
        captured = capsys.readouterr()
        assert "Coverage: 75.0%" in captured.out
        assert "Updated coverage badge to 75% (yellow)" in captured.out

    def test_main_function_no_coverage(self, tmp_path, monkeypatch, capsys):
        """Test main function when coverage cannot be determined."""
        from scripts.generate_badge import main

        monkeypatch.chdir(tmp_path)

        result = main()
        assert result == 1

        # Check output
        captured = capsys.readouterr()
        assert "Could not determine coverage percentage" in captured.out

    def test_main_function_no_readme(self, tmp_path, monkeypatch, capsys):
        """Test main function when README doesn't exist."""
        from scripts.generate_badge import main

        monkeypatch.chdir(tmp_path)

        # Create coverage data
        coverage_json = tmp_path / "coverage.json"
        coverage_json.write_text('{"totals": {"percent_covered": 80.0}}')

        result = main()
        assert result == 1

        # Check output
        captured = capsys.readouterr()
        assert "Coverage: 80.0%" in captured.out
        assert "README.md not found" in captured.out

    def test_update_readme_badge_no_existing_badge(self, tmp_path, monkeypatch):
        """Test when README has no existing badge."""
        from scripts.generate_badge import update_readme_badge

        readme = tmp_path / "README.md"
        readme.write_text("""# Test Project

No badge here yet.
""")

        monkeypatch.chdir(tmp_path)

        result = update_readme_badge(90)
        assert result is False

        # Content should remain unchanged
        content = readme.read_text()
        assert "coverage-90%25" not in content

    def test_badge_regex_pattern(self):
        """Test the badge regex pattern matches correctly."""
        import re

        pattern = r"!\[Coverage\]\(https://img\.shields\.io/badge/coverage-\d+%25-\w+\)"

        # Should match various badge formats
        assert re.search(
            pattern, "![Coverage](https://img.shields.io/badge/coverage-50%25-yellow)"
        )
        assert re.search(
            pattern, "![Coverage](https://img.shields.io/badge/coverage-100%25-green)"
        )
        assert re.search(
            pattern, "![Coverage](https://img.shields.io/badge/coverage-0%25-red)"
        )

        # Should not match invalid formats
        assert not re.search(
            pattern, "![Coverage](https://img.shields.io/badge/coverage-50%-yellow)"
        )
        assert not re.search(
            pattern, "![Coverage](https://shields.io/badge/coverage-50%25-yellow)"
        )
