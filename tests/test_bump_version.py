"""Tests for bump_version module."""

import json
import subprocess
from unittest.mock import Mock, patch

import pytest

from scripts.bump_version import (
    bump_version,
    create_git_tag,
    get_current_version,
    main,
    parse_version,
    update_package_json,
)


class TestBumpVersion:
    """Test cases for version bumping functionality."""

    def test_get_current_version_exists(self, tmp_path):
        """Test getting version from existing package.json."""
        package_json = tmp_path / "package.json"
        package_json.write_text(json.dumps({"version": "1.2.3"}))

        with patch("scripts.bump_version.Path", return_value=package_json):
            version = get_current_version()
            assert version == "1.2.3"

    def test_get_current_version_no_file(self):
        """Test getting version when package.json doesn't exist."""
        with patch("scripts.bump_version.Path") as mock_path:
            mock_path.return_value.exists.return_value = False
            version = get_current_version()
            assert version is None

    def test_get_current_version_no_version_field(self, tmp_path):
        """Test getting version when package.json has no version field."""
        package_json = tmp_path / "package.json"
        package_json.write_text(json.dumps({"name": "test"}))

        with patch("scripts.bump_version.Path", return_value=package_json):
            version = get_current_version()
            assert version == "0.0.0"

    def test_parse_version_valid(self):
        """Test parsing valid version strings."""
        assert parse_version("1.2.3") == (1, 2, 3)
        assert parse_version("v1.2.3") == (1, 2, 3)
        assert parse_version("10.20.30") == (10, 20, 30)

    def test_parse_version_invalid(self):
        """Test parsing invalid version strings."""
        with pytest.raises(ValueError, match="Invalid version format"):
            parse_version("invalid")

        with pytest.raises(ValueError, match="Invalid version format"):
            parse_version("1.2")

        with pytest.raises(ValueError, match="Invalid version format"):
            parse_version("a.b.c")

    def test_bump_version_major(self):
        """Test major version bump."""
        assert bump_version("1.2.3", "major") == "2.0.0"
        assert bump_version("0.5.7", "major") == "1.0.0"

    def test_bump_version_minor(self):
        """Test minor version bump."""
        assert bump_version("1.2.3", "minor") == "1.3.0"
        assert bump_version("0.5.7", "minor") == "0.6.0"

    def test_bump_version_patch(self):
        """Test patch version bump."""
        assert bump_version("1.2.3", "patch") == "1.2.4"
        assert bump_version("0.5.7", "patch") == "0.5.8"

    def test_bump_version_invalid_type(self):
        """Test invalid bump type."""
        with pytest.raises(ValueError, match="Invalid bump type"):
            bump_version("1.2.3", "invalid")

    def test_update_package_json(self, tmp_path):
        """Test updating package.json with new version."""
        package_json = tmp_path / "package.json"
        original_data = {
            "name": "test-package",
            "version": "1.0.0",
            "description": "Test",
        }
        package_json.write_text(json.dumps(original_data, indent=2))

        with patch("scripts.bump_version.Path", return_value=package_json):
            update_package_json("2.0.0")

        # Read updated file
        updated_data = json.loads(package_json.read_text())
        assert updated_data["version"] == "2.0.0"
        assert updated_data["name"] == "test-package"
        assert updated_data["description"] == "Test"

    def test_update_package_json_no_file(self):
        """Test updating package.json when file doesn't exist."""
        with patch("scripts.bump_version.Path") as mock_path:
            mock_path.return_value.exists.return_value = False
            # Should not raise error
            update_package_json("2.0.0")

    def test_create_git_tag_success(self):
        """Test creating git tag successfully."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            create_git_tag("1.2.3", "Release version 1.2.3")

            # Check git commands were called
            assert mock_run.call_count == 3
            calls = mock_run.call_args_list

            # Check git add
            assert calls[0][0][0] == ["git", "add", "package.json"]

            # Check git commit
            assert calls[1][0][0][:2] == ["git", "commit"]
            assert "chore: bump version to 1.2.3" in calls[1][0][0]

            # Check git tag
            assert calls[2][0][0][:4] == ["git", "tag", "-a", "v1.2.3"]
            assert "-m" in calls[2][0][0]

    def test_create_git_tag_failure(self):
        """Test handling git tag creation failure."""
        with patch("subprocess.run") as mock_run:
            # First two calls succeed (add, commit), third call fails (tag)
            mock_run.side_effect = [
                Mock(returncode=0),  # git add
                Mock(returncode=0),  # git commit
                subprocess.CalledProcessError(1, ["git", "tag"]),  # git tag fails
            ]

            # The function uses subprocess.run with check=True, so it raises CalledProcessError
            with pytest.raises(subprocess.CalledProcessError):
                create_git_tag("1.2.3", "Release version 1.2.3")

    @patch("scripts.bump_version.get_current_version")
    @patch("scripts.bump_version.update_package_json")
    @patch("scripts.bump_version.create_git_tag")
    def test_main_success(self, mock_tag, mock_update, mock_get_version):
        """Test main function with successful execution."""
        mock_get_version.return_value = "1.2.3"

        with patch("sys.argv", ["bump_version.py", "minor"]):
            result = main()
            assert result == 0

        mock_update.assert_called_once_with("1.3.0")
        mock_tag.assert_called_once_with("1.3.0", None)

    @patch("scripts.bump_version.get_current_version")
    def test_main_no_current_version(self, mock_get_version):
        """Test main function when current version cannot be determined."""
        mock_get_version.return_value = None

        with patch("sys.argv", ["bump_version.py", "minor"]):
            result = main()
            assert result == 1

    @patch("scripts.bump_version.get_current_version")
    @patch("scripts.bump_version.update_package_json")
    @patch("scripts.bump_version.create_git_tag")
    def test_main_with_message(self, mock_tag, mock_update, mock_get_version):
        """Test main function with custom message."""
        mock_get_version.return_value = "1.2.3"

        with patch(
            "sys.argv", ["bump_version.py", "patch", "-m", "Custom release message"]
        ):
            result = main()
            assert result == 0

        mock_update.assert_called_once_with("1.2.4")
        mock_tag.assert_called_once_with("1.2.4", "Custom release message")

    def test_main_invalid_args(self):
        """Test main function with invalid arguments."""
        with patch("sys.argv", ["bump_version.py"]), pytest.raises(SystemExit):
            main()

    @patch("scripts.bump_version.get_current_version")
    @patch("scripts.bump_version.update_package_json")
    @patch("scripts.bump_version.create_git_tag")
    def test_main_dry_run(self, mock_tag, mock_update, mock_get_version):
        """Test main function with dry run mode."""
        mock_get_version.return_value = "1.2.3"

        with patch("sys.argv", ["bump_version.py", "minor", "--dry-run"]):
            result = main()
            assert result == 0

        # Should not update or tag in dry run mode
        mock_update.assert_not_called()
        mock_tag.assert_not_called()

    @patch("scripts.bump_version.get_current_version")
    @patch("scripts.bump_version.update_package_json")
    @patch("scripts.bump_version.create_git_tag")
    def test_main_git_failure(self, mock_tag, mock_update, mock_get_version):
        """Test main function when git operation fails."""
        import subprocess

        mock_get_version.return_value = "1.2.3"
        mock_tag.side_effect = subprocess.CalledProcessError(1, "git tag")

        with patch("sys.argv", ["bump_version.py", "patch"]):
            result = main()
            assert result == 1

        mock_update.assert_called_once_with("1.2.4")
