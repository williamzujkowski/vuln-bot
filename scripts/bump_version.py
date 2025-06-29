#!/usr/bin/env python3
"""Bump version and create git tag."""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple


def get_current_version() -> Optional[str]:
    """Get current version from package.json."""
    package_json = Path("package.json")
    if package_json.exists():
        with open(package_json) as f:
            data = json.load(f)
            return data.get("version", "0.0.0")
    return None


def parse_version(version: str) -> Tuple[int, int, int]:
    """Parse version string into major, minor, patch."""
    match = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        raise ValueError(f"Invalid version format: {version}")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def bump_version(current: str, bump_type: str) -> str:
    """Bump version based on type."""
    major, minor, patch = parse_version(current)

    if bump_type == "major":
        return f"{major + 1}.0.0"
    elif bump_type == "minor":
        return f"{major}.{minor + 1}.0"
    elif bump_type == "patch":
        return f"{major}.{minor}.{patch + 1}"
    else:
        raise ValueError(f"Invalid bump type: {bump_type}")


def update_package_json(version: str) -> None:
    """Update version in package.json."""
    package_json = Path("package.json")
    if package_json.exists():
        with open(package_json) as f:
            data = json.load(f)

        data["version"] = version

        with open(package_json, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")

        print(f"Updated package.json to version {version}")


def create_git_tag(version: str, message: Optional[str] = None) -> None:
    """Create git tag and commit."""
    # Add files
    subprocess.run(["git", "add", "package.json"], check=True)

    # Commit
    commit_message = f"chore: bump version to {version}"
    subprocess.run(["git", "commit", "-m", commit_message], check=True)

    # Create tag
    tag_name = f"v{version}"
    tag_message = message or f"Release {tag_name}"
    subprocess.run(["git", "tag", "-a", tag_name, "-m", tag_message], check=True)

    print(f"Created git tag {tag_name}")
    print("\nTo push the changes and trigger a release:")
    print("  git push origin main")
    print(f"  git push origin {tag_name}")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Bump version and create git tag")
    parser.add_argument(
        "bump_type", choices=["major", "minor", "patch"], help="Type of version bump"
    )
    parser.add_argument("-m", "--message", help="Tag message (optional)")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes",
    )

    args = parser.parse_args()

    # Get current version
    current_version = get_current_version()
    if not current_version:
        print("Could not determine current version from package.json")
        return 1

    print(f"Current version: {current_version}")

    # Calculate new version
    new_version = bump_version(current_version, args.bump_type)
    print(f"New version: {new_version}")

    if args.dry_run:
        print("\nDry run mode - no changes made")
        return 0

    # Update files
    update_package_json(new_version)

    # Create git tag
    try:
        create_git_tag(new_version, args.message)
    except subprocess.CalledProcessError as e:
        print(f"Git operation failed: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
