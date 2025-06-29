#!/usr/bin/env python3
"""Generate coverage badge for README."""

import json
import re
import sys
from pathlib import Path
from typing import Optional


def get_coverage_percentage() -> Optional[float]:
    """Extract coverage percentage from pytest output or coverage.xml."""
    # Try to read from coverage.json if it exists
    coverage_json = Path("coverage.json")
    if coverage_json.exists():
        try:
            with open(coverage_json) as f:
                data = json.load(f)
                return data.get("totals", {}).get("percent_covered", 0)
        except Exception:
            pass

    # Try to read from .coverage file
    try:
        import coverage

        cov = coverage.Coverage()
        cov.load()
        return cov.report(show_missing=False)
    except Exception:
        pass

    # Fall back to parsing coverage.xml
    coverage_xml = Path("coverage.xml")
    if coverage_xml.exists():
        try:
            content = coverage_xml.read_text()
            match = re.search(r'line-rate="([0-9.]+)"', content)
            if match:
                return float(match.group(1)) * 100
        except Exception:
            pass

    return None


def get_badge_color(percentage: float) -> str:
    """Get badge color based on coverage percentage."""
    if percentage >= 80:
        return "green"
    elif percentage >= 60:
        return "yellow"
    elif percentage >= 40:
        return "orange"
    else:
        return "red"


def update_readme_badge(percentage: float) -> bool:
    """Update the coverage badge in README.md."""
    readme_path = Path("README.md")
    if not readme_path.exists():
        print("README.md not found")
        return False

    readme_content = readme_path.read_text()

    # Find and replace the coverage badge
    color = get_badge_color(percentage)
    new_badge = f"![Coverage](https://img.shields.io/badge/coverage-{percentage:.0f}%25-{color})"

    # Match the coverage badge pattern
    pattern = r"!\[Coverage\]\(https://img\.shields\.io/badge/coverage-\d+%25-\w+\)"

    if re.search(pattern, readme_content):
        updated_content = re.sub(pattern, new_badge, readme_content)
        readme_path.write_text(updated_content)
        print(f"Updated coverage badge to {percentage:.0f}% ({color})")
        return True
    else:
        print("Coverage badge not found in README.md")
        return False


def main() -> int:
    """Main function."""
    coverage = get_coverage_percentage()

    if coverage is None:
        print("Could not determine coverage percentage")
        return 1

    print(f"Coverage: {coverage:.1f}%")

    if update_readme_badge(coverage):
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())
