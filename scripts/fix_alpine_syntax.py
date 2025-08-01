#!/usr/bin/env python3
"""Fix Alpine.js syntax issues in the dashboard generator."""

import re
from pathlib import Path


def fix_alpine_syntax():
    """Fix all Alpine.js syntax issues in the dashboard generator."""

    file_path = Path("scripts/generate_alpine_dashboard.py")
    content = file_path.read_text()

    # Fix 1: Replace ${{}} with ${} in template literals
    content = re.sub(r"\$\{\{([^}]+)\}\}", r"${\1}", content)

    # Fix 2: Replace {{ }} with { } for Alpine.js object literals
    # This is more complex - we need to preserve CSS {{ }} but fix Alpine's

    # Fix Alpine :class directives
    content = content.replace(':class="{{ ', ':class="{ ')
    content = content.replace(' }}"', ' }"')

    # Fix x-data directives
    content = content.replace('x-data="{{ ', 'x-data="{ ')

    # Fix object literals in JavaScript
    content = content.replace("const severityOrder = {{ ", "const severityOrder = { ")
    content = content.replace(
        "const blob = new Blob([csvContent], {{ ",
        "const blob = new Blob([csvContent], { ",
    )
    content = content.replace("labels: {{ ", "labels: { ")
    content = content.replace("legend: {{ ", "legend: { ")
    content = content.replace("ticks: {{ ", "ticks: { ")

    # Fix 3: Ensure dashboard() function is properly exported to window
    # Find the dashboard function definition and make it global
    dashboard_pattern = r"(\s+)(function dashboard\(\) \{)"
    dashboard_replacement = r"\1window.dashboard = function() {"
    content = re.sub(dashboard_pattern, dashboard_replacement, content)

    # Write the fixed content
    file_path.write_text(content)
    print("✅ Fixed Alpine.js syntax issues")
    print("📝 Changes made:")
    print("  - Replaced ${{}} with ${} in template literals")
    print("  - Replaced {{ }} with { } in Alpine.js directives")
    print("  - Made dashboard() function global")


if __name__ == "__main__":
    fix_alpine_syntax()
