#!/usr/bin/env python3
"""Fix JavaScript brace issues in the dashboard generator."""

import re
from pathlib import Path


def fix_js_braces():
    """Fix JavaScript brace issues in the dashboard generator."""

    file_path = Path("scripts/generate_alpine_dashboard.py")
    content = file_path.read_text()

    # In the JavaScript sections within the Python string, we need single braces
    # But Python requires double braces to escape them in strings
    # So we need to ensure JavaScript object/function syntax uses single pairs

    # Fix patterns where we have {{ in JavaScript contexts that should be {
    replacements = [
        # Function definitions
        ("window.dashboard = function() {{", "window.dashboard = function() {"),
        ("return {{", "return {"),
        # Object properties in filters
        ("filters: {{", "filters: {"),
        # Computed properties
        ("get filteredVulns() {{", "get filteredVulns() {"),
        ("get totalPages() {{", "get totalPages() {"),
        ("get paginatedVulns() {{", "get paginatedVulns() {"),
        # Methods
        ("init() {{", "init() {"),
        ("setQuickFilter(filter) {{", "setQuickFilter(filter) {"),
        ("sort(field) {{", "sort(field) {"),
        ("resetFilters() {{", "resetFilters() {"),
        ("exportCSV() {{", "exportCSV() {"),
        ("setupKeyboardShortcuts() {{", "setupKeyboardShortcuts() {"),
        ("initCharts() {{", "initCharts() {"),
        # Conditionals and loops
        ("vulns.sort((a, b) => {{", "vulns.sort((a, b) => {"),
        ("this.$nextTick(() => {{", "this.$nextTick(() => {"),
        (
            "document.addEventListener('keydown', (e) => {{",
            "document.addEventListener('keydown', (e) => {",
        ),
        # Chart.js options need special handling - they should keep double braces
        # because they're within Python string literals
    ]

    # Apply replacements
    for old, new in replacements:
        content = content.replace(old, new)

    # Fix closing braces that are doubled
    # Look for patterns like }}; or }}, or }}) at end of lines
    content = re.sub(r"\}\}(\s*[;,\)])", r"}\1", content)

    # Special handling for if statements and other control structures
    if_patterns = [
        (r"if \(([^)]+)\) \{\{", r"if (\1) {"),
        (r"else if \(([^)]+)\) \{\{", r"else if (\1) {"),
        (r"else \{\{", r"else {"),
        (r"switch\(([^)]+)\) \{\{", r"switch(\1) {"),
    ]

    for pattern, replacement in if_patterns:
        content = re.sub(pattern, replacement, content)

    # Write the fixed content
    file_path.write_text(content)
    print("✅ Fixed JavaScript brace issues")
    print("📝 Changes made:")
    print("  - Fixed function definitions to use single braces")
    print("  - Fixed object literals to use single braces")
    print("  - Fixed method definitions to use single braces")
    print("  - Fixed control structures to use single braces")


if __name__ == "__main__":
    fix_js_braces()
