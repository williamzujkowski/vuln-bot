#!/usr/bin/env python3
"""Fix JavaScript brace issues in the dashboard generator using a template approach."""

from pathlib import Path


def fix_dashboard_braces():
    """Fix JavaScript brace issues by using a different templating approach."""

    file_path = Path("scripts/generate_alpine_dashboard.py")
    content = file_path.read_text()

    # First, let's identify the HTML template section
    # Find the start of the HTML content
    html_start = content.find('html_content = """<!DOCTYPE html>')
    html_end = content.find('</html>"""', html_start) + len('</html>"""')

    if html_start == -1 or html_end == -1:
        print("❌ Could not find HTML template section")
        return

    # Extract the parts
    before_html = content[:html_start]
    html_section = content[html_start:html_end]
    after_html = content[html_end:]

    # Replace double braces with a placeholder in the HTML section
    # We'll use a unique marker that won't conflict with anything
    OPEN_BRACE = "__OPEN_BRACE__"
    CLOSE_BRACE = "__CLOSE_BRACE__"

    # Replace {{ with the placeholder except in specific cases where we need double braces
    # (like in Python format strings that will be replaced later)
    modified_html = html_section

    # Replace all {{ and }} with placeholders
    modified_html = modified_html.replace("{{", OPEN_BRACE)
    modified_html = modified_html.replace("}}", CLOSE_BRACE)

    # Now create the new approach: use format() instead of embedded braces
    new_content = before_html + modified_html + after_html

    # Add a post-processing step after the placeholders are replaced
    # Find where we replace the placeholders
    replace_section = """        # Replace placeholders with actual data
        html_content = html_content.replace(
            "VULN_DATA_PLACEHOLDER", json.dumps(vuln_data, indent=2)
        )
        html_content = html_content.replace(
            "STATS_DATA_PLACEHOLDER", json.dumps(stats, indent=2)
        )"""

    new_replace_section = """        # Replace placeholders with actual data
        html_content = html_content.replace(
            "VULN_DATA_PLACEHOLDER", json.dumps(vuln_data, indent=2)
        )
        html_content = html_content.replace(
            "STATS_DATA_PLACEHOLDER", json.dumps(stats, indent=2)
        )

        # Replace brace placeholders with actual braces
        html_content = html_content.replace("__OPEN_BRACE__", "{")
        html_content = html_content.replace("__CLOSE_BRACE__", "}")"""

    new_content = new_content.replace(replace_section, new_replace_section)

    # Write the fixed content
    file_path.write_text(new_content)
    print("✅ Fixed JavaScript brace issues using placeholder approach")
    print("📝 Changes made:")
    print("  - Replaced {{ with __OPEN_BRACE__ placeholder")
    print("  - Replaced }} with __CLOSE_BRACE__ placeholder")
    print("  - Added post-processing to convert placeholders back to single braces")


if __name__ == "__main__":
    fix_dashboard_braces()
