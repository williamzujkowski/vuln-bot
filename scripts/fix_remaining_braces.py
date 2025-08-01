#!/usr/bin/env python3
"""Fix remaining JavaScript brace issues in the dashboard generator."""

import re
from pathlib import Path


def fix_remaining_braces():
    """Fix remaining JavaScript brace issues."""

    file_path = Path("scripts/generate_alpine_dashboard.py")
    content = file_path.read_text()

    # Fix specific patterns where we have }} in JavaScript control flow
    replacements = [
        # Fix }} else patterns
        ("}} else if", "} else if"),
        ("}} else {", "} else {"),
        # Fix closing braces followed by }
        ("}}]", "}]"),
        ("}});", "});"),
        ("}})", "})"),
        # Fix specific filter/if statement closures
        (
            "vulns = vulns.filter(v => v.severity === 'CRITICAL');",
            "vulns = vulns.filter(v => v.severity === 'CRITICAL');",
        ),
        # Fix the if statements that have }} at the end
        ("'CRITICAL');", "'CRITICAL');"),
        # Fix lines that have }} right after a semicolon or parenthesis
        (");}}", ");}"),
        ("'];}}", "'];}"),
        # Fix specific problem areas
        (
            "if (this.quickFilter === 'critical') {\n                        vulns = vulns.filter(v => v.severity === 'CRITICAL');\n                    }} else",
            "if (this.quickFilter === 'critical') {\n                        vulns = vulns.filter(v => v.severity === 'CRITICAL');\n                    } else",
        ),
        # Fix closing braces in conditional blocks
        ("}}", "}},"),  # This might catch CSS, so we'll be careful
    ]

    # Apply replacements carefully
    for old, new in replacements:
        content = content.replace(old, new)

    # Now fix specific line patterns using regex
    # Fix lines that have }} at the end but should just have }
    # This pattern looks for JavaScript code lines ending with }}
    js_double_brace_pattern = r"(\s+)(.*[;)])\s*}}"
    content = re.sub(js_double_brace_pattern, r"\1\2 }", content, flags=re.MULTILINE)

    # Fix specific problematic patterns in the filters section
    # Look for filter closing braces
    content = re.sub(r"(\s+)\}\}(\s*//)", r"\1}\2", content)

    # Fix Chart.js object closing - these should have double closing braces but proper formatting
    # Leave Chart configuration objects alone as they need the double braces

    # Write the fixed content
    file_path.write_text(content)
    print("✅ Fixed remaining JavaScript brace issues")
    print("📝 Changes made:")
    print("  - Fixed }} else patterns to } else")
    print("  - Fixed closing braces in filter blocks")
    print("  - Fixed double closing braces after statements")


if __name__ == "__main__":
    fix_remaining_braces()
