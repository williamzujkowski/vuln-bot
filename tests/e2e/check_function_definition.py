#!/usr/bin/env python3
"""Check how dashboard function is defined in deployed HTML."""

import asyncio
import requests
import re


async def check_function_definition():
    """Check the dashboard function definition."""
    print("🔍 Checking dashboard function definition...")

    # Fetch the HTML
    response = requests.get("https://williamzujkowski.github.io/vuln-bot/")
    html_content = response.text

    # Look for dashboard function definitions
    print("\n📊 FUNCTION DEFINITIONS:")
    
    # Check for old style
    if "function dashboard() {" in html_content:
        print("  ❌ Found OLD style: function dashboard() {")
        
    # Check for new style
    if "window.dashboard = function() {" in html_content:
        print("  ✅ Found NEW style: window.dashboard = function() {")
        
    # Check for Alpine initialization
    if 'x-data="dashboard()"' in html_content:
        print("  Found Alpine init: x-data=\"dashboard()\"")
        
    # Extract the script section with dashboard function
    script_match = re.search(r'function dashboard\(\).*?{.*?return {', html_content, re.DOTALL)
    if script_match:
        print(f"\n  Script excerpt:\n    {script_match.group(0)[:200]}...")
        
    # Check for specific syntax patterns
    print("\n📊 SYNTAX PATTERNS:")
    old_syntax_count = html_content.count("${{")
    new_syntax_count = html_content.count("${stats.")
    
    print(f"  Old syntax (${{{{) count: {old_syntax_count}")
    print(f"  New syntax (${{stats.) count: {new_syntax_count}")
    
    # Check specific examples
    if '"`+${{stats.week_count}}`"' in html_content:
        print("  ❌ Found OLD syntax: `+${{stats.week_count}}`")
    if '"`+${stats.week_count}`"' in html_content:
        print("  ✅ Found NEW syntax: `+${stats.week_count}`")


if __name__ == "__main__":
    asyncio.run(check_function_definition())