#!/usr/bin/env python3
"""Test the locally generated dashboard for JavaScript errors."""

import asyncio
from pathlib import Path

from playwright.async_api import async_playwright


async def test_local_dashboard():
    """Test local dashboard for JavaScript errors."""
    print("🔍 Testing local dashboard...")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        context = await browser.new_context()
        page = await context.new_page()

        # Capture console messages and errors
        console_messages = []
        page.on(
            "console",
            lambda msg: console_messages.append(
                {"type": msg.type, "text": msg.text, "location": msg.location}
            ),
        )

        # Get the absolute path to the local HTML file
        html_path = Path.cwd() / "public" / "index.html"
        print(f"📁 Loading: {html_path}")

        # Navigate to local file
        await page.goto(f"file://{html_path}")

        # Wait for Alpine.js to initialize
        await page.wait_for_timeout(2000)

        # Check for Alpine.js initialization
        alpine_check = await page.evaluate(
            """
            () => {
                return {
                    alpine_exists: typeof Alpine !== 'undefined',
                    dashboard_exists: typeof window.dashboard !== 'undefined',
                    dashboard_type: typeof window.dashboard,
                    body_has_x_data: !!document.querySelector('body[x-data]')
                };
            }
        """
        )

        print("\n✅ Alpine.js Check:")
        for key, value in alpine_check.items():
            print(f"  {key}: {value}")

        # Get Alpine component data
        component_check = await page.evaluate(
            """
            () => {
                try {
                    const body = document.querySelector('body[x-data="dashboard()"]');
                    if (body && typeof Alpine !== 'undefined') {
                        const component = Alpine.$data(body);
                        return {
                            has_component: !!component,
                            has_stats: component && 'stats' in component,
                            has_vulnerabilities: component && 'vulnerabilities' in component,
                            vuln_count: component && component.vulnerabilities ? component.vulnerabilities.length : 0,
                            stats_total: component && component.stats ? component.stats.total : 0
                        };
                    }
                    return { error: 'Could not get Alpine component' };
                } catch (e) {
                    return { error: e.toString() };
                }
            }
        """
        )

        print("\n✅ Component Check:")
        for key, value in component_check.items():
            print(f"  {key}: {value}")

        # Check for JavaScript errors
        js_errors = [msg for msg in console_messages if msg["type"] == "error"]

        if js_errors:
            print("\n❌ JavaScript Errors:")
            for err in js_errors[:5]:  # Show first 5 errors
                print(f"  {err['text']}")
                if err["location"]:
                    print(
                        f"    at {err['location']['url']}:{err['location']['lineNumber']}"
                    )
        else:
            print("\n✅ No JavaScript errors detected!")

        # Test basic functionality
        print("\n🧪 Testing Basic Functionality:")

        # Test search
        search_input = await page.query_selector(".search-input")
        if search_input:
            await search_input.type("CVE-2024")
            await page.wait_for_timeout(500)
            print("  ✅ Search input working")
        else:
            print("  ❌ Search input not found")

        # Test quick filter
        critical_filter = await page.query_selector('button:has-text("Critical")')
        if critical_filter:
            await critical_filter.click()
            await page.wait_for_timeout(500)
            print("  ✅ Quick filters working")
        else:
            print("  ❌ Critical filter button not found")

        # Check if table has data
        table_rows = await page.query_selector_all("tbody tr")
        print(f"  ✅ Table has {len(table_rows)} rows")

        await browser.close()

        print("\n✅ Local dashboard test completed!")
        return len(js_errors) == 0


if __name__ == "__main__":
    success = asyncio.run(test_local_dashboard())
    exit(0 if success else 1)
