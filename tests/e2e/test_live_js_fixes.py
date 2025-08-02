#!/usr/bin/env python3
"""Test the live site after JavaScript brace fixes."""

import asyncio

from playwright.async_api import async_playwright


async def test_live_js_fixes():
    """Test live site for JavaScript errors after fixes."""
    print("🔍 Testing live site after JavaScript fixes...")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
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

        print("📡 Navigating to live site...")
        await page.goto(
            "https://williamzujkowski.github.io/vuln-bot/", wait_until="networkidle"
        )

        # Wait for Alpine.js to initialize
        await page.wait_for_timeout(3000)

        # Check for Alpine.js initialization
        alpine_check = await page.evaluate(
            """
            () => {
                return {
                    alpine_exists: typeof Alpine !== 'undefined',
                    dashboard_exists: typeof window.dashboard !== 'undefined',
                    dashboard_type: typeof window.dashboard,
                    body_has_x_data: !!document.querySelector('body[x-data]'),
                    // Try to access Alpine component
                    component_accessible: (() => {
                        try {
                            const body = document.querySelector('body[x-data="dashboard()"]');
                            if (body && typeof Alpine !== 'undefined') {
                                const component = Alpine.$data(body);
                                return !!component;
                            }
                            return false;
                        } catch (e) {
                            return false;
                        }
                    })()
                };
            }
        """
        )

        print("\n✅ Alpine.js Status:")
        for key, value in alpine_check.items():
            print(f"  {key}: {value}")

        # Check for JavaScript errors
        js_errors = [msg for msg in console_messages if msg["type"] == "error"]

        if js_errors:
            print("\n❌ JavaScript Errors Found:")
            for err in js_errors[:5]:  # Show first 5 errors
                print(f"  {err['text']}")
                if err["location"]:
                    print(
                        f"    at {err['location']['url']}:{err['location']['lineNumber']}"
                    )
        else:
            print("\n✅ No JavaScript errors detected!")

        # Test dashboard functionality
        print("\n🧪 Testing Dashboard Functionality:")

        # Check if vulnerability data is loaded
        vuln_count = await page.evaluate(
            """
            () => {
                try {
                    const body = document.querySelector('body[x-data="dashboard()"]');
                    if (body && typeof Alpine !== 'undefined') {
                        const component = Alpine.$data(body);
                        return component && component.vulnerabilities ? component.vulnerabilities.length : 0;
                    }
                    return 0;
                } catch (e) {
                    return -1;
                }
            }
        """
        )
        print(f"  Vulnerabilities loaded: {vuln_count}")

        # Check if table has rows
        table_rows = await page.query_selector_all("tbody tr")
        print(f"  Table rows visible: {len(table_rows)}")

        # Test search functionality
        search_input = await page.query_selector(".search-input")
        if search_input:
            await search_input.type("CVE-2024")
            await page.wait_for_timeout(1000)
            filtered_rows = await page.query_selector_all("tbody tr")
            print(f"  Search working: {len(filtered_rows)} rows after filtering")
        else:
            print("  ❌ Search input not found")

        # Test quick filter buttons
        critical_button = await page.query_selector('button:has-text("Critical")')
        if critical_button:
            await critical_button.click()
            await page.wait_for_timeout(1000)
            critical_rows = await page.query_selector_all("tbody tr")
            print(f"  Quick filters working: {len(critical_rows)} critical vulns")
        else:
            print("  ❌ Critical filter button not found")

        # Check if charts are rendered
        charts_found = await page.evaluate(
            """
            () => {
                const canvases = document.querySelectorAll('canvas');
                return canvases.length;
            }
        """
        )
        print(f"  Charts rendered: {charts_found} charts found")

        # Take a screenshot for visual confirmation
        await page.screenshot(path="tests/e2e/live_site_fixed.png", full_page=False)
        print("\n📸 Screenshot saved to: tests/e2e/live_site_fixed.png")

        await browser.close()

        # Summary
        success = len(js_errors) == 0 and vuln_count > 0 and len(table_rows) > 0

        if success:
            print("\n✅ Live site is working correctly after JavaScript fixes!")
        else:
            print("\n⚠️  Some issues remain on the live site")

        return success


if __name__ == "__main__":
    success = asyncio.run(test_live_js_fixes())
    exit(0 if success else 1)
