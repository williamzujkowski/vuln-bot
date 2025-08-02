#!/usr/bin/env python3
"""Debug script to check JavaScript errors and data loading on live site."""

import asyncio
import json
import pytest

try:
    from playwright.async_api import async_playwright
except ImportError:
    playwright = None
    pytest.skip("Playwright not installed", allow_module_level=True)


async def debug_live_site():
    """Debug the live vuln-bot site."""
    print("🔍 Debugging live site...")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        context = await browser.new_context()
        page = await context.new_page()

        # Capture console messages
        console_messages = []
        page.on(
            "console",
            lambda msg: console_messages.append(
                {"type": msg.type, "text": msg.text, "location": msg.location}
            ),
        )

        # Capture network requests
        network_requests = []
        page.on(
            "request",
            lambda req: network_requests.append(
                {
                    "url": req.url,
                    "method": req.method,
                    "resource_type": req.resource_type,
                }
            ),
        )

        # Capture network responses
        network_responses = []
        page.on(
            "response",
            lambda res: network_responses.append(
                {"url": res.url, "status": res.status, "ok": res.ok}
            ),
        )

        print("📡 Navigating to site...")
        await page.goto(
            "https://williamzujkowski.github.io/vuln-bot/", wait_until="networkidle"
        )

        # Wait a bit for JavaScript to execute
        await page.wait_for_timeout(3000)

        # Check Alpine.js initialization
        alpine_initialized = await page.evaluate(
            """
            () => {
                return {
                    alpine_exists: typeof Alpine !== 'undefined',
                    alpine_version: typeof Alpine !== 'undefined' ? Alpine.version : null,
                    alpine_started: typeof Alpine !== 'undefined' ? Alpine.started : false
                }
            }
        """
        )

        # Check for vulnerability data
        data_check = await page.evaluate(
            """
            () => {
                const results = {
                    vulnerability_data_exists: typeof vulnerabilityData !== 'undefined',
                    stats_data_exists: typeof statsData !== 'undefined',
                    vulnerability_count: 0,
                    stats: null
                };

                if (typeof vulnerabilityData !== 'undefined') {
                    results.vulnerability_count = vulnerabilityData.length || 0;
                    results.sample_vuln = vulnerabilityData[0] || null;
                }

                if (typeof statsData !== 'undefined') {
                    results.stats = statsData;
                }

                return results;
            }
        """
        )

        # Check element visibility
        visibility_check = await page.evaluate(
            """
            () => {
                const checks = {};

                // Search input
                const searchInput = document.querySelector('.search-input');
                if (searchInput) {
                    const styles = window.getComputedStyle(searchInput);
                    checks.search_input = {
                        exists: true,
                        display: styles.display,
                        visibility: styles.visibility,
                        opacity: styles.opacity,
                        parent_display: searchInput.parentElement ? window.getComputedStyle(searchInput.parentElement).display : null
                    };
                }

                // Filters section
                const filtersSection = document.querySelector('.filters-section');
                if (filtersSection) {
                    const styles = window.getComputedStyle(filtersSection);
                    checks.filters_section = {
                        exists: true,
                        display: styles.display,
                        visibility: styles.visibility
                    };
                }

                // Table
                const table = document.querySelector('table');
                if (table) {
                    checks.table = {
                        exists: true,
                        row_count: table.querySelectorAll('tbody tr').length
                    };
                }

                return checks;
            }
        """
        )

        # Print results
        print("\n📊 CONSOLE MESSAGES:")
        for msg in console_messages:
            if msg["type"] in ["error", "warning"]:
                print(f"  {msg['type'].upper()}: {msg['text']}")

        print("\n🌐 NETWORK ISSUES:")
        failed_requests = [r for r in network_responses if not r["ok"]]
        for req in failed_requests:
            print(f"  ❌ {req['status']} - {req['url']}")

        print("\n🎯 ALPINE.JS STATUS:")
        print(f"  Exists: {alpine_initialized['alpine_exists']}")
        print(f"  Version: {alpine_initialized['alpine_version']}")
        print(f"  Started: {alpine_initialized['alpine_started']}")

        print("\n📦 DATA STATUS:")
        print(f"  Vulnerability data exists: {data_check['vulnerability_data_exists']}")
        print(f"  Stats data exists: {data_check['stats_data_exists']}")
        print(f"  Vulnerability count: {data_check['vulnerability_count']}")

        print("\n👁️ VISIBILITY STATUS:")
        print(json.dumps(visibility_check, indent=2))

        # Take screenshot
        await page.screenshot(path="debug_screenshot.png", full_page=True)
        print("\n📸 Screenshot saved as debug_screenshot.png")

        await browser.close()


if __name__ == "__main__":
    asyncio.run(debug_live_site())
