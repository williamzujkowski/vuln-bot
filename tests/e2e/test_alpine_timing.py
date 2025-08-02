#!/usr/bin/env python3
"""Test Alpine.js timing and initialization."""

import asyncio
import pytest

try:
    from playwright.async_api import async_playwright
except ImportError:
    pytest.skip("Playwright not installed", allow_module_level=True)


async def test_alpine_timing():
    """Test Alpine.js timing issues."""
    print("🔍 Testing Alpine.js timing...")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        context = await browser.new_context()
        page = await context.new_page()

        # Capture console messages
        console_messages = []
        page.on(
            "console",
            lambda msg: console_messages.append(
                {
                    "type": msg.type,
                    "text": msg.text,
                }
            ),
        )

        print("📡 Navigating to site...")
        await page.goto(
            "https://williamzujkowski.github.io/vuln-bot/", wait_until="networkidle"
        )

        # Wait for Alpine to initialize
        await page.wait_for_timeout(2000)

        # Check various states
        checks = await page.evaluate(
            """
            () => {
                // Force Alpine to re-evaluate if needed
                if (typeof Alpine !== 'undefined' && typeof window.dashboard !== 'undefined') {
                    // Try to get Alpine component
                    const bodyEl = document.querySelector('body[x-data]');
                    const alpineData = bodyEl ? Alpine.$data(bodyEl) : null;

                    return {
                        alpine_exists: typeof Alpine !== 'undefined',
                        window_dashboard_exists: typeof window.dashboard !== 'undefined',
                        body_has_x_data: !!bodyEl,
                        alpine_data_exists: !!alpineData,
                        alpine_data_has_stats: alpineData && 'stats' in alpineData,
                        vuln_data_exists: typeof vulnerabilityData !== 'undefined',
                        stats_data_exists: typeof statsData !== 'undefined',
                        vuln_data_length: typeof vulnerabilityData !== 'undefined' ? vulnerabilityData.length : 0
                    };
                }
                return {
                    alpine_exists: typeof Alpine !== 'undefined',
                    window_dashboard_exists: typeof window.dashboard !== 'undefined',
                    error: 'Alpine or dashboard not ready'
                };
            }
        """
        )

        print("\n📊 TIMING CHECK RESULTS:")
        for key, value in checks.items():
            print(f"  {key}: {value}")

        # Try to manually initialize Alpine component
        manual_init = await page.evaluate(
            """
            () => {
                try {
                    if (typeof window.dashboard === 'function' && typeof Alpine !== 'undefined') {
                        // Get the body element
                        const body = document.querySelector('body[x-data="dashboard()"]');
                        if (body) {
                            // Try to get the Alpine component
                            const component = Alpine.$data(body);
                            return {
                                success: true,
                                has_component: !!component,
                                component_keys: component ? Object.keys(component).slice(0, 10) : []
                            };
                        }
                    }
                    return { success: false, reason: 'Prerequisites not met' };
                } catch (e) {
                    return { success: false, error: e.toString() };
                }
            }
        """
        )

        print("\n📊 MANUAL INIT ATTEMPT:")
        print(f"  Result: {manual_init}")

        print("\n📊 ALPINE ERRORS (first 5):")
        alpine_errors = [
            msg for msg in console_messages if "Alpine Expression Error" in msg["text"]
        ][:5]
        for err in alpine_errors:
            print(f"  {err['text']}")

        await browser.close()


if __name__ == "__main__":
    asyncio.run(test_alpine_timing())
