#!/usr/bin/env python3
"""Test for timing issues with Alpine.js and dashboard function."""

import asyncio

from playwright.async_api import async_playwright


async def test_timing_issue():
    """Test timing of dashboard function and Alpine initialization."""
    print("🔍 Testing timing issue...")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        context = await browser.new_context()
        page = await context.new_page()

        # Add script to monitor when things are defined
        await page.add_init_script("""
            window.timingLog = [];

            // Monitor when Alpine is defined
            Object.defineProperty(window, 'Alpine', {
                get: function() { return this._Alpine; },
                set: function(val) {
                    window.timingLog.push({
                        event: 'Alpine defined',
                        time: Date.now(),
                        dashboardExists: typeof window.dashboard !== 'undefined'
                    });
                    this._Alpine = val;
                }
            });

            // Monitor when dashboard is defined
            Object.defineProperty(window, 'dashboard', {
                get: function() { return this._dashboard; },
                set: function(val) {
                    window.timingLog.push({
                        event: 'dashboard defined',
                        time: Date.now(),
                        alpineExists: typeof window.Alpine !== 'undefined'
                    });
                    this._dashboard = val;
                }
            });
        """)

        print("📡 Navigating to live site...")
        await page.goto("https://williamzujkowski.github.io/vuln-bot/")

        # Wait a bit
        await page.wait_for_timeout(3000)

        # Get timing log
        timing_log = await page.evaluate("() => window.timingLog")

        print("\n📊 Timing Log:")
        for entry in timing_log:
            print(f"  {entry['event']} - Alpine exists: {entry.get('alpineExists', 'N/A')}, Dashboard exists: {entry.get('dashboardExists', 'N/A')}")

        # Check current state
        state = await page.evaluate("""
            () => {
                return {
                    alpine: typeof window.Alpine,
                    dashboard: typeof window.dashboard,
                    _alpine: typeof window._Alpine,
                    _dashboard: typeof window._dashboard,
                    bodyXData: document.querySelector('body[x-data]')?.getAttribute('x-data'),
                    vulnerabilityDataDefined: typeof vulnerabilityData !== 'undefined',
                    statsDataDefined: typeof statsData !== 'undefined'
                };
            }
        """)

        print("\n📊 Current State:")
        for key, value in state.items():
            print(f"  {key}: {value}")

        # Try to manually initialize
        manual_init = await page.evaluate("""
            () => {
                try {
                    // Check if data is available
                    if (typeof vulnerabilityData === 'undefined') {
                        return { error: 'vulnerabilityData not defined' };
                    }

                    // Try to create dashboard function if it doesn't exist
                    if (typeof window.dashboard === 'undefined') {
                        window.dashboard = function() {
                            return {
                                vulnerabilities: vulnerabilityData,
                                stats: statsData,
                                // ... rest of the dashboard object
                                quickFilter: 'all',
                                search: ''
                            };
                        };
                        return { success: 'dashboard function created manually' };
                    }

                    return { info: 'dashboard already exists' };
                } catch (e) {
                    return { error: e.toString() };
                }
            }
        """)

        print(f"\n📊 Manual Init Result: {manual_init}")

        await browser.close()


if __name__ == "__main__":
    asyncio.run(test_timing_issue())
