#!/usr/bin/env python3
"""Check what version is deployed on GitHub Pages."""

import asyncio

from playwright.async_api import async_playwright


async def check_deployed_version():
    """Check the deployed version of the site."""
    print("🔍 Checking deployed version...")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        print("📡 Navigating to site...")
        await page.goto("https://williamzujkowski.github.io/vuln-bot/", wait_until="networkidle")

        # Check if window.dashboard is defined
        dashboard_check = await page.evaluate("""
            () => {
                return {
                    window_dashboard_exists: typeof window.dashboard !== 'undefined',
                    dashboard_exists: typeof dashboard !== 'undefined',
                    alpine_exists: typeof Alpine !== 'undefined',
                    script_content_sample: document.querySelector('script:not([src])')?.textContent?.substring(0, 200)
                }
            }
        """)

        print("\n📊 DEPLOYMENT CHECK:")
        print(f"  window.dashboard exists: {dashboard_check['window_dashboard_exists']}")
        print(f"  dashboard exists: {dashboard_check['dashboard_exists']}")
        print(f"  Alpine exists: {dashboard_check['alpine_exists']}")
        print(f"\n  Script sample: {dashboard_check['script_content_sample']}")

        # Check for our specific fixes
        html_content = await page.content()

        print("\n🔍 CHECKING FOR FIXES:")
        print(f"  Contains 'window.dashboard': {'window.dashboard' in html_content}")
        print(f"  Contains old syntax: {'${{' in html_content}")
        print(f"  Contains fixed syntax: {'${stats.' in html_content}")

        await browser.close()


if __name__ == "__main__":
    asyncio.run(check_deployed_version())
