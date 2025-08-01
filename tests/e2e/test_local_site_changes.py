#!/usr/bin/env python3
"""Test local changes to the site."""

import asyncio
from playwright.async_api import async_playwright


async def test_local_changes():
    """Verify our template changes work locally."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        context = await browser.new_context()
        page = await context.new_page()
        
        try:
            print("🌐 Testing local changes by serving the src directory...")
            
            # Navigate to the index template directly
            await page.goto(f"file://{'/home/william/git/vuln-bot/src/index.njk'}")
            
            # Take a screenshot
            await page.screenshot(path="local-test-screenshot.png")
            print("📸 Screenshot saved to local-test-screenshot.png")
            
            # Check if the table exists
            table = await page.query_selector("#vulnerability-table")
            if table:
                print("✅ Found vulnerability table with ID")
            else:
                print("❌ Vulnerability table not found")
            
            # Check for product column header
            headers = await page.query_selector_all("table th")
            header_texts = []
            for header in headers:
                text = await header.inner_text()
                header_texts.append(text)
            
            print(f"\n📊 Table headers: {header_texts}")
            
            if "Product" in header_texts:
                print("✅ Product column header found")
            else:
                print("❌ Product column header not found")
                
        except Exception as e:
            print(f"❌ Error: {e}")
        finally:
            await browser.close()


if __name__ == "__main__":
    asyncio.run(test_local_changes())