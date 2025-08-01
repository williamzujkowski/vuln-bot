#!/usr/bin/env python3
"""Verify that the product column on the live site shows only product names."""

import asyncio
from playwright.async_api import async_playwright


async def verify_product_column():
    """Check if product column displays only product names (not vendor/product)."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        
        try:
            print("📡 Navigating to live site...")
            await page.goto("https://williamzujkowski.github.io/vuln-bot/", wait_until="networkidle")
            
            # Wait for Alpine component to load
            await page.wait_for_function("() => window.vulnerabilityData && window.vulnerabilityData.length > 0", timeout=30000)
            
            # Get product column values from data
            product_values = await page.evaluate("""
                () => {
                    // Get the vulnerability data
                    const data = window.vulnerabilityData;
                    if (!data || data.length === 0) return [];
                    
                    // Get first 10 products
                    const products = [];
                    for (let i = 0; i < Math.min(10, data.length); i++) {
                        const vuln = data[i];
                        // Check both possible fields
                        const product = vuln.products || vuln.Products || vuln.product || 'Unknown';
                        products.push(product);
                    }
                    return products;
                }
            """)
            
            print(f"\n🔍 Checking first {len(product_values)} product values:")
            
            has_vendor_product = False
            for i, product in enumerate(product_values):
                # Check if it contains a slash (vendor/product pattern)
                if '/' in product:
                    print(f"  ❌ Row {i+1}: '{product}' (contains vendor/product)")
                    has_vendor_product = True
                else:
                    print(f"  ✅ Row {i+1}: '{product}' (product name only)")
            
            if has_vendor_product:
                print("\n❌ Product column still contains vendor/product format")
                return False
            else:
                print("\n✅ Product column correctly shows only product names!")
                return True
                
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
        finally:
            await browser.close()


if __name__ == "__main__":
    success = asyncio.run(verify_product_column())
    exit(0 if success else 1)