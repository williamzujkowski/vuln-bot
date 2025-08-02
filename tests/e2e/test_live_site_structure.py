#!/usr/bin/env python3
"""Test to understand the current structure of the live site."""

import asyncio
import pytest

try:
    from playwright.async_api import async_playwright
except ImportError:
    playwright = None
    pytest.skip("Playwright not installed", allow_module_level=True)


async def analyze_live_site():
    """Analyze the structure of the live website."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        context = await browser.new_context()
        page = await context.new_page()

        try:
            print("🌐 Analyzing live website structure...")
            await page.goto(
                "https://williamzujkowski.github.io/vuln-bot/", wait_until="networkidle"
            )

            # Take a screenshot
            await page.screenshot(path="live-site-current.png")
            print("📸 Screenshot saved to live-site-current.png")

            # Check what elements exist
            print("\n🔍 Checking for common elements:")

            elements_to_check = [
                ("Header", "header, .header, .dashboard-header, .site-header"),
                ("Table", "table, #vulnerability-table, .data-table, .vuln-table"),
                (
                    "Search",
                    "input[type='search'], input[placeholder*='search' i], .search-input",
                ),
                ("Filters", ".filters, .filter-section, select"),
                ("Results count", ".results-count, .results-info"),
                ("Alpine component", "[x-data]"),
            ]

            for name, selector in elements_to_check:
                count = await page.locator(selector).count()
                if count > 0:
                    print(f"  ✅ {name}: Found {count} element(s)")
                    # Get first matching element info
                    first = page.locator(selector).first
                    tag = await first.evaluate("el => el.tagName")
                    classes = await first.evaluate("el => el.className")
                    print(f"     First match: <{tag.lower()} class='{classes}'>")
                else:
                    print(f"  ❌ {name}: Not found")

            # Check page title
            title = await page.title()
            print(f"\n📄 Page title: {title}")

            # Check for JavaScript data
            print("\n💾 Checking JavaScript data:")
            js_data = await page.evaluate(
                """
                () => {
                    const result = {};
                    // Check for common data variables
                    const dataVars = [
                        'vulnerabilityData',
                        'vulnData',
                        'vulnerabilities',
                        'data',
                        'Alpine',
                        'Alpine.store'
                    ];

                    dataVars.forEach(varName => {
                        try {
                            const value = eval(`window.${varName}`);
                            if (value !== undefined) {
                                result[varName] = {
                                    exists: true,
                                    type: typeof value,
                                    isArray: Array.isArray(value),
                                    length: Array.isArray(value) ? value.length : null
                                };
                            }
                        } catch (e) {
                            // Variable doesn't exist
                        }
                    });

                    // Check Alpine components
                    const alpineComponents = document.querySelectorAll('[x-data]');
                    result.alpineComponents = alpineComponents.length;

                    return result;
                }
            """
            )

            for key, value in js_data.items():
                if key == "alpineComponents":
                    print(f"  Alpine components found: {value}")
                elif isinstance(value, dict) and value.get("exists"):
                    print(f"  ✅ window.{key}: {value['type']}")
                    if value["isArray"]:
                        print(f"     Array length: {value['length']}")

            # Get page content structure
            print("\n📋 Page structure:")
            structure = await page.evaluate(
                """
                () => {
                    const getStructure = (el, depth = 0) => {
                        if (depth > 3) return [];
                        const result = [];
                        const children = el.children;
                        for (let child of children) {
                            const tag = child.tagName.toLowerCase();
                            const id = child.id ? `#${child.id}` : '';
                            const classes = child.className ? `.${child.className.split(' ').join('.')}` : '';
                            result.push({
                                selector: `${tag}${id}${classes}`,
                                depth: depth,
                                childCount: child.children.length
                            });
                            if (child.children.length > 0 && depth < 3) {
                                result.push(...getStructure(child, depth + 1));
                            }
                        }
                        return result;
                    };
                    return getStructure(document.body);
                }
            """
            )

            # Print main structure elements
            main_elements = [
                s for s in structure if s["depth"] <= 1 and s["childCount"] > 0
            ]
            for elem in main_elements[:10]:
                indent = "  " * elem["depth"]
                print(f"{indent}{elem['selector']} ({elem['childCount']} children)")

            # Wait a bit to see if data loads
            print("\n⏳ Waiting for data to load...")
            await page.wait_for_timeout(5000)

            # Check again for data
            data_loaded = await page.evaluate(
                """
                () => {
                    const data = window.vulnerabilityData || window.vulnData || [];
                    return {
                        loaded: data.length > 0,
                        count: data.length,
                        sample: data.length > 0 ? data[0] : null
                    };
                }
            """
            )

            if data_loaded["loaded"]:
                print(f"✅ Data loaded: {data_loaded['count']} vulnerabilities")
                if data_loaded["sample"]:
                    print("\n📊 Sample data structure:")
                    sample = data_loaded["sample"]
                    for key in list(sample.keys())[:10]:
                        print(f"  - {key}: {type(sample.get(key)).__name__}")
            else:
                print("❌ No vulnerability data loaded")

        except Exception as e:
            print(f"❌ Error: {e}")
        finally:
            await browser.close()


if __name__ == "__main__":
    asyncio.run(analyze_live_site())
