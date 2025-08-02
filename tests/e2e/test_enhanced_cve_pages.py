#!/usr/bin/env python3
"""Test enhanced CVE detail pages with Playwright."""

import asyncio
from pathlib import Path

from playwright.async_api import async_playwright


async def test_enhanced_cve_pages():
    """Test the enhanced CVE detail pages."""
    print("🔍 Testing enhanced CVE detail pages...")

    # First, let's check if any pages were generated
    cve_dir = Path("src/cves")
    if not cve_dir.exists():
        print("❌ CVE directory not found. Run page generation first.")
        return False

    # Find some generated CVE pages
    cve_files = list(cve_dir.glob("CVE-*.md"))[:5]  # Test first 5
    if not cve_files:
        print("❌ No CVE pages found. Run page generation first.")
        return False

    print(f"📁 Found {len(list(cve_dir.glob('CVE-*.md')))} CVE pages")
    print(f"🧪 Testing {len(cve_files)} sample pages...")

    success_count = 0

    for cve_file in cve_files:
        print(f"\n📄 Testing {cve_file.name}...")

        # Read the content
        content = cve_file.read_text()

        # Check for required sections
        checks = {
            "Frontmatter": "---" in content and content.count("---") >= 2,
            "CVE ID": "cve_id:" in content,
            "Metadata section": "## Metadata" in content,
            "Problem Types": "## Problem Types" in content
            or "### Common Weakness Enumeration" in content,
            "Description": "## Overview" in content or "### Description" in content,
            "Technical Details": "## Technical Details" in content,
            "Affected Systems": "### Affected Systems" in content
            or "### Affected Products" in content,
            "References": "## References" in content,
            "Timeline": "## Timeline" in content,
            "Impacted Projects": "## Impacted Projects" in content
            or "impact_summary" in content,
            "CVSS Metrics": "### CVSS" in content or "cvss_score:" in content,
            "State info": "state:" in content or "assigner_org_id:" in content,
        }

        all_passed = True
        for check_name, check_result in checks.items():
            status = "✅" if check_result else "❌"
            print(f"  {status} {check_name}: {'found' if check_result else 'missing'}")
            if not check_result:
                all_passed = False

        # Check enrichment data
        if "enrichment:" in content or "deps_dev:" in content:
            print("  ✅ Enrichment data: found")
        else:
            print("  ⚠️  Enrichment data: not found (API might be unavailable)")

        # Check for schema validation markers
        if "validated_at:" in content or "schema_version:" in content:
            print("  ✅ Schema validation: performed")
        else:
            print("  ⚠️  Schema validation: not found")

        if all_passed:
            success_count += 1

    print(f"\n📊 Summary: {success_count}/{len(cve_files)} pages passed all checks")

    # Now test with Playwright if we have an 11ty build
    if Path("public/cves").exists():
        print("\n🌐 Testing built HTML pages with Playwright...")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            # Test one built page
            test_cve = cve_files[0].stem  # Get CVE ID without .md
            test_url = f"file://{Path.cwd()}/public/cves/{test_cve}/index.html"

            print(f"📡 Loading {test_url}...")

            try:
                await page.goto(test_url, wait_until="networkidle")

                # Check for key elements
                element_checks = {
                    "CVE title": await page.query_selector("h1"),
                    "Metadata grid": await page.query_selector(".metadata-grid"),
                    "Severity badge": await page.query_selector(".severity-badge"),
                    "CVSS score": await page.query_selector("[data-cvss-score]"),
                    "Description": await page.query_selector(".description"),
                    "References section": await page.query_selector(
                        ".references-section"
                    ),
                    "Impacted projects": await page.query_selector(
                        ".impacted-projects"
                    ),
                }

                for element_name, element in element_checks.items():
                    status = "✅" if element else "❌"
                    print(
                        f"  {status} {element_name}: {'present' if element else 'missing'}"
                    )

                # Check for JavaScript errors
                console_errors = []
                page.on(
                    "console",
                    lambda msg: (
                        console_errors.append(msg) if msg.type == "error" else None
                    ),
                )
                await page.wait_for_timeout(1000)

                if console_errors:
                    print(f"  ❌ JavaScript errors: {len(console_errors)}")
                else:
                    print("  ✅ No JavaScript errors")

                # Take a screenshot for visual verification
                await page.screenshot(path="tests/e2e/enhanced_cve_page.png")
                print("  📸 Screenshot saved: enhanced_cve_page.png")

            except Exception as e:
                print(f"  ❌ Error loading page: {e}")
                print("  ℹ️  HTML pages might not be built yet. Run 11ty build.")

            await browser.close()

    return success_count == len(cve_files)


async def test_enrichment_data():
    """Test if enrichment data is being added to pages."""
    print("\n🔍 Testing enrichment data...")

    # Look for a page with enrichment data
    cve_dir = Path("src/cves")
    enriched_count = 0
    deps_dev_count = 0
    cwe_count = 0

    for cve_file in list(cve_dir.glob("CVE-*.md"))[:20]:  # Check first 20
        content = cve_file.read_text()

        if "enrichment:" in content or "enrichment_timestamp:" in content:
            enriched_count += 1

            if "deps_dev:" in content or "affected_packages:" in content:
                deps_dev_count += 1

            if "problem_types:" in content or "CWE-" in content:
                cwe_count += 1

    print(f"  📊 Enriched pages: {enriched_count}/20")
    print(f"  📦 Pages with deps.dev data: {deps_dev_count}/20")
    print(f"  🔒 Pages with CWE data: {cwe_count}/20")

    return enriched_count > 0


if __name__ == "__main__":

    async def run_all_tests():
        """Run all tests."""
        print("🚀 Running enhanced CVE page tests...\n")

        # Test generated markdown files
        markdown_test = await test_enhanced_cve_pages()

        # Test enrichment data
        enrichment_test = await test_enrichment_data()

        print("\n✅ All tests completed!")
        return markdown_test and enrichment_test

    success = asyncio.run(run_all_tests())
    exit(0 if success else 1)
