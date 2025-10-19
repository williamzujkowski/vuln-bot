#!/usr/bin/env python3
"""
Comprehensive E2E validation of the vuln-bot platform.
Tests EPSS threshold enforcement, deps.dev links, CVE pages, and UX functionality.
"""

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any, Dict

try:
    from playwright.async_api import Page, async_playwright
except ImportError:
    playwright = None
    import pytest
    pytest.skip("Playwright not installed", allow_module_level=True)


class VulnBotE2EValidator:
    """Comprehensive E2E validator for vuln-bot platform."""

    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.test_results = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "base_url": base_url,
            "tests": {},
            "overall_passed": True,
            "screenshots": []
        }

    async def validate_epss_threshold_enforcement(self, page: Page) -> Dict[str, Any]:
        """Validate that no CVEs below 60% EPSS are displayed."""
        results = {
            "passed": True,
            "violations": [],
            "total_cves_checked": 0,
            "min_epss_found": None,
            "max_epss_found": None
        }

        try:
            await page.goto(self.base_url)
            await page.wait_for_load_state("networkidle")

            # Wait for vulnerability table to load
            await page.wait_for_selector("tbody tr", timeout=10000)

            # Get all vulnerability rows
            rows = await page.locator("tbody tr").all()
            epss_scores = []

            for row in rows:
                row_text = await row.text_content()

                # Extract EPSS score (format: "XX.X%")
                epss_matches = re.findall(r'(\d{1,2}(?:\.\d+)?%)', row_text)
                cve_match = re.search(r'CVE-\d{4}-\d+', row_text)

                if epss_matches and cve_match:
                    epss_value = float(epss_matches[0].replace('%', ''))
                    epss_scores.append(epss_value)

                    if epss_value < 60:
                        results["violations"].append({
                            "cve_id": cve_match.group(0),
                            "epss_score": epss_value,
                            "violation": f"EPSS {epss_value}% < 60%"
                        })

                results["total_cves_checked"] += 1

            if epss_scores:
                results["min_epss_found"] = min(epss_scores)
                results["max_epss_found"] = max(epss_scores)

            results["passed"] = len(results["violations"]) == 0

        except Exception as e:
            results["passed"] = False
            results["error"] = str(e)

        return results

    async def validate_cve_static_pages(self, page: Page) -> Dict[str, Any]:
        """Validate that CVE static pages load correctly with all data."""
        results = {
            "passed": True,
            "pages_tested": 0,
            "pages_failed": [],
            "missing_data": []
        }

        try:
            # Go to main page and get a few CVE links
            await page.goto(self.base_url)
            await page.wait_for_load_state("networkidle")

            # Get first 5 CVE links to test
            cve_links = await page.locator('a[href*="/cves/CVE-"]').all()
            test_links = cve_links[:5] if len(cve_links) > 5 else cve_links

            for link in test_links:
                href = await link.get_attribute("href")
                cve_id = re.search(r'CVE-\d{4}-\d+', href)

                if cve_id:
                    cve_id = cve_id.group(0)
                    cve_url = f"{self.base_url}/cves/{cve_id}/"

                    # Navigate to CVE page
                    response = await page.goto(cve_url)

                    if response.status != 200:
                        results["pages_failed"].append({
                            "cve_id": cve_id,
                            "status": response.status,
                            "url": cve_url
                        })
                    else:
                        # Check for required elements
                        missing = []

                        # Check for CVE title
                        if not await page.locator(f'h1:has-text("{cve_id}")').count():
                            missing.append("CVE title")

                        # Check for severity badge
                        if not await page.locator('.badge, .severity').count():
                            missing.append("Severity badge")

                        # Check for EPSS score
                        if not await page.locator('text=/EPSS.*\\d+/i').count():
                            missing.append("EPSS score")

                        # Check for description
                        if not await page.locator('.description, p').count():
                            missing.append("Description")

                        # Check for references section
                        if not await page.locator('h2:has-text("References"), h3:has-text("References")').count():
                            missing.append("References section")

                        if missing:
                            results["missing_data"].append({
                                "cve_id": cve_id,
                                "missing_elements": missing
                            })

                    results["pages_tested"] += 1

            results["passed"] = len(results["pages_failed"]) == 0 and len(results["missing_data"]) == 0

        except Exception as e:
            results["passed"] = False
            results["error"] = str(e)

        return results

    async def validate_deps_dev_links(self, page: Page) -> Dict[str, Any]:
        """Validate deps.dev links are present and functional."""
        results = {
            "passed": True,
            "cves_with_deps_links": 0,
            "broken_links": [],
            "missing_links": []
        }

        try:
            # Check a few CVE pages for deps.dev links
            await page.goto(self.base_url)
            await page.wait_for_load_state("networkidle")

            cve_links = await page.locator('a[href*="/cves/CVE-"]').all()
            test_links = cve_links[:3] if len(cve_links) > 3 else cve_links

            for link in test_links:
                href = await link.get_attribute("href")
                cve_id = re.search(r'CVE-\d{4}-\d+', href)

                if cve_id:
                    cve_id = cve_id.group(0)
                    cve_url = f"{self.base_url}/cves/{cve_id}/"

                    await page.goto(cve_url)
                    await page.wait_for_load_state("networkidle")

                    # Look for deps.dev links
                    deps_links = await page.locator('a[href*="deps.dev"]').all()

                    if deps_links:
                        results["cves_with_deps_links"] += 1

                        # Validate link format
                        for deps_link in deps_links:
                            link_href = await deps_link.get_attribute("href")

                            # Check if link follows deps.dev format
                            if not re.match(r'https://deps\.dev/\w+/[^/]+(/[^/]+)?', link_href):
                                results["broken_links"].append({
                                    "cve_id": cve_id,
                                    "link": link_href,
                                    "issue": "Invalid deps.dev URL format"
                                })

                            # Check for security attributes
                            rel = await deps_link.get_attribute("rel")
                            if not rel or "noopener" not in rel or "noreferrer" not in rel:
                                results["broken_links"].append({
                                    "cve_id": cve_id,
                                    "link": link_href,
                                    "issue": "Missing security attributes (rel='noopener noreferrer')"
                                })
                    else:
                        # Check if this CVE should have deps.dev data
                        page_text = await page.text_content("body")
                        if "package" in page_text.lower() or "npm" in page_text.lower() or "pip" in page_text.lower():
                            results["missing_links"].append({
                                "cve_id": cve_id,
                                "note": "CVE mentions packages but no deps.dev links found"
                            })

            results["passed"] = len(results["broken_links"]) == 0

        except Exception as e:
            results["passed"] = False
            results["error"] = str(e)

        return results

    async def validate_search_filter_performance(self, page: Page) -> Dict[str, Any]:
        """Test search and filter performance."""
        results = {
            "passed": True,
            "search_latency_ms": None,
            "filter_latency_ms": None,
            "issues": []
        }

        try:
            await page.goto(self.base_url)
            await page.wait_for_load_state("networkidle")

            # Test search performance
            search_input = page.locator('input[type="search"], input[placeholder*="Search" i]').first

            if await search_input.count():
                # Measure search latency
                start_time = time.time()
                await search_input.fill("CVE-2025")
                await page.wait_for_timeout(500)  # Wait for debounce
                search_time = (time.time() - start_time) * 1000

                results["search_latency_ms"] = search_time

                if search_time > 100:
                    results["issues"].append(f"Search latency {search_time:.0f}ms exceeds 100ms target")

            # Test filter performance
            epss_filter = page.locator('input[placeholder*="EPSS" i], input[id*="epss" i]').first

            if await epss_filter.count():
                start_time = time.time()
                await epss_filter.fill("80")
                await page.wait_for_timeout(300)  # Wait for filter
                filter_time = (time.time() - start_time) * 1000

                results["filter_latency_ms"] = filter_time

                if filter_time > 100:
                    results["issues"].append(f"Filter latency {filter_time:.0f}ms exceeds 100ms target")

            results["passed"] = len(results["issues"]) == 0

        except Exception as e:
            results["passed"] = False
            results["error"] = str(e)

        return results

    async def validate_mobile_ux(self, page: Page) -> Dict[str, Any]:
        """Validate mobile UX and responsiveness."""
        results = {
            "passed": True,
            "viewport_tests": [],
            "issues": []
        }

        viewports = [
            {"name": "iPhone 12", "width": 390, "height": 844},
            {"name": "iPad", "width": 768, "height": 1024},
            {"name": "Desktop", "width": 1920, "height": 1080}
        ]

        try:
            for viewport in viewports:
                await page.set_viewport_size(width=viewport["width"], height=viewport["height"])
                await page.goto(self.base_url)
                await page.wait_for_load_state("networkidle")

                viewport_result = {
                    "name": viewport["name"],
                    "width": viewport["width"],
                    "issues": []
                }

                # Check if table is scrollable on mobile
                if viewport["width"] < 768:
                    table = page.locator("table").first
                    if await table.count():
                        table_box = await table.bounding_box()
                        if table_box and table_box["width"] > viewport["width"]:
                            viewport_result["issues"].append("Table requires horizontal scrolling")

                # Check if filters are collapsible on mobile
                if viewport["width"] < 768:
                    filters = page.locator(".filters, [class*='filter']").first
                    if await filters.count() and await filters.is_visible():
                        # Check if filters take too much vertical space
                        filter_box = await filters.bounding_box()
                        if filter_box and filter_box["height"] > viewport["height"] * 0.5:
                            viewport_result["issues"].append("Filters occupy >50% of viewport height")

                # Take screenshot for manual review
                screenshot_path = f"screenshots/{viewport['name'].replace(' ', '_').lower()}_view.png"
                await page.screenshot(path=screenshot_path, full_page=False)
                self.test_results["screenshots"].append(screenshot_path)

                results["viewport_tests"].append(viewport_result)
                if viewport_result["issues"]:
                    results["issues"].extend(viewport_result["issues"])

            results["passed"] = len(results["issues"]) == 0

        except Exception as e:
            results["passed"] = False
            results["error"] = str(e)

        return results

    async def validate_reference_sections(self, page: Page) -> Dict[str, Any]:
        """Validate reference sections have proper categorization and links."""
        results = {
            "passed": True,
            "pages_checked": 0,
            "missing_categories": [],
            "broken_links": []
        }

        try:
            # Check a few CVE pages
            await page.goto(self.base_url)
            await page.wait_for_load_state("networkidle")

            cve_links = await page.locator('a[href*="/cves/CVE-"]').all()
            test_links = cve_links[:3] if len(cve_links) > 3 else cve_links

            for link in test_links:
                href = await link.get_attribute("href")
                cve_id = re.search(r'CVE-\d{4}-\d+', href)

                if cve_id:
                    cve_id = cve_id.group(0)
                    cve_url = f"{self.base_url}/cves/{cve_id}/"

                    await page.goto(cve_url)
                    await page.wait_for_load_state("networkidle")

                    # Look for references section
                    ref_section = page.locator('section:has(h2:text("References")), div:has(h3:text("References"))').first

                    if await ref_section.count():
                        # Check for categorized links
                        categories = ["Advisory", "Patch", "Exploit", "Technical"]
                        found_categories = []

                        for category in categories:
                            if await ref_section.locator(f'text=/{category}/i').count():
                                found_categories.append(category)

                        # Get all reference links
                        ref_links = await ref_section.locator("a[href]").all()

                        for ref_link in ref_links:
                            link_href = await ref_link.get_attribute("href")

                            # Validate link
                            if not link_href.startswith(("http://", "https://")):
                                results["broken_links"].append({
                                    "cve_id": cve_id,
                                    "link": link_href,
                                    "issue": "Invalid URL scheme"
                                })

                            # Check for security attributes
                            rel = await ref_link.get_attribute("rel")
                            target = await ref_link.get_attribute("target")

                            if not target or target != "_blank":
                                results["broken_links"].append({
                                    "cve_id": cve_id,
                                    "link": link_href,
                                    "issue": "Missing target='_blank'"
                                })

                            if not rel or "noopener" not in rel:
                                results["broken_links"].append({
                                    "cve_id": cve_id,
                                    "link": link_href,
                                    "issue": "Missing rel='noopener noreferrer'"
                                })

                        if not found_categories:
                            results["missing_categories"].append({
                                "cve_id": cve_id,
                                "note": "No reference categories found"
                            })

                    results["pages_checked"] += 1

            results["passed"] = len(results["broken_links"]) == 0 and len(results["missing_categories"]) == 0

        except Exception as e:
            results["passed"] = False
            results["error"] = str(e)

        return results

    async def run_all_validations(self) -> Dict[str, Any]:
        """Run all E2E validations."""
        print("🧪 Running Comprehensive E2E Validation Suite")
        print("=" * 60)

        # Create screenshots directory
        Path("screenshots").mkdir(exist_ok=True)

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            try:
                # 1. EPSS Threshold Enforcement
                print("\n📊 Validating EPSS Threshold Enforcement...")
                epss_results = await self.validate_epss_threshold_enforcement(page)
                self.test_results["tests"]["epss_threshold"] = epss_results

                if epss_results["passed"]:
                    print(f"✅ EPSS Threshold: All {epss_results['total_cves_checked']} CVEs ≥60%")
                    if epss_results.get('min_epss_found') is not None:
                        print(f"   Range: {epss_results['min_epss_found']:.1f}% - {epss_results['max_epss_found']:.1f}%")
                else:
                    print(f"❌ EPSS Threshold: {len(epss_results.get('violations', []))} violations found")
                    self.test_results["overall_passed"] = False

                # 2. CVE Static Pages
                print("\n📄 Validating CVE Static Pages...")
                cve_pages_results = await self.validate_cve_static_pages(page)
                self.test_results["tests"]["cve_pages"] = cve_pages_results

                if cve_pages_results["passed"]:
                    print(f"✅ CVE Pages: {cve_pages_results['pages_tested']} pages validated successfully")
                else:
                    print(f"❌ CVE Pages: {len(cve_pages_results['pages_failed'])} failed, "
                          f"{len(cve_pages_results['missing_data'])} missing data")
                    self.test_results["overall_passed"] = False

                # 3. Deps.dev Integration
                print("\n🔗 Validating Deps.dev Integration...")
                deps_results = await self.validate_deps_dev_links(page)
                self.test_results["tests"]["deps_dev"] = deps_results

                if deps_results["passed"]:
                    print(f"✅ Deps.dev: {deps_results['cves_with_deps_links']} CVEs have valid links")
                else:
                    print(f"❌ Deps.dev: {len(deps_results['broken_links'])} broken links found")
                    self.test_results["overall_passed"] = False

                # 4. Search/Filter Performance
                print("\n⚡ Testing Search/Filter Performance...")
                perf_results = await self.validate_search_filter_performance(page)
                self.test_results["tests"]["performance"] = perf_results

                if perf_results["passed"]:
                    print(f"✅ Performance: Search {perf_results['search_latency_ms']:.0f}ms, "
                          f"Filter {perf_results['filter_latency_ms']:.0f}ms")
                else:
                    print(f"❌ Performance: {', '.join(perf_results['issues'])}")
                    self.test_results["overall_passed"] = False

                # 5. Mobile UX
                print("\n📱 Validating Mobile UX...")
                mobile_results = await self.validate_mobile_ux(page)
                self.test_results["tests"]["mobile_ux"] = mobile_results

                if mobile_results["passed"]:
                    print(f"✅ Mobile UX: All {len(mobile_results['viewport_tests'])} viewports passed")
                else:
                    print(f"❌ Mobile UX: {len(mobile_results['issues'])} issues found")
                    for issue in mobile_results["issues"]:
                        print(f"   - {issue}")
                    self.test_results["overall_passed"] = False

                # 6. Reference Sections
                print("\n📚 Validating Reference Sections...")
                ref_results = await self.validate_reference_sections(page)
                self.test_results["tests"]["references"] = ref_results

                if ref_results["passed"]:
                    print(f"✅ References: {ref_results['pages_checked']} pages have proper references")
                else:
                    print(f"❌ References: {len(ref_results['broken_links'])} broken links, "
                          f"{len(ref_results['missing_categories'])} missing categories")
                    self.test_results["overall_passed"] = False

            finally:
                await browser.close()

        # Summary
        print("\n" + "=" * 60)
        if self.test_results["overall_passed"]:
            print("🎉 All E2E Validations PASSED!")
        else:
            print("⚠️  Some E2E Validations FAILED!")

        return self.test_results

    def generate_qa_report(self) -> str:
        """Generate comprehensive QA report."""
        report_lines = [
            "# 📊 Vuln-Bot E2E Validation Report",
            f"\n**Generated:** {self.test_results['timestamp']}",
            f"**URL Tested:** {self.test_results['base_url']}",
            f"**Overall Status:** {'✅ PASSED' if self.test_results['overall_passed'] else '❌ FAILED'}",
            "\n## Test Results Summary\n"
        ]

        for test_name, test_result in self.test_results["tests"].items():
            status = "✅" if test_result.get("passed", False) else "❌"
            report_lines.append(f"### {status} {test_name.replace('_', ' ').title()}")

            if test_name == "epss_threshold":
                report_lines.append(f"- CVEs Checked: {test_result.get('total_cves_checked', 0)}")
                if test_result.get("min_epss_found"):
                    report_lines.append(f"- EPSS Range: {test_result['min_epss_found']:.1f}% - {test_result['max_epss_found']:.1f}%")
                if test_result.get("violations"):
                    report_lines.append(f"- Violations: {len(test_result['violations'])}")

            elif test_name == "performance":
                if test_result.get("search_latency_ms"):
                    report_lines.append(f"- Search Latency: {test_result['search_latency_ms']:.0f}ms")
                if test_result.get("filter_latency_ms"):
                    report_lines.append(f"- Filter Latency: {test_result['filter_latency_ms']:.0f}ms")

            if test_result.get("error"):
                report_lines.append(f"- Error: {test_result['error']}")

            report_lines.append("")

        if self.test_results.get("screenshots"):
            report_lines.append("\n## Screenshots")
            for screenshot in self.test_results["screenshots"]:
                report_lines.append(f"- {screenshot}")

        report_lines.append("\n## Recommendations\n")

        # Add recommendations based on test results
        if not self.test_results["overall_passed"]:
            report_lines.append("### High Priority Issues:")

            if not self.test_results["tests"].get("epss_threshold", {}).get("passed"):
                report_lines.append("- **EPSS Threshold Violations**: Review data pipeline to ensure 60% filtering")

            if not self.test_results["tests"].get("deps_dev", {}).get("passed"):
                report_lines.append("- **Deps.dev Integration**: Fix broken links and add missing package data")

            if not self.test_results["tests"].get("mobile_ux", {}).get("passed"):
                report_lines.append("- **Mobile UX**: Optimize layouts for smaller viewports")

        report_lines.append("\n### Future Enhancements:")
        report_lines.append("- Add EPSS percentile rank display")
        report_lines.append("- Include CISA KEV status badges")
        report_lines.append("- Implement analyst-focused quick filters")
        report_lines.append("- Add vulnerability timeline visualization")
        report_lines.append("- Enable bulk CVE export with custom fields")

        return "\n".join(report_lines)


async def main():
    """Run comprehensive E2E validation."""
    validator = VulnBotE2EValidator()
    results = await validator.run_all_validations()

    # Save test results
    with open("tests/e2e/full_validation_results.json", "w") as f:
        json.dump(results, f, indent=2)

    # Generate and save QA report
    qa_report = validator.generate_qa_report()
    with open("tests/e2e/qa_report.md", "w") as f:
        f.write(qa_report)

    print("\n💾 Results saved to: tests/e2e/full_validation_results.json")
    print("📄 QA Report saved to: tests/e2e/qa_report.md")

    # Exit with appropriate code
    exit(0 if results["overall_passed"] else 1)


if __name__ == "__main__":
    asyncio.run(main())
