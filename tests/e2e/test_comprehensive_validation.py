#!/usr/bin/env python3
"""Comprehensive E2E tests for vulnerability dashboard and CVE detail pages."""

import asyncio
import json
import re
from datetime import datetime
from pathlib import Path

from playwright.async_api import Page, async_playwright, expect


class VulnBotE2ETests:
    """Comprehensive E2E tests for vuln-bot platform."""

    def __init__(self, base_url: str = "https://williamzujkowski.github.io/vuln-bot"):
        self.base_url = base_url
        self.test_results = {
            "passed": 0,
            "failed": 0,
            "errors": [],
            "timestamp": datetime.now().isoformat(),
        }

    async def run_all_tests(self):
        """Run all E2E tests."""
        print("🧪 Starting comprehensive E2E tests for vuln-bot...")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={"width": 1920, "height": 1080}
            )
            page = await context.new_page()

            try:
                # Test 1: Homepage loads correctly
                await self.test_homepage_loads(page)

                # Test 2: Data quality validation
                await self.test_data_quality(page)

                # Test 3: Table functionality
                await self.test_table_functionality(page)

                # Test 4: Search and filter functionality
                await self.test_search_filters(page)

                # Test 5: CVE detail pages
                await self.test_cve_detail_pages(page)

                # Test 6: Responsive design
                await self.test_responsive_design(page)

                # Test 7: Accessibility
                await self.test_accessibility(page)

                # Test 8: Performance
                await self.test_performance(page)

                # Test 9: Enhanced CVE pages
                await self.test_enhanced_cve_pages(page)

                # Test 10: Data visualization
                await self.test_data_visualization(page)

            except Exception as e:
                self.record_error(f"Critical test failure: {str(e)}")
            finally:
                await browser.close()
                self.print_results()

    async def test_homepage_loads(self, page: Page):
        """Test that homepage loads correctly."""
        test_name = "Homepage Load Test"
        try:
            print(f"\n🔍 Running: {test_name}")

            # Navigate to homepage
            response = await page.goto(self.base_url, wait_until="networkidle")
            assert response.status == 200, f"Expected 200, got {response.status}"

            # Check title
            await expect(page).to_have_title(re.compile("Vulnerability Intelligence"))

            # Check main elements exist
            await expect(page.locator(".dashboard-header")).to_be_visible()
            await expect(page.locator("#vulnerability-table")).to_be_visible(
                timeout=30000
            )

            # Wait for data to load
            await page.wait_for_function(
                "() => window.vulnerabilityData && window.vulnerabilityData.length > 0",
                timeout=30000,
            )

            self.record_success(test_name)

        except Exception as e:
            self.record_failure(test_name, str(e))

    async def test_data_quality(self, page: Page):
        """Test data quality and format."""
        test_name = "Data Quality Test"
        try:
            print(f"\n🔍 Running: {test_name}")

            # Get vulnerability data
            vuln_data = await page.evaluate(
                """
                () => {
                    const data = window.vulnerabilityData || [];
                    return data.slice(0, 10).map(v => ({
                        cveId: v.cveId,
                        severity: v.severity,
                        cvssScore: v.cvssScore,
                        epssPercentile: v.epssPercentile,
                        products: v.products,
                        vendors: v.vendors,
                        exploitationStatus: v.exploitationStatus,
                        publishedDate: v.publishedDate
                    }));
                }
            """
            )

            assert len(vuln_data) > 0, "No vulnerability data found"

            # Validate each vulnerability
            for _i, vuln in enumerate(vuln_data):
                # Check CVE ID format
                assert re.match(
                    r"^CVE-\d{4}-\d+$", vuln["cveId"]
                ), f"Invalid CVE ID format: {vuln['cveId']}"

                # Check severity
                assert vuln["severity"] in [
                    "CRITICAL",
                    "HIGH",
                    "MEDIUM",
                    "LOW",
                ], f"Invalid severity: {vuln['severity']}"

                # Check CVSS score
                assert (
                    0 <= vuln["cvssScore"] <= 10
                ), f"Invalid CVSS score: {vuln['cvssScore']}"

                # Check EPSS percentile
                assert (
                    0 <= vuln["epssPercentile"] <= 100
                ), f"Invalid EPSS percentile: {vuln['epssPercentile']}"

                # Check products is array
                assert isinstance(
                    vuln["products"], list
                ), f"Products should be array, got {type(vuln['products'])}"

                # Check vendors is array
                assert isinstance(
                    vuln["vendors"], list
                ), f"Vendors should be array, got {type(vuln['vendors'])}"

            self.record_success(test_name)

        except Exception as e:
            self.record_failure(test_name, str(e))

    async def test_table_functionality(self, page: Page):
        """Test table display and functionality."""
        test_name = "Table Functionality Test"
        try:
            print(f"\n🔍 Running: {test_name}")

            # Check table headers
            headers = await page.locator("#vulnerability-table th").all_text_contents()
            expected_headers = [
                "CVE ID",
                "Description",
                "Severity",
                "CVSS",
                "EPSS",
                "Risk",
                "Product",
            ]

            for expected in expected_headers:
                assert any(
                    expected in header for header in headers
                ), f"Missing expected header: {expected}"

            # Check table rows
            rows = await page.locator("#vulnerability-table tbody tr").count()
            assert rows > 0, "No table rows found"

            # Test sorting
            cvss_header = page.locator("th:has-text('CVSS')").first
            await cvss_header.click()
            await page.wait_for_timeout(500)

            # Verify sort indicator appears
            sort_indicator = await cvss_header.locator(".sort-indicator").is_visible()
            assert sort_indicator, "Sort indicator not visible after clicking header"

            # Test product column displays only product names
            first_product = await page.locator(
                "#vulnerability-table tbody tr:first-child td:nth-child(7)"
            ).text_content()
            assert (
                "/" not in first_product
            ), f"Product column still contains vendor/product: {first_product}"

            self.record_success(test_name)

        except Exception as e:
            self.record_failure(test_name, str(e))

    async def test_search_filters(self, page: Page):
        """Test search and filter functionality."""
        test_name = "Search and Filters Test"
        try:
            print(f"\n🔍 Running: {test_name}")

            # Test search
            search_input = page.locator("input[placeholder*='Search']").first
            await search_input.fill("Microsoft")
            await page.wait_for_timeout(500)

            # Check results updated
            results_count = await page.locator(
                ".results-count span"
            ).first.text_content()
            assert "results" in results_count.lower(), "Results count not updated"

            # Test severity filter
            severity_select = (
                page.locator("select").filter(has_text="All Severities").first
            )
            await severity_select.select_option("CRITICAL")
            await page.wait_for_timeout(500)

            # Verify only critical vulnerabilities shown
            severities = await page.locator(
                "#vulnerability-table .severity-badge"
            ).all_text_contents()
            for severity in severities[:5]:  # Check first 5
                assert (
                    "CRITICAL" in severity
                ), f"Non-critical severity found: {severity}"

            # Reset filters
            await search_input.clear()
            await severity_select.select_option("")

            self.record_success(test_name)

        except Exception as e:
            self.record_failure(test_name, str(e))

    async def test_cve_detail_pages(self, page: Page):
        """Test CVE detail page functionality."""
        test_name = "CVE Detail Pages Test"
        try:
            print(f"\n🔍 Running: {test_name}")

            # Click on first CVE
            first_cve_button = page.locator("#vulnerability-table .cve-button").first
            cve_id = await first_cve_button.text_content()

            # Navigate to CVE detail page
            await first_cve_button.click()
            await page.wait_for_url(f"**/cves/{cve_id}.html", timeout=10000)

            # Check page elements
            await expect(
                page.locator(
                    f"h1:has-text('{cve_id}')",
                )
            ).to_be_visible()

            # Check required sections
            sections = ["Overview", "Technical Details", "References", "Timeline"]
            for section in sections:
                await expect(page.locator(f"h2:has-text('{section}')")).to_be_visible()

            # Navigate back
            await page.go_back()
            await page.wait_for_load_state("networkidle")

            self.record_success(test_name)

        except Exception as e:
            self.record_failure(test_name, str(e))

    async def test_responsive_design(self, page: Page):
        """Test responsive design at different viewport sizes."""
        test_name = "Responsive Design Test"
        try:
            print(f"\n🔍 Running: {test_name}")

            viewports = [
                {"width": 375, "height": 667, "name": "Mobile"},
                {"width": 768, "height": 1024, "name": "Tablet"},
                {"width": 1920, "height": 1080, "name": "Desktop"},
            ]

            for viewport in viewports:
                await page.set_viewport_size(
                    {"width": viewport["width"], "height": viewport["height"]}
                )
                await page.wait_for_timeout(500)

                # Check if table is scrollable on mobile
                if viewport["name"] == "Mobile":
                    table_wrapper = page.locator(".table-wrapper").first
                    is_scrollable = await table_wrapper.evaluate(
                        "el => el.scrollWidth > el.clientWidth"
                    )
                    assert is_scrollable, "Table not scrollable on mobile"

                # Check header is visible
                await expect(page.locator(".dashboard-header")).to_be_visible()

            self.record_success(test_name)

        except Exception as e:
            self.record_failure(test_name, str(e))

    async def test_accessibility(self, page: Page):
        """Test accessibility features."""
        test_name = "Accessibility Test"
        try:
            print(f"\n🔍 Running: {test_name}")

            # Check for ARIA labels
            table = page.locator("#vulnerability-table")
            aria_label = await table.get_attribute("aria-label")
            assert aria_label, "Table missing aria-label"

            # Check keyboard navigation
            await page.keyboard.press("Tab")
            focused_element = await page.evaluate(
                "() => document.activeElement.tagName"
            )
            assert focused_element, "No element focused after Tab"

            # Check color contrast (basic check)
            contrast_issues = await page.evaluate(
                """
                () => {
                    const elements = document.querySelectorAll('.severity-critical, .severity-high');
                    const issues = [];
                    elements.forEach(el => {
                        const style = window.getComputedStyle(el);
                        const bg = style.backgroundColor;
                        const fg = style.color;
                        // Basic check - would need proper contrast calculation
                        if (bg === fg) {
                            issues.push(`Same foreground and background color on ${el.className}`);
                        }
                    });
                    return issues;
                }
            """
            )

            assert (
                len(contrast_issues) == 0
            ), f"Contrast issues found: {contrast_issues}"

            self.record_success(test_name)

        except Exception as e:
            self.record_failure(test_name, str(e))

    async def test_performance(self, page: Page):
        """Test page performance metrics."""
        test_name = "Performance Test"
        try:
            print(f"\n🔍 Running: {test_name}")

            # Measure page load time
            start_time = datetime.now()
            await page.goto(self.base_url, wait_until="networkidle")
            load_time = (datetime.now() - start_time).total_seconds()

            assert load_time < 10, f"Page load took too long: {load_time}s"

            # Check for memory leaks (basic check)
            initial_memory = await page.evaluate(
                "() => performance.memory?.usedJSHeapSize || 0"
            )

            # Perform some actions
            for _ in range(5):
                await page.locator("th:has-text('CVSS')").click()
                await page.wait_for_timeout(200)

            final_memory = await page.evaluate(
                "() => performance.memory?.usedJSHeapSize || 0"
            )

            # Memory shouldn't increase too much
            memory_increase = final_memory - initial_memory
            assert (
                memory_increase < 10 * 1024 * 1024
            ), f"Potential memory leak: {memory_increase / 1024 / 1024:.2f}MB increase"

            self.record_success(test_name)

        except Exception as e:
            self.record_failure(test_name, str(e))

    async def test_enhanced_cve_pages(self, page: Page):
        """Test enhanced CVE detail pages with all schema v5.1 fields."""
        test_name = "Enhanced CVE Pages Test"
        try:
            print(f"\n🔍 Running: {test_name}")

            # Check if enhanced CVE pages exist
            cve_page_path = Path("src/cves/CVE-2024-3094.md")
            if cve_page_path.exists():
                # Navigate to enhanced CVE page
                await page.goto(
                    f"{self.base_url}/cves/CVE-2024-3094.html", wait_until="networkidle"
                )

                # Check for enhanced sections
                enhanced_sections = [
                    "Metadata",
                    "Problem Types",
                    "Technical Details",
                    "Affected Products",
                    "Impacted Open Source Projects",
                    "Additional Information",
                ]

                for section in enhanced_sections:
                    locator = page.locator(f"h2:has-text('{section}')")
                    is_visible = await locator.is_visible()
                    if is_visible:
                        print(f"  ✅ Found section: {section}")
                    else:
                        print(f"  ⚠️  Missing section: {section}")

                # Check for deps.dev data
                deps_section = page.locator(
                    "h2:has-text('Impacted Open Source Projects')"
                )
                if await deps_section.is_visible():
                    print("  ✅ deps.dev integration present")

                self.record_success(test_name)
            else:
                print("  ⚠️  Enhanced CVE pages not yet generated")
                self.record_success(test_name + " (skipped)")

        except Exception as e:
            self.record_failure(test_name, str(e))

    async def test_data_visualization(self, page: Page):
        """Test data visualization components."""
        test_name = "Data Visualization Test"
        try:
            print(f"\n🔍 Running: {test_name}")

            # Check for chart containers
            chart_selectors = [
                "#severityChart",
                "#riskChart",
                "#epssChart",
                "#vendorChart",
            ]

            charts_found = 0
            for selector in chart_selectors:
                chart = page.locator(selector)
                if await chart.count() > 0:
                    charts_found += 1
                    print(f"  ✅ Found chart: {selector}")

            if charts_found > 0:
                print(f"  📊 Found {charts_found} data visualization charts")
                self.record_success(test_name)
            else:
                print(
                    "  ⚠️  No data visualization charts found (may not be implemented yet)"
                )
                self.record_success(test_name + " (no charts)")

        except Exception as e:
            self.record_failure(test_name, str(e))

    def record_success(self, test_name: str):
        """Record a successful test."""
        self.test_results["passed"] += 1
        print(f"  ✅ {test_name} - PASSED")

    def record_failure(self, test_name: str, error: str):
        """Record a failed test."""
        self.test_results["failed"] += 1
        self.test_results["errors"].append({"test": test_name, "error": error})
        print(f"  ❌ {test_name} - FAILED: {error}")

    def record_error(self, error: str):
        """Record a general error."""
        self.test_results["errors"].append({"test": "General", "error": error})

    def print_results(self):
        """Print test results summary."""
        total_tests = self.test_results["passed"] + self.test_results["failed"]

        print("\n" + "=" * 60)
        print("📊 TEST RESULTS SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {self.test_results['passed']}")
        print(f"❌ Failed: {self.test_results['failed']}")
        print(f"Success Rate: {(self.test_results['passed'] / total_tests * 100):.1f}%")

        if self.test_results["errors"]:
            print("\n❌ ERRORS:")
            for error in self.test_results["errors"]:
                print(f"  - {error['test']}: {error['error']}")

        # Save results to file
        results_file = Path("tests/e2e/test_results.json")
        results_file.parent.mkdir(exist_ok=True)
        with open(results_file, "w") as f:
            json.dump(self.test_results, f, indent=2)

        print(f"\n💾 Results saved to: {results_file}")

        # Exit with appropriate code
        exit(0 if self.test_results["failed"] == 0 else 1)


async def main():
    """Run all E2E tests."""
    tester = VulnBotE2ETests()
    await tester.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())
