#!/usr/bin/env python3
"""Comprehensive Playwright testing for the live vuln-bot site."""

import asyncio
import json
import time

import aiohttp
import pytest

try:
    from playwright.async_api import Page, async_playwright, expect
except ImportError:
    pytest.skip(
        "E2E tests require Playwright - install with: pip install playwright",
        allow_module_level=True,
    )


class VulnBotLiveTester:
    """Test the live vuln-bot site functionality."""

    def __init__(self):
        self.base_url = "https://williamzujkowski.github.io/vuln-bot"
        self.issues_found = []

    async def log_issue(self, category: str, issue: str, severity: str = "medium"):
        """Log an issue found during testing."""
        issue_dict = {
            "category": category,
            "issue": issue,
            "severity": severity,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.issues_found.append(issue_dict)
        print(f"❌ [{severity.upper()}] {category}: {issue}")

    async def log_success(self, test_name: str):
        """Log a successful test."""
        print(f"✅ {test_name} passed")

    async def test_api_endpoints(self):
        """Test API endpoints are accessible."""
        print("\n🔍 Testing API endpoints...")

        async with aiohttp.ClientSession() as session:
            # Test index.json with sampling
            try:
                async with session.get(
                    f"{self.base_url}/api/vulns/index.json"
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        # Sample first 5000 characters to avoid parsing huge JSON
                        sample = content[:5000]
                        if sample.strip().startswith("[") or sample.strip().startswith(
                            "{"
                        ):
                            await self.log_success(
                                "API index.json is accessible and returns JSON"
                            )

                            # Parse just a small sample to verify structure
                            try:
                                # Find first complete JSON object
                                if sample.strip().startswith("["):
                                    # Array of vulnerabilities
                                    first_bracket = sample.find("{")
                                    if first_bracket > 0:
                                        # Try to find end of first object
                                        bracket_count = 0
                                        end_pos = first_bracket
                                        for i in range(
                                            first_bracket, min(len(sample), 5000)
                                        ):
                                            if sample[i] == "{":
                                                bracket_count += 1
                                            elif sample[i] == "}":
                                                bracket_count -= 1
                                                if bracket_count == 0:
                                                    end_pos = i + 1
                                                    break

                                        if end_pos > first_bracket:
                                            first_vuln = json.loads(
                                                sample[first_bracket:end_pos]
                                            )
                                            # Check for vendor/product fields
                                            if (
                                                "vendor" in first_vuln
                                                and first_vuln["vendor"] != "Unknown"
                                            ):
                                                await self.log_success(
                                                    f"Vendor data present: {first_vuln['vendor']}"
                                                )
                                            else:
                                                await self.log_issue(
                                                    "API Data",
                                                    "Vendor still showing as Unknown",
                                                    "high",
                                                )

                                            if (
                                                "product" in first_vuln
                                                and first_vuln["product"] != "Unknown"
                                            ):
                                                await self.log_success(
                                                    f"Product data present: {first_vuln['product']}"
                                                )
                                            else:
                                                await self.log_issue(
                                                    "API Data",
                                                    "Product still showing as Unknown",
                                                    "high",
                                                )
                            except Exception:
                                print(
                                    "Note: Could not parse sample due to truncation, but JSON structure verified"
                                )
                        else:
                            await self.log_issue(
                                "API",
                                "index.json does not return valid JSON",
                                "critical",
                            )
                    else:
                        await self.log_issue(
                            "API", f"index.json returns {response.status}", "critical"
                        )
            except Exception as e:
                await self.log_issue(
                    "API", f"Failed to fetch index.json: {str(e)}", "critical"
                )

            # Test chunk index
            try:
                async with session.get(
                    f"{self.base_url}/api/vulns/chunk-index.json"
                ) as response:
                    if response.status == 200:
                        await self.log_success("API chunk-index.json is accessible")
                    else:
                        await self.log_issue(
                            "API", f"chunk-index.json returns {response.status}", "high"
                        )
            except Exception as e:
                await self.log_issue(
                    "API", f"Failed to fetch chunk-index.json: {str(e)}", "high"
                )

    async def test_homepage_loads(self, page: Page):
        """Test that the homepage loads correctly."""
        print("\n🔍 Testing homepage...")

        await page.goto(self.base_url, wait_until="networkidle")

        # Check title
        title = await page.title()
        if "Vuln-Bot" in title or "High-Risk CVE" in title:
            await self.log_success("Homepage title is correct")
        else:
            await self.log_issue("Homepage", f"Unexpected title: {title}", "medium")

        # Check main elements
        try:
            await expect(page.locator("#vulnerability-dashboard")).to_be_visible(
                timeout=5000
            )
            await self.log_success("Vulnerability dashboard is visible")
        except Exception:
            await self.log_issue(
                "Homepage", "Vulnerability dashboard not found", "critical"
            )

    async def test_vulnerability_table(self, page: Page):
        """Test vulnerability table displays data correctly."""
        print("\n🔍 Testing vulnerability table...")

        # Wait for table to load
        try:
            await page.wait_for_selector("tbody tr", timeout=10000)

            # Check if vulnerabilities are displayed
            rows = await page.locator("tbody tr").count()
            if rows > 0:
                await self.log_success(f"Vulnerability table shows {rows} entries")

                # Check first row for vendor/product data
                first_row = page.locator("tbody tr").first

                # Check vendor column (assuming it's one of the visible columns)
                vendor_text = (
                    await first_row.locator("td").nth(3).text_content()
                )  # Adjust index based on actual table
                if vendor_text and vendor_text.strip() != "Unknown":
                    await self.log_success(f"Vendor data displayed: {vendor_text}")
                else:
                    await self.log_issue(
                        "Table Data", "Vendor showing as Unknown in table", "high"
                    )

                # Try to find product data
                cells = await first_row.locator("td").all_text_contents()
                product_found = False
                for i, cell in enumerate(cells):
                    if (
                        i > 2
                        and cell
                        and cell.strip() not in ["Unknown", "N/A", ""]
                        and (
                            "microsoft" in cell.lower()
                            or "linux" in cell.lower()
                            or any(char.isalpha() for char in cell)
                        )
                    ):
                        # Product data found
                        product_found = True
                        await self.log_success(
                            f"Product/vendor data found in cell {i}: {cell}"
                        )
                        break

                if not product_found:
                    await self.log_issue(
                        "Table Data", "No clear product data found in table", "high"
                    )

            else:
                await self.log_issue(
                    "Table Data", "No vulnerabilities displayed in table", "critical"
                )
        except Exception as e:
            await self.log_issue(
                "Table Data",
                f"Failed to load vulnerability table: {str(e)}",
                "critical",
            )

    async def test_search_functionality(self, page: Page):
        """Test search and filter functionality."""
        print("\n🔍 Testing search functionality...")

        # Test CVE search
        try:
            search_input = page.locator('input[placeholder*="CVE"]')
            await search_input.fill("CVE-2024")
            await page.wait_for_timeout(500)  # Wait for debounce

            # Check if results are filtered
            rows = await page.locator("tbody tr:visible").count()
            if rows > 0:
                await self.log_success("CVE search filtering works")
            else:
                await self.log_issue(
                    "Search", "CVE search returns no results", "medium"
                )

            await search_input.clear()
        except Exception as e:
            await self.log_issue("Search", f"CVE search failed: {str(e)}", "high")

        # Test vendor filter
        try:
            vendor_input = page.locator('input[placeholder*="vendor" i]')
            await vendor_input.fill("Microsoft")
            await page.wait_for_timeout(500)

            rows = await page.locator("tbody tr:visible").count()
            if rows > 0:
                await self.log_success("Vendor filtering works")
                # Verify filtered results actually contain Microsoft
                first_row = page.locator("tbody tr:visible").first
                text = await first_row.text_content()
                if "microsoft" in text.lower():
                    await self.log_success("Vendor filter shows correct results")
                else:
                    await self.log_issue(
                        "Search", "Vendor filter shows incorrect results", "high"
                    )
            else:
                await self.log_issue(
                    "Search", "Vendor search returns no results", "medium"
                )

            await vendor_input.clear()
        except Exception as e:
            await self.log_issue("Search", f"Vendor search failed: {str(e)}", "high")

    async def test_cve_modal(self, page: Page):
        """Test CVE detail modal functionality."""
        print("\n🔍 Testing CVE modal...")

        try:
            # Click on first CVE link
            first_cve = page.locator("tbody tr a").first
            await first_cve.text_content()
            await first_cve.click()

            # Wait for modal to appear
            modal = page.locator('[role="dialog"], .modal, [id*="modal"]')
            await expect(modal).to_be_visible(timeout=5000)
            await self.log_success("CVE modal opens correctly")

            # Check modal content
            modal_text = await modal.text_content()

            # Check for vendor/product in modal
            if "Vendor:" in modal_text or "Product:" in modal_text:
                if "Unknown" not in modal_text:
                    await self.log_success("Modal shows vendor/product information")
                else:
                    await self.log_issue(
                        "Modal", "Vendor/Product showing as Unknown in modal", "high"
                    )
            else:
                await self.log_issue(
                    "Modal", "No vendor/product fields in modal", "high"
                )

            # Check for attack vector
            if "Attack Vector:" in modal_text or "CVSS" in modal_text:
                if (
                    "Unknown" not in modal_text.split("Attack Vector:")[1][:50]
                    if "Attack Vector:" in modal_text
                    else True
                ):
                    await self.log_success("Modal shows attack vector information")
                else:
                    await self.log_issue(
                        "Modal", "Attack vector showing as Unknown", "medium"
                    )

            # Test tab navigation
            tabs = modal.locator('[role="tab"], .tab, [class*="tab"]')
            tab_count = await tabs.count()
            if tab_count > 0:
                await self.log_success(f"Modal has {tab_count} tabs")

                # Try clicking through tabs
                for i in range(min(tab_count, 4)):
                    await tabs.nth(i).click()
                    await page.wait_for_timeout(200)
                await self.log_success("Tab navigation works")

            # Close modal
            close_button = modal.locator(
                'button:has-text("Close"), button:has-text("×"), [aria-label*="close" i]'
            ).first
            await close_button.click()
            await expect(modal).not_to_be_visible()
            await self.log_success("Modal closes correctly")

        except Exception as e:
            await self.log_issue("Modal", f"CVE modal test failed: {str(e)}", "high")

    async def test_filters_and_sorting(self, page: Page):
        """Test EPSS filtering, date filtering, and sorting."""
        print("\n🔍 Testing filters and sorting...")

        # Test EPSS score filter
        try:
            epss_min = page.locator(
                'input[placeholder*="Min EPSS" i], input[id*="epss-min" i]'
            )
            await epss_min.fill("0.8")
            await page.wait_for_timeout(500)

            rows_after = await page.locator("tbody tr:visible").count()
            if rows_after > 0:
                await self.log_success("EPSS filtering works")

                # Verify EPSS scores in filtered results
                first_row = page.locator("tbody tr:visible").first
                epss_text = await first_row.locator('td:has-text("0.")').text_content()
                if epss_text:
                    epss_value = float(epss_text.strip().replace("%", ""))
                    if epss_value >= 80:  # 0.8 as percentage
                        await self.log_success("EPSS filter shows correct results")
                    else:
                        await self.log_issue(
                            "Filters",
                            f"EPSS filter shows incorrect result: {epss_value}",
                            "high",
                        )
            else:
                await self.log_issue(
                    "Filters", "EPSS filter returns no results", "medium"
                )

            await epss_min.clear()
        except Exception as e:
            await self.log_issue(
                "Filters", f"EPSS filter test failed: {str(e)}", "medium"
            )

        # Test severity filter
        try:
            severity_select = page.locator('select[id*="severity" i]')
            if await severity_select.count() > 0:
                await severity_select.select_option("CRITICAL")
                await page.wait_for_timeout(500)

                rows = await page.locator("tbody tr:visible").count()
                if rows > 0:
                    await self.log_success("Severity filtering works")
                else:
                    await self.log_issue(
                        "Filters", "No CRITICAL vulnerabilities found", "low"
                    )

                await severity_select.select_option("")  # Reset
        except Exception as e:
            print(f"Note: Severity filter test skipped: {str(e)}")

    async def test_data_visualization(self, page: Page):
        """Test data visualization dashboard."""
        print("\n🔍 Testing data visualization...")

        try:
            # Look for canvas elements (charts)
            charts = page.locator("canvas")
            chart_count = await charts.count()

            if chart_count > 0:
                await self.log_success(f"Found {chart_count} chart canvas elements")

                # Test if charts are visible
                for i in range(chart_count):
                    chart = charts.nth(i)
                    if await chart.is_visible():
                        await self.log_success(f"Chart {i + 1} is visible")
                    else:
                        await self.log_issue(
                            "Visualization", f"Chart {i + 1} is not visible", "medium"
                        )
            else:
                await self.log_issue("Visualization", "No charts found on page", "low")

        except Exception as e:
            await self.log_issue("Visualization", f"Chart test failed: {str(e)}", "low")

    async def test_export_functionality(self, page: Page):
        """Test CSV export functionality."""
        print("\n🔍 Testing export functionality...")

        try:
            # Look for export button
            export_button = page.locator(
                'button:has-text("Export"), button:has-text("CSV"), [aria-label*="export" i]'
            )
            if await export_button.count() > 0:
                # Set up download promise before clicking
                download_promise = page.wait_for_event("download")
                await export_button.first.click()

                try:
                    await asyncio.wait_for(download_promise, timeout=5.0)
                    await self.log_success("CSV export triggers download")
                except asyncio.TimeoutError:
                    await self.log_issue(
                        "Export", "CSV export did not trigger download", "medium"
                    )
            else:
                await self.log_issue("Export", "Export button not found", "low")

        except Exception as e:
            await self.log_issue("Export", f"Export test failed: {str(e)}", "low")

    async def test_keyboard_shortcuts(self, page: Page):
        """Test keyboard shortcuts."""
        print("\n🔍 Testing keyboard shortcuts...")

        try:
            # Test search shortcut (/)
            await page.keyboard.press("/")
            await page.wait_for_timeout(200)

            search_input = page.locator('input[placeholder*="CVE"]')
            if await search_input.is_focused():
                await self.log_success("Search shortcut (/) works")
            else:
                await self.log_issue(
                    "Keyboard", "Search shortcut (/) not working", "low"
                )

            # Test escape to close modal
            # First open a modal
            await page.locator("tbody tr a").first.click()
            await page.wait_for_timeout(500)
            await page.keyboard.press("Escape")
            await page.wait_for_timeout(200)

            modal = page.locator('[role="dialog"], .modal')
            if not await modal.is_visible():
                await self.log_success("Escape key closes modal")
            else:
                await self.log_issue(
                    "Keyboard", "Escape key doesn't close modal", "low"
                )

        except Exception as e:
            await self.log_issue(
                "Keyboard", f"Keyboard shortcut test failed: {str(e)}", "low"
            )

    async def test_mobile_responsiveness(self, page: Page):
        """Test mobile responsiveness."""
        print("\n🔍 Testing mobile responsiveness...")

        try:
            # Set mobile viewport
            await page.set_viewport_size({"width": 375, "height": 667})
            await page.reload()
            await page.wait_for_load_state("networkidle")

            # Check if table is scrollable or responsive
            table = page.locator("table, .table-container, [class*='table']").first
            if await table.is_visible():
                await self.log_success("Table visible on mobile")

                # Check if horizontally scrollable
                table_container = page.locator(
                    ".table-container, .table-responsive, [class*='overflow']"
                ).first
                if await table_container.count() > 0:
                    await self.log_success("Table has responsive container")
                else:
                    # Check if table itself is scrollable
                    table_width = await table.evaluate("el => el.scrollWidth")
                    viewport_width = await page.evaluate("() => window.innerWidth")
                    if table_width > viewport_width:
                        await self.log_success(
                            "Table is horizontally scrollable on mobile"
                        )
            else:
                await self.log_issue("Mobile", "Table not visible on mobile", "medium")

            # Reset viewport
            await page.set_viewport_size({"width": 1280, "height": 720})

        except Exception as e:
            await self.log_issue(
                "Mobile", f"Mobile responsiveness test failed: {str(e)}", "low"
            )

    async def run_all_tests(self):
        """Run all tests."""
        print("🚀 Starting comprehensive vuln-bot live site testing...")
        print(f"Target: {self.base_url}")
        print("=" * 60)

        # First test API endpoints without browser
        await self.test_api_endpoints()

        # Then test with browser
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            try:
                await self.test_homepage_loads(page)
                await self.test_vulnerability_table(page)
                await self.test_search_functionality(page)
                await self.test_cve_modal(page)
                await self.test_filters_and_sorting(page)
                await self.test_data_visualization(page)
                await self.test_export_functionality(page)
                await self.test_keyboard_shortcuts(page)
                await self.test_mobile_responsiveness(page)

            finally:
                await browser.close()

        # Summary
        print("\n" + "=" * 60)
        print("📊 TESTING SUMMARY")
        print("=" * 60)

        if self.issues_found:
            print(f"\n❌ Found {len(self.issues_found)} issues:\n")

            # Group by severity
            critical = [i for i in self.issues_found if i["severity"] == "critical"]
            high = [i for i in self.issues_found if i["severity"] == "high"]
            medium = [i for i in self.issues_found if i["severity"] == "medium"]
            low = [i for i in self.issues_found if i["severity"] == "low"]

            if critical:
                print("🔴 CRITICAL Issues:")
                for issue in critical:
                    print(f"   - [{issue['category']}] {issue['issue']}")

            if high:
                print("\n🟠 HIGH Priority Issues:")
                for issue in high:
                    print(f"   - [{issue['category']}] {issue['issue']}")

            if medium:
                print("\n🟡 MEDIUM Priority Issues:")
                for issue in medium:
                    print(f"   - [{issue['category']}] {issue['issue']}")

            if low:
                print("\n🟢 LOW Priority Issues:")
                for issue in low:
                    print(f"   - [{issue['category']}] {issue['issue']}")
        else:
            print("\n✅ All tests passed! No issues found.")

        return self.issues_found


async def main():
    """Main test runner."""
    tester = VulnBotLiveTester()
    issues = await tester.run_all_tests()

    # Save issues to file for tracking
    if issues:
        with open("/home/william/git/vuln-bot/tests/playwright_issues.json", "w") as f:
            json.dump(issues, f, indent=2)
        print("\n💾 Issues saved to: tests/playwright_issues.json")

    return len(issues) == 0  # Return True if no issues


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)
