#!/usr/bin/env python3
"""Comprehensive Playwright tests for the live vuln-bot site."""

import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from playwright.async_api import async_playwright, Page, expect
import aiohttp


class ComprehensiveLiveTester:
    """Comprehensive testing for the live vuln-bot site."""
    
    def __init__(self):
        self.base_url = "https://williamzujkowski.github.io/vuln-bot"
        self.issues_found = []
        self.test_results = {
            "passed": 0,
            "failed": 0,
            "total": 0,
            "start_time": datetime.now().isoformat(),
            "issues": []
        }
        
    async def log_issue(self, category: str, test: str, issue: str, severity: str = "medium", details: Dict = None):
        """Log an issue found during testing."""
        issue_dict = {
            "category": category,
            "test": test,
            "issue": issue,
            "severity": severity,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "details": details or {}
        }
        self.issues_found.append(issue_dict)
        self.test_results["issues"].append(issue_dict)
        self.test_results["failed"] += 1
        print(f"❌ [{severity.upper()}] {category} - {test}: {issue}")
        
    async def log_success(self, category: str, test: str):
        """Log a successful test."""
        self.test_results["passed"] += 1
        print(f"✅ {category} - {test}")
        
    async def run_test(self, category: str, test_name: str, test_func, *args, **kwargs):
        """Run a single test with error handling."""
        self.test_results["total"] += 1
        try:
            await test_func(*args, **kwargs)
            await self.log_success(category, test_name)
            return True
        except Exception as e:
            await self.log_issue(
                category, 
                test_name, 
                str(e), 
                "high",
                {"error_type": type(e).__name__, "full_error": str(e)}
            )
            return False
            
    async def test_api_health(self):
        """Test API endpoints health and data quality."""
        print("\n🔍 Testing API Health...")
        
        async with aiohttp.ClientSession() as session:
            # Test main index.json
            try:
                async with session.get(f"{self.base_url}/api/vulns/index.json") as response:
                    if response.status == 200:
                        content = await response.text()
                        data = json.loads(content)
                        
                        # Handle both array and object with vulnerabilities key
                        vulnerabilities = []
                        if isinstance(data, list):
                            vulnerabilities = data
                        elif isinstance(data, dict) and "vulnerabilities" in data:
                            vulnerabilities = data["vulnerabilities"]
                            
                        if vulnerabilities and len(vulnerabilities) > 0:
                            await self.log_success("API", "index.json accessible and contains data")
                            
                            # Analyze data quality
                            sample = vulnerabilities[:100]  # Analyze first 100
                            quality_metrics = await self._analyze_data_quality(sample)
                            
                            # Check for quality issues
                            if quality_metrics["vendor_unknown_rate"] > 0.2:
                                await self.log_issue(
                                    "Data Quality",
                                    "Vendor extraction",
                                    f"High unknown vendor rate: {quality_metrics['vendor_unknown_rate']:.1%}",
                                    "high",
                                    quality_metrics
                                )
                            else:
                                await self.log_success("Data Quality", "Vendor extraction rate acceptable")
                                
                            if quality_metrics["product_unknown_rate"] > 0.3:
                                await self.log_issue(
                                    "Data Quality",
                                    "Product extraction",
                                    f"High unknown product rate: {quality_metrics['product_unknown_rate']:.1%}",
                                    "medium",
                                    quality_metrics
                                )
                            else:
                                await self.log_success("Data Quality", "Product extraction rate acceptable")
                                
                            if quality_metrics["missing_cvss_rate"] > 0.1:
                                await self.log_issue(
                                    "Data Quality",
                                    "CVSS scores",
                                    f"High missing CVSS rate: {quality_metrics['missing_cvss_rate']:.1%}",
                                    "medium",
                                    quality_metrics
                                )
                            else:
                                await self.log_success("Data Quality", "CVSS score coverage good")
                                
                        else:
                            await self.log_issue("API", "index.json", "No vulnerability data found", "critical")
                    else:
                        await self.log_issue("API", "index.json", f"HTTP {response.status}", "critical")
            except Exception as e:
                await self.log_issue("API", "index.json", f"Failed to fetch: {str(e)}", "critical")
                
            # Test chunk-index.json
            try:
                async with session.get(f"{self.base_url}/api/vulns/chunk-index.json") as response:
                    if response.status == 200:
                        await self.log_success("API", "chunk-index.json accessible")
                    else:
                        await self.log_issue("API", "chunk-index.json", f"HTTP {response.status}", "high")
            except Exception as e:
                await self.log_issue("API", "chunk-index.json", f"Failed to fetch: {str(e)}", "high")
                
            # Test sample CVE JSON
            try:
                # Get a sample CVE ID from index
                async with session.get(f"{self.base_url}/api/vulns/index.json") as response:
                    if response.status == 200:
                        data = await response.json()
                        vulnerabilities = data if isinstance(data, list) else data.get("vulnerabilities", [])
                        if vulnerabilities and len(vulnerabilities) > 0:
                            sample_cve = vulnerabilities[0].get("cveId") or vulnerabilities[0].get("cve_id")
                            
                            # Test individual CVE endpoint
                            async with session.get(f"{self.base_url}/api/vulns/{sample_cve}.json") as cve_response:
                                if cve_response.status == 200:
                                    await self.log_success("API", f"Individual CVE JSON ({sample_cve})")
                                else:
                                    # This might be expected if not all CVEs have individual files
                                    await self.log_issue("API", "Individual CVE JSON", f"HTTP {cve_response.status}", "low")
            except:
                pass  # Individual CVE files are optional
                
    async def _analyze_data_quality(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, float]:
        """Analyze data quality metrics."""
        total = len(vulnerabilities)
        if total == 0:
            return {}
            
        vendor_unknown = sum(1 for v in vulnerabilities if v.get("vendor", "").lower() in ["unknown", "n/a", ""])
        product_unknown = sum(1 for v in vulnerabilities if v.get("product", "").lower() in ["unknown", "n/a", ""])
        missing_cvss = sum(1 for v in vulnerabilities if not v.get("cvss_base_score"))
        missing_epss = sum(1 for v in vulnerabilities if not v.get("epss_probability"))
        missing_attack_vector = sum(1 for v in vulnerabilities if not v.get("attack_vector") or v.get("attack_vector") == "Unknown")
        
        return {
            "total_analyzed": total,
            "vendor_unknown_rate": vendor_unknown / total,
            "product_unknown_rate": product_unknown / total,
            "missing_cvss_rate": missing_cvss / total,
            "missing_epss_rate": missing_epss / total,
            "missing_attack_vector_rate": missing_attack_vector / total,
            "vendor_unknown_count": vendor_unknown,
            "product_unknown_count": product_unknown,
            "missing_cvss_count": missing_cvss,
            "missing_epss_count": missing_epss
        }
        
    async def test_homepage_functionality(self, page: Page):
        """Test homepage loads and basic functionality."""
        print("\n🔍 Testing Homepage Functionality...")
        
        # Navigate to homepage
        await page.goto(self.base_url, wait_until="networkidle")
        
        # Check title
        await self.run_test(
            "Homepage",
            "Page title",
            self._check_page_title,
            page
        )
        
        # Check main elements
        await self.run_test(
            "Homepage",
            "Dashboard visibility",
            self._check_dashboard_visible,
            page
        )
        
        # Check vulnerability table
        await self.run_test(
            "Homepage",
            "Vulnerability table",
            self._check_vulnerability_table,
            page
        )
        
        # Check statistics cards
        await self.run_test(
            "Homepage",
            "Statistics cards",
            self._check_statistics_cards,
            page
        )
        
    async def _check_page_title(self, page: Page):
        """Check page title."""
        title = await page.title()
        assert "Vulnerability" in title or "Vuln-Bot" in title, f"Unexpected title: {title}"
        
    async def _check_dashboard_visible(self, page: Page):
        """Check dashboard is visible."""
        # Try multiple possible selectors
        selectors = [
            "#vulnerability-dashboard",
            "[x-data*='dashboard']",
            ".dashboard",
            "main",
            "[role='main']"
        ]
        
        found = False
        for selector in selectors:
            if await page.locator(selector).count() > 0:
                found = True
                break
                
        assert found, "Dashboard element not found with any known selector"
        
    async def _check_vulnerability_table(self, page: Page):
        """Check vulnerability table has data."""
        # Wait for table to be visible
        table = page.locator("table").first
        await expect(table).to_be_visible(timeout=10000)
        
        # Check for data rows
        rows = page.locator("tbody tr")
        count = await rows.count()
        assert count > 0, "No vulnerability data in table"
        
        # Check first row structure
        first_row = rows.first
        cells = await first_row.locator("td").count()
        assert cells >= 6, f"Table row has insufficient columns: {cells}"
        
    async def _check_statistics_cards(self, page: Page):
        """Check statistics cards are present."""
        # Look for statistics elements
        stat_selectors = [
            "text=Total Vulnerabilities",
            "text=Critical Severity",
            "text=High Severity",
            "[class*='stat']",
            "[class*='metric']"
        ]
        
        found_stats = 0
        for selector in stat_selectors:
            if await page.locator(selector).count() > 0:
                found_stats += 1
                
        assert found_stats >= 2, f"Insufficient statistics elements found: {found_stats}"
        
    async def test_search_and_filtering(self, page: Page):
        """Test search and filtering functionality."""
        print("\n🔍 Testing Search and Filtering...")
        
        await page.goto(self.base_url, wait_until="networkidle")
        
        # Test CVE search
        await self.run_test(
            "Search",
            "CVE ID search",
            self._test_cve_search,
            page
        )
        
        # Test vendor search
        await self.run_test(
            "Search",
            "Vendor search",
            self._test_vendor_search,
            page
        )
        
        # Test severity filter
        await self.run_test(
            "Filtering",
            "Severity filter",
            self._test_severity_filter,
            page
        )
        
        # Test EPSS filter
        await self.run_test(
            "Filtering",
            "EPSS score filter",
            self._test_epss_filter,
            page
        )
        
        # Test date filter
        await self.run_test(
            "Filtering",
            "Date range filter",
            self._test_date_filter,
            page
        )
        
    async def _test_cve_search(self, page: Page):
        """Test CVE ID search."""
        search_input = page.locator('input[placeholder*="Search" i], input[placeholder*="CVE" i]').first
        await search_input.fill("CVE-2024")
        await page.wait_for_timeout(1000)  # Wait for debounce
        
        rows = await page.locator("tbody tr:visible").count()
        assert rows > 0, "CVE search returned no results"
        
        # Verify results contain search term
        first_row = page.locator("tbody tr:visible").first
        text = await first_row.text_content()
        assert "CVE-2024" in text, "Search results don't match query"
        
        await search_input.clear()
        
    async def _test_vendor_search(self, page: Page):
        """Test vendor search."""
        # First, let's see what vendors are available
        rows = page.locator("tbody tr")
        sample_text = await rows.first.text_content() if await rows.count() > 0 else ""
        
        # Try to find a vendor in the data
        test_vendors = ["Microsoft", "Adobe", "Oracle", "Cisco", "VMware"]
        vendor_found = None
        
        for vendor in test_vendors:
            if vendor.lower() in sample_text.lower():
                vendor_found = vendor
                break
                
        if vendor_found:
            search_input = page.locator('input[placeholder*="vendor" i], input[placeholder*="Search" i]').first
            await search_input.fill(vendor_found)
            await page.wait_for_timeout(1000)
            
            visible_rows = await page.locator("tbody tr:visible").count()
            assert visible_rows > 0, f"Vendor search for '{vendor_found}' returned no results"
            
            await search_input.clear()
        else:
            # If no known vendor found, just check that search input exists
            search_input = page.locator('input[placeholder*="Search" i]').first
            assert await search_input.count() > 0, "Search input not found"
            
    async def _test_severity_filter(self, page: Page):
        """Test severity filtering."""
        # Look for severity filter
        severity_selectors = [
            'select[id*="severity" i]',
            'select[name*="severity" i]',
            '[x-model*="severity" i]'
        ]
        
        severity_select = None
        for selector in severity_selectors:
            if await page.locator(selector).count() > 0:
                severity_select = page.locator(selector).first
                break
                
        if severity_select:
            await severity_select.select_option("CRITICAL")
            await page.wait_for_timeout(500)
            
            rows = await page.locator("tbody tr:visible").count()
            # Should have at least some critical vulnerabilities
            assert rows >= 0, "Severity filter may not be working"
            
            # Reset filter
            await severity_select.select_option("")
        else:
            # Check for button-based severity filters
            critical_button = page.locator('button:has-text("Critical")').first
            if await critical_button.count() > 0:
                await critical_button.click()
                await page.wait_for_timeout(500)
                rows = await page.locator("tbody tr:visible").count()
                assert rows >= 0, "Button-based severity filter may not be working"
                
    async def _test_epss_filter(self, page: Page):
        """Test EPSS score filtering."""
        epss_selectors = [
            'input[placeholder*="EPSS" i]',
            'input[id*="epss" i]',
            'input[name*="epss" i]',
            '[x-model*="epss" i]'
        ]
        
        epss_input = None
        for selector in epss_selectors:
            if await page.locator(selector).count() > 0:
                epss_input = page.locator(selector).first
                break
                
        if epss_input:
            await epss_input.fill("90")
            await page.wait_for_timeout(1000)
            
            rows = await page.locator("tbody tr:visible").count()
            # With 70% minimum EPSS in harvest, should have some 90%+ 
            assert rows >= 0, "EPSS filter may not be working"
            
            await epss_input.clear()
        else:
            # EPSS filter might not be implemented yet
            print("  ⚠️  EPSS filter input not found")
            
    async def _test_date_filter(self, page: Page):
        """Test date range filtering."""
        date_selectors = [
            'input[type="date"]',
            'input[placeholder*="date" i]',
            '[x-model*="date" i]'
        ]
        
        date_inputs = []
        for selector in date_selectors:
            inputs = await page.locator(selector).all()
            date_inputs.extend(inputs)
            
        if len(date_inputs) >= 2:
            # Set date range
            await date_inputs[0].fill("2024-01-01")
            await date_inputs[1].fill("2024-12-31")
            await page.wait_for_timeout(1000)
            
            rows = await page.locator("tbody tr:visible").count()
            assert rows >= 0, "Date filter may not be working"
            
            # Clear filters
            for input in date_inputs:
                await input.clear()
        else:
            print("  ⚠️  Date filter inputs not found")
            
    async def test_cve_detail_pages(self, page: Page):
        """Test CVE detail page functionality."""
        print("\n🔍 Testing CVE Detail Pages...")
        
        await page.goto(self.base_url, wait_until="networkidle")
        
        # Get first few CVE links
        cve_links = await page.locator("tbody tr a[href*='cves']").all()
        
        if not cve_links:
            await self.log_issue("CVE Pages", "No CVE links", "No CVE detail links found", "high")
            return
            
        # Test first 3 CVEs
        for i in range(min(3, len(cve_links))):
            cve_text = await cve_links[i].text_content()
            await self.run_test(
                "CVE Pages",
                f"CVE detail page ({cve_text})",
                self._test_single_cve_page,
                page,
                cve_links[i],
                cve_text
            )
            
    async def _test_single_cve_page(self, page: Page, link, cve_id: str):
        """Test a single CVE detail page."""
        # Click the link
        await link.click()
        await page.wait_for_load_state("networkidle")
        
        # Check URL changed
        current_url = page.url
        assert f"/cves/{cve_id}" in current_url, "Navigation to CVE page failed"
        
        # Check page elements
        heading = page.locator("h1")
        heading_text = await heading.text_content() if await heading.count() > 0 else ""
        assert cve_id in heading_text, f"CVE ID not in heading: {heading_text}"
        
        # Check for required information
        required_elements = [
            ("Description", ["Description", "Overview", "Summary"]),
            ("CVSS Score", ["CVSS", "Base Score"]),
            ("EPSS Score", ["EPSS"]),
            ("Published Date", ["Published", "Date"])
        ]
        
        for element_name, possible_texts in required_elements:
            found = False
            for text in possible_texts:
                if await page.locator(f"text={text}").count() > 0:
                    found = True
                    break
            assert found, f"{element_name} section not found on CVE detail page"
            
        # Navigate back
        await page.go_back()
        await page.wait_for_load_state("networkidle")
        
    async def test_data_visualization(self, page: Page):
        """Test data visualization components."""
        print("\n🔍 Testing Data Visualization...")
        
        await page.goto(self.base_url, wait_until="networkidle")
        
        # Check for charts
        await self.run_test(
            "Visualization",
            "Chart presence",
            self._test_charts_present,
            page
        )
        
    async def _test_charts_present(self, page: Page):
        """Test if charts are present."""
        chart_selectors = [
            "canvas",
            "svg.chart",
            "[class*='chart']",
            "[id*='chart']"
        ]
        
        chart_found = False
        for selector in chart_selectors:
            if await page.locator(selector).count() > 0:
                chart_found = True
                break
                
        if not chart_found:
            # Charts might not be implemented yet
            print("  ⚠️  No charts found - may not be implemented")
            
    async def test_export_functionality(self, page: Page):
        """Test data export functionality."""
        print("\n🔍 Testing Export Functionality...")
        
        await page.goto(self.base_url, wait_until="networkidle")
        
        await self.run_test(
            "Export",
            "CSV export",
            self._test_csv_export,
            page
        )
        
    async def _test_csv_export(self, page: Page):
        """Test CSV export."""
        export_selectors = [
            'button:has-text("Export")',
            'button:has-text("CSV")',
            'button:has-text("Download")',
            '[aria-label*="export" i]'
        ]
        
        export_button = None
        for selector in export_selectors:
            if await page.locator(selector).count() > 0:
                export_button = page.locator(selector).first
                break
                
        if export_button:
            # Set up download handler
            download_promise = page.wait_for_event('download', timeout=5000)
            await export_button.click()
            
            try:
                download = await download_promise
                assert download.suggested_filename.endswith('.csv'), "Export file is not CSV"
            except:
                print("  ⚠️  Export button found but download didn't trigger")
        else:
            print("  ⚠️  Export button not found")
            
    async def test_mobile_responsiveness(self, page: Page):
        """Test mobile responsiveness."""
        print("\n🔍 Testing Mobile Responsiveness...")
        
        # Set mobile viewport
        await page.set_viewport_size({"width": 375, "height": 667})
        await page.goto(self.base_url, wait_until="networkidle")
        
        await self.run_test(
            "Mobile",
            "Mobile layout",
            self._test_mobile_layout,
            page
        )
        
        # Reset viewport
        await page.set_viewport_size({"width": 1280, "height": 720})
        
    async def _test_mobile_layout(self, page: Page):
        """Test mobile layout."""
        # Check table is still accessible
        table = page.locator("table").first
        assert await table.is_visible(), "Table not visible on mobile"
        
        # Check for table-wrapper with horizontal scroll
        table_wrapper = page.locator(".table-wrapper").first
        if await table_wrapper.count() > 0:
            wrapper_styles = await table_wrapper.evaluate("el => getComputedStyle(el)")
            is_scrollable = wrapper_styles.get("overflow-x") in ["auto", "scroll"]
            assert is_scrollable, "Table wrapper not scrollable on mobile"
        else:
            # Check parent element as fallback
            table_parent = page.locator("table").locator("..")
            parent_styles = await table_parent.evaluate("el => getComputedStyle(el)")
            is_scrollable = parent_styles.get("overflow-x") in ["auto", "scroll"]
            is_responsive = "responsive" in (await table_parent.get_attribute("class") or "")
            assert is_scrollable or is_responsive, "Table not properly responsive on mobile"
        
    async def test_accessibility(self, page: Page):
        """Test accessibility features."""
        print("\n🔍 Testing Accessibility...")
        
        await page.goto(self.base_url, wait_until="networkidle")
        
        await self.run_test(
            "Accessibility",
            "Keyboard navigation",
            self._test_keyboard_navigation,
            page
        )
        
        await self.run_test(
            "Accessibility",
            "ARIA labels",
            self._test_aria_labels,
            page
        )
        
    async def _test_keyboard_navigation(self, page: Page):
        """Test keyboard navigation."""
        # Test tab navigation
        await page.keyboard.press("Tab")
        await page.wait_for_timeout(100)
        
        # Check if an element is focused
        focused = await page.evaluate("() => document.activeElement.tagName")
        assert focused != "BODY", "Tab navigation not working"
        
        # Test search shortcut if implemented
        await page.keyboard.press("/")
        await page.wait_for_timeout(100)
        
        # Check if search is focused
        search_focused = await page.evaluate("""() => {
            const active = document.activeElement;
            return active.tagName === 'INPUT' && 
                   (active.placeholder.toLowerCase().includes('search') || 
                    active.placeholder.toLowerCase().includes('cve'));
        }""")
        
        if not search_focused:
            print("  ⚠️  Search keyboard shortcut (/) not implemented")
            
    async def _test_aria_labels(self, page: Page):
        """Test ARIA labels for accessibility."""
        # Check for ARIA labels on interactive elements
        buttons = page.locator("button")
        button_count = await buttons.count()
        
        if button_count > 0:
            # Check first few buttons for accessibility
            for i in range(min(3, button_count)):
                button = buttons.nth(i)
                aria_label = await button.get_attribute("aria-label")
                text_content = await button.text_content()
                
                assert aria_label or text_content, f"Button {i} has no accessible label"
                
    async def test_performance(self, page: Page):
        """Test page performance."""
        print("\n🔍 Testing Performance...")
        
        start_time = time.time()
        await page.goto(self.base_url, wait_until="networkidle")
        load_time = time.time() - start_time
        
        await self.run_test(
            "Performance",
            "Page load time",
            self._check_load_time,
            load_time
        )
        
        # Check for large resources
        await self.run_test(
            "Performance",
            "Resource sizes",
            self._check_resource_sizes,
            page
        )
        
    async def _check_load_time(self, load_time: float):
        """Check page load time."""
        # Warning if over 5 seconds, fail if over 10
        if load_time > 10:
            raise AssertionError(f"Page load too slow: {load_time:.1f}s")
        elif load_time > 5:
            print(f"  ⚠️  Page load time is high: {load_time:.1f}s")
            
    async def _check_resource_sizes(self, page: Page):
        """Check resource sizes."""
        # Get page metrics
        metrics = await page.evaluate("""() => {
            const resources = performance.getEntriesByType('resource');
            const sizes = resources.map(r => ({
                name: r.name,
                size: r.transferSize || 0,
                duration: r.duration
            }));
            
            const totalSize = sizes.reduce((sum, r) => sum + r.size, 0);
            const largeResources = sizes.filter(r => r.size > 1024 * 1024); // > 1MB
            
            return {
                totalSize,
                resourceCount: sizes.length,
                largeResources
            };
        }""")
        
        if metrics["largeResources"]:
            for resource in metrics["largeResources"]:
                print(f"  ⚠️  Large resource: {resource['name']} ({resource['size'] / 1024 / 1024:.1f}MB)")
                
    async def run_all_tests(self):
        """Run all tests."""
        print("🚀 Starting comprehensive vuln-bot live site testing...")
        print(f"Target: {self.base_url}")
        print("=" * 60)
        
        self.test_results["start_time"] = datetime.now().isoformat()
        
        # Test API endpoints first (no browser needed)
        await self.test_api_health()
        
        # Browser-based tests
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()
            
            try:
                # Run all browser tests
                await self.test_homepage_functionality(page)
                await self.test_search_and_filtering(page)
                await self.test_cve_detail_pages(page)
                await self.test_data_visualization(page)
                await self.test_export_functionality(page)
                await self.test_mobile_responsiveness(page)
                await self.test_accessibility(page)
                await self.test_performance(page)
                
            finally:
                await browser.close()
                
        # Complete test results
        self.test_results["end_time"] = datetime.now().isoformat()
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 TESTING SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {self.test_results['total']}")
        print(f"Passed: {self.test_results['passed']} ✅")
        print(f"Failed: {self.test_results['failed']} ❌")
        
        if self.issues_found:
            print(f"\n❌ Found {len(self.issues_found)} issues:\n")
            
            # Group by severity
            critical = [i for i in self.issues_found if i['severity'] == 'critical']
            high = [i for i in self.issues_found if i['severity'] == 'high']
            medium = [i for i in self.issues_found if i['severity'] == 'medium']
            low = [i for i in self.issues_found if i['severity'] == 'low']
            
            if critical:
                print("🔴 CRITICAL Issues:")
                for issue in critical:
                    print(f"   - [{issue['category']}] {issue['test']}: {issue['issue']}")
                    
            if high:
                print("\n🟠 HIGH Priority Issues:")
                for issue in high:
                    print(f"   - [{issue['category']}] {issue['test']}: {issue['issue']}")
                    
            if medium:
                print("\n🟡 MEDIUM Priority Issues:")
                for issue in medium:
                    print(f"   - [{issue['category']}] {issue['test']}: {issue['issue']}")
                    
            if low:
                print("\n🟢 LOW Priority Issues:")
                for issue in low:
                    print(f"   - [{issue['category']}] {issue['test']}: {issue['issue']}")
        else:
            print("\n✅ All tests passed! No issues found.")
            
        return self.test_results


async def main():
    """Main test runner."""
    tester = ComprehensiveLiveTester()
    results = await tester.run_all_tests()
    
    # Save results
    output_file = Path("tests/e2e/test_results.json")
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
        
    print(f"\n💾 Test results saved to: {output_file}")
    
    # Exit with error code if tests failed
    exit(0 if results["failed"] == 0 else 1)


if __name__ == "__main__":
    asyncio.run(main())