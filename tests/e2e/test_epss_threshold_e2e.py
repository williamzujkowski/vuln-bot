#!/usr/bin/env python3
"""
End-to-end tests for EPSS threshold enforcement on the live site.
"""

import asyncio
import json
import time
from typing import Dict

try:
    import aiohttp
    from playwright.async_api import Page, async_playwright
except ImportError:
    playwright = None
    import pytest

    pytest.skip("Playwright not installed", allow_module_level=True)


class EPSSThresholdE2ETester:
    """E2E tester for EPSS threshold validation."""

    def __init__(self, base_url: str = "https://williamzujkowski.github.io/vuln-bot"):
        self.base_url = base_url
        self.expected_threshold = 60  # 60% minimum EPSS

    async def test_api_epss_compliance(self) -> Dict[str, any]:
        """Test that all API endpoints return only EPSS >= 60% vulnerabilities."""
        results = {
            "passed": True,
            "violations": [],
            "total_vulns": 0,
            "min_epss": None,
            "max_epss": None,
            "avg_epss": None,
        }

        async with aiohttp.ClientSession() as session:
            # Test main index endpoint
            try:
                async with session.get(
                    f"{self.base_url}/api/vulns/index.json"
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        vulnerabilities = data.get("vulnerabilities", [])
                        results["total_vulns"] = len(vulnerabilities)

                        epss_scores = []
                        violations = []

                        for vuln in vulnerabilities:
                            epss_score = vuln.get("epssScore")
                            if epss_score is not None:
                                epss_scores.append(epss_score)
                                if epss_score < self.expected_threshold:
                                    violations.append(
                                        {
                                            "cveId": vuln.get("cveId"),
                                            "epssScore": epss_score,
                                            "violation": f"EPSS {epss_score}% < {self.expected_threshold}%",
                                        }
                                    )

                        if epss_scores:
                            results["min_epss"] = min(epss_scores)
                            results["max_epss"] = max(epss_scores)
                            results["avg_epss"] = sum(epss_scores) / len(epss_scores)

                        results["violations"] = violations
                        results["passed"] = len(violations) == 0

            except Exception as e:
                results["passed"] = False
                results["error"] = str(e)

        return results

    async def test_chunk_epss_compliance(self) -> Dict[str, any]:
        """Test that all chunk files comply with EPSS threshold."""
        results = {
            "passed": True,
            "chunks_tested": 0,
            "violations": [],
            "total_vulns_across_chunks": 0,
        }

        async with aiohttp.ClientSession() as session:
            try:
                # Get chunk index
                async with session.get(
                    f"{self.base_url}/api/vulns/chunk-index.json"
                ) as response:
                    if response.status == 200:
                        chunk_index = await response.json()
                        chunks = chunk_index.get("chunks", [])

                        for chunk in chunks:
                            chunk_file = chunk.get("file")
                            if chunk_file:
                                try:
                                    async with session.get(
                                        f"{self.base_url}/api/vulns/{chunk_file}"
                                    ) as chunk_response:
                                        if chunk_response.status == 200:
                                            chunk_data = await chunk_response.json()
                                            vulnerabilities = chunk_data.get(
                                                "vulnerabilities", []
                                            )
                                            results["chunks_tested"] += 1
                                            results["total_vulns_across_chunks"] += len(
                                                vulnerabilities
                                            )

                                            for vuln in vulnerabilities:
                                                epss_score = vuln.get("epssScore")
                                                if (
                                                    epss_score is not None
                                                    and epss_score
                                                    < self.expected_threshold
                                                ):
                                                    results["violations"].append(
                                                        {
                                                            "chunk": chunk_file,
                                                            "cveId": vuln.get("cveId"),
                                                            "epssScore": epss_score,
                                                            "violation": f"EPSS {epss_score}% < {self.expected_threshold}%",
                                                        }
                                                    )
                                except Exception as e:
                                    results["violations"].append(
                                        {
                                            "chunk": chunk_file,
                                            "error": f"Failed to fetch chunk: {str(e)}",
                                        }
                                    )

                        results["passed"] = len(results["violations"]) == 0

            except Exception as e:
                results["passed"] = False
                results["error"] = str(e)

        return results

    async def test_dashboard_epss_filter_default(self, page: Page) -> Dict[str, any]:
        """Test that dashboard defaults to 60% EPSS filter."""
        results = {"passed": True, "default_value": None, "error": None}

        try:
            await page.goto(self.base_url)
            await page.wait_for_load_state("networkidle")

            # Look for EPSS filter input
            epss_selectors = [
                'input[placeholder*="EPSS" i]',
                'input[id*="epss" i]',
                'input[name*="epss" i]',
                '[x-model*="epss" i]',
            ]

            epss_input = None
            for selector in epss_selectors:
                if await page.locator(selector).count() > 0:
                    epss_input = page.locator(selector).first
                    break

            if epss_input:
                # Check default value
                default_value = await epss_input.input_value()
                results["default_value"] = default_value

                # Should default to 60
                if default_value != "60":
                    results["passed"] = False
                    results["error"] = (
                        f"Expected default EPSS filter to be 60, got {default_value}"
                    )
            else:
                results["passed"] = False
                results["error"] = "EPSS filter input not found"

        except Exception as e:
            results["passed"] = False
            results["error"] = str(e)

        return results

    async def test_dashboard_epss_filter_functionality(
        self, page: Page
    ) -> Dict[str, any]:
        """Test that EPSS filter works correctly on the dashboard."""
        results = {"passed": True, "tests": [], "error": None}

        try:
            await page.goto(self.base_url)
            await page.wait_for_load_state("networkidle")

            # Find EPSS filter input
            epss_input = None
            epss_selectors = [
                'input[placeholder*="EPSS" i]',
                'input[id*="epss" i]',
                'input[name*="epss" i]',
            ]

            for selector in epss_selectors:
                if await page.locator(selector).count() > 0:
                    epss_input = page.locator(selector).first
                    break

            if epss_input:
                test_cases = [
                    {"value": "90", "name": "High threshold (90%)"},
                    {"value": "60", "name": "Default threshold (60%)"},
                    {"value": "80", "name": "Medium threshold (80%)"},
                ]

                for test_case in test_cases:
                    test_result = {
                        "name": test_case["name"],
                        "passed": True,
                        "visible_rows": 0,
                        "error": None,
                    }

                    try:
                        # Set filter value
                        await epss_input.fill(test_case["value"])
                        await page.wait_for_timeout(1000)  # Wait for debounce

                        # Count visible rows
                        visible_rows = await page.locator("tbody tr:visible").count()
                        test_result["visible_rows"] = visible_rows

                        # Should have some results for reasonable thresholds
                        if int(test_case["value"]) <= 95 and visible_rows == 0:
                            test_result["passed"] = False
                            test_result["error"] = (
                                f"No results for {test_case['value']}% threshold"
                            )

                    except Exception as e:
                        test_result["passed"] = False
                        test_result["error"] = str(e)

                    results["tests"].append(test_result)
                    if not test_result["passed"]:
                        results["passed"] = False
            else:
                results["passed"] = False
                results["error"] = "EPSS filter input not found"

        except Exception as e:
            results["passed"] = False
            results["error"] = str(e)

        return results

    async def test_vulnerability_table_epss_display(self, page: Page) -> Dict[str, any]:
        """Test that vulnerability table displays EPSS scores correctly."""
        results = {
            "passed": True,
            "vulnerabilities_checked": 0,
            "violations": [],
            "error": None,
        }

        try:
            await page.goto(self.base_url)
            await page.wait_for_load_state("networkidle")

            # Wait for table to load
            await page.wait_for_selector("tbody tr", timeout=10000)

            # Get first few rows
            rows = await page.locator("tbody tr").all()

            for i, row in enumerate(rows[:10]):  # Check first 10 rows
                try:
                    row_text = await row.text_content()

                    # Look for EPSS score in the row (should be percentage)
                    # Common formats: "85.5%", "90.1%", etc.
                    import re

                    epss_matches = re.findall(r"(\d{1,2}(?:\.\d+)?%)", row_text)

                    if epss_matches:
                        for match in epss_matches:
                            epss_value = float(match.replace("%", ""))
                            if epss_value < self.expected_threshold:
                                # Get CVE ID from the row
                                cve_match = re.search(r"CVE-\d{4}-\d+", row_text)
                                cve_id = (
                                    cve_match.group(0) if cve_match else f"Row {i+1}"
                                )

                                results["violations"].append(
                                    {
                                        "cveId": cve_id,
                                        "epssScore": epss_value,
                                        "violation": f"EPSS {epss_value}% < {self.expected_threshold}%",
                                    }
                                )

                    results["vulnerabilities_checked"] += 1

                except Exception:
                    # Skip individual row errors
                    continue

            results["passed"] = len(results["violations"]) == 0

        except Exception as e:
            results["passed"] = False
            results["error"] = str(e)

        return results

    async def run_all_tests(self) -> Dict[str, any]:
        """Run all EPSS threshold E2E tests."""
        test_results = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "expected_threshold": self.expected_threshold,
            "tests": {},
            "overall_passed": True,
        }

        print(f"🧪 Running EPSS Threshold E2E Tests (≥{self.expected_threshold}%)")
        print("=" * 60)

        # API compliance tests
        print("🔍 Testing API EPSS Compliance...")
        api_results = await self.test_api_epss_compliance()
        test_results["tests"]["api_compliance"] = api_results

        if api_results["passed"]:
            print(
                f"✅ API Compliance: {api_results['total_vulns']} vulnerabilities, "
                f"EPSS range {api_results['min_epss']:.1f}%-{api_results['max_epss']:.1f}%"
            )
        else:
            print(
                f"❌ API Compliance: {len(api_results.get('violations', []))} violations found"
            )
            test_results["overall_passed"] = False

        # Chunk compliance tests
        print("🔍 Testing Chunk EPSS Compliance...")
        chunk_results = await self.test_chunk_epss_compliance()
        test_results["tests"]["chunk_compliance"] = chunk_results

        if chunk_results["passed"]:
            print(
                f"✅ Chunk Compliance: {chunk_results['chunks_tested']} chunks, "
                f"{chunk_results['total_vulns_across_chunks']} total vulnerabilities"
            )
        else:
            print(
                f"❌ Chunk Compliance: {len(chunk_results.get('violations', []))} violations found"
            )
            test_results["overall_passed"] = False

        # Browser-based tests
        print("🔍 Testing Dashboard EPSS Filter...")
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            try:
                # Test default filter value
                default_results = await self.test_dashboard_epss_filter_default(page)
                test_results["tests"]["dashboard_default"] = default_results

                if default_results["passed"]:
                    print(
                        f"✅ Dashboard Default: EPSS filter defaults to {default_results['default_value']}%"
                    )
                else:
                    print(f"❌ Dashboard Default: {default_results['error']}")
                    test_results["overall_passed"] = False

                # Test filter functionality
                filter_results = await self.test_dashboard_epss_filter_functionality(
                    page
                )
                test_results["tests"]["dashboard_filter"] = filter_results

                if filter_results["passed"]:
                    print(
                        f"✅ Dashboard Filter: {len(filter_results['tests'])} test cases passed"
                    )
                else:
                    print("❌ Dashboard Filter: Some test cases failed")
                    test_results["overall_passed"] = False

                # Test table display
                table_results = await self.test_vulnerability_table_epss_display(page)
                test_results["tests"]["table_display"] = table_results

                if table_results["passed"]:
                    print(
                        f"✅ Table Display: {table_results['vulnerabilities_checked']} vulnerabilities checked"
                    )
                else:
                    print(
                        f"❌ Table Display: {len(table_results.get('violations', []))} violations found"
                    )
                    test_results["overall_passed"] = False

            finally:
                await browser.close()

        # Summary
        print("\n" + "=" * 60)
        if test_results["overall_passed"]:
            print("🎉 All EPSS Threshold E2E Tests PASSED!")
        else:
            print("⚠️  Some EPSS Threshold E2E Tests FAILED!")

            # Show violations summary
            all_violations = []
            for _test_name, test_result in test_results["tests"].items():
                violations = test_result.get("violations", [])
                if violations:
                    all_violations.extend(violations)

            if all_violations:
                print(f"\n🚨 Found {len(all_violations)} total violations:")
                for violation in all_violations[:10]:  # Show first 10
                    print(
                        f"   - {violation.get('cveId', 'Unknown')}: {violation.get('violation', 'Unknown issue')}"
                    )
                if len(all_violations) > 10:
                    print(f"   ... and {len(all_violations) - 10} more")

        return test_results


async def main():
    """Main test runner."""
    tester = EPSSThresholdE2ETester()
    results = await tester.run_all_tests()

    # Save results
    output_file = Path("tests/e2e/epss_threshold_results.json")
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n💾 Results saved to: {output_file}")

    # Exit with error code if tests failed
    exit(0 if results["overall_passed"] else 1)


if __name__ == "__main__":
    from pathlib import Path

    asyncio.run(main())
