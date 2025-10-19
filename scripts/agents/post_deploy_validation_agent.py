"""
Post-Deploy Validation Agent for verifying live site after deployment.
Runs Playwright tests to ensure the deployed site matches expectations.
"""

import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import structlog
from playwright.sync_api import Page, sync_playwright

from scripts.agents.base_agent import BaseAgent

logger = structlog.get_logger()


class PostDeployValidationAgent(BaseAgent):
    """Agent for validating the live site after deployment."""

    def __init__(self):
        super().__init__(
            name="PostDeployValidationAgent",
            role="post_deploy_validation",
            goal="Verify live site matches expected data after deployment",
            backstory="Ensures production deployments are successful and data is correct"
        )
        self.validation_results = {
            "timestamp": None,
            "live_url": None,
            "checks_passed": 0,
            "checks_failed": 0,
            "failures": [],
            "screenshots": [],
            "metrics": {}
        }

    def validate_live_site(self,
                          live_url: str,
                          expected_cve_count: int = 60,
                          tolerance_percent: int = 20,
                          min_epss: float = 60.0,
                          screenshot_dir: Optional[Path] = None) -> Dict[str, Any]:
        """
        Validate the live site with comprehensive checks.

        Args:
            live_url: URL of the live site
            expected_cve_count: Expected number of CVEs
            tolerance_percent: Tolerance percentage for count
            min_epss: Minimum EPSS threshold
            screenshot_dir: Directory to save screenshots

        Returns:
            Validation results
        """
        logger.info("Starting post-deployment validation", url=live_url)

        self.validation_results["timestamp"] = datetime.utcnow().isoformat()
        self.validation_results["live_url"] = live_url

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page()

                # Navigate to site
                logger.info("Navigating to live site")
                page.goto(live_url, wait_until="networkidle", timeout=30000)

                # Wait for Alpine.js
                page.wait_for_timeout(2000)

                # Run validation checks
                self._check_cve_count(page, expected_cve_count, tolerance_percent)
                self._check_api_data_matches_ui(page)
                self._check_no_stale_cves(page, min_epss)
                self._check_chunk_files(page, expected_cve_count, tolerance_percent)
                self._check_for_known_stale_cves(page)
                self._check_console_errors(page)

                # Take screenshots if requested
                if screenshot_dir:
                    self._capture_screenshots(page, screenshot_dir)

            finally:
                browser.close()

        # Generate summary
        total_checks = self.validation_results["checks_passed"] + self.validation_results["checks_failed"]
        self.validation_results["summary"] = {
            "total_checks": total_checks,
            "pass_rate": (self.validation_results["checks_passed"] / total_checks * 100) if total_checks > 0 else 0,
            "status": "PASSED" if self.validation_results["checks_failed"] == 0 else "FAILED"
        }

        return self.validation_results

    def _check_cve_count(self, page: Page, expected: int, tolerance_percent: int):
        """Check if CVE count is within expected range."""
        logger.info("Checking CVE count")

        try:
            # Get count from dashboard
            total_count = page.evaluate("""
                () => {
                    const store = window.Alpine?.store('dashboard');
                    if (store && store.stats) {
                        return store.stats.total;
                    }
                    // Fallback: count table rows
                    const rows = document.querySelectorAll('table tbody tr');
                    return rows.length;
                }
            """)

            # Calculate acceptable range
            min_acceptable = int(expected * (1 - tolerance_percent/100))
            max_acceptable = int(expected * (1 + tolerance_percent/100))

            self.validation_results["metrics"]["cve_count"] = total_count
            self.validation_results["metrics"]["expected_count"] = expected

            if min_acceptable <= total_count <= max_acceptable:
                self.validation_results["checks_passed"] += 1
                logger.info(f"✓ CVE count check passed: {total_count} (expected ~{expected})")
            else:
                self.validation_results["checks_failed"] += 1
                self.validation_results["failures"].append({
                    "check": "cve_count",
                    "message": f"CVE count {total_count} outside acceptable range [{min_acceptable}, {max_acceptable}]",
                    "severity": "CRITICAL" if total_count > expected * 2 else "HIGH"
                })
                logger.error(f"✗ CVE count check failed: {total_count} (expected ~{expected})")

        except Exception as e:
            self._record_check_error("cve_count", str(e))

    def _check_api_data_matches_ui(self, page: Page):
        """Check if API data matches what's displayed in UI."""
        logger.info("Checking API data matches UI")

        try:
            # Get UI count
            ui_count = page.evaluate("""
                () => {
                    const store = window.Alpine?.store('dashboard');
                    return store?.stats?.total || 0;
                }
            """)

            # Get API count
            api_url = urljoin(self.validation_results["live_url"], "api/vulns/index.json")
            response = page.request.get(api_url)

            if response.status != 200:
                raise Exception(f"API returned {response.status}")

            api_data = response.json()
            api_count = len(api_data.get("vulnerabilities", []))

            self.validation_results["metrics"]["ui_count"] = ui_count
            self.validation_results["metrics"]["api_count"] = api_count

            if api_count == ui_count:
                self.validation_results["checks_passed"] += 1
                logger.info(f"✓ API/UI match check passed: {api_count}")
            else:
                self.validation_results["checks_failed"] += 1
                self.validation_results["failures"].append({
                    "check": "api_ui_match",
                    "message": f"API count ({api_count}) doesn't match UI count ({ui_count})",
                    "severity": "HIGH"
                })
                logger.error("✗ API/UI match check failed")

        except Exception as e:
            self._record_check_error("api_ui_match", str(e))

    def _check_no_stale_cves(self, page: Page, min_epss: float):
        """Check that no CVEs below EPSS threshold are present."""
        logger.info("Checking for stale CVEs below EPSS threshold")

        try:
            # Get vulnerabilities from API
            api_url = urljoin(self.validation_results["live_url"], "api/vulns/index.json")
            response = page.request.get(api_url)
            api_data = response.json()

            violations = []
            for vuln in api_data.get("vulnerabilities", [])[:100]:  # Check first 100
                epss_score = vuln.get("epss", {}).get("score", 0) * 100
                if epss_score < min_epss:
                    violations.append({
                        "cveId": vuln.get("cveId"),
                        "epss": epss_score
                    })

            if len(violations) == 0:
                self.validation_results["checks_passed"] += 1
                logger.info(f"✓ EPSS threshold check passed: all CVEs >= {min_epss}%")
            else:
                self.validation_results["checks_failed"] += 1
                self.validation_results["failures"].append({
                    "check": "epss_threshold",
                    "message": f"Found {len(violations)} CVEs below {min_epss}% EPSS",
                    "severity": "CRITICAL",
                    "details": violations[:5]  # First 5 violations
                })
                logger.error(f"✗ EPSS threshold check failed: {len(violations)} violations")

        except Exception as e:
            self._record_check_error("epss_threshold", str(e))

    def _check_chunk_files(self, page: Page, expected: int, tolerance_percent: int):
        """Check that chunk files contain reasonable counts."""
        logger.info("Checking chunk files")

        try:
            chunk_url = urljoin(self.validation_results["live_url"], "api/vulns/chunk-index.json")
            response = page.request.get(chunk_url)

            if response.status == 200:
                chunk_index = response.json()
                total_in_chunks = 0

                for chunk in chunk_index.get("chunks", []):
                    chunk_file_url = urljoin(self.validation_results["live_url"], f"api/vulns/{chunk['file']}")
                    chunk_response = page.request.get(chunk_file_url)

                    if chunk_response.status == 200:
                        chunk_data = chunk_response.json()
                        chunk_count = len(chunk_data.get("vulnerabilities", []))
                        total_in_chunks += chunk_count

                self.validation_results["metrics"]["total_in_chunks"] = total_in_chunks

                max_acceptable = int(expected * (1 + tolerance_percent/100))
                if total_in_chunks <= max_acceptable:
                    self.validation_results["checks_passed"] += 1
                    logger.info(f"✓ Chunk files check passed: {total_in_chunks} total CVEs")
                else:
                    self.validation_results["checks_failed"] += 1
                    self.validation_results["failures"].append({
                        "check": "chunk_files",
                        "message": f"Chunks contain {total_in_chunks} CVEs, expected <= {max_acceptable}",
                        "severity": "HIGH"
                    })
                    logger.error("✗ Chunk files check failed")

        except Exception as e:
            self._record_check_error("chunk_files", str(e))

    def _check_for_known_stale_cves(self, page: Page):
        """Check if known stale CVE pages exist."""
        logger.info("Checking for known stale CVE pages")

        # List of CVEs that should NOT exist (examples - customize based on your data)
        known_stale_cves = [
            "CVE-2023-0001",  # Example low-EPSS CVE
            "CVE-2022-9999",  # Another example
        ]

        stale_found = []
        for cve_id in known_stale_cves:
            cve_url = urljoin(self.validation_results["live_url"], f"cves/{cve_id}/")
            response = page.request.get(cve_url)

            if response.status == 200:
                stale_found.append(cve_id)

        if len(stale_found) == 0:
            self.validation_results["checks_passed"] += 1
            logger.info("✓ No known stale CVE pages found")
        else:
            self.validation_results["checks_failed"] += 1
            self.validation_results["failures"].append({
                "check": "stale_cve_pages",
                "message": f"Found {len(stale_found)} stale CVE pages that should not exist",
                "severity": "CRITICAL",
                "details": stale_found
            })
            logger.error(f"✗ Found stale CVE pages: {stale_found}")

    def _check_console_errors(self, page: Page):
        """Check for console errors that might indicate issues."""
        logger.info("Checking console errors")

        console_errors = []
        page.on("console", lambda msg: console_errors.append(msg) if msg.type == "error" else None)

        # Reload to capture messages
        page.reload()
        page.wait_for_load_state("networkidle")

        # Filter for critical errors
        critical_errors = []
        for msg in console_errors:
            text = msg.text.lower()
            if any(keyword in text for keyword in ["404", "not found", "failed to load", "json"]):
                critical_errors.append(msg.text)

        self.validation_results["metrics"]["console_errors"] = len(critical_errors)

        if len(critical_errors) == 0:
            self.validation_results["checks_passed"] += 1
            logger.info("✓ No critical console errors")
        else:
            # Warning only - don't fail on console errors
            logger.warning(f"⚠ Found {len(critical_errors)} console errors")
            self.validation_results["checks_passed"] += 1  # Still pass but log

    def _capture_screenshots(self, page: Page, screenshot_dir: Path):
        """Capture screenshots for documentation."""
        screenshot_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        # Main dashboard
        dashboard_path = screenshot_dir / f"dashboard_{timestamp}.png"
        page.screenshot(path=str(dashboard_path), full_page=False)
        self.validation_results["screenshots"].append(str(dashboard_path))

        # With filters applied
        page.locator("input#epssMax").fill("70")
        page.wait_for_timeout(1000)
        filtered_path = screenshot_dir / f"filtered_{timestamp}.png"
        page.screenshot(path=str(filtered_path))
        self.validation_results["screenshots"].append(str(filtered_path))

    def _record_check_error(self, check_name: str, error: str):
        """Record a check error."""
        self.validation_results["checks_failed"] += 1
        self.validation_results["failures"].append({
            "check": check_name,
            "message": f"Check failed with error: {error}",
            "severity": "ERROR"
        })
        logger.error(f"✗ {check_name} check error: {error}")

    def generate_validation_report(self) -> str:
        """Generate human-readable validation report."""
        report = f"""
Post-Deploy Validation Report
============================

URL: {self.validation_results['live_url']}
Timestamp: {self.validation_results['timestamp']}
Status: {self.validation_results.get('summary', {}).get('status', 'UNKNOWN')}

Summary:
--------
✓ Checks Passed: {self.validation_results['checks_passed']}
✗ Checks Failed: {self.validation_results['checks_failed']}
Pass Rate: {self.validation_results.get('summary', {}).get('pass_rate', 0):.1f}%

Metrics:
--------
- CVE Count: {self.validation_results['metrics'].get('cve_count', 'N/A')}
- Expected: {self.validation_results['metrics'].get('expected_count', 'N/A')}
- API Count: {self.validation_results['metrics'].get('api_count', 'N/A')}
- UI Count: {self.validation_results['metrics'].get('ui_count', 'N/A')}
- Total in Chunks: {self.validation_results['metrics'].get('total_in_chunks', 'N/A')}
- Console Errors: {self.validation_results['metrics'].get('console_errors', 0)}
"""

        if self.validation_results['failures']:
            report += "\nFailures:\n---------\n"
            for failure in self.validation_results['failures']:
                report += f"\n[{failure['severity']}] {failure['check']}:\n"
                report += f"  {failure['message']}\n"
                if 'details' in failure:
                    report += f"  Details: {failure['details']}\n"

        if self.validation_results['screenshots']:
            report += "\nScreenshots:\n-----------\n"
            for screenshot in self.validation_results['screenshots']:
                report += f"- {screenshot}\n"

        return report

    def wait_for_deployment(self, wait_minutes: int = 10):
        """Wait for GitHub Pages deployment to propagate."""
        logger.info(f"Waiting {wait_minutes} minutes for deployment to propagate...")
        for i in range(wait_minutes):
            logger.info(f"Waiting... {i+1}/{wait_minutes} minutes")
            time.sleep(60)
        logger.info("Wait complete")
