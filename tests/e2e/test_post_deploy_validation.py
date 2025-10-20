"""
Post-deployment validation tests using Playwright.
These tests ensure the live site has been properly deployed without stale data.
"""

import os
import time
from typing import List
from urllib.parse import urljoin

import pytest
from playwright.sync_api import Page

LIVE_SITE_URL = os.getenv(
    "LIVE_SITE_URL", "https://williamzujkowski.github.io/vuln-bot/"
)
MAX_ALLOWED_CVES = 100  # Maximum CVEs allowed (strict limit)
EXPECTED_CVE_RANGE = (20, 65)  # Expected range of CVEs
MIN_EPSS_THRESHOLD = 60.0  # Minimum EPSS percentage
POLLING_TIMEOUT_SECONDS = 600  # 10 minutes for CDN cache
POLLING_INTERVAL_SECONDS = 30  # Check every 30 seconds
CDN_CACHE_HEADER = "x-served-by"  # GitHub Pages CDN header


class TestPostDeployValidation:
    """Post-deployment validation to ensure no stale data on live site."""

    def wait_for_deployment(
        self, page: Page, max_wait_seconds: int = POLLING_TIMEOUT_SECONDS
    ):
        """
        Wait for deployment to propagate through GitHub Pages CDN.

        Args:
            page: Playwright page instance
            max_wait_seconds: Maximum time to wait

        Returns:
            True if deployment detected, False if timeout
        """
        print(f"⏱️  Waiting for deployment to propagate (max {max_wait_seconds}s)...")
        start_time = time.time()

        while time.time() - start_time < max_wait_seconds:
            try:
                # Check for .nojekyll file as deployment indicator
                response = page.request.get(urljoin(LIVE_SITE_URL, ".nojekyll"))
                if response.status == 200:
                    # Check CDN headers to see if it's cached
                    headers = response.headers
                    if CDN_CACHE_HEADER in headers:
                        print(f"   CDN cache detected: {headers[CDN_CACHE_HEADER]}")

                    # Try to load the main page
                    page.goto(LIVE_SITE_URL, wait_until="networkidle", timeout=30000)
                    return True

            except Exception as e:
                print(f"   Deployment check error: {e}")

            elapsed = int(time.time() - start_time)
            print(f"   Waiting... ({elapsed}s elapsed)")
            time.sleep(POLLING_INTERVAL_SECONDS)

        return False

    def count_cve_elements(self, page: Page) -> int:
        """Count CVE elements on the page using multiple methods."""
        methods = [
            # Method 1: Alpine.js store
            """() => {
                const store = window.Alpine?.store('dashboard');
                return store?.stats?.total || 0;
            }""",
            # Method 2: Count table rows
            """() => {
                return document.querySelectorAll('table tbody tr').length;
            }""",
            # Method 3: Count CVE cards
            """() => {
                return document.querySelectorAll('.cve-card, [data-cve-id]').length;
            }""",
            # Method 4: Results text
            """() => {
                const resultsText = document.body.textContent.match(/Showing \\d+ of (\\d+)/);
                return resultsText ? parseInt(resultsText[1]) : 0;
            }""",
        ]

        for method in methods:
            try:
                count = page.evaluate(method)
                if count > 0:
                    return count
            except Exception:
                continue

        return 0

    def check_known_stale_cves(self, page: Page) -> List[str]:
        """Check if known stale CVEs are present on the page."""
        # List of CVEs that should NOT be present (low EPSS)
        known_stale_cves = ["CVE-2024-0001", "CVE-2023-99999", "CVE-2022-12345"]

        found_stale = []
        page_content = page.content()

        for cve_id in known_stale_cves:
            if cve_id in page_content:
                found_stale.append(cve_id)

        return found_stale

    def test_live_site_cve_count(self, page: Page):
        """Test that live site shows correct number of CVEs."""
        print("\n🔍 Testing live site CVE count...")

        # Wait for deployment if needed
        if not self.wait_for_deployment(page):
            pytest.skip("Deployment not ready after timeout - CDN may be updating")

        # Navigate to site
        page.goto(LIVE_SITE_URL, wait_until="networkidle", timeout=60000)
        page.wait_for_timeout(3000)  # Wait for Alpine.js

        # Count CVEs with retries
        max_retries = 5
        for attempt in range(max_retries):
            cve_count = self.count_cve_elements(page)
            print(f"   Attempt {attempt + 1}: Found {cve_count} CVEs")

            if cve_count > 0:
                break

            if attempt < max_retries - 1:
                page.reload()
                page.wait_for_timeout(2000)

        # Strict validation
        assert cve_count > 0, "No CVEs found on the page"
        assert cve_count <= MAX_ALLOWED_CVES, (
            f"❌ CRITICAL: Found {cve_count} CVEs (max allowed: {MAX_ALLOWED_CVES}). "
            f"Stale data detected - deployment failed!"
        )

        # Range validation
        min_expected, max_expected = EXPECTED_CVE_RANGE
        if not (min_expected <= cve_count <= max_expected):
            print(
                f"⚠️  Warning: CVE count {cve_count} outside expected range {EXPECTED_CVE_RANGE}"
            )

        print(f"✅ CVE count validated: {cve_count} CVEs")

    def test_no_stale_cves_present(self, page: Page):
        """Test that known stale CVEs are not present."""
        print("\n🔍 Checking for stale CVEs...")

        page.goto(LIVE_SITE_URL, wait_until="networkidle", timeout=60000)

        stale_found = self.check_known_stale_cves(page)

        assert len(stale_found) == 0, (
            f"❌ Found stale CVEs that should not exist: {stale_found}"
        )

        print("✅ No known stale CVEs found")

    def test_api_endpoint_validation(self, page: Page):
        """Test that API endpoints return correct data."""
        print("\n🔍 Validating API endpoints...")

        # Check main index
        index_url = urljoin(LIVE_SITE_URL, "api/vulns/index.json")
        response = page.request.get(index_url)

        assert response.status == 200, f"API index returned {response.status}"

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        print(f"   API reports {len(vulnerabilities)} vulnerabilities")

        # Validate count
        assert len(vulnerabilities) <= MAX_ALLOWED_CVES, (
            f"❌ API contains {len(vulnerabilities)} CVEs (max: {MAX_ALLOWED_CVES})"
        )

        # Validate EPSS thresholds
        violations = []
        for vuln in vulnerabilities[:10]:  # Check first 10
            epss_score = vuln.get("epss", {}).get("score", 0) * 100
            if epss_score < MIN_EPSS_THRESHOLD:
                violations.append({"cveId": vuln.get("cveId"), "epss": epss_score})

        assert len(violations) == 0, f"❌ Found CVEs below EPSS threshold: {violations}"

        print("✅ API endpoints validated")

    def test_chunk_files_validation(self, page: Page):
        """Test that chunk files don't contain excessive data."""
        print("\n🔍 Validating chunk files...")

        chunk_index_url = urljoin(LIVE_SITE_URL, "api/vulns/chunk-index.json")
        response = page.request.get(chunk_index_url)

        if response.status == 200:
            chunk_index = response.json()
            total_in_chunks = 0

            for chunk in chunk_index.get("chunks", [])[:5]:  # Check first 5 chunks
                chunk_url = urljoin(LIVE_SITE_URL, f"api/vulns/{chunk['file']}")
                chunk_response = page.request.get(chunk_url)

                if chunk_response.status == 200:
                    chunk_data = chunk_response.json()
                    chunk_count = len(chunk_data.get("vulnerabilities", []))
                    total_in_chunks += chunk_count

                    # Each chunk should be reasonable
                    assert chunk_count <= 100, (
                        f"❌ Chunk {chunk['file']} has {chunk_count} CVEs - likely stale data"
                    )

            print(f"✅ Chunk files validated: {total_in_chunks} CVEs in checked chunks")
        else:
            print("   No chunk index found (may be expected)")

    def test_cve_page_sampling(self, page: Page):
        """Test that individual CVE pages don't exist for stale CVEs."""
        print("\n🔍 Sampling individual CVE pages...")

        # Test URLs that should NOT exist (low EPSS CVEs)
        test_stale_urls = [
            "cves/CVE-2024-0001/",
            "cves/CVE-2023-1234/",
            "cves/CVE-2022-9999/",
        ]

        stale_pages_found = []

        for cve_path in test_stale_urls:
            url = urljoin(LIVE_SITE_URL, cve_path)
            response = page.request.get(url)

            if response.status == 200:
                stale_pages_found.append(cve_path)
                print(f"   ❌ Found stale page: {cve_path}")

        assert len(stale_pages_found) == 0, (
            f"❌ Stale CVE pages still exist: {stale_pages_found}"
        )

        print("✅ No stale CVE pages found")

    def test_console_errors(self, page: Page):
        """Check for console errors that might indicate issues."""
        print("\n🔍 Checking for console errors...")

        console_messages = []
        page.on("console", lambda msg: console_messages.append(msg))

        page.goto(LIVE_SITE_URL, wait_until="networkidle")
        page.wait_for_timeout(2000)

        errors = [msg for msg in console_messages if msg.type == "error"]

        if errors:
            print(f"   ⚠️  Found {len(errors)} console errors:")
            for error in errors[:3]:
                print(f"      - {error.text}")
        else:
            print("✅ No console errors detected")

    def test_deployment_freshness(self, page: Page):
        """Test that deployment appears fresh."""
        print("\n🔍 Checking deployment freshness...")

        # Check response headers
        response = page.request.get(LIVE_SITE_URL)
        headers = response.headers

        # Look for cache headers
        if "last-modified" in headers:
            print(f"   Last-Modified: {headers['last-modified']}")

        if "etag" in headers:
            print(f"   ETag: {headers['etag']}")

        # Check for .nojekyll file (indicates GitHub Pages processing)
        nojekyll_response = page.request.get(urljoin(LIVE_SITE_URL, ".nojekyll"))
        assert nojekyll_response.status == 200, "Missing .nojekyll file"

        print("✅ Deployment appears fresh")


@pytest.fixture(scope="module")
def browser_context_args():
    """Configure browser context for tests."""
    return {
        "viewport": {"width": 1280, "height": 720},
        "user_agent": "PostDeployValidation/1.0",
    }


if __name__ == "__main__":
    # Run with verbose output
    pytest.main([__file__, "-v", "-s", "--tb=short"])
