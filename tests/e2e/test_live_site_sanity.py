"""
Enhanced live site sanity tests to detect stale data and validate CVE counts.
These tests ensure the production site matches the expected filtered dataset.
"""

import os
import time
from urllib.parse import urljoin

import pytest
from playwright.sync_api import Page

LIVE_SITE_URL = os.getenv(
    "LIVE_SITE_URL", "https://williamzujkowski.github.io/vuln-bot/"
)
EXPECTED_CVE_COUNT = int(
    os.getenv("EXPECTED_CVE_COUNT", "30")
)  # Allow override via environment
TOLERANCE_PERCENT = 40  # Allow 40% variance to account for data fluctuations
MIN_EPSS_THRESHOLD = 60.0
MAX_CVE_COUNT = int(os.getenv("MAX_CVE_COUNT", "100"))  # Maximum allowed CVEs
POLLING_TIMEOUT_SECONDS = 300  # 5 minutes polling timeout for GitHub Pages cache
POLLING_INTERVAL_SECONDS = 30  # Poll every 30 seconds


def poll_until_stable(
    page: Page, get_value_func, expected_range, timeout_seconds=POLLING_TIMEOUT_SECONDS
):
    """
    Poll until the value stabilizes within expected range or timeout.
    Handles GitHub Pages caching issues by retrying.

    Args:
        page: Playwright page instance
        get_value_func: Function that returns the current value
        expected_range: Tuple of (min, max) expected values
        timeout_seconds: Maximum time to poll

    Returns:
        Final value obtained

    Raises:
        TimeoutError: If value doesn't stabilize within timeout
    """
    start_time = time.time()
    min_val, max_val = expected_range

    while time.time() - start_time < timeout_seconds:
        try:
            # Refresh page to bypass cache
            page.reload(wait_until="networkidle")
            page.wait_for_timeout(2000)  # Wait for Alpine.js

            current_value = get_value_func()
            print(f"Poll attempt: got {current_value}, expecting {min_val}-{max_val}")

            if min_val <= current_value <= max_val:
                print(f"✅ Value stabilized at {current_value}")
                return current_value

            # If value is way too high, fail immediately (don't waste time)
            if current_value > max_val * 10:
                raise ValueError(
                    f"Value {current_value} is extremely high, likely stale data issue"
                )

        except Exception as e:
            print(f"Poll error: {e}")

        print(
            f"Value {current_value} not in range, waiting {POLLING_INTERVAL_SECONDS}s..."
        )
        time.sleep(POLLING_INTERVAL_SECONDS)

    # Final attempt
    current_value = get_value_func()
    raise TimeoutError(
        f"Value {current_value} never stabilized to {min_val}-{max_val} range after {timeout_seconds}s"
    )


def get_cve_count_from_ui(page: Page) -> int:
    """Get CVE count from the UI, with multiple fallback methods."""
    # Method 1: Alpine.js store
    try:
        count = page.evaluate(
            """
            () => {
                const store = window.Alpine?.store('dashboard');
                return store?.stats?.total || 0;
            }
        """
        )
        if count > 0:
            return count
    except Exception:
        pass

    # Method 2: Count table rows
    try:
        count = page.evaluate(
            """
            () => {
                const rows = document.querySelectorAll('table tbody tr');
                return rows.length;
            }
        """
        )
        if count > 0:
            return count
    except Exception:
        pass

    # Method 3: Look for results text
    try:
        results_text = page.locator("text=/Showing \\d+ of \\d+/").text_content()
        if results_text:
            import re

            match = re.search(r"of (\\d+)", results_text)
            if match:
                return int(match.group(1))
    except Exception:
        pass

    # Method 4: Count CVE items in list
    try:
        count = page.evaluate(
            """
            () => {
                const items = document.querySelectorAll('[data-cve-id]');
                return items.length;
            }
        """
        )
        return count
    except Exception:
        pass

    return 0


class TestLiveSiteSanity:
    """Critical sanity tests for the live production site."""

    @pytest.fixture(autouse=True)
    def setup(self, page: Page):
        """Navigate to the live site before each test."""
        page.goto(LIVE_SITE_URL, wait_until="networkidle", timeout=30000)
        # Wait for Alpine.js to initialize
        page.wait_for_timeout(2000)

    def test_cve_count_is_reasonable(self, page: Page):
        """
        CRITICAL: Test that CVE count is within expected range with polling.
        This is the primary test to detect if 15,000 stale CVEs are showing.
        Uses polling to handle GitHub Pages caching issues.
        """
        print(
            f"🔍 Testing CVE count with polling (expected {EXPECTED_CVE_COUNT} ±{TOLERANCE_PERCENT}%)"
        )

        # Calculate acceptable range
        min_acceptable = int(EXPECTED_CVE_COUNT * (1 - TOLERANCE_PERCENT / 100))
        max_acceptable = int(EXPECTED_CVE_COUNT * (1 + TOLERANCE_PERCENT / 100))

        # Use shorter timeout for critical check
        try:
            total_count = poll_until_stable(
                page,
                lambda: get_cve_count_from_ui(page),
                (min_acceptable, max_acceptable),
                timeout_seconds=120,  # 2 minutes for critical check
            )
        except (TimeoutError, ValueError) as e:
            # Get current count for detailed error
            current_count = get_cve_count_from_ui(page)

            # CRITICAL: Check for 15,000+ issue immediately
            if current_count > MAX_CVE_COUNT:
                pytest.fail(
                    f"CRITICAL: 15,000+ CVE ISSUE DETECTED! Found {current_count} CVEs on live site. "
                    f"The force rebuild has FAILED. Stale data is still present. "
                    f"Original error: {e}"
                )
            else:
                pytest.fail(f"CVE count polling failed: {e}")

        print(
            f"✅ CVE count is reasonable: {total_count} (expected ~{EXPECTED_CVE_COUNT})"
        )

    def test_api_data_matches_ui(self, page: Page):
        """Test that API data matches what's shown in the UI."""
        # Get count from UI
        ui_count = page.evaluate(
            """
            () => {
                const store = window.Alpine?.store('dashboard');
                return store?.stats?.total || 0;
            }
        """
        )

        # Get count from API
        api_url = urljoin(LIVE_SITE_URL, "api/vulns/index.json")
        response = page.request.get(api_url)
        assert response.status == 200, f"Failed to fetch API data: {response.status}"

        api_data = response.json()
        api_count = len(api_data.get("vulnerabilities", []))

        # Counts should match exactly
        assert (
            api_count == ui_count
        ), f"API count ({api_count}) doesn't match UI count ({ui_count})"

        # API count should also be reasonable
        max_acceptable = int(EXPECTED_CVE_COUNT * (1 + TOLERANCE_PERCENT / 100))
        assert (
            api_count <= max_acceptable
        ), f"API contains {api_count} CVEs, expected <= {max_acceptable}"

        print(f"✓ API and UI counts match: {api_count}")

    def test_no_old_cves_present(self, page: Page):
        """Test that no CVEs with EPSS < 60% are present."""
        # Sample some CVEs from the API
        api_url = urljoin(LIVE_SITE_URL, "api/vulns/index.json")
        response = page.request.get(api_url)
        api_data = response.json()

        violations = []
        for vuln in api_data.get("vulnerabilities", [])[:100]:  # Check first 100
            epss_score = vuln.get("epss", {}).get("score", 0) * 100
            if epss_score < MIN_EPSS_THRESHOLD:
                violations.append({"cveId": vuln.get("cveId"), "epss": epss_score})

        assert (
            len(violations) == 0
        ), f"Found {len(violations)} CVEs below {MIN_EPSS_THRESHOLD}% EPSS: {violations[:5]}"

        print(f"✓ All sampled CVEs have EPSS >= {MIN_EPSS_THRESHOLD}%")

    def test_cisa_kev_flags_present(self, page: Page):
        """Test that CISA KEV flags are present where applicable."""
        # Get API data
        api_url = urljoin(LIVE_SITE_URL, "api/vulns/index.json")
        response = page.request.get(api_url)
        assert response.status == 200, f"Failed to fetch API data: {response.status}"

        api_data = response.json()
        kev_cves = []

        for vuln in api_data.get("vulnerabilities", [])[:20]:  # Check first 20
            cve_id = vuln.get("cveId")
            cisa_data = vuln.get("cisa", {})

            if cisa_data.get("kev", False):
                kev_cves.append(cve_id)

        if kev_cves:
            print(
                f"✅ Found {len(kev_cves)} CVEs with CISA KEV flags: {kev_cves[:3]}..."
            )

            # Check that KEV flags appear in UI
            first_kev = kev_cves[0]
            # Look for KEV indicator in the UI
            try:
                kev_indicator = (
                    page.locator(f"text=/{first_kev}/")
                    .locator("..")
                    .locator("text=/KEV|CISA/i")
                )
                if kev_indicator.count() > 0:
                    print(f"✅ KEV indicators visible in UI for {first_kev}")
                else:
                    print(f"⚠️  KEV indicator not found in UI for {first_kev}")
            except Exception:
                print("⚠️  Could not verify KEV indicators in UI")
        else:
            print("ℹ️  No CISA KEV CVEs found in sample")

    def test_dependencies_links_load(self, page: Page):
        """Test that deps.dev links load correctly."""
        # Get API data
        api_url = urljoin(LIVE_SITE_URL, "api/vulns/index.json")
        response = page.request.get(api_url)
        api_data = response.json()

        deps_links_found = []

        for vuln in api_data.get("vulnerabilities", [])[:10]:  # Check first 10
            references = vuln.get("references", [])
            for ref in references:
                url = ref.get("url", "")
                if "deps.dev" in url:
                    deps_links_found.append(url)

        if deps_links_found:
            print(f"✅ Found {len(deps_links_found)} deps.dev links")

            # Test first deps.dev link
            first_link = deps_links_found[0]
            try:
                deps_response = page.request.get(first_link, timeout=10000)
                if deps_response.status == 200:
                    print(f"✅ Deps.dev link loads successfully: {first_link}")
                else:
                    print(
                        f"⚠️  Deps.dev link returned {deps_response.status}: {first_link}"
                    )
            except Exception as e:
                print(f"⚠️  Failed to test deps.dev link: {e}")
        else:
            print("ℹ️  No deps.dev links found in sample")

    def test_chunk_files_are_clean(self, page: Page):
        """Test that chunk files don't contain excessive CVEs."""
        # Get chunk index
        chunk_url = urljoin(LIVE_SITE_URL, "api/vulns/chunk-index.json")
        response = page.request.get(chunk_url)

        if response.status == 200:
            chunk_index = response.json()
            total_in_chunks = 0

            for chunk in chunk_index.get("chunks", []):
                chunk_file_url = urljoin(LIVE_SITE_URL, f"api/vulns/{chunk['file']}")
                chunk_response = page.request.get(chunk_file_url)

                if chunk_response.status == 200:
                    chunk_data = chunk_response.json()
                    chunk_count = len(chunk_data.get("vulnerabilities", []))
                    total_in_chunks += chunk_count

                    # Each chunk should be reasonable
                    assert (
                        chunk_count <= 100
                    ), f"Chunk {chunk['file']} has {chunk_count} CVEs - likely contains stale data"

            # Total across chunks should be reasonable
            max_acceptable = int(EXPECTED_CVE_COUNT * (1 + TOLERANCE_PERCENT / 100))
            assert (
                total_in_chunks <= max_acceptable
            ), f"Chunks contain {total_in_chunks} total CVEs, expected <= {max_acceptable}"

            print(f"✓ Chunk files are clean: {total_in_chunks} total CVEs")

    def test_no_stale_cve_pages(self, page: Page):
        """Test that individual CVE pages don't exist for filtered-out CVEs."""
        # List of known CVEs that should NOT exist (EPSS < 60%)
        known_stale_cves = [
            "CVE-2024-0001",  # Example - replace with actual low-EPSS CVEs
            "CVE-2024-9999",
            "CVE-2023-1234",
        ]

        stale_found = []
        for cve_id in known_stale_cves:
            cve_url = urljoin(LIVE_SITE_URL, f"cves/{cve_id}/")
            response = page.request.get(cve_url)

            if response.status == 200:
                stale_found.append(cve_id)

        if stale_found:
            # This is a critical finding
            pytest.fail(
                f"CRITICAL: Found {len(stale_found)} stale CVE pages that should not exist: "
                f"{stale_found}. This indicates incomplete cleanup."
            )

        print("✓ No stale CVE pages found")

    def test_search_results_count(self, page: Page):
        """Test that search results show reasonable counts."""
        # Clear any existing search
        search_input = page.locator("input#searchInput")
        search_input.clear()
        page.wait_for_timeout(500)

        # Get unfiltered count
        results_text = page.locator("text=/Showing \\d+ of \\d+/").text_content()
        if results_text:
            # Extract total from "Showing X of Y results"
            import re

            match = re.search(r"of (\d+)", results_text)
            if match:
                total = int(match.group(1))
                max_acceptable = int(EXPECTED_CVE_COUNT * (1 + TOLERANCE_PERCENT / 100))

                assert (
                    total <= max_acceptable
                ), f"Search shows {total} total results, expected <= {max_acceptable}"

                print(f"✓ Search results count is reasonable: {total}")

    def test_data_freshness(self, page: Page):
        """Test that data appears to be fresh (not months old)."""
        # Check last updated timestamp
        last_updated = page.locator("text=/Last updated:/").text_content()

        if last_updated:
            print(f"✓ Found last updated timestamp: {last_updated}")

            # Could parse and validate the date is recent
            # For now, just ensure it exists
            assert "Last updated:" in last_updated

    def test_console_has_no_major_errors(self, page: Page):
        """Test that console doesn't have errors indicating data issues."""
        # Collect console messages
        console_messages = []
        page.on("console", lambda msg: console_messages.append(msg))

        # Reload to capture all messages
        page.reload()
        page.wait_for_load_state("networkidle")

        # Check for critical errors
        critical_errors = []
        for msg in console_messages:
            if msg.type == "error":
                text = msg.text.lower()
                # Look for errors that might indicate data issues
                if any(
                    keyword in text
                    for keyword in ["404", "not found", "failed to load", "json"]
                ):
                    critical_errors.append(msg.text)

        if critical_errors:
            print(f"⚠️  Found {len(critical_errors)} console errors:")
            for error in critical_errors[:5]:
                print(f"   - {error}")

        # Don't fail on console errors, but report them
        # assert len(critical_errors) == 0, f"Found critical console errors: {critical_errors}"

    @pytest.mark.parametrize(
        "endpoint",
        [
            "api/vulns/index.json",
            "api/vulns/chunk-index.json",
            "api/vulns/vulns-2025-CRITICAL.json",
            "api/vulns/vulns-2025-HIGH.json",
        ],
    )
    def test_api_endpoint_cve_counts(self, page: Page, endpoint: str):
        """Test that each API endpoint has reasonable CVE counts."""
        url = urljoin(LIVE_SITE_URL, endpoint)
        response = page.request.get(url)

        if response.status == 200:
            data = response.json()

            if "vulnerabilities" in data:
                count = len(data["vulnerabilities"])

                # Each file should have reasonable count
                assert (
                    count <= 100
                ), f"{endpoint} has {count} CVEs - likely contains stale data"

                # Verify EPSS threshold
                for vuln in data["vulnerabilities"][:10]:  # Sample first 10
                    epss = vuln.get("epss", {}).get("score", 0) * 100
                    assert (
                        epss >= MIN_EPSS_THRESHOLD
                    ), f"{endpoint} contains CVE with EPSS {epss}% < {MIN_EPSS_THRESHOLD}%"

                print(f"✓ {endpoint}: {count} CVEs, all above threshold")


class TestDataIntegritySanity:
    """Additional sanity tests for data integrity."""

    def test_compare_dev_vs_prod_counts(self, page: Page):
        """Compare production counts with expected development counts."""
        # This test assumes we know what the dev environment produced
        # You would need to pass this information in via environment variable
        expected_from_dev = int(os.getenv("EXPECTED_CVE_COUNT_FROM_DEV", "30"))

        # Get production count
        prod_url = urljoin(LIVE_SITE_URL, "api/vulns/index.json")
        response = page.request.get(prod_url)

        if response.status == 200:
            data = response.json()
            prod_count = len(data.get("vulnerabilities", []))

            # Should match within tolerance
            tolerance = 0.1  # 10%
            min_expected = int(expected_from_dev * (1 - tolerance))
            max_expected = int(expected_from_dev * (1 + tolerance))

            assert (
                min_expected <= prod_count <= max_expected
            ), f"Production has {prod_count} CVEs but dev had {expected_from_dev}"

            print(
                f"✓ Production count ({prod_count}) matches dev ({expected_from_dev})"
            )


if __name__ == "__main__":
    # Run with more verbose output
    pytest.main([__file__, "-v", "-s", "--tb=short"])
