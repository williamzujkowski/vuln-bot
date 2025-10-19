"""
End-to-end tests for validating the live production site.
These tests run against the deployed GitHub Pages site to ensure data quality.
"""

import json
import os
from urllib.parse import urljoin

import pytest
from playwright.sync_api import Page, expect

LIVE_SITE_URL = os.getenv(
    "LIVE_SITE_URL", "https://williamzujkowski.github.io/vuln-bot/"
)
EXPECTED_MAX_CVES = 50  # Maximum expected CVEs with EPSS >= 60%
MIN_EPSS_THRESHOLD = 60.0


class TestLiveSiteValidation:
    """Comprehensive validation tests for the production site."""

    @pytest.fixture(autouse=True)
    def setup(self, page: Page):
        """Navigate to the live site before each test."""
        page.goto(LIVE_SITE_URL, wait_until="networkidle")
        # Wait for Alpine.js to initialize
        page.wait_for_timeout(1000)

    def test_homepage_loads_successfully(self, page: Page):
        """Test that the homepage loads with expected elements."""
        # Check title
        expect(page).to_have_title("Vuln-Bot: High-Risk CVE Intelligence")

        # Check main heading
        heading = page.locator("h1").first
        expect(heading).to_contain_text("High-Risk CVE Intelligence")

        # Check that vulnerability table exists
        table = page.locator("table#vulnerabilityTable")
        expect(table).to_be_visible()

        # Check that search box exists
        search_box = page.locator("input#searchInput")
        expect(search_box).to_be_visible()

    def test_cve_count_within_expected_range(self, page: Page):
        """Test that the total CVE count is within expected range."""
        # Wait for data to load
        page.wait_for_function("window.Alpine && window.Alpine.store('dashboard')")

        # Get total count from the UI
        total_count = page.evaluate(
            """
            () => {
                const store = window.Alpine.store('dashboard');
                return store.stats.total;
            }
        """
        )

        assert total_count > 0, "No CVEs found on the dashboard"
        assert (
            total_count <= EXPECTED_MAX_CVES
        ), f"Too many CVEs found: {total_count} > {EXPECTED_MAX_CVES}"

        print(f"✓ Found {total_count} CVEs (within expected range)")

    def test_no_cves_below_epss_threshold(self, page: Page):
        """Test that no CVEs have EPSS score below 60%."""
        # Wait for data to load
        page.wait_for_function("window.Alpine && window.Alpine.store('dashboard')")

        # Get all vulnerabilities
        vulnerabilities = page.evaluate(
            """
            () => {
                const store = window.Alpine.store('dashboard');
                return store.vulnerabilities;
            }
        """
        )

        violations = []
        for vuln in vulnerabilities:
            epss_score = vuln.get("epss", {}).get("score", 0) * 100
            if epss_score < MIN_EPSS_THRESHOLD:
                violations.append({"cveId": vuln.get("cveId"), "epss": epss_score})

        assert (
            len(violations) == 0
        ), f"Found {len(violations)} CVEs below {MIN_EPSS_THRESHOLD}% EPSS: {violations}"

        print(f"✓ All {len(vulnerabilities)} CVEs have EPSS >= {MIN_EPSS_THRESHOLD}%")

    def test_epss_filter_accuracy(self, page: Page):
        """Test that EPSS filters work correctly."""
        # Set EPSS max to 70%
        epss_max_slider = page.locator("input#epssMax")
        epss_max_slider.fill("70")
        epss_max_slider.dispatch_event("input")

        # Wait for filter to apply
        page.wait_for_timeout(500)

        # Get filtered results
        filtered_count = page.evaluate(
            """
            () => {
                const store = window.Alpine.store('dashboard');
                return store.stats.filtered;
            }
        """
        )

        # Get filtered vulnerabilities
        filtered_vulns = page.evaluate(
            """
            () => {
                const store = window.Alpine.store('dashboard');
                return store.filteredResults;
            }
        """
        )

        # Verify all filtered vulns are within range
        for vuln in filtered_vulns:
            epss_score = vuln.get("epss", {}).get("score", 0) * 100
            assert (
                60 <= epss_score <= 70
            ), f"CVE {vuln.get('cveId')} has EPSS {epss_score}% outside range"

        print(f"✓ EPSS filter correctly shows {filtered_count} CVEs between 60-70%")

    def test_cve_detail_pages_load(self, page: Page):
        """Test that individual CVE detail pages load correctly."""
        # Get first 5 CVEs to test
        cve_links = page.locator("a[href*='/cves/']").all()[:5]

        tested_cves = []
        for link in cve_links:
            cve_id = link.get_attribute("href").split("/")[-2]

            # Open in new tab to avoid navigation issues
            with page.context.new_page() as detail_page:
                detail_url = urljoin(LIVE_SITE_URL, f"cves/{cve_id}/")
                detail_page.goto(detail_url, wait_until="networkidle")

                # Check page title contains CVE ID
                expect(detail_page).to_have_title(f"{cve_id}")

                # Check CVE ID is displayed
                heading = detail_page.locator("h1")
                expect(heading).to_contain_text(cve_id)

                # Check EPSS score is displayed and >= 60%
                epss_element = detail_page.locator("text=/EPSS.*%/")
                expect(epss_element).to_be_visible()

                epss_text = epss_element.text_content()
                epss_value = float(epss_text.split()[1].rstrip("%"))
                assert (
                    epss_value >= MIN_EPSS_THRESHOLD
                ), f"{cve_id} has EPSS {epss_value}% < {MIN_EPSS_THRESHOLD}%"

                tested_cves.append(cve_id)

        print(f"✓ Tested {len(tested_cves)} CVE detail pages: {', '.join(tested_cves)}")

    def test_threat_intel_flags_render(self, page: Page):
        """Test that threat intelligence flags render correctly."""
        # Look for deps.dev enrichments
        deps_dev_links = page.locator("a[href*='deps.dev']").count()

        # Look for categorized references
        reference_categories = ["patch", "advisory", "technical", "exploit"]
        category_counts = {}

        for category in reference_categories:
            count = page.locator(f"[data-category='{category}']").count()
            if count > 0:
                category_counts[category] = count

        # Open a CVE modal to check reference rendering
        first_cve_link = page.locator("button[onclick*='showCveModal']").first
        if first_cve_link.is_visible():
            first_cve_link.click()

            # Wait for modal to open
            modal = page.locator("#cveModal")
            expect(modal).to_be_visible()

            # Check for reference categories in modal
            modal_refs = modal.locator(".reference-item")
            assert modal_refs.count() > 0, "No references found in CVE modal"

            # Close modal
            page.locator("button[onclick*='closeCveModal']").click()

        print(f"✓ Found {deps_dev_links} deps.dev enrichments")
        print(f"✓ Reference categories: {category_counts}")

    def test_data_visualization_charts(self, page: Page):
        """Test that data visualization charts render correctly."""
        # Check if charts container exists
        charts_container = page.locator("#dataVisualization")

        if charts_container.is_visible():
            # Check for canvas elements
            charts = page.locator("canvas").all()
            assert len(charts) >= 3, f"Expected at least 3 charts, found {len(charts)}"

            # Verify charts have rendered (have non-zero dimensions)
            for i, chart in enumerate(charts):
                box = chart.bounding_box()
                assert box is not None, f"Chart {i} has no bounding box"
                assert (
                    box["width"] > 0 and box["height"] > 0
                ), f"Chart {i} has zero dimensions"

            print(f"✓ All {len(charts)} visualization charts rendered correctly")

    def test_no_stale_data_indicators(self, page: Page):
        """Test for indicators of stale or outdated data."""
        # Check last updated timestamp
        last_updated = page.locator("text=/Last updated:/").text_content()
        assert last_updated is not None, "No last updated timestamp found"

        # Check for error messages
        error_messages = page.locator(".error, .alert-danger").count()
        assert error_messages == 0, f"Found {error_messages} error messages on page"

        # Check that data loads without console errors
        console_errors = []
        page.on(
            "console",
            lambda msg: console_errors.append(msg) if msg.type == "error" else None,
        )
        page.reload()
        page.wait_for_load_state("networkidle")

        # Filter out expected errors (e.g., favicon)
        real_errors = [
            err for err in console_errors if "favicon" not in err.text.lower()
        ]
        assert (
            len(real_errors) == 0
        ), f"Console errors detected: {[err.text for err in real_errors]}"

        print("✓ No stale data indicators found")

    def test_api_endpoints_accessible(self, page: Page):
        """Test that API endpoints return valid data."""
        api_endpoints = [
            "api/vulns/index.json",
            "api/vulns/chunk-index.json",
            "api/vulns/vulns-2025-CRITICAL.json",
            "api/vulns/vulns-2025-HIGH.json",
        ]

        for endpoint in api_endpoints:
            url = urljoin(LIVE_SITE_URL, endpoint)
            response = page.request.get(url)

            assert (
                response.status == 200
            ), f"API endpoint {endpoint} returned {response.status}"

            # Validate JSON structure
            try:
                data = response.json()
                if "index.json" in endpoint:
                    assert (
                        "vulnerabilities" in data
                    ), f"Missing 'vulnerabilities' in {endpoint}"
                    assert (
                        len(data["vulnerabilities"]) > 0
                    ), f"No vulnerabilities in {endpoint}"
                elif "chunk-index.json" in endpoint:
                    assert "chunks" in data, f"Missing 'chunks' in {endpoint}"
                else:
                    assert (
                        "vulnerabilities" in data
                    ), f"Missing 'vulnerabilities' in {endpoint}"

                    # Verify EPSS threshold compliance in chunks
                    for vuln in data.get("vulnerabilities", []):
                        epss_score = vuln.get("epss", {}).get("score", 0) * 100
                        assert (
                            epss_score >= MIN_EPSS_THRESHOLD
                        ), f"CVE {vuln.get('cveId')} in {endpoint} has EPSS {epss_score}% < {MIN_EPSS_THRESHOLD}%"

                print(f"✓ API endpoint {endpoint} valid")
            except Exception as e:
                pytest.fail(f"Failed to parse JSON from {endpoint}: {e}")


class TestDataIntegrity:
    """Tests to ensure data integrity and no stale files."""

    def test_no_duplicate_cves(self, page: Page):
        """Test that there are no duplicate CVEs in the dataset."""
        page.goto(urljoin(LIVE_SITE_URL, "api/vulns/index.json"))
        data = page.evaluate("() => document.body.textContent")
        vulns_data = json.loads(data)

        cve_ids = [v["cveId"] for v in vulns_data["vulnerabilities"]]
        unique_ids = set(cve_ids)

        assert len(cve_ids) == len(
            unique_ids
        ), f"Found {len(cve_ids) - len(unique_ids)} duplicate CVEs"

        print(f"✓ No duplicate CVEs found among {len(cve_ids)} entries")

    def test_consistent_data_across_chunks(self, page: Page):
        """Test that chunk files contain consistent data."""
        # Get chunk index
        page.goto(urljoin(LIVE_SITE_URL, "api/vulns/chunk-index.json"))
        chunk_index = json.loads(page.evaluate("() => document.body.textContent"))

        total_from_chunks = 0
        all_cves_from_chunks = set()

        for chunk in chunk_index["chunks"]:
            chunk_url = urljoin(LIVE_SITE_URL, f"api/vulns/{chunk['file']}")
            page.goto(chunk_url)
            chunk_data = json.loads(page.evaluate("() => document.body.textContent"))

            chunk_vulns = chunk_data["vulnerabilities"]
            total_from_chunks += len(chunk_vulns)

            for vuln in chunk_vulns:
                all_cves_from_chunks.add(vuln["cveId"])

        # Compare with index total
        page.goto(urljoin(LIVE_SITE_URL, "api/vulns/index.json"))
        index_data = json.loads(page.evaluate("() => document.body.textContent"))
        index_total = len(index_data["vulnerabilities"])

        assert (
            total_from_chunks == index_total
        ), f"Chunk total ({total_from_chunks}) doesn't match index total ({index_total})"

        print(f"✓ Data consistency verified across {len(chunk_index['chunks'])} chunks")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
