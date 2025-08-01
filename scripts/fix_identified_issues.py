#!/usr/bin/env python3
"""Fix all issues identified by Playwright tests."""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def fix_mobile_responsiveness():
    """Fix mobile responsiveness issue with table."""
    print("🔧 Fixing mobile responsiveness...")

    dashboard_script = Path("scripts/generate_alpine_dashboard.py")
    content = dashboard_script.read_text()

    # Add better mobile styles
    mobile_styles = """
        /* Enhanced Mobile Responsiveness */
        @media (max-width: 768px) {
            .table-wrapper {
                overflow-x: auto;
                -webkit-overflow-scrolling: touch;
                margin: 0 -1rem;
                padding: 0 1rem;
            }

            table {
                min-width: 600px;
            }

            /* Add scroll indicator */
            .table-wrapper::after {
                content: '→ Scroll for more';
                position: absolute;
                right: 1rem;
                top: 1rem;
                background: rgba(0,0,0,0.8);
                color: white;
                padding: 0.25rem 0.5rem;
                border-radius: 4px;
                font-size: 0.75rem;
                pointer-events: none;
                opacity: 0;
                transition: opacity 0.3s;
            }

            .table-wrapper:not(:hover)::after {
                opacity: 1;
            }

            /* Responsive table cells */
            td, th {
                white-space: nowrap;
                min-width: 100px;
            }

            /* Hide less important columns on mobile */
            th:nth-child(5), td:nth-child(5) { /* Risk Score */
                display: none;
            }

            .stats-card {
                padding: 1rem;
            }

            .stat-value {
                font-size: 1.75rem;
            }

            .filter-grid {
                grid-template-columns: 1fr;
            }

            .quick-filters {
                flex-wrap: wrap;
                justify-content: center;
            }

            .filter-chip {
                font-size: 0.875rem;
                padding: 0.375rem 0.75rem;
            }
        }"""

    # Insert mobile styles before the closing style tag
    content = content.replace(
        "        /* Responsive */", mobile_styles + "\n\n        /* Responsive */"
    )

    dashboard_script.write_text(content)
    print("✅ Mobile responsiveness fixed")


def fix_export_functionality():
    """Fix CSV export functionality."""
    print("🔧 Fixing export functionality...")

    dashboard_script = Path("scripts/generate_alpine_dashboard.py")
    content = dashboard_script.read_text()

    # Find the Alpine.js component section
    alpine_component = """
                exportCSV() {
                    const headers = ['CVE ID', 'Severity', 'CVSS Score', 'EPSS %', 'Risk Score', 'Vendor', 'Product', 'Attack Vector', 'Published'];
                    const rows = this.filteredVulns.map(v => [
                        v.cve_id,
                        v.severity,
                        v.cvss_score || '',
                        v.epss_percentile || '',
                        v.risk_score || '',
                        v.vendors?.join(';') || 'Unknown',
                        v.products || 'Unknown',
                        v.attack_vector || 'Unknown',
                        v.published_date
                    ]);

                    let csv = headers.join(',') + '\\n';
                    rows.forEach(row => {
                        csv += row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',') + '\\n';
                    });

                    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
                    const link = document.createElement('a');
                    const url = URL.createObjectURL(blob);
                    link.setAttribute('href', url);
                    link.setAttribute('download', `vulnerabilities_${new Date().toISOString().split('T')[0]}.csv`);
                    link.style.visibility = 'hidden';
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);

                    // Analytics tracking
                    if (typeof gtag !== 'undefined') {
                        gtag('event', 'export', {
                            'event_category': 'data',
                            'event_label': 'csv',
                            'value': this.filteredVulns.length
                        });
                    }
                },"""

    # Replace the exportCSV function
    if "exportCSV()" in content:
        # Find the existing exportCSV function and replace it
        start = content.find("exportCSV()")
        if start > 0:
            # Find the end of the function (next method or closing brace)
            brace_count = 0
            in_function = False
            end = start

            for i in range(start, len(content)):
                if content[i] == "{":
                    brace_count += 1
                    in_function = True
                elif content[i] == "}" and in_function:
                    brace_count -= 1
                    if brace_count == 0:
                        end = i + 1
                        break

            if end > start:
                # Replace the function
                content = content[:start] + alpine_component.strip() + content[end:]
    else:
        # Add the export function if it doesn't exist
        # Find where to insert it (after init or another method)
        insert_pos = content.find("resetFilters()")
        if insert_pos > 0:
            # Find the end of resetFilters
            end_pos = content.find("},", insert_pos) + 2
            content = content[:end_pos] + "\n\n" + alpine_component + content[end_pos:]

    # Also ensure the Export button is in the header
    if "Export CSV" not in content:
        export_button = """
                    <button class="export-btn" @click="exportCSV()">Export CSV</button>"""

        # Find where to insert the button (in the header)
        header_end = content.find("</div>", content.find("header-content"))
        if header_end > 0:
            content = content[:header_end] + export_button + "\n" + content[header_end:]

    dashboard_script.write_text(content)
    print("✅ Export functionality fixed")


def add_epss_filter():
    """Add EPSS filter input to the dashboard."""
    print("🔧 Adding EPSS filter...")

    # The EPSS filter already exists in the code (lines 877-883)
    # But let's make sure it's properly labeled and visible
    dashboard_script = Path("scripts/generate_alpine_dashboard.py")
    content = dashboard_script.read_text()

    # Check if EPSS filter exists
    if "EPSS %" in content and "filters.epss_min" in content:
        print("✅ EPSS filter already exists")
    else:
        # Add EPSS filter if missing
        epss_filter = """
                        <div class="filter-group">
                            <label>EPSS Score %</label>
                            <div style="display: flex; gap: 0.5rem;">
                                <input type="number" x-model.number="filters.epss_min" placeholder="Min" min="0" max="100" step="1">
                                <input type="number" x-model.number="filters.epss_max" placeholder="Max" min="0" max="100" step="1">
                            </div>
                        </div>"""

        # Insert after CVSS filter
        cvss_pos = content.find("</div>", content.find("CVSS Score"))
        if cvss_pos > 0:
            insert_pos = content.find("</div>", cvss_pos + 1) + 6
            content = content[:insert_pos] + "\n" + epss_filter + content[insert_pos:]

        dashboard_script.write_text(content)
        print("✅ EPSS filter added")


def update_test_expectations():
    """Update test to handle table-wrapper for mobile check."""
    print("🔧 Updating test expectations...")

    test_file = Path("tests/e2e/comprehensive_live_test.py")
    content = test_file.read_text()

    # Update the mobile layout test
    old_test = """    async def _test_mobile_layout(self, page: Page):
        \"\"\"Test mobile layout.\"\"\"
        # Check table is still accessible
        table = page.locator("table").first
        assert await table.is_visible(), "Table not visible on mobile"

        # Check for horizontal scroll or responsive wrapper
        table_parent = page.locator("table").locator("..")
        parent_styles = await table_parent.evaluate("el => getComputedStyle(el)")

        # Table should be in a scrollable container or be responsive
        is_scrollable = parent_styles.get("overflow-x") in ["auto", "scroll"]
        is_responsive = "responsive" in await table_parent.get_attribute("class") or ""

        assert is_scrollable or is_responsive, "Table not properly responsive on mobile\""""

    new_test = """    async def _test_mobile_layout(self, page: Page):
        \"\"\"Test mobile layout.\"\"\"
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
            assert is_scrollable or is_responsive, "Table not properly responsive on mobile\""""

    content = content.replace(old_test, new_test)
    test_file.write_text(content)
    print("✅ Test expectations updated")


def main():
    """Run all fixes."""
    print("🚀 Fixing identified issues...\n")

    fix_mobile_responsiveness()
    fix_export_functionality()
    add_epss_filter()
    update_test_expectations()

    print("\n✅ All fixes applied!")
    print("\nNext steps:")
    print("1. Regenerate the dashboard: python scripts/generate_alpine_dashboard.py")
    print("2. Commit and push changes")
    print("3. Wait for GitHub Actions to deploy")
    print("4. Re-run tests to verify fixes")


if __name__ == "__main__":
    main()
