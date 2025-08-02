#!/usr/bin/env python3
"""Comprehensive test for live website data quality."""

import asyncio
import re
from datetime import datetime

from playwright.async_api import async_playwright


async def test_live_site_data_quality():
    """Test the live website for data quality issues."""
    issues = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        try:
            print("🌐 Testing live website: https://williamzujkowski.github.io/vuln-bot/")
            await page.goto("https://williamzujkowski.github.io/vuln-bot/", wait_until="networkidle", timeout=60000)

            # Wait for data to load
            print("⏳ Waiting for vulnerability data to load...")
            await page.wait_for_function("() => window.vulnerabilityData && window.vulnerabilityData.length > 0", timeout=30000)

            # Get all vulnerability data
            vuln_data = await page.evaluate("""
                () => {
                    const data = window.vulnerabilityData || [];
                    // Get first 50 for analysis
                    return data.slice(0, 50).map(v => ({
                        cve_id: v.cve_id || v.CVE_ID,
                        description: v.description || v.Description,
                        severity: v.severity || v.Severity,
                        cvss_score: v.cvss_score || v.CVSS_Score,
                        epss_score: v.epss_score || v.EPSS_Score,
                        risk_score: v.risk_score || v.Risk_Score,
                        products: v.products || v.Products,
                        vendors: v.vendors || v.Vendors,
                        vendors_list: v.vendors_list || v.VendorsList,
                        products_list: v.products_list || v.ProductsList,
                        published_date: v.published_date || v.Published_Date,
                        exploitation_status: v.exploitation_status || v.Exploitation_Status,
                        tags: v.tags || v.Tags || [],
                        references: v.references || v.References || []
                    }));
                }
            """)

            print(f"\n📊 Analyzing {len(vuln_data)} vulnerabilities for data quality issues...")

            # Check for data quality issues
            for i, vuln in enumerate(vuln_data):
                row_issues = []

                # 1. Check CVE ID format
                if not vuln['cve_id'] or not re.match(r'^CVE-\d{4}-\d+$', vuln['cve_id']):
                    row_issues.append(f"Invalid CVE ID format: {vuln['cve_id']}")

                # 2. Check description
                if not vuln['description'] or vuln['description'].strip() == '':
                    row_issues.append("Missing description")
                elif '...' in vuln['description'] and len(vuln['description']) < 200:
                    row_issues.append("Description appears truncated")

                # 3. Check severity
                valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
                if vuln['severity'] not in valid_severities:
                    row_issues.append(f"Invalid severity: {vuln['severity']}")

                # 4. Check CVSS score
                try:
                    cvss = float(vuln['cvss_score'])
                    if cvss < 0 or cvss > 10:
                        row_issues.append(f"CVSS score out of range: {cvss}")
                except (ValueError, TypeError):
                    row_issues.append(f"Invalid CVSS score: {vuln['cvss_score']}")

                # 5. Check EPSS score
                try:
                    epss = float(vuln['epss_score'])
                    if epss < 0 or epss > 100:
                        row_issues.append(f"EPSS score out of range: {epss}")
                except (ValueError, TypeError):
                    row_issues.append(f"Invalid EPSS score: {vuln['epss_score']}")

                # 6. Check products field
                if vuln['products']:
                    # Check if it still contains vendor/product format
                    if '/' in str(vuln['products']):
                        row_issues.append(f"Product field still contains vendor/product: {vuln['products']}")
                else:
                    row_issues.append("Missing products")

                # 7. Check vendors field
                if not vuln['vendors']:
                    row_issues.append("Missing vendors")

                # 8. Check date format
                if vuln['published_date']:
                    try:
                        # Try to parse the date
                        if 'T' in vuln['published_date']:
                            datetime.fromisoformat(vuln['published_date'].replace('Z', '+00:00'))
                    except (ValueError, TypeError):
                        row_issues.append(f"Invalid date format: {vuln['published_date']}")
                else:
                    row_issues.append("Missing published date")

                # 9. Check exploitation status
                valid_statuses = ['UNKNOWN', 'KNOWN', 'ACTIVE', 'PUBLIC', 'NONE']
                if vuln['exploitation_status'] not in valid_statuses:
                    row_issues.append(f"Invalid exploitation status: {vuln['exploitation_status']}")

                # 10. Check for data consistency
                if vuln['products_list'] and vuln['vendors_list'] and len(vuln['products_list']) > 0 and len(vuln['vendors_list']) == 0:
                    # Check if products_list has entries not in vendors_list
                    row_issues.append("Products exist but no vendors")

                if row_issues:
                    issues.append({
                        'cve_id': vuln['cve_id'],
                        'row': i + 1,
                        'issues': row_issues
                    })

            # Check the rendered table for visual issues
            print("\n🔍 Checking rendered table for visual issues...")

            # Get table rows
            table_rows = await page.query_selector_all('#vulnerability-table tbody tr')
            print(f"Found {len(table_rows)} table rows")

            # Check first few rows for rendering issues
            for i in range(min(5, len(table_rows))):
                row = table_rows[i]
                cells = await row.query_selector_all('td')

                if len(cells) < 8:  # Expected number of columns
                    issues.append({
                        'cve_id': f'Row {i+1}',
                        'row': i + 1,
                        'issues': [f"Missing columns: found {len(cells)}, expected 8"]
                    })

                # Check if any cells are empty or have display issues
                for j, cell in enumerate(cells):
                    text = await cell.inner_text()
                    if not text or text.strip() == '':
                        column_names = ['CVE ID', 'Description', 'Severity', 'CVSS', 'EPSS', 'Risk', 'Product', 'Date']
                        issues.append({
                            'cve_id': f'Row {i+1}',
                            'row': i + 1,
                            'issues': [f"Empty {column_names[j]} column"]
                        })

            # Summary
            print("\n📋 Data Quality Summary:")
            print(f"  - Total vulnerabilities analyzed: {len(vuln_data)}")
            print(f"  - Issues found: {len(issues)}")

            if issues:
                print("\n❌ Data Quality Issues Found:")
                # Group issues by type
                issue_types = {}
                for issue in issues:
                    for problem in issue['issues']:
                        issue_type = problem.split(':')[0]
                        issue_types[issue_type] = issue_types.get(issue_type, 0) + 1

                print("\n📊 Issues by Type:")
                for issue_type, count in sorted(issue_types.items(), key=lambda x: x[1], reverse=True):
                    print(f"  - {issue_type}: {count}")

                print("\n🔍 Sample Issues (first 10):")
                for issue in issues[:10]:
                    print(f"\n  CVE: {issue['cve_id']} (Row {issue['row']})")
                    for problem in issue['issues']:
                        print(f"    - {problem}")
            else:
                print("\n✅ No data quality issues found!")

            return issues

        except Exception as e:
            print(f"❌ Error during testing: {e}")
            import traceback
            traceback.print_exc()
            return None
        finally:
            await browser.close()


if __name__ == "__main__":
    issues = asyncio.run(test_live_site_data_quality())
    if issues is None:
        exit(1)
    elif len(issues) > 0:
        print(f"\n⚠️  Found {len(issues)} data quality issues that need fixing")
        exit(1)
    else:
        print("\n✅ All data quality checks passed!")
        exit(0)
