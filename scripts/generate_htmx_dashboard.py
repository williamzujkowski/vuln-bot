#!/usr/bin/env python3
"""
Generate static HTMX dashboard for GitHub Pages
This script pre-renders all HTMX fragments as static files
"""

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import List

# Configuration
OUTPUT_DIR = Path("public")
FRAGMENTS_DIR = OUTPUT_DIR / "fragments"
DB_PATH = Path(".cache/vulns.db")
BASE_PATH = "/vuln-bot"  # GitHub Pages base path

# Ensure output directories exist
OUTPUT_DIR.mkdir(exist_ok=True)
FRAGMENTS_DIR.mkdir(exist_ok=True)
(FRAGMENTS_DIR / "filter").mkdir(exist_ok=True)
(FRAGMENTS_DIR / "sort").mkdir(exist_ok=True)
(FRAGMENTS_DIR / "page").mkdir(exist_ok=True)


class HTMXDashboardGenerator:
    def __init__(self, db_path: Path):
        self.db = sqlite3.connect(db_path)
        self.db.row_factory = sqlite3.Row
        self.vulnerabilities = []
        self.base_path = BASE_PATH
        self.load_vulnerabilities()

    def load_vulnerabilities(self):
        """Load all vulnerabilities from database"""
        cursor = self.db.cursor()
        rows = cursor.execute("""
            SELECT
                cve_id,
                title,
                severity,
                cvss_score,
                epss_percentile,
                published_date,
                last_modified_date,
                vendors,
                products,
                tags,
                description,
                attack_vector,
                attack_complexity,
                scope,
                user_interaction,
                privileges_required,
                confidentiality_impact,
                integrity_impact,
                availability_impact
            FROM vulnerabilities
            ORDER BY epss_percentile DESC, cvss_score DESC
        """).fetchall()

        # Convert to list of dicts and add risk_score
        self.vulnerabilities = []
        for row in rows:
            vuln = dict(row)
            # Calculate risk score (simplified formula)
            cvss = vuln.get('cvss_score', 0) or 0
            epss = vuln.get('epss_percentile', 0) or 0
            vuln['risk_score'] = int((cvss * 10 + epss) / 2)
            self.vulnerabilities.append(vuln)

    def generate_stats_fragment(self) -> str:
        """Generate statistics fragment"""
        # Calculate stats
        total = len(self.vulnerabilities)
        critical = sum(1 for v in self.vulnerabilities if v["severity"] == "CRITICAL")
        high = sum(1 for v in self.vulnerabilities if v["severity"] == "HIGH")

        # Get today's count
        today = datetime.now().date().isoformat()
        today_count = sum(
            1 for v in self.vulnerabilities if v["published_date"].startswith(today)
        )

        # Get week change
        week_ago = (datetime.now() - timedelta(days=7)).date().isoformat()
        week_count = sum(
            1 for v in self.vulnerabilities if v["published_date"] >= week_ago
        )

        # Get KEV count
        kev_count = sum(
            1
            for v in self.vulnerabilities
            if v["tags"] and "KEV" in json.loads(v["tags"])
        )

        return f"""
        <div class="stats-grid" id="stats-container">
            <div class="stat-card">
                <div class="stat-icon">🛡️</div>
                <div class="stat-value">{total}</div>
                <div class="stat-label">Total Vulnerabilities</div>
                <div class="stat-change negative">
                    <span>+{week_count}</span>
                    <span>from last week</span>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-icon">🚨</div>
                <div class="stat-value">{critical}</div>
                <div class="stat-label">Critical Severity</div>
                <div class="stat-change negative">
                    <span>+{today_count}</span>
                    <span>new today</span>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-icon">⚠️</div>
                <div class="stat-value">{high}</div>
                <div class="stat-label">High Severity</div>
                <div class="stat-trend">
                    <span>{round(high/total*100)}%</span>
                    <span>of total</span>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-icon">⭐</div>
                <div class="stat-value">{kev_count}</div>
                <div class="stat-label">KEV Listed</div>
                <div class="stat-trend">
                    <span>Known</span>
                    <span>Exploited</span>
                </div>
            </div>
        </div>
        """

    def generate_charts_fragment(self) -> str:
        """Generate charts fragment with data"""
        # Prepare chart data
        severity_counts = {
            "CRITICAL": sum(1 for v in self.vulnerabilities if v["severity"] == "CRITICAL"),
            "HIGH": sum(1 for v in self.vulnerabilities if v["severity"] == "HIGH"),
            "MEDIUM": sum(1 for v in self.vulnerabilities if v["severity"] == "MEDIUM"),
            "LOW": sum(1 for v in self.vulnerabilities if v["severity"] == "LOW"),
        }

        # EPSS distribution
        epss_ranges = {
            "90-100%": sum(1 for v in self.vulnerabilities if v["epss_percentile"] >= 90),
            "70-89%": sum(
                1 for v in self.vulnerabilities if 70 <= v["epss_percentile"] < 90
            ),
            "50-69%": sum(
                1 for v in self.vulnerabilities if 50 <= v["epss_percentile"] < 70
            ),
            "<50%": sum(1 for v in self.vulnerabilities if v["epss_percentile"] < 50),
        }

        return f"""
        <div class="charts-grid" id="charts-container">
            <div class="chart-card">
                <h3 class="chart-title">Severity Distribution</h3>
                <div class="chart-container">
                    <canvas id="severity-chart"></canvas>
                </div>
            </div>

            <div class="chart-card">
                <h3 class="chart-title">EPSS Score Distribution</h3>
                <div class="chart-container">
                    <canvas id="epss-chart"></canvas>
                </div>
            </div>
        </div>

        <script>
            window.chartData = {{
                severity: {{
                    labels: {list(severity_counts.keys())},
                    datasets: [{{
                        data: {list(severity_counts.values())},
                        backgroundColor: ['#dc2626', '#ef4444', '#f59e0b', '#3b82f6']
                    }}]
                }},
                epss: {{
                    labels: {list(epss_ranges.keys())},
                    datasets: [{{
                        data: {list(epss_ranges.values())},
                        backgroundColor: ['#dc2626', '#ef4444', '#f59e0b', '#10b981']
                    }}]
                }}
            }};
        </script>
        """

    def generate_table_fragment(
        self,
        vulns: List[sqlite3.Row],
        page: int = 1,
        per_page: int = 50,
        sort_field: str = "epss_percentile",
        sort_order: str = "desc",
    ) -> str:
        """Generate vulnerability table fragment"""
        # Sort vulnerabilities
        reverse = sort_order == "desc"
        if sort_field in ["severity"]:
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            vulns = sorted(
                vulns, key=lambda v: severity_order.get(v[sort_field], 0), reverse=reverse
            )
        else:
            vulns = sorted(vulns, key=lambda v: v[sort_field] or 0, reverse=reverse)

        # Paginate
        total = len(vulns)
        total_pages = (total + per_page - 1) // per_page
        start = (page - 1) * per_page
        end = start + per_page
        page_vulns = vulns[start:end]

        # Generate table HTML
        rows_html = ""
        for vuln in page_vulns:
            severity_class = f"severity-{vuln['severity'].lower()}"
            vendors = (
                ", ".join(json.loads(vuln["vendors"])[:3])
                if vuln["vendors"]
                else "Unknown"
            )
            pub_date = vuln["published_date"][:10] if vuln["published_date"] else "Unknown"

            rows_html += f"""
        <tr class="vulnerability-row" data-cve="{vuln['cve_id']}">
            <td>
                <a href="#" onclick="openCveModal('{vuln['cve_id']}'); return false;"
                   class="cve-link">{vuln['cve_id']}</a>
            </td>
            <td><span class="severity-badge {severity_class}">{vuln['severity']}</span></td>
            <td>{vuln['cvss_score']}</td>
            <td>{vuln['epss_percentile']}</td>
            <td>{vuln['risk_score']}</td>
            <td class="truncate">{vuln['title'] or 'No title available'}</td>
            <td class="truncate">{vendors}</td>
            <td>{pub_date}</td>
        </tr>
            """

        # Sort indicators
        sort_indicators = {}
        for field in ["cve_id", "severity", "cvss_score", "epss_percentile", "risk_score", "published_date"]:
            if field == sort_field:
                sort_indicators[field] = " ↓" if sort_order == "desc" else " ↑"
            else:
                sort_indicators[field] = ""

        return f"""
        <div class="table-container" id="vulnerabilities-table">
            <table class="data-table">
                <thead>
                    <tr>
                        <th class="sortable" data-sort="cve_id"
                            hx-get="{self.base_path}/fragments/sort/cve_id.html"
                            hx-target="#vulnerabilities-table"
                            hx-swap="outerHTML">
                            CVE ID{sort_indicators.get('cve_id', '')}
                        </th>
                        <th class="sortable" data-sort="severity"
                            hx-get="{self.base_path}/fragments/sort/severity.html"
                            hx-target="#vulnerabilities-table"
                            hx-swap="outerHTML">
                            Severity{sort_indicators.get('severity', '')}
                        </th>
                        <th class="sortable" data-sort="cvss_score"
                            hx-get="{self.base_path}/fragments/sort/cvss_score.html"
                            hx-target="#vulnerabilities-table"
                            hx-swap="outerHTML">
                            CVSS{sort_indicators.get('cvss_score', '')}
                        </th>
                        <th class="sortable" data-sort="epss_percentile"
                            hx-get="{self.base_path}/fragments/sort/epss_percentile.html"
                            hx-target="#vulnerabilities-table"
                            hx-swap="outerHTML">
                            EPSS %{sort_indicators.get('epss_percentile', '')}
                        </th>
                        <th class="sortable" data-sort="risk_score"
                            hx-get="{self.base_path}/fragments/sort/risk_score.html"
                            hx-target="#vulnerabilities-table"
                            hx-swap="outerHTML">
                            Risk Score{sort_indicators.get('risk_score', '')}
                        </th>
                        <th>Title</th>
                        <th>Vendors</th>
                        <th class="sortable" data-sort="published_date"
                            hx-get="{self.base_path}/fragments/sort/published_date.html"
                            hx-target="#vulnerabilities-table"
                            hx-swap="outerHTML">
                            Published{sort_indicators.get('published_date', '')}
                        </th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>

            <div class="pagination">
                <button class="page-btn"
                        {"disabled" if page <= 1 else ""}
                        {'hx-get="' + self.base_path + '/fragments/page/' + str(page - 1) + '.html" hx-target="#vulnerabilities-table" hx-swap="outerHTML"' if page > 1 else ""}>
                    Previous
                </button>
                <span class="page-info">
                    Page {page} of {total_pages} • {total} vulnerabilities
                </span>
                <button class="page-btn"
                        {"disabled" if page >= total_pages else ""}
                        {'hx-get="' + self.base_path + '/fragments/page/' + str(page + 1) + '.html" hx-target="#vulnerabilities-table" hx-swap="outerHTML"' if page < total_pages else ""}>
                    Next
                </button>
            </div>
        </div>

        <script>
            // Update result count
            document.getElementById('result-count').textContent = 'Showing {len(page_vulns)} of {total} results';
        </script>
        """

    def filter_vulnerabilities(self, filter_type: str) -> List[sqlite3.Row]:
        """Filter vulnerabilities based on quick filter type"""
        if filter_type == "all":
            return self.vulnerabilities
        elif filter_type == "critical":
            return [v for v in self.vulnerabilities if v["severity"] == "CRITICAL"]
        elif filter_type == "today":
            today = datetime.now().date().isoformat()
            return [
                v for v in self.vulnerabilities if v["published_date"].startswith(today)
            ]
        elif filter_type == "kev":
            return [
                v
                for v in self.vulnerabilities
                if v["tags"] and "KEV" in json.loads(v["tags"])
            ]
        elif filter_type == "network":
            return [
                v
                for v in self.vulnerabilities
                if v["attack_vector"] and v["attack_vector"] == "NETWORK"
            ]
        else:
            return self.vulnerabilities

    def generate_all_fragments(self):
        """Generate all static fragments"""
        print("Generating HTMX fragments...")

        # Stats fragment
        with open(FRAGMENTS_DIR / "stats.html", "w") as f:
            f.write(self.generate_stats_fragment())
        print("✓ Generated stats fragment")

        # Charts fragment
        with open(FRAGMENTS_DIR / "charts.html", "w") as f:
            f.write(self.generate_charts_fragment())
        print("✓ Generated charts fragment")

        # Main vulnerabilities table
        with open(FRAGMENTS_DIR / "vulnerabilities.html", "w") as f:
            f.write(self.generate_table_fragment(self.vulnerabilities))
        print("✓ Generated main vulnerabilities table")

        # Filter fragments
        filters = ["all", "critical", "today", "kev", "network"]
        for filter_type in filters:
            filtered_vulns = self.filter_vulnerabilities(filter_type)
            with open(FRAGMENTS_DIR / "filter" / f"{filter_type}.html", "w") as f:
                f.write(self.generate_table_fragment(filtered_vulns))
        print(f"✓ Generated {len(filters)} filter fragments")

        # Sort fragments
        sort_fields = [
            "cve_id",
            "severity",
            "cvss_score",
            "epss_percentile",
            "risk_score",
            "published_date",
        ]
        for field in sort_fields:
            for order in ["asc", "desc"]:
                with open(FRAGMENTS_DIR / "sort" / f"{field}_{order}.html", "w") as f:
                    f.write(
                        self.generate_table_fragment(
                            self.vulnerabilities, sort_field=field, sort_order=order
                        )
                    )
        print(f"✓ Generated {len(sort_fields) * 2} sort fragments")

        # Pagination fragments (first 10 pages)
        for page_num in range(1, min(11, (len(self.vulnerabilities) // 50) + 2)):
            with open(FRAGMENTS_DIR / "page" / f"{page_num}.html", "w") as f:
                f.write(self.generate_table_fragment(self.vulnerabilities, page=page_num))
        print("✓ Generated pagination fragments")

    def export_data(self):
        """Export vulnerability data as JSON and CSV"""
        print("Exporting data files...")

        # Export as JSON
        data = []
        for vuln in self.vulnerabilities:
            data.append(
                {
                    "cve_id": vuln["cve_id"],
                    "title": vuln["title"],
                    "severity": vuln["severity"],
                    "cvss_score": vuln["cvss_score"],
                    "epss_percentile": vuln["epss_percentile"],
                    "risk_score": vuln["risk_score"],
                    "vendors": json.loads(vuln["vendors"]) if vuln["vendors"] else [],
                    "tags": json.loads(vuln["tags"]) if vuln["tags"] else [],
                    "published_date": vuln["published_date"],
                }
            )

        (OUTPUT_DIR / "data").mkdir(exist_ok=True)
        with open(OUTPUT_DIR / "data" / "vulnerabilities.json", "w") as f:
            json.dump(data, f, indent=2)
        print("✓ Exported JSON data")

        # Export as CSV
        import csv

        with open(OUTPUT_DIR / "data" / "vulnerabilities.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "CVE ID",
                    "Severity",
                    "CVSS",
                    "EPSS %",
                    "Risk Score",
                    "Title",
                    "Vendors",
                    "Published",
                ]
            )
            for vuln in self.vulnerabilities:
                vendors = (
                    ", ".join(json.loads(vuln["vendors"])[:3])
                    if vuln["vendors"]
                    else ""
                )
                writer.writerow(
                    [
                        vuln["cve_id"],
                        vuln["severity"],
                        vuln["cvss_score"],
                        vuln["epss_percentile"],
                        vuln["risk_score"],
                        vuln["title"] or "",
                        vendors,
                        vuln["published_date"][:10] if vuln["published_date"] else "",
                    ]
                )
        print("✓ Exported CSV data")

    def create_dashboard_html(self):
        """Create the main dashboard HTML with HTMX"""
        dashboard_template = Path("src/dashboard-htmx.html")
        if dashboard_template.exists():
            with open(dashboard_template) as f:
                html = f.read()
        else:
            # Fallback to embedded template
            html = self.get_dashboard_template()

        # Replace API endpoints with static fragments
        replacements = {
            "/api/stats": f"{self.base_path}/fragments/stats.html",
            "/api/vulnerabilities": f"{self.base_path}/fragments/vulnerabilities.html",
            "/api/charts": f"{self.base_path}/fragments/charts.html",
            "/api/filter/quick": f"{self.base_path}/fragments/filter/{{filter}}.html",
            "/api/sort": f"{self.base_path}/fragments/sort/{{field}}_{{order}}.html",
            "/api/export/csv": f"{self.base_path}/data/vulnerabilities.csv",
            "/fragments/stats.html": f"{self.base_path}/fragments/stats.html",
            "/fragments/vulnerabilities.html": f"{self.base_path}/fragments/vulnerabilities.html",
            "/fragments/charts.html": f"{self.base_path}/fragments/charts.html",
            "/fragments/filter/": f"{self.base_path}/fragments/filter/",
            "/data/vulnerabilities.csv": f"{self.base_path}/data/vulnerabilities.csv",
        }

        for old, new in replacements.items():
            html = html.replace(f'hx-get="{old}"', f'hx-get="{new}"')
            html = html.replace(f'hx-post="{old}"', f'hx-get="{new}"')

        # Add HTMX static adapter script
        adapter_script = """
        <script>
        // HTMX Static Adapter for GitHub Pages
        document.body.addEventListener('htmx:configRequest', (event) => {
            // Handle dynamic URLs
            let url = event.detail.path;

            // Handle quick filters
            if (url.includes('{filter}')) {
                const filterMatch = event.detail.elt.getAttribute('hx-vals');
                if (filterMatch) {
                    const filter = JSON.parse(filterMatch).filter;
                    url = url.replace('{filter}', filter);
                }
            }

            // Handle sorting
            if (url.includes('{field}_{order}')) {
                const field = event.detail.elt.dataset.sort || 'epss_percentile';
                const currentOrder = event.detail.elt.textContent.includes('↓') ? 'desc' : 'asc';
                const newOrder = currentOrder === 'desc' ? 'asc' : 'desc';
                url = url.replace('{field}', field).replace('{order}', newOrder);
            }

            event.detail.path = url;
        });

        // CVE Modal function
        function openCveModal(cveId) {
            // For static version, we'll show a simple modal with basic info
            const modal = document.getElementById('cve-modal') || createCveModal();
            const modalContent = modal.querySelector('.modal-content');

            // Find vulnerability data from table
            const row = document.querySelector(`tr[data-cve="${cveId}"]`);
            if (row) {
                const cells = row.querySelectorAll('td');
                modalContent.innerHTML = `
                    <h2>${cveId}</h2>
                    <p><strong>Severity:</strong> ${cells[1].textContent}</p>
                    <p><strong>CVSS Score:</strong> ${cells[2].textContent}</p>
                    <p><strong>EPSS:</strong> ${cells[3].textContent}</p>
                    <p><strong>Risk Score:</strong> ${cells[4].textContent}</p>
                    <p><strong>Title:</strong> ${cells[5].textContent}</p>
                    <p><strong>Vendors:</strong> ${cells[6].textContent}</p>
                    <p><strong>Published:</strong> ${cells[7].textContent}</p>
                    <button onclick="document.getElementById('cve-modal').style.display='none'">Close</button>
                `;
            }

            modal.style.display = 'block';
        }

        function createCveModal() {
            const modal = document.createElement('div');
            modal.id = 'cve-modal';
            modal.className = 'modal';
            modal.innerHTML = '<div class="modal-content"></div>';
            modal.style.cssText = `
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0,0,0,0.8);
                z-index: 1000;
            `;
            document.body.appendChild(modal);

            // Close on background click
            modal.addEventListener('click', (e) => {
                if (e.target === modal) modal.style.display = 'none';
            });

            return modal;
        }
        </script>
        """

        # Insert adapter script before closing body tag
        html = html.replace("</body>", adapter_script + "\n</body>")

        # Write the dashboard HTML
        with open(OUTPUT_DIR / "index.html", "w") as f:
            f.write(html)
        print("✓ Created dashboard HTML")

    def get_dashboard_template(self) -> str:
        """Get the embedded dashboard template"""
        # This is a fallback if src/dashboard-htmx.html doesn't exist
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Intelligence Dashboard</title>
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <style>/* Add your styles here */</style>
</head>
<body>
    <div class="dashboard">
        <h1>Vulnerability Intelligence Dashboard</h1>
        <div hx-get="/fragments/vulnerabilities.html" hx-trigger="load"></div>
    </div>
</body>
</html>"""

    def copy_service_worker(self):
        """Copy service worker if it exists"""
        sw_source = Path("src/sw.js")
        if sw_source.exists():
            import shutil

            shutil.copy(sw_source, OUTPUT_DIR / "sw.js")
            print("✓ Copied service worker")


def main():
    """Main function"""
    # Check if database exists
    if not DB_PATH.exists():
        print(f"Error: Database not found at {DB_PATH}")
        print("Creating test database...")
        # Import the create_test_db module
        import sys

        sys.path.insert(0, "scripts")
        from create_test_db import create_test_database

        create_test_database()
        print("✓ Created test database")

    # Generate dashboard
    generator = HTMXDashboardGenerator(DB_PATH)
    generator.generate_all_fragments()
    generator.export_data()
    generator.create_dashboard_html()
    generator.copy_service_worker()

    print("\n✅ HTMX dashboard generated successfully!")
    print(f"📁 Output directory: {OUTPUT_DIR}")
    print("🚀 Ready to deploy to GitHub Pages")


if __name__ == "__main__":
    main()
