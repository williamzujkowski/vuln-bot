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
        self.load_vulnerabilities()

    def load_vulnerabilities(self):
        """Load all vulnerabilities from database"""
        cursor = self.db.cursor()
        self.vulnerabilities = cursor.execute("""
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
                privileges_required,
                user_interaction,
                scope,
                confidentiality_impact,
                integrity_impact,
                availability_impact
            FROM vulnerabilities
            WHERE epss_percentile >= 70
            ORDER BY epss_percentile DESC
        """).fetchall()

    def generate_stats_fragment(self) -> str:
        """Generate statistics fragment"""
        cursor = self.db.cursor()

        # Calculate statistics
        stats = cursor.execute("""
            SELECT
                COUNT(*) as total,
                COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) as critical,
                COUNT(CASE WHEN epss_percentile >= 90 THEN 1 END) as high_epss,
                AVG(COALESCE(cvss_score * 10, 50)) as avg_risk
            FROM vulnerabilities
            WHERE epss_percentile >= 70
        """).fetchone()

        # Week-over-week change
        week_ago = (datetime.now() - timedelta(days=7)).isoformat()
        week_change = cursor.execute(
            """
            SELECT COUNT(*) as new_vulns
            FROM vulnerabilities
            WHERE published_date >= ? AND epss_percentile >= 70
        """,
            (week_ago,),
        ).fetchone()

        # Today's new
        today = datetime.now().date().isoformat()
        today_new = cursor.execute(
            """
            SELECT COUNT(*) as new_today
            FROM vulnerabilities
            WHERE published_date >= ? AND epss_percentile >= 70
        """,
            (today,),
        ).fetchone()

        return f"""
        <div class="stats-grid" id="stats-container">
            <div class="stat-card">
                <div class="stat-icon">🛡️</div>
                <div class="stat-value">{stats["total"]}</div>
                <div class="stat-label">Total Vulnerabilities</div>
                <div class="stat-change {"negative" if week_change["new_vulns"] > 0 else ""}">
                    <span>{"+" if week_change["new_vulns"] > 0 else ""}{week_change["new_vulns"]}</span>
                    <span>from last week</span>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-icon">🚨</div>
                <div class="stat-value">{stats["critical"]}</div>
                <div class="stat-label">Critical Severity</div>
                <div class="stat-change negative">
                    <span>+{today_new["new_today"]}</span>
                    <span>new today</span>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-icon">📈</div>
                <div class="stat-value">{stats["high_epss"]}</div>
                <div class="stat-label">High EPSS (≥90%)</div>
                <div class="stat-change">
                    <span>Exploitation likely</span>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-icon">⚡</div>
                <div class="stat-value">{int(stats["avg_risk"])}</div>
                <div class="stat-label">Average Risk Score</div>
                <div class="stat-change">
                    <span>Out of 100</span>
                </div>
            </div>
        </div>
        """

    def generate_vulnerability_row(self, vuln: sqlite3.Row) -> str:
        """Generate a single vulnerability table row"""
        severity_class = f"severity-{vuln['severity'].lower()}"

        # Parse JSON fields
        vendors = json.loads(vuln["vendors"]) if vuln["vendors"] else []

        # Format date
        pub_date = datetime.fromisoformat(vuln["published_date"])
        days_old = (datetime.now() - pub_date).days
        if days_old == 0:
            date_str = "Today"
        elif days_old == 1:
            date_str = "Yesterday"
        elif days_old < 7:
            date_str = f"{days_old} days ago"
        else:
            date_str = pub_date.strftime("%b %d, %Y")

        # Risk score calculation
        risk_score = self.calculate_risk_score(vuln)
        risk_class = "critical" if risk_score >= 80 else "high"

        return f"""
        <tr class="vulnerability-row" data-cve="{vuln["cve_id"]}">
            <td>
                <a href="#"
                   class="cve-link"
                   data-cve="{vuln["cve_id"]}"
                   onclick="openCveModal('{vuln["cve_id"]}'); return false;">
                    {vuln["cve_id"]}
                </a>
            </td>
            <td><span class="severity-badge {severity_class}">{vuln["severity"]}</span></td>
            <td>{vuln["cvss_score"] or "N/A"}</td>
            <td>{vuln["epss_percentile"]}%</td>
            <td>
                <div class="risk-score {risk_class}">
                    <span>{risk_score}</span>
                </div>
            </td>
            <td class="title-cell">{vuln["title"][:80]}{"..." if len(vuln["title"]) > 80 else ""}</td>
            <td>{", ".join(vendors[:2])}{"..." if len(vendors) > 2 else ""}</td>
            <td>{date_str}</td>
        </tr>
        """

    def calculate_risk_score(self, vuln: sqlite3.Row) -> int:
        """Calculate risk score for a vulnerability"""
        score = 0

        # CVSS contribution (40%)
        score += (vuln["cvss_score"] or 0) * 4

        # EPSS contribution (40%)
        score += (vuln["epss_percentile"] or 0) * 0.4

        # Severity bonus (10%)
        severity_bonus = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
        score += severity_bonus.get(vuln["severity"], 0)

        # Recency bonus (10%)
        pub_date = datetime.fromisoformat(vuln["published_date"])
        days_old = (datetime.now() - pub_date).days
        if days_old <= 7:
            score += 10
        elif days_old <= 30:
            score += 5

        return min(int(score), 100)

    def generate_table_fragment(
        self,
        vulns: List[sqlite3.Row],
        page: int = 1,
        per_page: int = 50,
        sort_field: str = "epss_percentile",
        sort_order: str = "desc",
    ) -> str:
        """Generate vulnerability table fragment"""
        total = len(vulns)
        total_pages = (total + per_page - 1) // per_page

        # Sort vulnerabilities
        if sort_field == "risk_score":
            vulns = sorted(
                vulns,
                key=lambda v: self.calculate_risk_score(v),
                reverse=(sort_order == "desc"),
            )
        else:
            vulns = sorted(
                vulns, key=lambda v: v[sort_field] or 0, reverse=(sort_order == "desc")
            )

        # Paginate
        start = (page - 1) * per_page
        end = start + per_page
        page_vulns = vulns[start:end]

        # Generate rows
        rows = [self.generate_vulnerability_row(vuln) for vuln in page_vulns]

        # Sort indicators
        sort_indicators = {
            "cve_id": "",
            "severity": "",
            "cvss_score": "",
            "epss_percentile": "",
            "risk_score": "",
            "published_date": "",
        }
        if sort_field in sort_indicators:
            sort_indicators[sort_field] = " ↓" if sort_order == "desc" else " ↑"

        return f"""
        <div class="table-container" id="vulnerabilities-table">
            <table class="data-table">
                <thead>
                    <tr>
                        <th class="sortable" data-sort="cve_id"
                            hx-get="/fragments/sort/cve_id.html"
                            hx-target="#vulnerabilities-table"
                            hx-swap="outerHTML">
                            CVE ID{sort_indicators["cve_id"]}
                        </th>
                        <th class="sortable" data-sort="severity"
                            hx-get="/fragments/sort/severity.html"
                            hx-target="#vulnerabilities-table"
                            hx-swap="outerHTML">
                            Severity{sort_indicators["severity"]}
                        </th>
                        <th class="sortable" data-sort="cvss_score"
                            hx-get="/fragments/sort/cvss_score.html"
                            hx-target="#vulnerabilities-table"
                            hx-swap="outerHTML">
                            CVSS{sort_indicators["cvss_score"]}
                        </th>
                        <th class="sortable" data-sort="epss_percentile"
                            hx-get="/fragments/sort/epss_percentile.html"
                            hx-target="#vulnerabilities-table"
                            hx-swap="outerHTML">
                            EPSS %{sort_indicators["epss_percentile"]}
                        </th>
                        <th class="sortable" data-sort="risk_score"
                            hx-get="/fragments/sort/risk_score.html"
                            hx-target="#vulnerabilities-table"
                            hx-swap="outerHTML">
                            Risk Score{sort_indicators["risk_score"]}
                        </th>
                        <th>Title</th>
                        <th>Vendors</th>
                        <th class="sortable" data-sort="published_date"
                            hx-get="/fragments/sort/published_date.html"
                            hx-target="#vulnerabilities-table"
                            hx-swap="outerHTML">
                            Published{sort_indicators["published_date"]}
                        </th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(rows)}
                </tbody>
            </table>

            <div class="pagination">
                <button class="page-btn"
                        {"disabled" if page <= 1 else ""}
                        {'hx-get="/fragments/page/' + str(page - 1) + '.html" hx-target="#vulnerabilities-table" hx-swap="outerHTML"' if page > 1 else ""}>
                    Previous
                </button>
                <span class="page-info">
                    Page {page} of {total_pages} • {total} vulnerabilities
                </span>
                <button class="page-btn"
                        {"disabled" if page >= total_pages else ""}
                        {'hx-get="/fragments/page/' + str(page + 1) + '.html" hx-target="#vulnerabilities-table" hx-swap="outerHTML"' if page < total_pages else ""}>
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
                if v["attack_vector"] == "NETWORK"
                or "network" in v["title"].lower()
                or "remote" in v["title"].lower()
            ]
        else:
            return self.vulnerabilities

    def generate_charts_fragment(self) -> str:
        """Generate charts fragment with data"""
        cursor = self.db.cursor()

        # Severity distribution
        severity_data = cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM vulnerabilities
            WHERE epss_percentile >= 70
            GROUP BY severity
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                END
        """).fetchall()

        # 30-day trend
        trend_data = []
        for i in range(29, -1, -1):
            date = (datetime.now() - timedelta(days=i)).date()
            count = cursor.execute(
                """
                SELECT COUNT(*) as count
                FROM vulnerabilities
                WHERE DATE(published_date) = ? AND epss_percentile >= 70
            """,
                (date.isoformat(),),
            ).fetchone()["count"]
            trend_data.append({"date": date.strftime("%b %d"), "count": count})

        # Top vendors
        vendor_counts = {}
        for vuln in self.vulnerabilities:
            if vuln["vendors"]:
                vendors = json.loads(vuln["vendors"])
                for vendor in vendors:
                    vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1

        top_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[
            :10
        ]

        # EPSS distribution
        epss_ranges = [
            {"label": "90-100%", "min": 90, "max": 100, "color": "#dc2626"},
            {"label": "80-89%", "min": 80, "max": 89, "color": "#ef4444"},
            {"label": "70-79%", "min": 70, "max": 79, "color": "#f59e0b"},
        ]

        epss_data = []
        for range_def in epss_ranges:
            count = len(
                [
                    v
                    for v in self.vulnerabilities
                    if range_def["min"] <= v["epss_percentile"] <= range_def["max"]
                ]
            )
            epss_data.append(
                {
                    "label": range_def["label"],
                    "count": count,
                    "color": range_def["color"],
                }
            )

        return f"""
        <div class="charts-grid" id="charts-container">
            <div class="chart-card">
                <h3 class="chart-title">Severity Distribution</h3>
                <div class="chart-container">
                    <canvas id="severity-chart"></canvas>
                </div>
            </div>

            <div class="chart-card">
                <h3 class="chart-title">30-Day Trend</h3>
                <div class="chart-container">
                    <canvas id="trend-chart"></canvas>
                </div>
            </div>

            <div class="chart-card">
                <h3 class="chart-title">Top Vendors</h3>
                <div class="chart-container">
                    <canvas id="vendor-chart"></canvas>
                </div>
            </div>

            <div class="chart-card">
                <h3 class="chart-title">EPSS Distribution</h3>
                <div class="chart-container">
                    <canvas id="epss-chart"></canvas>
                </div>
            </div>
        </div>

        <script>
            // Chart data and initialization
            const chartOptions = {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        labels: {{ color: '#cbd5e1' }}
                    }}
                }},
                scales: {{
                    x: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ color: 'rgba(148, 163, 184, 0.1)' }} }},
                    y: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ color: 'rgba(148, 163, 184, 0.1)' }} }}
                }}
            }};

            // Severity Chart
            new Chart(document.getElementById('severity-chart'), {{
                type: 'doughnut',
                data: {{
                    labels: {[row["severity"] for row in severity_data]},
                    datasets: [{{
                        data: {[row["count"] for row in severity_data]},
                        backgroundColor: ['#dc2626', '#ef4444', '#f59e0b', '#3b82f6'],
                        borderWidth: 0
                    }}]
                }},
                options: {{
                    ...chartOptions,
                    cutout: '70%'
                }}
            }});

            // Trend Chart
            new Chart(document.getElementById('trend-chart'), {{
                type: 'line',
                data: {{
                    labels: {[d["date"] for d in trend_data]},
                    datasets: [{{
                        label: 'New CVEs',
                        data: {[d["count"] for d in trend_data]},
                        borderColor: '#00d4ff',
                        backgroundColor: 'rgba(0, 212, 255, 0.1)',
                        tension: 0.4,
                        fill: true
                    }}]
                }},
                options: chartOptions
            }});

            // Vendor Chart
            new Chart(document.getElementById('vendor-chart'), {{
                type: 'bar',
                data: {{
                    labels: {[v[0] for v in top_vendors]},
                    datasets: [{{
                        label: 'Vulnerabilities',
                        data: {[v[1] for v in top_vendors]},
                        backgroundColor: '#8b5cf6'
                    }}]
                }},
                options: {{
                    ...chartOptions,
                    indexAxis: 'y'
                }}
            }});

            // EPSS Chart
            new Chart(document.getElementById('epss-chart'), {{
                type: 'bar',
                data: {{
                    labels: {[d["label"] for d in epss_data]},
                    datasets: [{{
                        label: 'Count',
                        data: {[d["count"] for d in epss_data]},
                        backgroundColor: {[d["color"] for d in epss_data]}
                    }}]
                }},
                options: chartOptions
            }});
        </script>
        """

    def generate_all_fragments(self):
        """Generate all static fragments"""
        print("🔨 Generating HTMX fragments...")

        # Generate stats
        with open(FRAGMENTS_DIR / "stats.html", "w") as f:
            f.write(self.generate_stats_fragment())

        # Generate main table
        with open(FRAGMENTS_DIR / "vulnerabilities.html", "w") as f:
            f.write(self.generate_table_fragment(self.vulnerabilities))

        # Generate charts
        with open(FRAGMENTS_DIR / "charts.html", "w") as f:
            f.write(self.generate_charts_fragment())

        # Generate filter fragments
        filters = ["all", "critical", "today", "kev", "network"]
        for filter_type in filters:
            filtered = self.filter_vulnerabilities(filter_type)
            with open(FRAGMENTS_DIR / "filter" / f"{filter_type}.html", "w") as f:
                f.write(self.generate_table_fragment(filtered))

        # Generate sort fragments
        sort_fields = [
            "cve_id",
            "severity",
            "cvss_score",
            "epss_percentile",
            "risk_score",
            "published_date",
        ]
        for field in sort_fields:
            # Generate both asc and desc versions
            for order in ["asc", "desc"]:
                with open(FRAGMENTS_DIR / "sort" / f"{field}_{order}.html", "w") as f:
                    f.write(
                        self.generate_table_fragment(
                            self.vulnerabilities, sort_field=field, sort_order=order
                        )
                    )

        # Generate pagination fragments (first 10 pages)
        for page in range(1, min(11, (len(self.vulnerabilities) + 49) // 50 + 1)):
            with open(FRAGMENTS_DIR / "page" / f"{page}.html", "w") as f:
                f.write(self.generate_table_fragment(self.vulnerabilities, page=page))

        print(f"✅ Generated {len(list(FRAGMENTS_DIR.rglob('*.html')))} fragments")

    def generate_main_dashboard(self):
        """Generate the main dashboard HTML"""
        html = Path("src/dashboard-htmx.html").read_text()

        # Replace API endpoints with static fragment paths
        replacements = {
            "/api/stats": "/fragments/stats.html",
            "/api/vulnerabilities": "/fragments/vulnerabilities.html",
            "/api/charts": "/fragments/charts.html",
            "/api/filter/quick": "/fragments/filter/{filter}.html",
            "/api/sort": "/fragments/sort/{field}_{order}.html",
            "/api/export/csv": "/data/vulnerabilities.csv",
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

        # Write main dashboard
        with open(OUTPUT_DIR / "index.html", "w") as f:
            f.write(html)

        print("✅ Generated main dashboard")

    def generate_csv_export(self):
        """Generate CSV export file"""
        csv_lines = ["CVE ID,Severity,CVSS,EPSS %,Risk Score,Title,Vendors,Published"]

        for vuln in self.vulnerabilities:
            vendors = json.loads(vuln["vendors"]) if vuln["vendors"] else []
            risk_score = self.calculate_risk_score(vuln)

            csv_lines.append(
                f'"{vuln["cve_id"]}","{vuln["severity"]}",{vuln["cvss_score"] or ""},'
                f'{vuln["epss_percentile"]},{risk_score},"{vuln["title"].replace('"', '""')}",'
                f'"{", ".join(vendors)}",{vuln["published_date"]}'
            )

        # Create data directory
        data_dir = OUTPUT_DIR / "data"
        data_dir.mkdir(exist_ok=True)

        with open(data_dir / "vulnerabilities.csv", "w") as f:
            f.write("\n".join(csv_lines))

        print("✅ Generated CSV export")

    def generate_vulnerability_data_json(self):
        """Generate JSON data file for client-side search"""
        data = []
        for vuln in self.vulnerabilities:
            data.append(
                {
                    "cve_id": vuln["cve_id"],
                    "title": vuln["title"],
                    "severity": vuln["severity"],
                    "cvss_score": vuln["cvss_score"],
                    "epss_percentile": vuln["epss_percentile"],
                    "risk_score": self.calculate_risk_score(vuln),
                    "vendors": json.loads(vuln["vendors"]) if vuln["vendors"] else [],
                    "tags": json.loads(vuln["tags"]) if vuln["tags"] else [],
                    "published_date": vuln["published_date"],
                }
            )

        # Create data directory if not exists
        data_dir = OUTPUT_DIR / "data"
        data_dir.mkdir(exist_ok=True)

        with open(data_dir / "vulnerabilities.json", "w") as f:
            json.dump(data, f, separators=(",", ":"))

        print(f"✅ Generated vulnerabilities.json ({len(data)} CVEs)")


def main():
    """Generate static HTMX dashboard"""
    print("🚀 Generating Static HTMX Dashboard for GitHub Pages")

    if not DB_PATH.exists():
        print(f"❌ Database not found at {DB_PATH}")
        print("   Run 'python -m scripts.main harvest' first")
        return

    generator = HTMXDashboardGenerator(DB_PATH)

    # Generate all components
    generator.generate_all_fragments()
    generator.generate_main_dashboard()
    generator.generate_csv_export()
    generator.generate_vulnerability_data_json()

    print("\n✅ Dashboard generation complete!")
    print(f"📁 Output directory: {OUTPUT_DIR}")
    print("🌐 Ready to deploy to GitHub Pages")


if __name__ == "__main__":
    main()
