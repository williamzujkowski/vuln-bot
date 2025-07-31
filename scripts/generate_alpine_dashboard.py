#!/usr/bin/env python3
"""
Generate pure client-side Alpine.js dashboard for GitHub Pages
This creates a single HTML file with embedded data and client-side functionality
"""

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict

# Configuration
OUTPUT_DIR = Path("public")
DB_PATH = Path(".cache/vulns.db")
BASE_PATH = "/vuln-bot"  # GitHub Pages base path

# Ensure output directories exist
OUTPUT_DIR.mkdir(exist_ok=True)
(OUTPUT_DIR / "data").mkdir(exist_ok=True)


class AlpineDashboardGenerator:
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
            cvss = vuln.get("cvss_score", 0) or 0
            epss = vuln.get("epss_percentile", 0) or 0
            vuln["risk_score"] = int((cvss * 10 + epss) / 2)

            # Parse JSON fields safely
            vuln["vendors_list"] = (
                json.loads(vuln["vendors"]) if vuln["vendors"] else []
            )
            vuln["products_list"] = (
                json.loads(vuln["products"]) if vuln["products"] else []
            )
            vuln["tags_list"] = json.loads(vuln["tags"]) if vuln["tags"] else []

            # Format published date
            if vuln["published_date"]:
                vuln["published_short"] = vuln["published_date"][:10]
            else:
                vuln["published_short"] = "Unknown"

            self.vulnerabilities.append(vuln)

    def generate_stats(self) -> Dict[str, Any]:
        """Generate dashboard statistics"""
        total = len(self.vulnerabilities)
        critical = sum(1 for v in self.vulnerabilities if v["severity"] == "CRITICAL")
        high = sum(1 for v in self.vulnerabilities if v["severity"] == "HIGH")
        medium = sum(1 for v in self.vulnerabilities if v["severity"] == "MEDIUM")
        low = sum(1 for v in self.vulnerabilities if v["severity"] == "LOW")

        # Get today's count
        today = datetime.now().date().isoformat()
        today_count = sum(
            1
            for v in self.vulnerabilities
            if v["published_date"] and v["published_date"].startswith(today)
        )

        # Get week change
        week_ago = (datetime.now() - timedelta(days=7)).date().isoformat()
        week_count = sum(
            1
            for v in self.vulnerabilities
            if v["published_date"] and v["published_date"] >= week_ago
        )

        # Get KEV count
        kev_count = sum(1 for v in self.vulnerabilities if "KEV" in v["tags_list"])

        return {
            "total": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "today_count": today_count,
            "week_count": week_count,
            "kev_count": kev_count,
            "severity_distribution": {
                "CRITICAL": critical,
                "HIGH": high,
                "MEDIUM": medium,
                "LOW": low,
            },
            "epss_distribution": {
                "90-100%": sum(
                    1 for v in self.vulnerabilities if v["epss_percentile"] >= 90
                ),
                "70-89%": sum(
                    1 for v in self.vulnerabilities if 70 <= v["epss_percentile"] < 90
                ),
                "50-69%": sum(
                    1 for v in self.vulnerabilities if 50 <= v["epss_percentile"] < 70
                ),
                "<50%": sum(
                    1 for v in self.vulnerabilities if v["epss_percentile"] < 50
                ),
            },
        }

    def create_dashboard_html(self):
        """Create the complete Alpine.js dashboard"""
        stats = self.generate_stats()

        # Prepare vulnerability data for JSON embedding (only essential fields)
        vuln_data = []
        for vuln in self.vulnerabilities:
            vuln_data.append(
                {
                    "cve_id": vuln["cve_id"],
                    "title": vuln["title"] or "No title available",
                    "severity": vuln["severity"],
                    "cvss_score": vuln["cvss_score"],
                    "epss_percentile": vuln["epss_percentile"],
                    "risk_score": vuln["risk_score"],
                    "vendors": vuln["vendors_list"][:3],  # Limit to first 3 vendors
                    "tags": vuln["tags_list"],
                    "published_date": vuln["published_date"],
                    "published_short": vuln["published_short"],
                    "attack_vector": vuln["attack_vector"],
                    "description": vuln["description"],
                }
            )

        html_content = f"""<!DOCTYPE html>  # noqa: B608
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Intelligence Dashboard</title>

    <!-- Alpine.js -->
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>

    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>
        /* Modern Dark Theme */
        :root {{
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: #1e1e2a;
            --bg-hover: #252535;

            --accent-primary: #00d4ff;
            --accent-secondary: #7c3aed;
            --accent-danger: #ef4444;
            --accent-success: #10b981;

            --text-primary: #ffffff;
            --text-secondary: #a3a3b8;
            --text-muted: #6b6b85;

            --gradient-primary: linear-gradient(135deg, #00d4ff 0%, #7c3aed 100%);
            --shadow-glow: 0 0 40px rgba(0, 212, 255, 0.3);

            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}

        /* Layout */
        .dashboard {{
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }}

        /* Header */
        .header {{
            background: rgba(18, 18, 26, 0.9);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding: 1rem 2rem;
            position: sticky;
            top: 0;
            z-index: 100;
        }}

        .header-content {{
            max-width: 1600px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .brand {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}

        .brand-icon {{
            width: 48px;
            height: 48px;
            background: var(--gradient-primary);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 1.5rem;
        }}

        .brand h1 {{
            font-size: 1.75rem;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        /* Main Content */
        .main {{
            flex: 1;
            padding: 2rem;
            max-width: 1600px;
            margin: 0 auto;
            width: 100%;
        }}

        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}

        .stat-card {{
            background: var(--bg-card);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 20px;
            padding: 2rem;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}

        .stat-card:hover {{
            transform: translateY(-4px);
            box-shadow: var(--shadow-glow);
        }}

        .stat-value {{
            font-size: 2.5rem;
            font-weight: 700;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        .stat-label {{
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
        }}

        /* Filters */
        .filters-section {{
            background: var(--bg-card);
            border-radius: 20px;
            padding: 2rem;
            margin-bottom: 2rem;
        }}

        .filter-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }}

        .filter-group {{
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }}

        .filter-group label {{
            color: var(--text-secondary);
            font-size: 0.875rem;
            font-weight: 500;
        }}

        .filter-group input,
        .filter-group select {{
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 0.75rem;
            color: var(--text-primary);
            transition: all 0.3s ease;
        }}

        .filter-group input:focus,
        .filter-group select:focus {{
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 3px rgba(0, 212, 255, 0.1);
        }}

        /* Search */
        .search-box {{
            position: relative;
            margin-bottom: 1rem;
        }}

        .search-input {{
            width: 100%;
            padding: 1rem 3rem 1rem 1.5rem;
            background: rgba(255, 255, 255, 0.05);
            border: 2px solid transparent;
            border-radius: 16px;
            font-size: 1rem;
            color: var(--text-primary);
        }}

        .search-input:focus {{
            outline: none;
            border-color: var(--accent-primary);
            background: rgba(0, 212, 255, 0.05);
        }}

        /* Quick Filters */
        .quick-filters {{
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
            margin-bottom: 2rem;
        }}

        .filter-chip {{
            padding: 0.75rem 1.5rem;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 30px;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.3s ease;
        }}

        .filter-chip:hover {{
            background: rgba(0, 212, 255, 0.1);
            border-color: var(--accent-primary);
            color: var(--accent-primary);
        }}

        .filter-chip.active {{
            background: var(--gradient-primary);
            color: white;
            border-color: transparent;
        }}

        /* Data Table */
        .data-section {{
            background: var(--bg-card);
            border-radius: 20px;
            padding: 2rem;
            overflow: hidden;
        }}

        .table-wrapper {{
            overflow-x: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th {{
            text-align: left;
            padding: 1rem;
            color: var(--text-secondary);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            font-weight: 600;
            cursor: pointer;
            user-select: none;
        }}

        th:hover {{
            color: var(--accent-primary);
        }}

        td {{
            padding: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }}

        tbody tr {{
            transition: background-color 0.2s ease;
        }}

        tbody tr:hover {{
            background: rgba(0, 212, 255, 0.02);
        }}

        /* Severity Badges */
        .severity-badge {{
            display: inline-flex;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .severity-critical {{
            background: rgba(220, 38, 38, 0.2);
            color: #dc2626;
            border: 1px solid rgba(220, 38, 38, 0.3);
        }}

        .severity-high {{
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}

        .severity-medium {{
            background: rgba(245, 158, 11, 0.2);
            color: #f59e0b;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }}

        .severity-low {{
            background: rgba(59, 130, 246, 0.2);
            color: #3b82f6;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }}

        /* Pagination */
        .pagination {{
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 1rem;
            margin-top: 2rem;
        }}

        .page-btn {{
            padding: 0.5rem 1rem;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.3s ease;
        }}

        .page-btn:hover:not(:disabled) {{
            background: rgba(0, 212, 255, 0.1);
            border-color: var(--accent-primary);
            color: var(--accent-primary);
        }}

        .page-btn:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}

        /* Charts */
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 2rem;
            margin: 2rem 0;
        }}

        .chart-card {{
            background: var(--bg-card);
            border-radius: 20px;
            padding: 1.5rem;
        }}

        .chart-title {{
            font-size: 1.25rem;
            margin-bottom: 1rem;
            color: var(--text-secondary);
        }}

        .chart-container {{
            position: relative;
            height: 300px;
        }}

        /* Modal */
        .modal {{
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }}

        .modal.show {{
            display: flex;
        }}

        .modal-content {{
            background: var(--bg-card);
            border-radius: 20px;
            padding: 2rem;
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        }}

        .modal h2 {{
            margin-bottom: 1rem;
            color: var(--accent-primary);
        }}

        .modal-close {{
            background: var(--accent-primary);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 8px;
            cursor: pointer;
            margin-top: 1rem;
        }}

        /* Responsive */
        @media (max-width: 768px) {{
            .header-content {{
                flex-direction: column;
                gap: 1rem;
            }}

            .main {{
                padding: 1rem;
            }}

            .stats-grid {{
                grid-template-columns: 1fr;
            }}

            .filter-grid {{
                grid-template-columns: 1fr;
            }}

            .quick-filters {{
                justify-content: center;
            }}

            .charts-grid {{
                grid-template-columns: 1fr;
            }}
        }}

        .truncate {{
            max-width: 200px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}

        .cve-link {{
            color: var(--accent-primary);
            text-decoration: none;
        }}

        .cve-link:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body x-data="dashboard()">
    <div class="dashboard">
        <!-- Header -->
        <header class="header">
            <div class="header-content">
                <div class="brand">
                    <div class="brand-icon">VB</div>
                    <div>
                        <h1>Vuln-Bot Intelligence</h1>
                        <p style="color: var(--text-muted); font-size: 0.875rem;">
                            Real-time Vulnerability Monitoring
                        </p>
                    </div>
                </div>
                <div style="display: flex; gap: 1rem;">
                    <button class="filter-chip" @click="exportCSV()">
                        Export CSV
                    </button>
                </div>
            </div>
        </header>

        <!-- Main Content -->
        <main class="main">
            <!-- Stats Section -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value" x-text="stats.total"></div>
                    <div class="stat-label">Total Vulnerabilities</div>
                    <div class="stat-change negative">
                        <span x-text="`+${{stats.week_count}}`"></span>
                        <span>from last week</span>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-value" x-text="stats.critical"></div>
                    <div class="stat-label">Critical Severity</div>
                    <div class="stat-change negative">
                        <span x-text="`+${{stats.today_count}}`"></span>
                        <span>new today</span>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-value" x-text="stats.high"></div>
                    <div class="stat-label">High Severity</div>
                    <div class="stat-trend">
                        <span x-text="`${{Math.round(stats.high / stats.total * 100)}}%`"></span>
                        <span>of total</span>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-value" x-text="stats.kev_count"></div>
                    <div class="stat-label">KEV Listed</div>
                    <div class="stat-trend">
                        <span>Known</span>
                        <span>Exploited</span>
                    </div>
                </div>
            </div>

            <!-- Quick Filters -->
            <div class="quick-filters">
                <button class="filter-chip"
                        :class="{{ 'active': quickFilter === 'all' }}"
                        @click="setQuickFilter('all')">
                    All Vulnerabilities
                </button>
                <button class="filter-chip"
                        :class="{{ 'active': quickFilter === 'critical' }}"
                        @click="setQuickFilter('critical')">
                    <span class="severity-badge severity-critical">Critical</span>
                </button>
                <button class="filter-chip"
                        :class="{{ 'active': quickFilter === 'today' }}"
                        @click="setQuickFilter('today')">
                    📅 Today's CVEs
                </button>
                <button class="filter-chip"
                        :class="{{ 'active': quickFilter === 'kev' }}"
                        @click="setQuickFilter('kev')">
                    ⭐ KEV Listed
                </button>
                <button class="filter-chip"
                        :class="{{ 'active': quickFilter === 'network' }}"
                        @click="setQuickFilter('network')">
                    🌐 Network Vector
                </button>
            </div>

            <!-- Filters Section -->
            <div class="filters-section" x-data="{{ expanded: true }}">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                    <h2 style="font-size: 1.25rem;">Filters</h2>
                    <button @click="expanded = !expanded"
                            style="background: none; border: none; color: var(--text-secondary); cursor: pointer;">
                        <span x-text="expanded ? '−' : '+'"></span>
                    </button>
                </div>

                <div x-show="expanded" x-transition>
                    <!-- Search -->
                    <div class="search-box">
                        <input type="text"
                               x-model="search"
                               class="search-input"
                               placeholder="Search CVE ID, vendor, or keyword..."
                               @keydown.slash.window.prevent="$el.focus()">
                    </div>

                    <!-- Filter Grid -->
                    <div class="filter-grid">
                        <div class="filter-group">
                            <label>Severity</label>
                            <select x-model="filters.severity">
                                <option value="">All</option>
                                <option value="CRITICAL">Critical</option>
                                <option value="HIGH">High</option>
                                <option value="MEDIUM">Medium</option>
                                <option value="LOW">Low</option>
                            </select>
                        </div>

                        <div class="filter-group">
                            <label>CVSS Score</label>
                            <div style="display: flex; gap: 0.5rem;">
                                <input type="number" x-model.number="filters.cvss_min" placeholder="Min" min="0" max="10" step="0.1">
                                <input type="number" x-model.number="filters.cvss_max" placeholder="Max" min="0" max="10" step="0.1">
                            </div>
                        </div>

                        <div class="filter-group">
                            <label>EPSS %</label>
                            <div style="display: flex; gap: 0.5rem;">
                                <input type="number" x-model.number="filters.epss_min" placeholder="Min" min="0" max="100" value="70">
                                <input type="number" x-model.number="filters.epss_max" placeholder="Max" min="0" max="100" value="100">
                            </div>
                        </div>

                        <div class="filter-group">
                            <label>Published Date</label>
                            <div style="display: flex; gap: 0.5rem;">
                                <input type="date" x-model="filters.published_from">
                                <input type="date" x-model="filters.published_to">
                            </div>
                        </div>

                        <div class="filter-group">
                            <label>Vendor</label>
                            <input type="text" x-model="filters.vendor" placeholder="e.g., Microsoft">
                        </div>
                    </div>

                    <div style="display: flex; gap: 1rem; margin-top: 1rem;">
                        <button class="filter-chip active" @click="resetFilters()" @keydown.r.window.prevent="resetFilters()">
                            Reset
                        </button>
                    </div>
                </div>
            </div>

            <!-- Charts Section -->
            <div class="charts-grid">
                <div class="chart-card">
                    <h3 class="chart-title">Severity Distribution</h3>
                    <div class="chart-container">
                        <canvas x-ref="severityChart"></canvas>
                    </div>
                </div>

                <div class="chart-card">
                    <h3 class="chart-title">EPSS Score Distribution</h3>
                    <div class="chart-container">
                        <canvas x-ref="epssChart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Data Table -->
            <div class="data-section">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                    <h2 style="font-size: 1.5rem;">Vulnerabilities</h2>
                    <div x-text="`Showing ${{Math.min(perPage, filteredVulns.length)}} of ${{filteredVulns.length}} results`"
                         style="color: var(--text-secondary);"></div>
                </div>

                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th @click="sort('cve_id')" style="cursor: pointer;">
                                    CVE ID <span x-show="sortField === 'cve_id'" x-text="sortOrder === 'asc' ? '↑' : '↓'"></span>
                                </th>
                                <th @click="sort('severity')" style="cursor: pointer;">
                                    Severity <span x-show="sortField === 'severity'" x-text="sortOrder === 'asc' ? '↑' : '↓'"></span>
                                </th>
                                <th @click="sort('cvss_score')" style="cursor: pointer;">
                                    CVSS <span x-show="sortField === 'cvss_score'" x-text="sortOrder === 'asc' ? '↑' : '↓'"></span>
                                </th>
                                <th @click="sort('epss_percentile')" style="cursor: pointer;">
                                    EPSS % <span x-show="sortField === 'epss_percentile'" x-text="sortOrder === 'asc' ? '↑' : '↓'"></span>
                                </th>
                                <th @click="sort('risk_score')" style="cursor: pointer;">
                                    Risk Score <span x-show="sortField === 'risk_score'" x-text="sortOrder === 'asc' ? '↑' : '↓'"></span>
                                </th>
                                <th>Title</th>
                                <th>Vendors</th>
                                <th @click="sort('published_date')" style="cursor: pointer;">
                                    Published <span x-show="sortField === 'published_date'" x-text="sortOrder === 'asc' ? '↑' : '↓'"></span>
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            <template x-for="vuln in paginatedVulns" :key="vuln.cve_id">
                                <tr class="vulnerability-row" :data-cve="vuln.cve_id">
                                    <td>
                                        <a href="#" @click.prevent="openModal(vuln)" class="cve-link" x-text="vuln.cve_id"></a>
                                    </td>
                                    <td>
                                        <span class="severity-badge" :class="`severity-${{vuln.severity.toLowerCase()}}`" x-text="vuln.severity"></span>
                                    </td>
                                    <td x-text="vuln.cvss_score"></td>
                                    <td x-text="vuln.epss_percentile"></td>
                                    <td x-text="vuln.risk_score"></td>
                                    <td class="truncate" x-text="vuln.title"></td>
                                    <td class="truncate" x-text="vuln.vendors.join(', ') || 'Unknown'"></td>
                                    <td x-text="vuln.published_short"></td>
                                </tr>
                            </template>
                        </tbody>
                    </table>

                    <div class="pagination">
                        <button class="page-btn"
                                @click="currentPage--"
                                :disabled="currentPage <= 1">
                            Previous
                        </button>
                        <span x-text="`Page ${{currentPage}} of ${{totalPages}} • ${{filteredVulns.length}} vulnerabilities`"></span>
                        <button class="page-btn"
                                @click="currentPage++"
                                :disabled="currentPage >= totalPages">
                            Next
                        </button>
                    </div>
                </div>
            </div>
        </main>

        <!-- CVE Modal -->
        <div x-ref="modal" class="modal" :class="{{ 'show': showModal }}" @click.self="closeModal()">
            <div class="modal-content">
                <template x-if="selectedVuln">
                    <div>
                        <h2 x-text="selectedVuln.cve_id"></h2>
                        <p><strong>Severity:</strong> <span x-text="selectedVuln.severity"></span></p>
                        <p><strong>CVSS Score:</strong> <span x-text="selectedVuln.cvss_score"></span></p>
                        <p><strong>EPSS:</strong> <span x-text="selectedVuln.epss_percentile + '%'"></span></p>
                        <p><strong>Risk Score:</strong> <span x-text="selectedVuln.risk_score"></span></p>
                        <p><strong>Title:</strong> <span x-text="selectedVuln.title"></span></p>
                        <p><strong>Vendors:</strong> <span x-text="selectedVuln.vendors.join(', ') || 'Unknown'"></span></p>
                        <p><strong>Published:</strong> <span x-text="selectedVuln.published_short"></span></p>
                        <template x-if="selectedVuln.description">
                            <p><strong>Description:</strong> <span x-text="selectedVuln.description"></span></p>
                        </template>
                        <button class="modal-close" @click="closeModal()">Close</button>
                    </div>
                </template>
            </div>
        </div>
    </div>

    <script>
        // Embed vulnerability data
        const vulnerabilityData = {json.dumps(vuln_data, indent=2)};
        const statsData = {json.dumps(stats, indent=2)};

        function dashboard() {{
            return {{
                // Data
                vulnerabilities: vulnerabilityData,
                stats: statsData,

                // UI State
                search: '',
                quickFilter: 'all',
                sortField: 'epss_percentile',
                sortOrder: 'desc',
                currentPage: 1,
                perPage: 50,
                showModal: false,
                selectedVuln: null,

                // Filters
                filters: {{
                    severity: '',
                    cvss_min: null,
                    cvss_max: null,
                    epss_min: 70,
                    epss_max: 100,
                    published_from: '',
                    published_to: '',
                    vendor: ''
                }},

                // Initialization
                init() {{
                    this.$nextTick(() => {{
                        this.initCharts();
                        this.setupKeyboardShortcuts();
                    }});
                }},

                // Computed Properties
                get filteredVulns() {{
                    let vulns = [...this.vulnerabilities];

                    // Quick filter
                    if (this.quickFilter === 'critical') {{
                        vulns = vulns.filter(v => v.severity === 'CRITICAL');
                    }} else if (this.quickFilter === 'today') {{
                        const today = new Date().toISOString().split('T')[0];
                        vulns = vulns.filter(v => v.published_date && v.published_date.startsWith(today));
                    }} else if (this.quickFilter === 'kev') {{
                        vulns = vulns.filter(v => v.tags.includes('KEV'));
                    }} else if (this.quickFilter === 'network') {{
                        vulns = vulns.filter(v => v.attack_vector === 'NETWORK');
                    }}

                    // Search
                    if (this.search) {{
                        const searchLower = this.search.toLowerCase();
                        vulns = vulns.filter(v =>
                            v.cve_id.toLowerCase().includes(searchLower) ||
                            v.title.toLowerCase().includes(searchLower) ||
                            v.vendors.some(vendor => vendor.toLowerCase().includes(searchLower))
                        );
                    }}

                    // Advanced filters
                    if (this.filters.severity) {{
                        vulns = vulns.filter(v => v.severity === this.filters.severity);
                    }}

                    if (this.filters.cvss_min !== null) {{
                        vulns = vulns.filter(v => v.cvss_score >= this.filters.cvss_min);
                    }}

                    if (this.filters.cvss_max !== null) {{
                        vulns = vulns.filter(v => v.cvss_score <= this.filters.cvss_max);
                    }}

                    if (this.filters.epss_min !== null) {{
                        vulns = vulns.filter(v => v.epss_percentile >= this.filters.epss_min);
                    }}

                    if (this.filters.epss_max !== null) {{
                        vulns = vulns.filter(v => v.epss_percentile <= this.filters.epss_max);
                    }}

                    if (this.filters.published_from) {{
                        vulns = vulns.filter(v => v.published_date >= this.filters.published_from);
                    }}

                    if (this.filters.published_to) {{
                        vulns = vulns.filter(v => v.published_date <= this.filters.published_to);
                    }}

                    if (this.filters.vendor) {{
                        const vendorLower = this.filters.vendor.toLowerCase();
                        vulns = vulns.filter(v =>
                            v.vendors.some(vendor => vendor.toLowerCase().includes(vendorLower))
                        );
                    }}

                    // Sorting
                    vulns.sort((a, b) => {{
                        let aVal = a[this.sortField];
                        let bVal = b[this.sortField];

                        // Handle special cases
                        if (this.sortField === 'severity') {{
                            const severityOrder = {{ 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 }};
                            aVal = severityOrder[aVal] || 0;
                            bVal = severityOrder[bVal] || 0;
                        }}

                        if (aVal < bVal) return this.sortOrder === 'asc' ? -1 : 1;
                        if (aVal > bVal) return this.sortOrder === 'asc' ? 1 : -1;
                        return 0;
                    }});

                    return vulns;
                }},

                get totalPages() {{
                    return Math.ceil(this.filteredVulns.length / this.perPage);
                }},

                get paginatedVulns() {{
                    const start = (this.currentPage - 1) * this.perPage;
                    const end = start + this.perPage;
                    return this.filteredVulns.slice(start, end);
                }},

                // Methods
                setQuickFilter(filter) {{
                    this.quickFilter = filter;
                    this.currentPage = 1;
                }},

                sort(field) {{
                    if (this.sortField === field) {{
                        this.sortOrder = this.sortOrder === 'asc' ? 'desc' : 'asc';
                    }} else {{
                        this.sortField = field;
                        this.sortOrder = 'desc';
                    }}
                    this.currentPage = 1;
                }},

                resetFilters() {{
                    this.search = '';
                    this.quickFilter = 'all';
                    this.filters = {{
                        severity: '',
                        cvss_min: null,
                        cvss_max: null,
                        epss_min: 70,
                        epss_max: 100,
                        published_from: '',
                        published_to: '',
                        vendor: ''
                    }};
                    this.currentPage = 1;
                }},

                openModal(vuln) {{
                    this.selectedVuln = vuln;
                    this.showModal = true;
                }},

                closeModal() {{
                    this.showModal = false;
                    this.selectedVuln = null;
                }},

                exportCSV() {{
                    const headers = ['CVE ID', 'Severity', 'CVSS', 'EPSS %', 'Risk Score', 'Title', 'Vendors', 'Published'];
                    const csvContent = [
                        headers.join(','),
                        ...this.filteredVulns.map(v => [
                            v.cve_id,
                            v.severity,
                            v.cvss_score,
                            v.epss_percentile,
                            v.risk_score,
                            `"${{v.title.replace(/"/g, '""')}}"`,
                            `"${{v.vendors.join(', ')}}"`,
                            v.published_short
                        ].join(','))
                    ].join('\\n');

                    const blob = new Blob([csvContent], {{ type: 'text/csv' }});
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'vulnerabilities.csv';
                    a.click();
                    window.URL.revokeObjectURL(url);
                }},

                setupKeyboardShortcuts() {{
                    document.addEventListener('keydown', (e) => {{
                        // Only trigger shortcuts when not in input fields
                        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') {{
                            return;
                        }}

                        switch(e.key) {{
                            case '/':
                                e.preventDefault();
                                document.querySelector('.search-input').focus();
                                break;
                            case 'r':
                                e.preventDefault();
                                this.resetFilters();
                                break;
                            case 'e':
                                e.preventDefault();
                                this.exportCSV();
                                break;
                            case 'Escape':
                                if (this.showModal) {{
                                    this.closeModal();
                                }}
                                break;
                        }}
                    }});
                }},

                initCharts() {{
                    // Severity Chart
                    if (this.$refs.severityChart) {{
                        new Chart(this.$refs.severityChart, {{
                            type: 'doughnut',
                            data: {{
                                labels: ['Critical', 'High', 'Medium', 'Low'],
                                datasets: [{{
                                    data: [
                                        this.stats.severity_distribution.CRITICAL,
                                        this.stats.severity_distribution.HIGH,
                                        this.stats.severity_distribution.MEDIUM,
                                        this.stats.severity_distribution.LOW
                                    ],
                                    backgroundColor: ['#dc2626', '#ef4444', '#f59e0b', '#3b82f6']
                                }}]
                            }},
                            options: {{
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: {{
                                    legend: {{
                                        labels: {{ color: '#cbd5e1' }}
                                    }}
                                }}
                            }}
                        }});
                    }}

                    // EPSS Chart
                    if (this.$refs.epssChart) {{
                        new Chart(this.$refs.epssChart, {{
                            type: 'bar',
                            data: {{
                                labels: ['90-100%', '70-89%', '50-69%', '<50%'],
                                datasets: [{{
                                    data: [
                                        this.stats.epss_distribution['90-100%'],
                                        this.stats.epss_distribution['70-89%'],
                                        this.stats.epss_distribution['50-69%'],
                                        this.stats.epss_distribution['<50%']
                                    ],
                                    backgroundColor: ['#dc2626', '#ef4444', '#f59e0b', '#10b981']
                                }}]
                            }},
                            options: {{
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: {{
                                    legend: {{ display: false }},
                                }},
                                scales: {{
                                    y: {{
                                        ticks: {{ color: '#cbd5e1' }}
                                    }},
                                    x: {{
                                        ticks: {{ color: '#cbd5e1' }}
                                    }}
                                }}
                            }}
                        }});
                    }}
                }}
            }}
        }}
    </script>
</body>
</html>"""

        # Write the dashboard HTML
        with open(OUTPUT_DIR / "index.html", "w") as f:
            f.write(html_content)
        print("✓ Created Alpine.js dashboard HTML")

    def export_csv_data(self):
        """Export CSV for download"""
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
                    ", ".join(vuln["vendors_list"][:3]) if vuln["vendors_list"] else ""
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
                        vuln["published_short"],
                    ]
                )
        print("✓ Exported CSV data")


def main():
    """Main function"""
    # Check if database exists
    if not DB_PATH.exists():
        print(f"Error: Database not found at {DB_PATH}")
        print("Creating test database...")
        import sys

        sys.path.insert(0, "scripts")
        from create_test_db import create_test_database

        create_test_database()
        print("✓ Created test database")

    # Generate dashboard
    generator = AlpineDashboardGenerator(DB_PATH)
    generator.create_dashboard_html()
    generator.export_csv_data()

    print("\n✅ Alpine.js dashboard generated successfully!")
    print(f"📁 Output directory: {OUTPUT_DIR}")
    print("🚀 Ready to deploy to GitHub Pages")


if __name__ == "__main__":
    main()
