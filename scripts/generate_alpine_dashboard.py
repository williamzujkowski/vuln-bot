#!/usr/bin/env python3
"""
Generate pure client-side Alpine.js dashboard for GitHub Pages
This creates a single HTML file with embedded data and client-side functionality
"""

import json
import sqlite3
import sys
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
        """Load all vulnerabilities from cache database"""
        cursor = self.db.cursor()
        rows = cursor.execute("""
            SELECT cve_id, data, risk_score, severity, published_date, last_modified_date
            FROM vulnerability_cache
            ORDER BY risk_score DESC
        """).fetchall()

        # Convert cache data to vulnerability objects
        self.vulnerabilities = []
        for row in rows:
            try:
                # Parse the JSON data from cache
                vuln_data = json.loads(row["data"])

                # Extract CVSS score from cvss_metrics
                cvss_score = 0
                if vuln_data.get("cvss_metrics"):
                    for metric in vuln_data["cvss_metrics"]:
                        if metric.get("base_score"):
                            cvss_score = max(cvss_score, metric["base_score"])

                # Extract EPSS percentile
                epss_percentile = 0
                if vuln_data.get("epss_score") and isinstance(
                    vuln_data["epss_score"], dict
                ):
                    epss_percentile = vuln_data["epss_score"].get("percentile", 0)

                # Create vulnerability dict with both cache fields and parsed data
                vuln = {
                    "cve_id": row["cve_id"],
                    "risk_score": row["risk_score"],
                    "severity": row["severity"],
                    "published_date": row["published_date"],
                    "last_modified_date": row["last_modified_date"],
                    "cvss_score": cvss_score,
                    "epss_percentile": epss_percentile,
                    **vuln_data,  # Merge in all the JSON data
                }

                # Ensure required fields exist with defaults
                vuln.setdefault("title", vuln.get("cve_id", "Unknown"))
                vuln.setdefault("description", "No description available")
                vuln.setdefault("vendors", [])
                vuln.setdefault("products", [])
                vuln.setdefault("tags", [])

                # Ensure lists are properly formatted - use correct field names
                vendors_raw = vuln.get("affected_vendors", vuln.get("vendors", []))
                if isinstance(vendors_raw, str):
                    vuln["vendors_list"] = (
                        json.loads(vendors_raw) if vendors_raw else []
                    )
                else:
                    vuln["vendors_list"] = vendors_raw if vendors_raw else []

                products_raw = vuln.get("affected_products", vuln.get("products", []))
                if isinstance(products_raw, str):
                    vuln["products_list"] = (
                        json.loads(products_raw) if products_raw else []
                    )
                else:
                    vuln["products_list"] = products_raw if products_raw else []

                if isinstance(vuln["tags"], str):
                    vuln["tags_list"] = json.loads(vuln["tags"]) if vuln["tags"] else []
                else:
                    vuln["tags_list"] = vuln["tags"] if vuln["tags"] else []

                # Format published date
                if vuln["published_date"]:
                    vuln["published_short"] = str(vuln["published_date"])[:10]
                else:
                    vuln["published_short"] = "Unknown"

                self.vulnerabilities.append(vuln)

            except (json.JSONDecodeError, KeyError, TypeError) as e:
                print(
                    f"Warning: Failed to parse vulnerability {row.get('cve_id', 'unknown')}: {e}"
                )
                continue

    def _create_enhanced_title(self, vuln) -> str:
        """Create enhanced title format: [SEVERITY] Vendor Product vVersion"""
        components = []

        # Add severity
        components.append(f"[{vuln['severity']}]")

        # Add primary vendor
        vendors = vuln.get("vendors_list", [])
        if vendors:
            vendor = vendors[0].title()
            components.append(vendor)

        # Add primary product
        products = vuln.get("products_list", [])
        if products:
            product = products[0].title()
            components.append(product)

        # Extract version information (simplified)
        version_info = self._extract_version_info(vuln)
        if version_info:
            components.append(version_info)

        # If no vendor/product info, fall back to original title (truncated)
        if len(components) == 1:  # Only severity
            fallback_title = (
                vuln["title"][:80] + "..."
                if len(vuln.get("title", "")) > 80
                else vuln.get("title", "")
            )
            return f"{components[0]} {fallback_title}"

        return " ".join(components)

    def _extract_products(self, vuln) -> str:
        """Extract primary product name for Product column"""
        products = vuln.get("products_list", [])
        vendors = vuln.get("vendors_list", [])

        if products and vendors:
            return f"{vendors[0]}/{products[0]}"
        elif products:
            return products[0]
        elif vendors:
            return vendors[0]
        else:
            return "Unknown Product"

    def _extract_version_info(self, vuln) -> str:
        """Extract version information from title"""
        import re

        title = vuln.get("title", "")
        version_patterns = [
            r"\bv?(\d+\.\d+(?:\.\d+)*)\b",
            r"\bversion\s+(\d+\.\d+(?:\.\d+)*)\b",
            r"\bbefore\s+(\d+\.\d+(?:\.\d+)*)\b",
        ]

        for pattern in version_patterns:
            matches = re.findall(pattern, title.lower())
            if matches:
                return f"v{matches[0]}"

        return ""

    def _extract_cwe_ids(self, vuln) -> list:
        """Extract CWE IDs from description or other fields"""
        import re

        text = f"{vuln.get('title', '')} {vuln.get('description', '')}"
        cwe_pattern = r"CWE-(\d+)"
        matches = re.findall(cwe_pattern, text)
        return [f"CWE-{match}" for match in matches[:3]]  # Limit to first 3

    def _get_kev_status(self, vuln) -> bool:
        """Check if vulnerability is in CISA KEV catalog"""
        tags = vuln.get("tags_list", [])
        return any(
            "kev" in tag.lower() or "known exploited" in tag.lower() for tag in tags
        )

    def _detect_patch_status(self, vuln) -> str:
        """Detect patch availability from description/title"""
        text = f"{vuln.get('title', '')} {vuln.get('description', '')}".lower()
        if any(word in text for word in ["patch", "update", "fixed", "patched"]):
            return "Available"
        elif any(word in text for word in ["no patch", "unpatched", "0-day"]):
            return "Unavailable"
        else:
            return "Unknown"

    def _get_exploitation_status(self, vuln) -> str:
        """Determine exploitation status"""
        tags = vuln.get("tags_list", [])
        title_desc = f"{vuln.get('title', '')} {vuln.get('description', '')}".lower()

        if any("exploit" in tag.lower() or "active" in tag.lower() for tag in tags):
            return "Active"
        elif any(word in title_desc for word in ["exploit", "poc", "proof of concept"]):
            return "PoC Available"
        elif any(word in title_desc for word in ["weaponized", "malware"]):
            return "Weaponized"
        else:
            return "Unknown"

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

        # Prepare vulnerability data for JSON embedding with enhanced fields
        vuln_data = []
        for vuln in self.vulnerabilities:
            # Create enhanced title format: [SEVERITY] Vendor Product vVersion
            enhanced_title = self._create_enhanced_title(vuln)
            products_display = self._extract_products(vuln)

            vuln_data.append(
                {
                    "cve_id": vuln["cve_id"],
                    "title": enhanced_title,
                    "originalTitle": vuln["title"] or "No title available",
                    "products": products_display,  # New field for Product column
                    "severity": vuln["severity"],
                    "cvss_score": vuln["cvss_score"],
                    "epss_percentile": vuln["epss_percentile"],
                    "risk_score": vuln["risk_score"],
                    "vendors": vuln["vendors_list"][:3],  # Limit to first 3 vendors
                    "tags": vuln["tags_list"],
                    "published_date": vuln["published_date"],
                    "published_short": vuln["published_short"],
                    "last_modified_date": vuln.get("last_modified_date"),
                    "attack_vector": vuln["attack_vector"],
                    "description": vuln["description"] or "No description available",
                    # Enhanced modal fields
                    "attack_complexity": vuln.get("attack_complexity"),
                    "scope": vuln.get("scope"),
                    "user_interaction": vuln.get("user_interaction"),
                    "privileges_required": vuln.get("privileges_required"),
                    "confidentiality_impact": vuln.get("confidentiality_impact"),
                    "integrity_impact": vuln.get("integrity_impact"),
                    "availability_impact": vuln.get("availability_impact"),
                    "cwe_ids": self._extract_cwe_ids(vuln),
                    "kev_status": self._get_kev_status(vuln),
                    "patch_status": self._detect_patch_status(vuln),
                    "exploitation_status": self._get_exploitation_status(vuln),
                }
            )

        # B608 is false positive - generating HTML not SQL
        # Build HTML content without f-string to avoid Bandit false positive
        html_content = """<!DOCTYPE html>
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
        :root __OPEN_BRACE__
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
        __CLOSE_BRACE__

        * __OPEN_BRACE__
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        __CLOSE_BRACE__

        body __OPEN_BRACE__
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        __CLOSE_BRACE__

        /* Layout */
        .dashboard __OPEN_BRACE__
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        __CLOSE_BRACE__

        /* Header */
        .header __OPEN_BRACE__
            background: rgba(18, 18, 26, 0.9);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding: 1rem 2rem;
            position: sticky;
            top: 0;
            z-index: 100;
        __CLOSE_BRACE__

        .header-content __OPEN_BRACE__
            max-width: 1600px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        __CLOSE_BRACE__

        .brand __OPEN_BRACE__
            display: flex;
            align-items: center;
            gap: 1rem;
        __CLOSE_BRACE__

        .brand-icon __OPEN_BRACE__
            width: 48px;
            height: 48px;
            background: var(--gradient-primary);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 1.5rem;
        __CLOSE_BRACE__

        .brand h1 __OPEN_BRACE__
            font-size: 1.75rem;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        __CLOSE_BRACE__

        /* Main Content */
        .main __OPEN_BRACE__
            flex: 1;
            padding: 2rem;
            max-width: 1600px;
            margin: 0 auto;
            width: 100%;
        __CLOSE_BRACE__

        /* Stats Grid */
        .stats-grid __OPEN_BRACE__
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        __CLOSE_BRACE__

        .stat-card __OPEN_BRACE__
            background: var(--bg-card);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 20px;
            padding: 2rem;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        __CLOSE_BRACE__

        .stat-card:hover __OPEN_BRACE__
            transform: translateY(-4px);
            box-shadow: var(--shadow-glow);
        __CLOSE_BRACE__

        .stat-value __OPEN_BRACE__
            font-size: 2.5rem;
            font-weight: 700;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        __CLOSE_BRACE__

        .stat-label __OPEN_BRACE__
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
        __CLOSE_BRACE__

        /* Filters */
        .filters-section __OPEN_BRACE__
            background: var(--bg-card);
            border-radius: 20px;
            padding: 2rem;
            margin-bottom: 2rem;
        __CLOSE_BRACE__

        .filter-grid __OPEN_BRACE__
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        __CLOSE_BRACE__

        .filter-group __OPEN_BRACE__
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        __CLOSE_BRACE__

        .filter-group label __OPEN_BRACE__
            color: var(--text-secondary);
            font-size: 0.875rem;
            font-weight: 500;
        __CLOSE_BRACE__

        .filter-group input,
        .filter-group select __OPEN_BRACE__
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 0.75rem;
            color: var(--text-primary);
            transition: all 0.3s ease;
        __CLOSE_BRACE__

        .filter-group input:focus,
        .filter-group select:focus __OPEN_BRACE__
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 3px rgba(0, 212, 255, 0.1);
        __CLOSE_BRACE__

        /* Search */
        .search-box __OPEN_BRACE__
            position: relative;
            margin-bottom: 1rem;
        __CLOSE_BRACE__

        .search-input __OPEN_BRACE__
            width: 100%;
            padding: 1rem 3rem 1rem 1.5rem;
            background: rgba(255, 255, 255, 0.05);
            border: 2px solid transparent;
            border-radius: 16px;
            font-size: 1rem;
            color: var(--text-primary);
        __CLOSE_BRACE__

        .search-input:focus __OPEN_BRACE__
            outline: none;
            border-color: var(--accent-primary);
            background: rgba(0, 212, 255, 0.05);
        __CLOSE_BRACE__

        /* Quick Filters */
        .quick-filters __OPEN_BRACE__
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
            margin-bottom: 2rem;
        __CLOSE_BRACE__

        .filter-chip __OPEN_BRACE__
            padding: 0.75rem 1.5rem;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 30px;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.3s ease;
        __CLOSE_BRACE__

        .filter-chip:hover __OPEN_BRACE__
            background: rgba(0, 212, 255, 0.1);
            border-color: var(--accent-primary);
            color: var(--accent-primary);
        __CLOSE_BRACE__

        .filter-chip.active __OPEN_BRACE__
            background: var(--gradient-primary);
            color: white;
            border-color: transparent;
        __CLOSE_BRACE__

        /* Data Table */
        .data-section __OPEN_BRACE__
            background: var(--bg-card);
            border-radius: 20px;
            padding: 2rem;
            overflow: hidden;
        __CLOSE_BRACE__

        .table-wrapper __OPEN_BRACE__
            overflow-x: auto;
        __CLOSE_BRACE__

        table __OPEN_BRACE__
            width: 100%;
            border-collapse: collapse;
        __CLOSE_BRACE__

        th __OPEN_BRACE__
            text-align: left;
            padding: 1rem;
            color: var(--text-secondary);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            font-weight: 600;
            cursor: pointer;
            user-select: none;
        __CLOSE_BRACE__

        th:hover __OPEN_BRACE__
            color: var(--accent-primary);
        __CLOSE_BRACE__

        td __OPEN_BRACE__
            padding: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        __CLOSE_BRACE__

        tbody tr __OPEN_BRACE__
            transition: background-color 0.2s ease;
        __CLOSE_BRACE__

        tbody tr:hover __OPEN_BRACE__
            background: rgba(0, 212, 255, 0.02);
        __CLOSE_BRACE__

        /* Severity Badges */
        .severity-badge __OPEN_BRACE__
            display: inline-flex;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        __CLOSE_BRACE__

        .severity-critical __OPEN_BRACE__
            background: rgba(220, 38, 38, 0.2);
            color: #dc2626;
            border: 1px solid rgba(220, 38, 38, 0.3);
        __CLOSE_BRACE__

        .severity-high __OPEN_BRACE__
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.3);
        __CLOSE_BRACE__

        .severity-medium __OPEN_BRACE__
            background: rgba(245, 158, 11, 0.2);
            color: #f59e0b;
            border: 1px solid rgba(245, 158, 11, 0.3);
        __CLOSE_BRACE__

        .severity-low __OPEN_BRACE__
            background: rgba(59, 130, 246, 0.2);
            color: #3b82f6;
            border: 1px solid rgba(59, 130, 246, 0.3);
        __CLOSE_BRACE__

        /* Pagination */
        .pagination __OPEN_BRACE__
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 1rem;
            margin-top: 2rem;
        __CLOSE_BRACE__

        .page-btn __OPEN_BRACE__
            padding: 0.5rem 1rem;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.3s ease;
        __CLOSE_BRACE__

        .page-btn:hover:not(:disabled) __OPEN_BRACE__
            background: rgba(0, 212, 255, 0.1);
            border-color: var(--accent-primary);
            color: var(--accent-primary);
        __CLOSE_BRACE__

        .page-btn:disabled __OPEN_BRACE__
            opacity: 0.5;
            cursor: not-allowed;
        __CLOSE_BRACE__

        /* Charts */
        .charts-grid __OPEN_BRACE__
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 2rem;
            margin: 2rem 0;
        __CLOSE_BRACE__

        .chart-card __OPEN_BRACE__
            background: var(--bg-card);
            border-radius: 20px;
            padding: 1.5rem;
        __CLOSE_BRACE__

        .chart-title __OPEN_BRACE__
            font-size: 1.25rem;
            margin-bottom: 1rem;
            color: var(--text-secondary);
        __CLOSE_BRACE__

        .chart-container __OPEN_BRACE__
            position: relative;
            height: 300px;
        __CLOSE_BRACE__



        /* Enhanced Mobile Responsiveness */
        @media (max-width: 768px) __OPEN_BRACE__
            .table-wrapper __OPEN_BRACE__
                overflow-x: auto;
                -webkit-overflow-scrolling: touch;
                margin: 0 -1rem;
                padding: 0 1rem;
            __CLOSE_BRACE__

            table __OPEN_BRACE__
                min-width: 600px;
            __CLOSE_BRACE__

            /* Add scroll indicator */
            .table-wrapper::after __OPEN_BRACE__
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
            __CLOSE_BRACE__

            .table-wrapper:not(:hover)::after __OPEN_BRACE__
                opacity: 1;
            __CLOSE_BRACE__

            /* Responsive table cells */
            td, th __OPEN_BRACE__
                white-space: nowrap;
                min-width: 100px;
            __CLOSE_BRACE__

            /* Hide less important columns on mobile */
            th:nth-child(5), td:nth-child(5) __OPEN_BRACE__ /* Risk Score */
                display: none;
            __CLOSE_BRACE__

            .stats-card __OPEN_BRACE__
                padding: 1rem;
            __CLOSE_BRACE__

            .stat-value __OPEN_BRACE__
                font-size: 1.75rem;
            __CLOSE_BRACE__

            .filter-grid __OPEN_BRACE__
                grid-template-columns: 1fr;
            __CLOSE_BRACE__

            .quick-filters __OPEN_BRACE__
                flex-wrap: wrap;
                justify-content: center;
            __CLOSE_BRACE__

            .filter-chip __OPEN_BRACE__
                font-size: 0.875rem;
                padding: 0.375rem 0.75rem;
            __CLOSE_BRACE__
        __CLOSE_BRACE__

        /* Responsive */
        @media (max-width: 768px) __OPEN_BRACE__
            .header-content __OPEN_BRACE__
                flex-direction: column;
                gap: 1rem;
            __CLOSE_BRACE__

            .main __OPEN_BRACE__
                padding: 1rem;
            __CLOSE_BRACE__

            .stats-grid __OPEN_BRACE__
                grid-template-columns: 1fr;
            __CLOSE_BRACE__

            .filter-grid __OPEN_BRACE__
                grid-template-columns: 1fr;
            __CLOSE_BRACE__

            .quick-filters __OPEN_BRACE__
                justify-content: center;
            __CLOSE_BRACE__

            .charts-grid __OPEN_BRACE__
                grid-template-columns: 1fr;
            __CLOSE_BRACE__
        __CLOSE_BRACE__

        .truncate __OPEN_BRACE__
            max-width: 200px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        __CLOSE_BRACE__

        .cve-link __OPEN_BRACE__
            color: var(--accent-primary);
            text-decoration: none;
        __CLOSE_BRACE__

        .cve-link:hover __OPEN_BRACE__
            text-decoration: underline;
        __CLOSE_BRACE__
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

            <!-- Stats Section -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value" x-text="stats.total"></div>
                    <div class="stat-label">Total Vulnerabilities</div>
                    <div class="stat-change positive">
                        <span x-text="`+${stats.week_count}`"></span>
                        <span>from last week</span>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-value" x-text="stats.critical"></div>
                    <div class="stat-label">Critical Severity</div>
                    <div class="stat-change negative">
                        <span x-text="`+${stats.today_count}`"></span>
                        <span>new today</span>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-value" x-text="stats.high"></div>
                    <div class="stat-label">High Severity</div>
                    <div class="stat-trend">
                        <span x-text="`${Math.round(stats.high / stats.total * 100)}%`"></span>
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
                        :class="{ 'active': quickFilter === 'all' }"
                        @click="setQuickFilter('all')">
                    All Vulnerabilities
                </button>
                <button class="filter-chip"
                        :class="{ 'active': quickFilter === 'critical' }"
                        @click="setQuickFilter('critical')">
                    <span class="severity-badge severity-critical">Critical</span>
                </button>
                <button class="filter-chip"
                        :class="{ 'active': quickFilter === 'today' }"
                        @click="setQuickFilter('today')">
                    📅 Today's CVEs
                </button>
                <button class="filter-chip"
                        :class="{ 'active': quickFilter === 'kev' }"
                        @click="setQuickFilter('kev')">
                    ⭐ KEV Listed
                </button>
                <button class="filter-chip"
                        :class="{ 'active': quickFilter === 'network' }"
                        @click="setQuickFilter('network')">
                    🌐 Network Vector
                </button>
            </div>

            <!-- Filters Section -->
            <div class="filters-section" x-data="{ expanded: true }">
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
                    <div x-text="`Showing ${Math.min(perPage, filteredVulns.length)} of ${filteredVulns.length} results`"
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
                                <th>Product</th>
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
                                        <a :href="`/vuln-bot/cves/${vuln.cve_id}/`" class="cve-link" x-text="vuln.cve_id"></a>
                                    </td>
                                    <td>
                                        <span class="severity-badge" :class="`severity-${vuln.severity.toLowerCase()}`" x-text="vuln.severity"></span>
                                    </td>
                                    <td x-text="vuln.cvss_score"></td>
                                    <td x-text="vuln.epss_percentile"></td>
                                    <td x-text="vuln.risk_score"></td>
                                    <td class="truncate" x-text="vuln.products"></td>
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
                        <span x-text="`Page ${currentPage} of ${totalPages} • ${filteredVulns.length} vulnerabilities`"></span>
                        <button class="page-btn"
                                @click="currentPage++"
                                :disabled="currentPage >= totalPages">
                            Next
                        </button>
                    </div>
                </div>
            </div>
        </main>

    </div>

    <script>
        // Embed vulnerability data (using window to ensure global scope)
        window.vulnerabilityData = VULN_DATA_PLACEHOLDER;
        window.statsData = STATS_DATA_PLACEHOLDER;

        window.dashboard = function() __OPEN_BRACE__
            return __OPEN_BRACE__
                // Data
                vulnerabilities: window.vulnerabilityData,
                stats: window.statsData,

                // UI State
                search: '',
                quickFilter: 'all',
                sortField: 'epss_percentile',
                sortOrder: 'desc',
                currentPage: 1,
                perPage: 50,

                // Filters
                filters: __OPEN_BRACE__
                    severity: '',
                    cvss_min: null,
                    cvss_max: null,
                    epss_min: 0,
                    epss_max: 100,
                    published_from: '',
                    published_to: '',
                    vendor: ''
                __CLOSE_BRACE__,

                // Initialization
                init() __OPEN_BRACE__
                    this.$nextTick(() => __OPEN_BRACE__
                        this.initCharts();
                        this.setupKeyboardShortcuts();
                    __CLOSE_BRACE__);
                __CLOSE_BRACE__,

                // Computed Properties
                get filteredVulns() __OPEN_BRACE__
                    let vulns = [...this.vulnerabilities];

                    // Quick filter
                    if (this.quickFilter === 'critical') __OPEN_BRACE__
                        vulns = vulns.filter(v => v.severity === 'CRITICAL');
                    __CLOSE_BRACE__ else if (this.quickFilter === 'today') __OPEN_BRACE__
                        const today = new Date().toISOString().split('T')[0];
                        vulns = vulns.filter(v => v.published_date && v.published_date.startsWith(today));
                    __CLOSE_BRACE__ else if (this.quickFilter === 'kev') __OPEN_BRACE__
                        vulns = vulns.filter(v => v.tags.includes('KEV'));
                    __CLOSE_BRACE__ else if (this.quickFilter === 'network') __OPEN_BRACE__
                        vulns = vulns.filter(v => v.attack_vector === 'NETWORK');
                    __CLOSE_BRACE__

                    // Search
                    if (this.search) __OPEN_BRACE__
                        const searchLower = this.search.toLowerCase();
                        vulns = vulns.filter(v =>
                            v.cve_id.toLowerCase().includes(searchLower) ||
                            v.title.toLowerCase().includes(searchLower) ||
                            v.vendors.some(vendor => vendor.toLowerCase().includes(searchLower))
                        );
                    __CLOSE_BRACE__

                    // Advanced filters
                    if (this.filters.severity) __OPEN_BRACE__
                        vulns = vulns.filter(v => v.severity === this.filters.severity);
                    __CLOSE_BRACE__

                    if (this.filters.cvss_min !== null) __OPEN_BRACE__
                        vulns = vulns.filter(v => v.cvss_score >= this.filters.cvss_min);
                    __CLOSE_BRACE__

                    if (this.filters.cvss_max !== null) __OPEN_BRACE__
                        vulns = vulns.filter(v => v.cvss_score <= this.filters.cvss_max);
                    __CLOSE_BRACE__

                    if (this.filters.epss_min !== null) __OPEN_BRACE__
                        vulns = vulns.filter(v => v.epss_percentile >= this.filters.epss_min);
                    __CLOSE_BRACE__

                    if (this.filters.epss_max !== null) __OPEN_BRACE__
                        vulns = vulns.filter(v => v.epss_percentile <= this.filters.epss_max);
                    __CLOSE_BRACE__

                    if (this.filters.published_from) __OPEN_BRACE__
                        vulns = vulns.filter(v => v.published_date >= this.filters.published_from);
                    __CLOSE_BRACE__

                    if (this.filters.published_to) __OPEN_BRACE__
                        vulns = vulns.filter(v => v.published_date <= this.filters.published_to);
                    __CLOSE_BRACE__

                    if (this.filters.vendor) __OPEN_BRACE__
                        const vendorLower = this.filters.vendor.toLowerCase();
                        vulns = vulns.filter(v =>
                            v.vendors.some(vendor => vendor.toLowerCase().includes(vendorLower))
                        );
                    __CLOSE_BRACE__

                    // Sorting
                    vulns.sort((a, b) => __OPEN_BRACE__
                        let aVal = a[this.sortField];
                        let bVal = b[this.sortField];

                        // Handle special cases
                        if (this.sortField === 'severity') __OPEN_BRACE__
                            const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 __CLOSE_BRACE__;
                            aVal = severityOrder[aVal] || 0;
                            bVal = severityOrder[bVal] || 0;
                        __CLOSE_BRACE__

                        if (aVal < bVal) return this.sortOrder === 'asc' ? -1 : 1;
                        if (aVal > bVal) return this.sortOrder === 'asc' ? 1 : -1;
                        return 0;
                    __CLOSE_BRACE__);

                    return vulns;
                __CLOSE_BRACE__,

                get totalPages() __OPEN_BRACE__
                    return Math.ceil(this.filteredVulns.length / this.perPage);
                __CLOSE_BRACE__,

                get paginatedVulns() __OPEN_BRACE__
                    const start = (this.currentPage - 1) * this.perPage;
                    const end = start + this.perPage;
                    return this.filteredVulns.slice(start, end);
                __CLOSE_BRACE__,

                // Methods
                setQuickFilter(filter) __OPEN_BRACE__
                    this.quickFilter = filter;
                    this.currentPage = 1;
                __CLOSE_BRACE__,

                sort(field) __OPEN_BRACE__
                    if (this.sortField === field) __OPEN_BRACE__
                        this.sortOrder = this.sortOrder === 'asc' ? 'desc' : 'asc';
                    __CLOSE_BRACE__ else __OPEN_BRACE__
                        this.sortField = field;
                        this.sortOrder = 'desc';
                    __CLOSE_BRACE__
                    this.currentPage = 1;
                __CLOSE_BRACE__,

                resetFilters() __OPEN_BRACE__
                    this.search = '';
                    this.quickFilter = 'all';
                    this.filters = __OPEN_BRACE__
                        severity: '',
                        cvss_min: null,
                        cvss_max: null,
                        epss_min: 0,
                        epss_max: 100,
                        published_from: '',
                        published_to: '',
                        vendor: ''
                    __CLOSE_BRACE__;
                    this.currentPage = 1;
                __CLOSE_BRACE__,


                exportCSV() __OPEN_BRACE__
                    const headers = ['CVE ID', 'Severity', 'CVSS', 'EPSS %', 'Risk Score', 'Product', 'Vendors', 'Published'];
                    const csvContent = [
                        headers.join(','),
                        ...this.filteredVulns.map(v => [
                            v.cve_id,
                            v.severity,
                            v.cvss_score,
                            v.epss_percentile,
                            v.risk_score,
                            `"${v.products.replace(/"/g, '""')}"`,
                            `"${v.vendors.join(', ')}"`,
                            v.published_short
                        ].join(','))
                    ].join('\\n');

                    const blob = new Blob([csvContent], { type: 'text/csv' __CLOSE_BRACE__);
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'vulnerabilities.csv';
                    a.click();
                    window.URL.revokeObjectURL(url);
                __CLOSE_BRACE__,

                setupKeyboardShortcuts() __OPEN_BRACE__
                    document.addEventListener('keydown', (e) => __OPEN_BRACE__
                        // Only trigger shortcuts when not in input fields
                        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') __OPEN_BRACE__
                            return;
                        __CLOSE_BRACE__

                        switch(e.key) __OPEN_BRACE__
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
                        __CLOSE_BRACE__
                    __CLOSE_BRACE__);
                __CLOSE_BRACE__,

                initCharts() __OPEN_BRACE__
                    // Severity Chart
                    if (this.$refs.severityChart) __OPEN_BRACE__
                        new Chart(this.$refs.severityChart, __OPEN_BRACE__
                            type: 'doughnut',
                            data: __OPEN_BRACE__
                                labels: ['Critical', 'High', 'Medium', 'Low'],
                                datasets: [__OPEN_BRACE__
                                    data: [
                                        this.stats.severity_distribution.CRITICAL,
                                        this.stats.severity_distribution.HIGH,
                                        this.stats.severity_distribution.MEDIUM,
                                        this.stats.severity_distribution.LOW
                                    ],
                                    backgroundColor: ['#dc2626', '#ef4444', '#f59e0b', '#3b82f6']
                                __CLOSE_BRACE__]
                            __CLOSE_BRACE__,
                            options: __OPEN_BRACE__
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: __OPEN_BRACE__
                                    legend: __OPEN_BRACE__
                                        labels: { color: '#cbd5e1' __CLOSE_BRACE__
                                    __CLOSE_BRACE__
                                __CLOSE_BRACE__
                            __CLOSE_BRACE__
                        __CLOSE_BRACE__);
                    __CLOSE_BRACE__

                    // EPSS Chart
                    if (this.$refs.epssChart) __OPEN_BRACE__
                        new Chart(this.$refs.epssChart, __OPEN_BRACE__
                            type: 'bar',
                            data: __OPEN_BRACE__
                                labels: ['90-100%', '70-89%', '50-69%', '<50%'],
                                datasets: [__OPEN_BRACE__
                                    data: [
                                        this.stats.epss_distribution['90-100%'],
                                        this.stats.epss_distribution['70-89%'],
                                        this.stats.epss_distribution['50-69%'],
                                        this.stats.epss_distribution['<50%']
                                    ],
                                    backgroundColor: ['#dc2626', '#ef4444', '#f59e0b', '#10b981']
                                __CLOSE_BRACE__]
                            __CLOSE_BRACE__,
                            options: __OPEN_BRACE__
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: __OPEN_BRACE__
                                    legend: { display: false __CLOSE_BRACE__,
                                __CLOSE_BRACE__,
                                scales: __OPEN_BRACE__
                                    y: __OPEN_BRACE__
                                        ticks: { color: '#cbd5e1' __CLOSE_BRACE__
                                    __CLOSE_BRACE__,
                                    x: __OPEN_BRACE__
                                        ticks: { color: '#cbd5e1' __CLOSE_BRACE__
                                    __CLOSE_BRACE__
                                __CLOSE_BRACE__
                            __CLOSE_BRACE__
                        __CLOSE_BRACE__);
                    __CLOSE_BRACE__
                __CLOSE_BRACE__
            __CLOSE_BRACE__
        __CLOSE_BRACE__
    </script>
</body>
</html>"""

        # Replace placeholders with actual data
        html_content = html_content.replace(
            "VULN_DATA_PLACEHOLDER", json.dumps(vuln_data, indent=2)
        )
        html_content = html_content.replace(
            "STATS_DATA_PLACEHOLDER", json.dumps(stats, indent=2)
        )

        # Replace brace placeholders with actual braces
        html_content = html_content.replace("__OPEN_BRACE__", "{")
        html_content = html_content.replace("__CLOSE_BRACE__", "}")

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
        print("Please run the vulnerability harvest first to create the database:")
        print("python -m scripts.main harvest --cache-dir .cache/")
        sys.exit(1)

    # Generate dashboard
    generator = AlpineDashboardGenerator(DB_PATH)
    generator.create_dashboard_html()
    generator.export_csv_data()

    print("\n✅ Alpine.js dashboard generated successfully!")
    print(f"📁 Output directory: {OUTPUT_DIR}")
    print("🚀 Ready to deploy to GitHub Pages")


if __name__ == "__main__":
    main()
