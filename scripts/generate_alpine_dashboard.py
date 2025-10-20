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
import pytz

# Configuration
OUTPUT_DIR = Path("public")
DB_PATH = Path(".cache/vulns.db")
BASE_PATH = "/vuln-bot"  # GitHub Pages base path

# Ensure output directories exist
OUTPUT_DIR.mkdir(exist_ok=True)
(OUTPUT_DIR / "data").mkdir(exist_ok=True)


class AlpineDashboardGenerator:
    def __init__(self, json_path: Path = None, db_path: Path = None):
        self.vulnerabilities = []
        self.base_path = BASE_PATH

        # Prefer JSON API over SQLite database
        if json_path and json_path.exists():
            self.load_from_json(json_path)
        elif db_path and db_path.exists():
            self.db = sqlite3.connect(db_path)
            self.db.row_factory = sqlite3.Row
            self.load_from_database()
        else:
            print("Warning: No data source found. Dashboard will be empty.")

    def load_from_json(self, json_path: Path):
        """Load vulnerabilities from JSON API file"""
        print(f"Loading vulnerabilities from {json_path}")
        with open(json_path) as f:
            data = json.load(f)

        vulnerabilities = data.get("vulnerabilities", [])
        print(f"Found {len(vulnerabilities)} vulnerabilities")

        for vuln_data in vulnerabilities:
            try:
                # Map JSON API fields to dashboard format
                vuln = {
                    "cve_id": vuln_data["cveId"],
                    "title": vuln_data.get("originalTitle", vuln_data.get("title", "")),
                    "severity": vuln_data["severity"],
                    "cvss_score": vuln_data.get("cvssScore", 0),
                    "epss_percentile": vuln_data.get("epssPercentile", 0),
                    "risk_score": vuln_data.get("riskScore", 0),
                    "published_date": vuln_data.get("publishedDate", ""),
                    "last_modified_date": vuln_data.get("lastModifiedDate", ""),
                    "attack_vector": vuln_data.get("attackVector", "UNKNOWN"),
                    "attack_complexity": vuln_data.get("attackComplexity", ""),
                    "privileges_required": vuln_data.get("privilegesRequired", ""),
                    "user_interaction": vuln_data.get("userInteraction", ""),
                    "scope": vuln_data.get("scope", ""),
                    "confidentiality_impact": vuln_data.get(
                        "confidentialityImpact", ""
                    ),
                    "integrity_impact": vuln_data.get("integrityImpact", ""),
                    "availability_impact": vuln_data.get("availabilityImpact", ""),
                    "description": vuln_data.get(
                        "description", "No description available"
                    ),
                }

                # Handle vendors and products (already lists in JSON)
                vuln["vendors_list"] = vuln_data.get("vendors", [])
                vuln["products_list"] = vuln_data.get("products", [])
                vuln["tags_list"] = vuln_data.get("tags", [])

                # Preserve exploitation status and enrichments
                vuln["exploitationStatus"] = vuln_data.get("exploitationStatus", "")
                vuln["enrichments"] = vuln_data.get("enrichments", {})

                # Add SSVC data
                vuln["ssvc"] = vuln_data.get("ssvc", {})

                # Format published date
                if vuln["published_date"]:
                    vuln["published_short"] = str(vuln["published_date"])[:10]
                else:
                    vuln["published_short"] = "Unknown"

                # Calculate KEV status for use in stats
                vuln["kev_status"] = self._get_kev_status(vuln)

                self.vulnerabilities.append(vuln)

            except (KeyError, TypeError) as e:
                print(
                    f"Warning: Failed to parse vulnerability {vuln_data.get('cveId', 'unknown')}: {e}"
                )
                continue

        print(f"Successfully loaded {len(self.vulnerabilities)} vulnerabilities")

    def load_from_database(self):
        """Load all vulnerabilities from cache database"""
        cursor = self.db.cursor()
        rows = cursor.execute(
            """
            SELECT cve_id, data, risk_score, severity, published_date, last_modified_date
            FROM vulnerability_cache
            ORDER BY risk_score DESC
        """
        ).fetchall()

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

        if products:
            # Return just the product name, properly capitalized
            return products[0].title()
        elif vendors:
            # If no product, fall back to vendor
            return vendors[0].title()
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
        # Check exploitationStatus field first
        exploitation_status = vuln.get("exploitationStatus", "")
        if exploitation_status == "KNOWN_EXPLOITED":
            return True

        # Check enrichments.cisa_kev
        enrichments = vuln.get("enrichments", {})
        if isinstance(enrichments, dict):
            cisa_kev = enrichments.get("cisa_kev", {})
            if isinstance(cisa_kev, dict) and cisa_kev.get("isKnownExploited"):
                return True

        # Fallback to tags
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
        # Check exploitationStatus field first
        exploitation_status = vuln.get("exploitationStatus", "")
        status_map = {
            "KNOWN_EXPLOITED": "KEV Listed",
            "POC_AVAILABLE": "PoC Available",
            "ACTIVE_EXPLOITATION": "Active",
        }
        if exploitation_status in status_map:
            return status_map[exploitation_status]

        # Check enrichments for exploit references
        enrichments = vuln.get("enrichments", {})
        if isinstance(enrichments, dict):
            exploit_refs = enrichments.get("exploit_references", [])
            if exploit_refs:
                return "PoC Available"

        # Fallback to tags and text analysis
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

    def _calculate_triage_priority(self, vuln) -> str:
        """Calculate triage priority based on EPSS, CVSS, and Attack Complexity
        Returns: CRITICAL-URGENT, HIGH-PRIORITY, or MONITOR
        """
        epss = vuln.get("epss_percentile", 0)
        cvss = vuln.get("cvss_score", 0)
        attack_complexity = (vuln.get("attack_complexity") or "").upper()

        # CRITICAL-URGENT: EPSS ≥95% AND CVSS ≥9.0 AND Low Complexity
        if epss >= 95 and cvss >= 9.0 and attack_complexity == "LOW":
            return "CRITICAL-URGENT"
        # HIGH-PRIORITY: EPSS ≥80% AND CVSS ≥7.0
        elif epss >= 80 and cvss >= 7.0:
            return "HIGH-PRIORITY"
        # MONITOR: Everything else (EPSS 60-80%)
        else:
            return "MONITOR"

    def _detect_technology_category(self, vuln) -> list:
        """Detect technology categories for filtering
        Returns: List of category tags
        """
        categories = []
        vendors = [v.lower() for v in vuln.get("vendors_list", [])]
        products = [p.lower() for p in vuln.get("products_list", [])]
        all_text = " ".join(vendors + products).lower()

        # Web Servers
        if any(
            keyword in all_text
            for keyword in ["apache", "nginx", "iis", "httpd", "tomcat"]
        ):
            categories.append("web-servers")

        # Databases
        if any(
            keyword in all_text
            for keyword in [
                "postgresql",
                "mysql",
                "mongodb",
                "redis",
                "mariadb",
                "oracle",
                "mssql",
            ]
        ):
            categories.append("databases")

        # Containers/K8s
        if any(
            keyword in all_text
            for keyword in ["docker", "kubernetes", "containerd", "k8s", "podman"]
        ):
            categories.append("containers-k8s")

        # Windows
        if any(
            keyword in all_text
            for keyword in ["microsoft", "windows", "azure", "exchange", "sharepoint"]
        ):
            categories.append("windows")

        # Linux
        if any(
            keyword in all_text
            for keyword in ["linux", "ubuntu", "redhat", "centos", "debian", "fedora"]
        ):
            categories.append("linux")

        # Network Gear
        if any(
            keyword in all_text
            for keyword in ["cisco", "fortinet", "palo alto", "juniper", "netgear"]
        ):
            categories.append("network-gear")

        # CMS
        if any(
            keyword in all_text
            for keyword in ["wordpress", "drupal", "joomla", "typo3"]
        ):
            categories.append("cms")

        return categories

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

        # Get KEV count - use kev_status boolean
        kev_count = sum(1 for v in self.vulnerabilities if v.get("kev_status", False))

        # NEW: Priority distribution
        critical_urgent = sum(
            1
            for v in self.vulnerabilities
            if self._calculate_triage_priority(v) == "CRITICAL-URGENT"
        )
        high_priority = sum(
            1
            for v in self.vulnerabilities
            if self._calculate_triage_priority(v) == "HIGH-PRIORITY"
        )
        monitor = sum(
            1
            for v in self.vulnerabilities
            if self._calculate_triage_priority(v) == "MONITOR"
        )

        # NEW: Exploitation status distribution
        kev_listed = sum(1 for v in self.vulnerabilities if v.get("kev_status", False))
        poc_available = sum(
            1
            for v in self.vulnerabilities
            if not v.get("kev_status", False)
            and self._get_exploitation_status(v) != "Unknown"
        )
        not_listed = sum(
            1
            for v in self.vulnerabilities
            if not v.get("kev_status", False)
            and self._get_exploitation_status(v) == "Unknown"
        )

        return {
            "total": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "today_count": today_count,
            "week_count": week_count,
            "kev_count": kev_count,
            "last_updated": datetime.now().isoformat(),
            "dashboard_built": datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S %Z'),
            # NEW: Priority distribution for chart
            "priority_distribution": {
                "CRITICAL-URGENT": critical_urgent,
                "HIGH-PRIORITY": high_priority,
                "MONITOR": monitor,
            },
            # NEW: Exploitation status for chart
            "exploitation_distribution": {
                "KEV Listed": kev_listed,
                "PoC Available": poc_available,
                "Not Listed": not_listed,
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
                    # NEW: Phase 2 enhancements
                    "triage_priority": self._calculate_triage_priority(vuln),
                    "tech_categories": self._detect_technology_category(vuln),
                    # SSVC data (Phase 2 - Frontend Integration)
                    "ssvc": vuln.get("ssvc", {}),
                    # Enrichments data (CRITICAL: needed for KEV detection)
                    "enrichments": vuln.get("enrichments", {}),
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

        /* Priority Badges */
        .priority-badge __OPEN_BRACE__
            display: inline-flex;
            align-items: center;
            gap: 0.375rem;
            padding: 0.5rem 1rem;
            border-radius: 24px;
            font-size: 0.875rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        __CLOSE_BRACE__

        .priority-critical-urgent __OPEN_BRACE__
            background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
            color: #ffffff;
            border: 2px solid rgba(220, 38, 38, 0.5);
            box-shadow: 0 0 20px rgba(220, 38, 38, 0.4);
        __CLOSE_BRACE__

        .priority-high-priority __OPEN_BRACE__
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
            color: #ffffff;
            border: 2px solid rgba(245, 158, 11, 0.5);
            box-shadow: 0 0 15px rgba(245, 158, 11, 0.3);
        __CLOSE_BRACE__

        .priority-monitor __OPEN_BRACE__
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: #ffffff;
            border: 2px solid rgba(16, 185, 129, 0.5);
        __CLOSE_BRACE__

        /* SSVC Badges */
        .ssvc-badge __OPEN_BRACE__
            display: inline-flex;
            align-items: center;
            gap: 0.375rem;
            padding: 0.375rem 0.875rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        __CLOSE_BRACE__

        .ssvc-act __OPEN_BRACE__
            background: rgba(220, 38, 38, 0.15);
            color: #dc2626;
            border: 1px solid rgba(220, 38, 38, 0.3);
        __CLOSE_BRACE__

        .ssvc-attend __OPEN_BRACE__
            background: rgba(245, 158, 11, 0.15);
            color: #f59e0b;
            border: 1px solid rgba(245, 158, 11, 0.3);
        __CLOSE_BRACE__

        .ssvc-track __OPEN_BRACE__
            background: rgba(59, 130, 246, 0.15);
            color: #3b82f6;
            border: 1px solid rgba(59, 130, 246, 0.3);
        __CLOSE_BRACE__

        /* Row highlighting for critical priorities */
        tbody tr.critical-urgent __OPEN_BRACE__
            background: rgba(220, 38, 38, 0.05);
            border-left: 4px solid #dc2626;
        __CLOSE_BRACE__

        tbody tr.critical-urgent:hover __OPEN_BRACE__
            background: rgba(220, 38, 38, 0.1);
        __CLOSE_BRACE__

        /* Warning icons */
        .warning-icon __OPEN_BRACE__
            color: #ef4444;
            font-size: 1.25rem;
            animation: pulse 2s ease-in-out infinite;
        __CLOSE_BRACE__

        @keyframes pulse __OPEN_BRACE__
            0%, 100% { opacity: 1; __CLOSE_BRACE__
            50% { opacity: 0.6; __CLOSE_BRACE__
        __CLOSE_BRACE__

        /* Tech category pills */
        .tech-pill __OPEN_BRACE__
            display: inline-block;
            padding: 0.25rem 0.625rem;
            background: rgba(124, 58, 237, 0.15);
            border: 1px solid rgba(124, 58, 237, 0.3);
            border-radius: 16px;
            color: #a78bfa;
            font-size: 0.75rem;
            font-weight: 500;
            margin: 0.125rem;
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



        /* ========================================
           MOBILE RESPONSIVENESS ENHANCEMENTS
           ======================================== */

        /* Mobile: Card-Based Layout */
        @media (max-width: 768px) __OPEN_BRACE__
            /* Default to 10 items per page on mobile */
            body[x-data] __OPEN_BRACE__
                --mobile-per-page: 10;
            __CLOSE_BRACE__

            /* Mobile Header Adjustments */
            .header __OPEN_BRACE__
                padding: 0.75rem 1rem;
            __CLOSE_BRACE__

            .header-content __OPEN_BRACE__
                flex-direction: column;
                gap: 0.75rem;
            __CLOSE_BRACE__

            .brand __OPEN_BRACE__
                flex-direction: row;
                width: 100%;
            __CLOSE_BRACE__

            .brand-icon __OPEN_BRACE__
                width: 40px;
                height: 40px;
                font-size: 1.25rem;
            __CLOSE_BRACE__

            .brand h1 __OPEN_BRACE__
                font-size: 1.25rem;
            __CLOSE_BRACE__

            /* Mobile Stats Grid - 2 columns */
            .stats-grid __OPEN_BRACE__
                grid-template-columns: repeat(2, 1fr);
                gap: 0.75rem;
                margin-bottom: 1rem;
            __CLOSE_BRACE__

            .stat-card __OPEN_BRACE__
                padding: 1rem;
            __CLOSE_BRACE__

            .stat-value __OPEN_BRACE__
                font-size: 1.5rem;
            __CLOSE_BRACE__

            .stat-label __OPEN_BRACE__
                font-size: 0.75rem;
            __CLOSE_BRACE__

            .stat-change __OPEN_BRACE__
                font-size: 0.7rem;
            __CLOSE_BRACE__

            /* Mobile Main Content */
            .main __OPEN_BRACE__
                padding: 0.75rem;
            __CLOSE_BRACE__

            /* Collapsible Filters Section */
            .filters-section __OPEN_BRACE__
                padding: 1rem;
                margin-bottom: 1rem;
            __CLOSE_BRACE__

            .filter-grid __OPEN_BRACE__
                grid-template-columns: 1fr;
                gap: 0.75rem;
            __CLOSE_BRACE__

            .filter-group input,
            .filter-group select __OPEN_BRACE__
                padding: 0.625rem;
                font-size: 0.875rem;
            __CLOSE_BRACE__

            /* Mobile Search Box */
            .search-input __OPEN_BRACE__
                padding: 0.75rem 1rem;
                font-size: 0.875rem;
                width: 100%;
            __CLOSE_BRACE__

            /* Mobile Quick Filters - Wrapping Pills */
            .quick-filters __OPEN_BRACE__
                flex-wrap: wrap;
                gap: 0.5rem;
                justify-content: flex-start;
                margin-bottom: 1rem;
            __CLOSE_BRACE__

            .filter-chip __OPEN_BRACE__
                padding: 0.5rem 0.875rem;
                font-size: 0.8rem;
                min-height: 44px;
                display: inline-flex;
                align-items: center;
                justify-content: center;
                flex: 0 1 auto;
            __CLOSE_BRACE__

            /* Priority Filter Pills - Stack on small screens */
            .quick-filters button __OPEN_BRACE__
                flex: 1 1 calc(50% - 0.25rem);
                min-width: 120px;
            __CLOSE_BRACE__

            /* Mobile Charts */
            .charts-grid __OPEN_BRACE__
                grid-template-columns: 1fr;
                gap: 1rem;
                margin: 1rem 0;
            __CLOSE_BRACE__

            .chart-card __OPEN_BRACE__
                padding: 1rem;
            __CLOSE_BRACE__

            .chart-container __OPEN_BRACE__
                height: 250px;
            __CLOSE_BRACE__

            /* CARD-BASED LAYOUT FOR TABLE ON MOBILE */
            .data-section __OPEN_BRACE__
                padding: 1rem;
            __CLOSE_BRACE__

            /* Hide table, show cards */
            .table-wrapper table __OPEN_BRACE__
                display: none;
            __CLOSE_BRACE__

            /* Mobile Card View */
            .mobile-card-view __OPEN_BRACE__
                display: block;
            __CLOSE_BRACE__

            .vulnerability-card __OPEN_BRACE__
                background: var(--bg-card);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 1rem;
                margin-bottom: 1rem;
                position: relative;
                transition: all 0.3s ease;
            __CLOSE_BRACE__

            .vulnerability-card:hover __OPEN_BRACE__
                box-shadow: 0 4px 12px rgba(0, 212, 255, 0.15);
                transform: translateY(-2px);
            __CLOSE_BRACE__

            .vulnerability-card.critical-urgent __OPEN_BRACE__
                border-left: 4px solid #dc2626;
                background: rgba(220, 38, 38, 0.05);
            __CLOSE_BRACE__

            .card-header __OPEN_BRACE__
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                margin-bottom: 0.75rem;
                gap: 0.5rem;
            __CLOSE_BRACE__

            .card-cve-id __OPEN_BRACE__
                flex: 1;
            __CLOSE_BRACE__

            .card-cve-id a __OPEN_BRACE__
                color: var(--accent-primary);
                text-decoration: none;
                font-weight: 700;
                font-size: 1rem;
                font-family: monospace;
            __CLOSE_BRACE__

            .card-priority __OPEN_BRACE__
                position: absolute;
                top: 0.75rem;
                right: 0.75rem;
            __CLOSE_BRACE__

            .card-badges __OPEN_BRACE__
                display: flex;
                flex-wrap: wrap;
                gap: 0.5rem;
                margin-bottom: 0.75rem;
            __CLOSE_BRACE__

            .card-info-grid __OPEN_BRACE__
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 0.5rem;
                margin-bottom: 0.75rem;
            __CLOSE_BRACE__

            .card-info-item __OPEN_BRACE__
                text-align: center;
                padding: 0.5rem;
                background: rgba(255, 255, 255, 0.03);
                border-radius: 6px;
            __CLOSE_BRACE__

            .card-info-label __OPEN_BRACE__
                font-size: 0.65rem;
                color: var(--text-muted);
                text-transform: uppercase;
                letter-spacing: 0.05em;
                display: block;
                margin-bottom: 0.25rem;
            __CLOSE_BRACE__

            .card-info-value __OPEN_BRACE__
                font-size: 0.875rem;
                font-weight: 700;
                color: var(--text-primary);
            __CLOSE_BRACE__

            .card-description __OPEN_BRACE__
                font-size: 0.8rem;
                color: var(--text-secondary);
                line-height: 1.4;
                margin-bottom: 0.75rem;
                display: -webkit-box;
                -webkit-line-clamp: 2;
                -webkit-box-orient: vertical;
                overflow: hidden;
            __CLOSE_BRACE__

            .card-footer __OPEN_BRACE__
                display: flex;
                flex-wrap: wrap;
                gap: 0.25rem;
                padding-top: 0.75rem;
                border-top: 1px solid rgba(255, 255, 255, 0.05);
            __CLOSE_BRACE__

            .vendor-pill __OPEN_BRACE__
                display: inline-block;
                padding: 0.25rem 0.625rem;
                background: rgba(124, 58, 237, 0.15);
                border: 1px solid rgba(124, 58, 237, 0.3);
                border-radius: 12px;
                color: #a78bfa;
                font-size: 0.7rem;
                font-weight: 500;
            __CLOSE_BRACE__

            .exploit-badge __OPEN_BRACE__
                display: inline-flex;
                align-items: center;
                gap: 0.25rem;
                padding: 0.375rem 0.625rem;
                background: rgba(239, 68, 68, 0.15);
                border: 1px solid rgba(239, 68, 68, 0.3);
                border-radius: 6px;
                color: #ef4444;
                font-size: 0.75rem;
                font-weight: 600;
            __CLOSE_BRACE__

            /* Mobile Pagination */
            .pagination __OPEN_BRACE__
                flex-direction: column;
                gap: 0.5rem;
                margin-top: 1.5rem;
            __CLOSE_BRACE__

            .page-btn __OPEN_BRACE__
                width: 100%;
                padding: 0.75rem 1rem;
                min-height: 44px;
            __CLOSE_BRACE__

            /* Touch-Friendly Buttons */
            button, a, .clickable __OPEN_BRACE__
                min-height: 44px;
                min-width: 44px;
            __CLOSE_BRACE__

            /* Hide desktop-only elements */
            .hide-mobile __OPEN_BRACE__
                display: none !important;
            __CLOSE_BRACE__
        __CLOSE_BRACE__

        /* Desktop: Hide card view, show table */
        @media (min-width: 769px) __OPEN_BRACE__
            .mobile-card-view __OPEN_BRACE__
                display: none;
            __CLOSE_BRACE__

            .table-wrapper table __OPEN_BRACE__
                display: table;
            __CLOSE_BRACE__
        __CLOSE_BRACE__

        /* Small Mobile (< 640px) - Ultra Compact */
        @media (max-width: 640px) __OPEN_BRACE__
            .stats-grid __OPEN_BRACE__
                grid-template-columns: 1fr;
            __CLOSE_BRACE__

            .card-info-grid __OPEN_BRACE__
                grid-template-columns: repeat(2, 1fr);
            __CLOSE_BRACE__

            .quick-filters button __OPEN_BRACE__
                flex: 1 1 100%;
            __CLOSE_BRACE__

            .filter-chip __OPEN_BRACE__
                width: 100%;
                justify-content: center;
            __CLOSE_BRACE__
        __CLOSE_BRACE__

        /* Landscape Mobile Optimization */
        @media (max-width: 896px) and (orientation: landscape) __OPEN_BRACE__
            .header __OPEN_BRACE__
                padding: 0.5rem 1rem;
            __CLOSE_BRACE__

            .stats-grid __OPEN_BRACE__
                grid-template-columns: repeat(4, 1fr);
                gap: 0.5rem;
            __CLOSE_BRACE__

            .stat-card __OPEN_BRACE__
                padding: 0.75rem;
            __CLOSE_BRACE__

            .filters-section __OPEN_BRACE__
                max-height: 40vh;
                overflow-y: auto;
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
                <div style="display: flex; gap: 1rem; align-items: center;">
                    <div style="padding: 0.5rem 1rem; background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 20px; color: #10b981; font-size: 0.875rem; font-weight: 600;">
                        🎯 EPSS ≥60%
                    </div>
                    <button class="filter-chip" @click="exportCSV()">
                        Export CSV
                    </button>
                </div>
            </div>

            <!-- Stats Section -->
            <div class="stats-grid">
                <div class="stat-card" style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border: 2px solid #00ff00;">
                    <div class="stat-value" style="font-family: 'Courier New', monospace; color: #00ff00; font-size: 1rem;" x-text="stats.dashboard_built"></div>
                    <div class="stat-label" style="color: #00ff00;">Build Timestamp (ET)</div>
                    <div class="stat-trend" style="font-family: monospace; font-size: 0.75rem;">
                        <span style="color: #00ff00;">🔄</span>
                        <span style="color: #a3a3b8;">Check for CDN cache</span>
                    </div>
                </div>

                <div class="stat-card" style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border: 2px solid #3b82f6;">
                    <div class="stat-value" style="font-family: 'Courier New', monospace; color: #3b82f6; font-size: 0.875rem;" x-text="new Date(stats.last_updated).toLocaleString()"></div>
                    <div class="stat-label" style="color: #3b82f6;">Data Last Updated</div>
                    <div class="stat-trend" style="font-family: monospace; font-size: 0.75rem;">
                        <span x-show="(new Date() - new Date(stats.last_updated)) / (1000 * 60 * 60) > 24" style="color: #ef4444;">⚠ Stale (>24h)</span>
                        <span x-show="(new Date() - new Date(stats.last_updated)) / (1000 * 60 * 60) <= 24" style="color: #10b981;">✓ Fresh</span>
                    </div>
                </div>

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

            <!-- Priority Quick Filters -->
            <div style="margin-bottom: 1.5rem;">
                <h3 style="font-size: 1rem; color: var(--text-secondary); margin-bottom: 0.75rem;">Triage Priority</h3>
                <div class="quick-filters">
                    <button class="filter-chip"
                            :class="{ 'active': quickFilter === 'all' }"
                            @click="setQuickFilter('all')">
                        Show All
                    </button>
                    <button class="filter-chip"
                            :class="{ 'active': quickFilter === 'critical-urgent' }"
                            @click="setQuickFilter('critical-urgent')">
                        🔴 Critical Urgent <span x-text="`(${countByPriority('CRITICAL-URGENT')} - ${Math.round(countByPriority('CRITICAL-URGENT') / stats.total * 100)}%)`"></span>
                    </button>
                    <button class="filter-chip"
                            :class="{ 'active': quickFilter === 'high-priority' }"
                            @click="setQuickFilter('high-priority')">
                        🟡 High Priority <span x-text="`(${countByPriority('HIGH-PRIORITY')} - ${Math.round(countByPriority('HIGH-PRIORITY') / stats.total * 100)}%)`"></span>
                    </button>
                    <button class="filter-chip"
                            :class="{ 'active': quickFilter === 'monitor' }"
                            @click="setQuickFilter('monitor')">
                        🟢 Monitor <span x-text="`(${countByPriority('MONITOR')} - ${Math.round(countByPriority('MONITOR') / stats.total * 100)}%)`"></span>
                    </button>
                </div>
            </div>

            <!-- Technology Stack Filters -->
            <div style="margin-bottom: 1.5rem;">
                <h3 style="font-size: 1rem; color: var(--text-secondary); margin-bottom: 0.75rem;">Technology Categories</h3>
                <div class="quick-filters">
                    <button class="filter-chip"
                            :class="{ 'active': techFilter === 'web-servers' }"
                            @click="setTechFilter('web-servers')">
                        Web Servers <span x-text="`(${countByTech('web-servers')})`"></span>
                    </button>
                    <button class="filter-chip"
                            :class="{ 'active': techFilter === 'databases' }"
                            @click="setTechFilter('databases')">
                        Databases <span x-text="`(${countByTech('databases')})`"></span>
                    </button>
                    <button class="filter-chip"
                            :class="{ 'active': techFilter === 'containers-k8s' }"
                            @click="setTechFilter('containers-k8s')">
                        Containers/K8s <span x-text="`(${countByTech('containers-k8s')})`"></span>
                    </button>
                    <button class="filter-chip"
                            :class="{ 'active': techFilter === 'windows' }"
                            @click="setTechFilter('windows')">
                        Windows <span x-text="`(${countByTech('windows')})`"></span>
                    </button>
                    <button class="filter-chip"
                            :class="{ 'active': techFilter === 'linux' }"
                            @click="setTechFilter('linux')">
                        Linux <span x-text="`(${countByTech('linux')})`"></span>
                    </button>
                    <button class="filter-chip"
                            :class="{ 'active': techFilter === 'network-gear' }"
                            @click="setTechFilter('network-gear')">
                        Network Gear <span x-text="`(${countByTech('network-gear')})`"></span>
                    </button>
                    <button class="filter-chip"
                            :class="{ 'active': techFilter === 'cms' }"
                            @click="setTechFilter('cms')">
                        CMS <span x-text="`(${countByTech('cms')})`"></span>
                    </button>
                </div>
            </div>

            <!-- Quick Filters (Keep existing ones) -->
            <div style="margin-bottom: 1.5rem;">
                <h3 style="font-size: 1rem; color: var(--text-secondary); margin-bottom: 0.75rem;">Quick Filters</h3>
                <div class="quick-filters">
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
                            <label>CVSS Score</label>
                            <div style="display: flex; gap: 0.5rem;">
                                <input type="number" x-model.number="filters.cvss_min" placeholder="Min" min="0" max="10" step="0.1">
                                <input type="number" x-model.number="filters.cvss_max" placeholder="Max" min="0" max="10" step="0.1">
                            </div>
                        </div>

                        <div class="filter-group">
                            <label>Attack Complexity</label>
                            <select x-model="filters.attack_complexity">
                                <option value="">All</option>
                                <option value="LOW">Low</option>
                                <option value="HIGH">High</option>
                            </select>
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

                        <div class="filter-group">
                            <label>KEV Listed</label>
                            <select x-model="filters.kev_listed">
                                <option value="">All</option>
                                <option value="yes">Yes</option>
                                <option value="no">No</option>
                            </select>
                        </div>

                        <div class="filter-group">
                            <label>Exploit Status</label>
                            <select x-model="filters.exploit_status">
                                <option value="">All</option>
                                <option value="kev">KEV Listed</option>
                                <option value="exploit">Exploit Available</option>
                                <option value="none">No Known Exploit</option>
                            </select>
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
                    <h3 class="chart-title">Priority Distribution</h3>
                    <div class="chart-container">
                        <canvas x-ref="priorityChart"></canvas>
                    </div>
                </div>

                <div class="chart-card">
                    <h3 class="chart-title">Exploitation Status</h3>
                    <div class="chart-container">
                        <canvas x-ref="exploitationChart"></canvas>
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
                    <!-- DESKTOP TABLE VIEW -->
                    <table>
                        <thead>
                            <tr>
                                <th @click="sort('cve_id')" style="cursor: pointer;">
                                    CVE ID <span x-show="sortField === 'cve_id'" x-text="sortOrder === 'asc' ? '↑' : '↓'"></span>
                                </th>
                                <th @click="sort('triage_priority')" style="cursor: pointer;">
                                    Priority <span x-show="sortField === 'triage_priority'" x-text="sortOrder === 'asc' ? '↑' : '↓'"></span>
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
                                <th @click="sort('kev_status')" style="cursor: pointer;">
                                    Exploit Status <span x-show="sortField === 'kev_status'" x-text="sortOrder === 'asc' ? '↑' : '↓'"></span>
                                </th>
                                <th @click="sort('published_date')" style="cursor: pointer;">
                                    Published <span x-show="sortField === 'published_date'" x-text="sortOrder === 'asc' ? '↑' : '↓'"></span>
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            <template x-for="vuln in paginatedVulns" :key="vuln.cve_id">
                                <tr class="vulnerability-row"
                                    :class="{ 'critical-urgent': vuln.triage_priority === 'CRITICAL-URGENT' }"
                                    :data-cve="vuln.cve_id">
                                    <td>
                                        <a :href="`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.cve_id}`" class="cve-link" x-text="vuln.cve_id" target="_blank" rel="noopener noreferrer"></a>
                                    </td>
                                    <td>
                                        <span class="priority-badge"
                                              :class="`priority-${vuln.triage_priority.toLowerCase().replace('_', '-')}`">
                                            <span x-show="vuln.triage_priority === 'CRITICAL-URGENT'">🔴</span>
                                            <span x-show="vuln.triage_priority === 'HIGH-PRIORITY'">🟡</span>
                                            <span x-show="vuln.triage_priority === 'MONITOR'">🟢</span>
                                            <span x-text="vuln.triage_priority.replace('-', ' ')"></span>
                                        </span>
                                    </td>
                                    <td>
                                        <div style="display: flex; align-items: center; gap: 0.5rem;">
                                            <span x-show="vuln.severity === 'CRITICAL' && vuln.kev_status" class="warning-icon">⚠️</span>
                                            <span class="severity-badge" :class="`severity-${vuln.severity.toLowerCase()}`" x-text="vuln.severity"></span>
                                        </div>
                                    </td>
                                    <td x-text="vuln.cvss_score"></td>
                                    <td x-text="vuln.epss_percentile"></td>
                                    <td x-text="vuln.risk_score"></td>
                                    <td class="truncate" x-text="vuln.products"></td>
                                    <td class="truncate" x-text="vuln.vendors.join(', ') || 'Unknown'"></td>
                                    <td>
                                        <span x-show="vuln.kev_status" style="color: #ef4444; font-weight: 600;">🔴 KEV Listed</span>
                                        <span x-show="!vuln.kev_status && vuln.exploitation_status !== 'Unknown'" style="color: #f59e0b;" x-text="vuln.exploitation_status"></span>
                                        <span x-show="!vuln.kev_status && vuln.exploitation_status === 'Unknown'" style="color: #6b6b85;">⚪ Not Listed</span>
                                    </td>
                                    <td x-text="vuln.published_short"></td>
                                </tr>
                            </template>
                        </tbody>
                    </table>

                    <!-- MOBILE CARD VIEW -->
                    <div class="mobile-card-view">
                        <template x-for="vuln in paginatedVulns" :key="vuln.cve_id">
                            <div class="vulnerability-card"
                                 :class="{ 'critical-urgent': vuln.triage_priority === 'CRITICAL-URGENT' }">
                                <!-- Card Header: CVE ID + Priority Badge -->
                                <div class="card-header">
                                    <div class="card-cve-id">
                                        <a :href="`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.cve_id}`"
                                           x-text="vuln.cve_id"
                                           target="_blank"
                                           rel="noopener noreferrer"></a>
                                    </div>
                                    <div class="card-priority">
                                        <span class="priority-badge"
                                              :class="`priority-${vuln.triage_priority.toLowerCase().replace('_', '-')}`">
                                            <span x-show="vuln.triage_priority === 'CRITICAL-URGENT'">🔴</span>
                                            <span x-show="vuln.triage_priority === 'HIGH-PRIORITY'">🟡</span>
                                            <span x-show="vuln.triage_priority === 'MONITOR'">🟢</span>
                                        </span>
                                    </div>
                                </div>

                                <!-- Badges: Severity + SSVC + Exploit Status -->
                                <div class="card-badges">
                                    <span class="severity-badge" :class="`severity-${vuln.severity.toLowerCase()}`" x-text="vuln.severity"></span>
                                    <span x-show="vuln.ssvc?.priorityTier"
                                          class="ssvc-badge"
                                          :class="`ssvc-${vuln.ssvc?.priorityTier?.toLowerCase()}`"
                                          style="font-size: 0.7rem; padding: 0.25rem 0.625rem;">
                                        <span x-show="vuln.ssvc?.priorityTier === 'ACT'">🔴</span>
                                        <span x-show="vuln.ssvc?.priorityTier === 'ATTEND'">🟠</span>
                                        <span x-show="vuln.ssvc?.priorityTier === 'TRACK'">🔵</span>
                                        <span x-text="vuln.ssvc?.priorityTier"></span>
                                    </span>
                                    <span x-show="vuln.kev_status" class="exploit-badge">
                                        🔴 KEV
                                    </span>
                                    <span x-show="!vuln.kev_status && vuln.exploitation_status !== 'Unknown'"
                                          class="exploit-badge"
                                          style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.3); color: #f59e0b;"
                                          x-text="vuln.exploitation_status"></span>
                                </div>

                                <!-- Score Grid: CVSS, EPSS, Risk -->
                                <div class="card-info-grid">
                                    <div class="card-info-item">
                                        <span class="card-info-label">CVSS</span>
                                        <span class="card-info-value" x-text="vuln.cvss_score"></span>
                                    </div>
                                    <div class="card-info-item">
                                        <span class="card-info-label">EPSS</span>
                                        <span class="card-info-value" x-text="vuln.epss_percentile + '%'"></span>
                                    </div>
                                    <div class="card-info-item">
                                        <span class="card-info-label">Risk</span>
                                        <span class="card-info-value" x-text="vuln.risk_score"></span>
                                    </div>
                                </div>

                                <!-- Description (truncated to 2 lines) -->
                                <div class="card-description" x-text="vuln.description"></div>

                                <!-- Footer: Vendors + Published Date -->
                                <div class="card-footer">
                                    <template x-for="vendor in vuln.vendors.slice(0, 3)" :key="vendor">
                                        <span class="vendor-pill" x-text="vendor"></span>
                                    </template>
                                    <span style="color: var(--text-muted); font-size: 0.7rem; margin-left: auto;" x-text="vuln.published_short"></span>
                                </div>
                            </div>
                        </template>
                    </div>

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
                techFilter: '',
                sortField: 'triage_priority',
                sortOrder: 'asc',
                currentPage: 1,
                perPage: 50,

                // Filters
                filters: __OPEN_BRACE__
                    cvss_min: null,
                    cvss_max: null,
                    attack_complexity: '',
                    published_from: '',
                    published_to: '',
                    vendor: '',
                    kev_listed: '',
                    exploit_status: ''
                __CLOSE_BRACE__,

                // Initialization
                init() __OPEN_BRACE__
                    // Set mobile defaults
                    if (window.innerWidth <= 768) __OPEN_BRACE__
                        this.perPage = 10;  // Default to 10 items on mobile
                    __CLOSE_BRACE__

                    this.$nextTick(() => __OPEN_BRACE__
                        this.initCharts();
                        this.setupKeyboardShortcuts();
                    __CLOSE_BRACE__);

                    // Auto-collapse filters on mobile after selection
                    if (window.innerWidth <= 768) __OPEN_BRACE__
                        this.$watch('filters', () => __OPEN_BRACE__
                            const filtersSection = document.querySelector('.filters-section [x-data]');
                            if (filtersSection) __OPEN_BRACE__
                                // Auto-collapse after 2 seconds on mobile
                                setTimeout(() => __OPEN_BRACE__
                                    Alpine.store('filtersExpanded', false);
                                __CLOSE_BRACE__, 2000);
                            __CLOSE_BRACE__
                        __CLOSE_BRACE__);
                    __CLOSE_BRACE__
                __CLOSE_BRACE__,

                // Computed Properties
                get filteredVulns() __OPEN_BRACE__
                    let vulns = [...this.vulnerabilities];

                    // Priority quick filter
                    if (this.quickFilter === 'critical-urgent') __OPEN_BRACE__
                        vulns = vulns.filter(v => v.triage_priority === 'CRITICAL-URGENT');
                    __CLOSE_BRACE__ else if (this.quickFilter === 'high-priority') __OPEN_BRACE__
                        vulns = vulns.filter(v => v.triage_priority === 'HIGH-PRIORITY');
                    __CLOSE_BRACE__ else if (this.quickFilter === 'monitor') __OPEN_BRACE__
                        vulns = vulns.filter(v => v.triage_priority === 'MONITOR');
                    __CLOSE_BRACE__ else if (this.quickFilter === 'kev') __OPEN_BRACE__
                        vulns = vulns.filter(v => v.kev_status === true);
                    __CLOSE_BRACE__ else if (this.quickFilter === 'network') __OPEN_BRACE__
                        vulns = vulns.filter(v => v.attack_vector === 'Network');
                    __CLOSE_BRACE__

                    // Technology filter
                    if (this.techFilter) __OPEN_BRACE__
                        vulns = vulns.filter(v => v.tech_categories && v.tech_categories.includes(this.techFilter));
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
                    if (this.filters.cvss_min !== null) __OPEN_BRACE__
                        vulns = vulns.filter(v => v.cvss_score >= this.filters.cvss_min);
                    __CLOSE_BRACE__

                    if (this.filters.cvss_max !== null) __OPEN_BRACE__
                        vulns = vulns.filter(v => v.cvss_score <= this.filters.cvss_max);
                    __CLOSE_BRACE__

                    if (this.filters.attack_complexity) __OPEN_BRACE__
                        vulns = vulns.filter(v => v.attack_complexity && v.attack_complexity.toUpperCase() === this.filters.attack_complexity);
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

                    // KEV filter
                    if (this.filters.kev_listed === 'yes') __OPEN_BRACE__
                        vulns = vulns.filter(v => v.kev_status === true);
                    __CLOSE_BRACE__ else if (this.filters.kev_listed === 'no') __OPEN_BRACE__
                        vulns = vulns.filter(v => !v.kev_status);
                    __CLOSE_BRACE__

                    // Exploit Status filter
                    if (this.filters.exploit_status === 'kev') __OPEN_BRACE__
                        vulns = vulns.filter(v => v.kev_status === true);
                    __CLOSE_BRACE__ else if (this.filters.exploit_status === 'exploit') __OPEN_BRACE__
                        vulns = vulns.filter(v => !v.kev_status && v.exploitation_status && v.exploitation_status !== 'Unknown');
                    __CLOSE_BRACE__ else if (this.filters.exploit_status === 'none') __OPEN_BRACE__
                        vulns = vulns.filter(v => !v.kev_status && (!v.exploitation_status || v.exploitation_status === 'Unknown'));
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
                        __CLOSE_BRACE__ else if (this.sortField === 'triage_priority') __OPEN_BRACE__
                            const priorityOrder = { 'CRITICAL-URGENT': 3, 'HIGH-PRIORITY': 2, 'MONITOR': 1 __CLOSE_BRACE__;
                            aVal = priorityOrder[aVal] || 0;
                            bVal = priorityOrder[bVal] || 0;
                        __CLOSE_BRACE__ else if (this.sortField === 'kev_listed') __OPEN_BRACE__
                            aVal = a.kev_status ? 1 : 0;
                            bVal = b.kev_status ? 1 : 0;
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
                countByPriority(priority) __OPEN_BRACE__
                    return this.vulnerabilities.filter(v => v.triage_priority === priority).length;
                __CLOSE_BRACE__,

                countByTech(category) __OPEN_BRACE__
                    return this.vulnerabilities.filter(v => v.tech_categories && v.tech_categories.includes(category)).length;
                __CLOSE_BRACE__,

                setQuickFilter(filter) __OPEN_BRACE__
                    this.quickFilter = filter;
                    this.techFilter = '';  // Reset tech filter
                    this.currentPage = 1;
                __CLOSE_BRACE__,

                setTechFilter(category) __OPEN_BRACE__
                    if (this.techFilter === category) __OPEN_BRACE__
                        this.techFilter = '';  // Toggle off
                    __CLOSE_BRACE__ else __OPEN_BRACE__
                        this.techFilter = category;
                        this.quickFilter = 'all';  // Reset priority filter
                    __CLOSE_BRACE__
                    this.currentPage = 1;
                __CLOSE_BRACE__,

                sort(field) __OPEN_BRACE__
                    if (this.sortField === field) __OPEN_BRACE__
                        this.sortOrder = this.sortOrder === 'asc' ? 'desc' : 'asc';
                    __CLOSE_BRACE__ else __OPEN_BRACE__
                        this.sortField = field;
                        this.sortOrder = (field === 'triage_priority') ? 'desc' : 'desc';
                    __CLOSE_BRACE__
                    this.currentPage = 1;
                __CLOSE_BRACE__,

                resetFilters() __OPEN_BRACE__
                    this.search = '';
                    this.quickFilter = 'all';
                    this.techFilter = '';
                    this.filters = __OPEN_BRACE__
                        cvss_min: null,
                        cvss_max: null,
                        attack_complexity: '',
                        published_from: '',
                        published_to: '',
                        vendor: '',
                        kev_listed: '',
                        exploit_status: ''
                    __CLOSE_BRACE__;
                    this.currentPage = 1;
                __CLOSE_BRACE__,


                exportCSV() __OPEN_BRACE__
                    const headers = ['CVE ID', 'Severity', 'CVSS', 'EPSS %', 'Risk Score', 'KEV Listed', 'Exploit Status', 'Product', 'Vendors', 'Published'];
                    const csvContent = [
                        headers.join(','),
                        ...this.filteredVulns.map(v => [
                            v.cve_id,
                            v.severity,
                            v.cvss_score,
                            v.epss_percentile,
                            v.risk_score,
                            v.kev_status ? 'Yes' : 'No',
                            v.kev_status ? 'KEV Listed' : (v.exploitation_status && v.exploitation_status !== 'Unknown' ? v.exploitation_status : 'Not Listed'),
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
                    // Priority Distribution Chart
                    if (this.$refs.priorityChart) __OPEN_BRACE__
                        new Chart(this.$refs.priorityChart, __OPEN_BRACE__
                            type: 'doughnut',
                            data: __OPEN_BRACE__
                                labels: ['Critical-Urgent', 'High-Priority', 'Monitor'],
                                datasets: [__OPEN_BRACE__
                                    data: [
                                        this.stats.priority_distribution['CRITICAL-URGENT'],
                                        this.stats.priority_distribution['HIGH-PRIORITY'],
                                        this.stats.priority_distribution['MONITOR']
                                    ],
                                    backgroundColor: ['#dc2626', '#f59e0b', '#10b981'],
                                    borderWidth: 2,
                                    borderColor: '#12121a'
                                __CLOSE_BRACE__]
                            __CLOSE_BRACE__,
                            options: __OPEN_BRACE__
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: __OPEN_BRACE__
                                    legend: __OPEN_BRACE__
                                        labels: {
                                            color: '#cbd5e1',
                                            font: { size: 14 __CLOSE_BRACE__
                                        __CLOSE_BRACE__
                                    __CLOSE_BRACE__,
                                    tooltip: __OPEN_BRACE__
                                        callbacks: __OPEN_BRACE__
                                            label: function(context) __OPEN_BRACE__
                                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                                const percentage = ((context.parsed / total) * 100).toFixed(1);
                                                return context.label + ': ' + context.parsed + ' (' + percentage + '%)';
                                            __CLOSE_BRACE__
                                        __CLOSE_BRACE__
                                    __CLOSE_BRACE__
                                __CLOSE_BRACE__
                            __CLOSE_BRACE__
                        __CLOSE_BRACE__);
                    __CLOSE_BRACE__

                    // Exploitation Status Chart
                    if (this.$refs.exploitationChart) __OPEN_BRACE__
                        new Chart(this.$refs.exploitationChart, __OPEN_BRACE__
                            type: 'bar',
                            data: __OPEN_BRACE__
                                labels: ['KEV Listed', 'PoC Available', 'Not Listed'],
                                datasets: [__OPEN_BRACE__
                                    data: [
                                        this.stats.exploitation_distribution['KEV Listed'],
                                        this.stats.exploitation_distribution['PoC Available'],
                                        this.stats.exploitation_distribution['Not Listed']
                                    ],
                                    backgroundColor: ['#dc2626', '#f59e0b', '#6b6b85'],
                                    borderWidth: 1,
                                    borderColor: '#12121a'
                                __CLOSE_BRACE__]
                            __CLOSE_BRACE__,
                            options: __OPEN_BRACE__
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: __OPEN_BRACE__
                                    legend: { display: false __CLOSE_BRACE__,
                                    tooltip: __OPEN_BRACE__
                                        callbacks: __OPEN_BRACE__
                                            label: function(context) __OPEN_BRACE__
                                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                                const percentage = ((context.parsed.y / total) * 100).toFixed(1);
                                                return context.label + ': ' + context.parsed.y + ' (' + percentage + '%)';
                                            __CLOSE_BRACE__
                                        __CLOSE_BRACE__
                                    __CLOSE_BRACE__
                                __CLOSE_BRACE__,
                                scales: __OPEN_BRACE__
                                    y: __OPEN_BRACE__
                                        beginAtZero: true,
                                        ticks: {
                                            color: '#cbd5e1',
                                            stepSize: 10
                                        __CLOSE_BRACE__,
                                        grid: __OPEN_BRACE__
                                            color: 'rgba(255, 255, 255, 0.05)'
                                        __CLOSE_BRACE__
                                    __CLOSE_BRACE__,
                                    x: __OPEN_BRACE__
                                        ticks: {
                                            color: '#cbd5e1',
                                            font: { size: 12 __CLOSE_BRACE__
                                        __CLOSE_BRACE__,
                                        grid: __OPEN_BRACE__
                                            display: false
                                        __CLOSE_BRACE__
                                    __CLOSE_BRACE__
                                __CLOSE_BRACE__
                            __CLOSE_BRACE__
                        __CLOSE_BRACE__);
                    __CLOSE_BRACE__
                __CLOSE_BRACE__
            __CLOSE_BRACE__
        __CLOSE_BRACE__
    </script>

    <!-- CVE Details Modal -->
    <div x-data="cveModal()"
         x-show="isOpen"
         x-cloak
         @keydown.window="handleKeydown($event)"
         class="modal-overlay"
         style="display: none;">

        <!-- Backdrop -->
        <div class="modal-backdrop" @click="closeModal()"></div>

        <!-- Modal Container -->
        <div class="modal-container">
            <div class="modal-content">

                <!-- Loading State -->
                <div x-show="loading" class="modal-loading">
                    <div class="loading-spinner"></div>
                    <p class="loading-text">Loading vulnerability details...</p>
                </div>

                <!-- Error State -->
                <div x-show="error && !loading" class="modal-error">
                    <div class="error-icon">⚠️</div>
                    <div class="error-content">
                        <h3>Error Loading CVE Details</h3>
                        <p x-text="error"></p>
                        <button @click="closeModal()" class="btn btn-primary">Close</button>
                    </div>
                </div>

                <!-- Modal Content (when loaded successfully) -->
                <template x-if="vulnerability && !loading && !error">
                    <div>
                        <!-- Modal Header -->
                        <div class="modal-header">
                            <div class="modal-title-section">
                                <h2 class="modal-title">
                                    <span x-text="vulnerability.cveId"></span>
                                    <span class="severity-badge"
                                          :class="getSeverityClass(vulnerability.cvssScore || 0)"
                                          x-text="vulnerability.severity"></span>
                                </h2>
                                <p class="modal-description" x-text="vulnerability.description || 'No description available'"></p>
                            </div>
                            <button @click="closeModal()"
                                    class="modal-close"
                                    aria-label="Close modal">
                                ✕
                            </button>
                        </div>

                        <!-- Tab Navigation -->
                        <nav class="tab-nav" role="tablist">
                            <button @click="switchTab('overview')"
                                    :class="__OPEN_BRACE__ 'tab-active': activeTab === 'overview' __CLOSE_BRACE__"
                                    class="tab-button"
                                    role="tab"
                                    aria-label="Overview"
                                    accesskey="1">
                                Overview
                                <span class="keyboard-hint">(Alt+1)</span>
                            </button>
                            <button @click="switchTab('technical')"
                                    :class="__OPEN_BRACE__ 'tab-active': activeTab === 'technical' __CLOSE_BRACE__"
                                    class="tab-button"
                                    role="tab"
                                    aria-label="Technical Details"
                                    accesskey="2">
                                Technical
                                <span class="keyboard-hint">(Alt+2)</span>
                            </button>
                            <button @click="switchTab('timeline')"
                                    :class="__OPEN_BRACE__ 'tab-active': activeTab === 'timeline' __CLOSE_BRACE__"
                                    class="tab-button"
                                    role="tab"
                                    aria-label="Timeline"
                                    accesskey="3">
                                Timeline
                                <span class="keyboard-hint">(Alt+3)</span>
                            </button>
                            <button @click="switchTab('references')"
                                    :class="__OPEN_BRACE__ 'tab-active': activeTab === 'references' __CLOSE_BRACE__"
                                    class="tab-button"
                                    role="tab"
                                    aria-label="References"
                                    accesskey="4">
                                References
                                <span class="keyboard-hint">(Alt+4)</span>
                            </button>
                            <button @click="switchTab('ssvc')"
                                    :class="__OPEN_BRACE__ 'tab-active': activeTab === 'ssvc' __CLOSE_BRACE__"
                                    class="tab-button"
                                    role="tab"
                                    aria-label="SSVC Decision Tree"
                                    accesskey="5">
                                SSVC Decision Tree
                                <span class="keyboard-hint">(Alt+5)</span>
                            </button>
                        </nav>

                        <!-- Tab Content Container -->
                        <div class="modal-body">

                            <!-- Overview Tab -->
                            <div x-show="activeTab === 'overview'"
                                 role="tabpanel"
                                 id="overview-tab"
                                 class="tab-content tab-panel">
                                <div class="overview-grid">
                                    <div class="card">
                                        <h3 class="card-title">Risk Summary</h3>
                                        <div class="risk-metrics">
                                            <div class="metric">
                                                <span class="metric-label">CVSS Score</span>
                                                <span class="metric-value cvss-score"
                                                      :class="getSeverityClass(vulnerability.cvssScore || 0)"
                                                      x-text="vulnerability.cvssScore || 'N/A'"></span>
                                                <span class="metric-description" x-text="getRiskLevelText(vulnerability.cvssScore || 0)"></span>
                                            </div>
                                            <div class="metric">
                                                <span class="metric-label">EPSS Score</span>
                                                <span class="metric-value" x-text="`${vulnerability.epssScore || 0}%`"></span>
                                                <span class="metric-description">Exploitation Probability</span>
                                            </div>
                                        </div>
                                    </div>

                                    <div class="card full-width">
                                        <h3 class="card-title">Details</h3>
                                        <dl class="details-grid">
                                            <div class="detail-item">
                                                <dt>Published</dt>
                                                <dd x-text="formatDate(vulnerability.publishedDate)"></dd>
                                            </div>
                                            <div class="detail-item">
                                                <dt>Last Modified</dt>
                                                <dd x-text="formatDate(vulnerability.lastModifiedDate)"></dd>
                                            </div>
                                            <div class="detail-item">
                                                <dt>Attack Vector</dt>
                                                <dd x-text="vulnerability.attackVector || 'Unknown'"></dd>
                                            </div>
                                        </dl>
                                    </div>
                                </div>
                            </div>

                            <!-- Technical Tab -->
                            <div x-show="activeTab === 'technical'"
                                 role="tabpanel"
                                 id="technical-tab"
                                 class="tab-content tab-panel">
                                <div class="technical-grid">
                                    <div class="card">
                                        <h3 class="card-title">CVSS Metrics</h3>
                                        <div class="metrics-list">
                                            <template x-for="metric in getCvssMetrics(vulnerability)">
                                                <div class="metric-row">
                                                    <span x-text="metric.label"></span>
                                                    <strong x-text="metric.value"></strong>
                                                </div>
                                            </template>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <!-- Timeline Tab -->
                            <div x-show="activeTab === 'timeline'"
                                 role="tabpanel"
                                 id="timeline-tab"
                                 class="tab-content tab-panel">
                                <div class="timeline-container">
                                    <h3 class="timeline-title">Vulnerability Timeline</h3>
                                    <div class="timeline">
                                        <template x-for="event in getTimelineEvents(vulnerability)">
                                            <div class="timeline-event">
                                                <div class="timeline-marker" :class="`marker-${event.type}`"></div>
                                                <div class="timeline-content">
                                                    <span class="timeline-date" x-text="formatDate(event.date)"></span>
                                                    <p class="timeline-description" x-text="event.event"></p>
                                                </div>
                                            </div>
                                        </template>
                                    </div>
                                </div>
                            </div>

                            <!-- References Tab -->
                            <div x-show="activeTab === 'references'"
                                 role="tabpanel"
                                 id="references-tab"
                                 class="tab-content tab-panel">
                                <div class="references-container">
                                    <h3 class="references-title">External References</h3>
                                    <div class="references-list">
                                        <template x-if="vulnerability.references && vulnerability.references.length > 0">
                                            <template x-for="ref in vulnerability.references">
                                                <div class="reference-item">
                                                    <a :href="ref.url"
                                                       target="_blank"
                                                       rel="noopener noreferrer"
                                                       class="reference-link">
                                                        <span x-text="ref.url"></span>
                                                        <span class="external-link-icon">↗</span>
                                                    </a>
                                                </div>
                                            </template>
                                        </template>
                                        <template x-if="!vulnerability.references || vulnerability.references.length === 0">
                                            <p class="no-references">No external references available</p>
                                        </template>
                                    </div>
                                </div>
                            </div>

                            <!-- SSVC Tab -->
                            <div x-show="activeTab === 'ssvc'"
                                 role="tabpanel"
                                 id="ssvc-tab"
                                 aria-labelledby="ssvc-tab-button"
                                 class="tab-content tab-panel">

                                <div class="ssvc-container">
                                    <h3>SSVC Prioritization Decision Tree</h3>

                                    <!-- Priority Tier Banner -->
                                    <div x-show="vulnerability.ssvc?.priorityTier"
                                         class="ssvc-priority-banner"
                                         :class="__OPEN_BRACE__
                                             'priority-act': vulnerability.ssvc?.priorityTier === 'ACT',
                                             'priority-attend': vulnerability.ssvc?.priorityTier === 'ATTEND',
                                             'priority-track': vulnerability.ssvc?.priorityTier === 'TRACK'
                                         __CLOSE_BRACE__">
                                        <div class="priority-icon">
                                            <span x-show="vulnerability.ssvc?.priorityTier === 'ACT'">🔴</span>
                                            <span x-show="vulnerability.ssvc?.priorityTier === 'ATTEND'">🟠</span>
                                            <span x-show="vulnerability.ssvc?.priorityTier === 'TRACK'">🔵</span>
                                        </div>
                                        <div class="priority-label">
                                            <div class="priority-tier" x-text="`Priority: ${vulnerability.ssvc?.priorityTier || 'Unknown'}`"></div>
                                            <div class="priority-action" x-text="getPriorityAction(vulnerability.ssvc?.priorityTier)"></div>
                                        </div>
                                        <div class="ssvc-score">
                                            <span class="score-label">SSVC Score</span>
                                            <span class="score-value" x-text="vulnerability.ssvc?.ssvcScore || 0"></span>
                                            <span class="score-total">/60</span>
                                        </div>
                                    </div>

                                    <!-- Decision Factors Grid -->
                                    <div class="ssvc-factors-grid" x-show="vulnerability.ssvc?.priorityTier">
                                        <!-- Exploitation Factor -->
                                        <div class="ssvc-factor">
                                            <div class="factor-label">
                                                <span class="factor-icon">⚔️</span>
                                                <span class="factor-title">Exploitation</span>
                                            </div>
                                            <div class="factor-value"
                                                 :class="`exploitation-${vulnerability.ssvc?.exploitation || 'none'}`"
                                                 x-text="formatExploitation(vulnerability.ssvc?.exploitation)">
                                            </div>
                                            <div class="factor-description" x-text="getExploitationDesc(vulnerability.ssvc?.exploitation)"></div>
                                        </div>

                                        <!-- Automatable Factor -->
                                        <div class="ssvc-factor">
                                            <div class="factor-label">
                                                <span class="factor-icon">🤖</span>
                                                <span class="factor-title">Automatable</span>
                                            </div>
                                            <div class="factor-value"
                                                 :class="`automatable-${vulnerability.ssvc?.automatable || 'no'}`"
                                                 x-text="(vulnerability.ssvc?.automatable || 'no').toUpperCase()">
                                            </div>
                                            <div class="factor-description" x-text="getAutomatableDesc(vulnerability.ssvc?.automatable)"></div>
                                        </div>

                                        <!-- Technical Impact Factor -->
                                        <div class="ssvc-factor">
                                            <div class="factor-label">
                                                <span class="factor-icon">💥</span>
                                                <span class="factor-title">Technical Impact</span>
                                            </div>
                                            <div class="factor-value"
                                                 :class="`impact-${vulnerability.ssvc?.technicalImpact || 'partial'}`"
                                                 x-text="(vulnerability.ssvc?.technicalImpact || 'partial').toUpperCase()">
                                            </div>
                                            <div class="factor-description" x-text="getImpactDesc(vulnerability.ssvc?.technicalImpact)"></div>
                                        </div>
                                    </div>

                                    <!-- Compact Notation -->
                                    <div class="ssvc-notation-display" x-show="vulnerability.ssvc?.compactNotation">
                                        <strong>Compact Notation:</strong>
                                        <code x-text="vulnerability.ssvc?.compactNotation || 'N/A'"></code>
                                        <span class="notation-help">(Exploitation / Automatable / Technical Impact)</span>
                                    </div>

                                    <!-- Inference Indicator -->
                                    <div x-show="vulnerability.ssvc?.inferred" class="ssvc-inference-notice">
                                        <span class="notice-icon">ℹ️</span>
                                        <div class="notice-content">
                                            <strong>Inferred Decision</strong>
                                            <p x-show="vulnerability.ssvc?.confidence">
                                                Confidence: <span x-text="`${Math.round((vulnerability.ssvc?.confidence || 0) * 100)}%`"></span>
                                            </p>
                                            <p class="notice-text">This SSVC decision was automatically inferred from available vulnerability data using CVSS vectors and KEV status.</p>
                                        </div>
                                    </div>

                                    <!-- No SSVC Data Message -->
                                    <div x-show="!vulnerability.ssvc?.priorityTier" class="no-ssvc-message">
                                        <p>⚠️ SSVC data not available for this vulnerability.</p>
                                        <p class="help-text">This CVE may not have been assessed by CISA or may be outside the scoring criteria.</p>
                                    </div>
                                </div>
                            </div>

                        </div>
                    </div>
                </template>
            </div>
        </div>
    </div>

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
                    "SSVC Priority",
                    "SSVC Notation",
                    "Title",
                    "Vendors",
                    "Published",
                ]
            )
            for vuln in self.vulnerabilities:
                vendors = (
                    ", ".join(vuln["vendors_list"][:3]) if vuln["vendors_list"] else ""
                )
                # Extract SSVC data
                ssvc = vuln.get("ssvc", {})
                ssvc_priority = ssvc.get("priorityTier", "") if ssvc else ""
                ssvc_notation = ssvc.get("compactNotation", "") if ssvc else ""

                writer.writerow(
                    [
                        vuln["cve_id"],
                        vuln["severity"],
                        vuln["cvss_score"],
                        vuln["epss_percentile"],
                        vuln["risk_score"],
                        ssvc_priority,
                        ssvc_notation,
                        vuln["title"] or "",
                        vendors,
                        vuln["published_short"],
                    ]
                )
        print("✓ Exported CSV data")


def main():
    """Main function"""
    # Prefer JSON API over SQLite database (use api/vulns which has FILTERED data)
    # CRITICAL: This path must point to the FILTERED vulnerabilities (EPSS ≥60%)
    # NOT src/api/vulns/index.json which contains ALL harvested CVEs
    JSON_API_PATH = Path("api/vulns/index.json")

    if JSON_API_PATH.exists():
        print(f"Using JSON API data from {JSON_API_PATH}")
        generator = AlpineDashboardGenerator(json_path=JSON_API_PATH)
    elif DB_PATH.exists():
        print(f"Using SQLite database from {DB_PATH}")
        generator = AlpineDashboardGenerator(db_path=DB_PATH)
    else:
        print("Error: No data source found!")
        print(f"  - JSON API not found at {JSON_API_PATH}")
        print(f"  - Database not found at {DB_PATH}")
        print("\nPlease run the vulnerability harvest first:")
        print("python -m scripts.main harvest --cache-dir .cache/")
        sys.exit(1)

    # Generate dashboard
    generator.create_dashboard_html()
    generator.export_csv_data()

    print("\n✅ Alpine.js dashboard generated successfully!")
    print(f"📁 Output directory: {OUTPUT_DIR}")
    print(f"📊 Total vulnerabilities: {len(generator.vulnerabilities)}")
    print("🚀 Ready to deploy to GitHub Pages")


if __name__ == "__main__":
    main()
