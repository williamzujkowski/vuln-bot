#!/usr/bin/env python3
"""
Intelligent incremental generator for CVE pages and dashboard.
Only updates files for CVEs that have changed since last generation.
"""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import structlog

logger = structlog.get_logger(__name__)

class IncrementalGenerator:
    """Manages incremental generation of CVE pages and dashboard."""

    def __init__(self, db_path: Path, output_dir: Path = Path("public")):
        """Initialize the incremental generator.

        Args:
            db_path: Path to the vulnerability cache database
            output_dir: Output directory for generated files
        """
        self.db_path = db_path
        self.output_dir = output_dir
        self.cve_pages_dir = output_dir / "cves"
        self.dashboard_file = output_dir / "index.html"

        # Create metadata directory for tracking generation state
        self.metadata_dir = output_dir / ".generation_metadata"
        self.metadata_dir.mkdir(exist_ok=True)
        self.last_generation_file = self.metadata_dir / "last_generation.json"

    def get_last_generation_metadata(self) -> Dict:
        """Get metadata from the last generation run."""
        if not self.last_generation_file.exists():
            return {
                "last_run": None,
                "cve_hashes": {},
                "dashboard_hash": None,
                "generated_cves": [],
            }

        try:
            with open(self.last_generation_file) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"Failed to load generation metadata: {e}")
            return {
                "last_run": None,
                "cve_hashes": {},
                "dashboard_hash": None,
                "generated_cves": [],
            }

    def save_generation_metadata(self, metadata: Dict):
        """Save generation metadata for next run."""
        metadata["last_run"] = datetime.now(timezone.utc).isoformat()

        try:
            with open(self.last_generation_file, 'w') as f:
                json.dump(metadata, f, indent=2)
        except OSError as e:
            logger.error(f"Failed to save generation metadata: {e}")

    def calculate_cve_hash(self, cve_data: Dict) -> str:
        """Calculate a hash of CVE data to detect changes."""
        # Include relevant fields that would affect the generated page
        relevant_fields = {
            'cve_id': cve_data.get('cve_id'),
            'description': cve_data.get('description'),
            'cvss_score': cve_data.get('cvss_score'),
            'epss_percentile': cve_data.get('epss_percentile'),
            'severity': cve_data.get('severity'),
            'risk_score': cve_data.get('risk_score'),
            'published_date': cve_data.get('published_date'),
            'last_modified_date': cve_data.get('last_modified_date'),
            'affected_vendors': cve_data.get('affected_vendors', cve_data.get('vendors', [])),
            'affected_products': cve_data.get('affected_products', cve_data.get('products', [])),
            'tags': cve_data.get('tags', []),
            'attack_vector': cve_data.get('attack_vector'),
            'attack_complexity': cve_data.get('attack_complexity'),
            'privileges_required': cve_data.get('privileges_required'),
            'user_interaction': cve_data.get('user_interaction'),
        }

        # Create a stable string representation
        data_str = json.dumps(relevant_fields, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(data_str.encode()).hexdigest()

    def load_vulnerabilities_from_db(self) -> List[Dict]:
        """Load vulnerabilities from the cache database."""
        if not self.db_path.exists():
            logger.error(f"Database not found at {self.db_path}")
            return []

        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        cursor = db.cursor()

        rows = cursor.execute("""
            SELECT cve_id, data, risk_score, severity, published_date, last_modified_date
            FROM vulnerability_cache
            ORDER BY risk_score DESC
        """).fetchall()

        vulnerabilities = []
        for row in rows:
            try:
                vuln_data = json.loads(row["data"])

                # Extract CVSS score from cvss_metrics
                cvss_score = 0
                if vuln_data.get("cvss_metrics"):
                    for metric in vuln_data["cvss_metrics"]:
                        if metric.get("base_score"):
                            cvss_score = max(cvss_score, metric["base_score"])

                # Extract EPSS percentile
                epss_percentile = 0
                if vuln_data.get("epss_score") and isinstance(vuln_data["epss_score"], dict):
                    epss_percentile = vuln_data["epss_score"].get("percentile", 0)

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
                # Use correct field names for vendors and products
                vendors = vuln.get("affected_vendors", vuln.get("vendors", []))
                products = vuln.get("affected_products", vuln.get("products", []))
                vuln["vendors"] = vendors if isinstance(vendors, list) else []
                vuln["products"] = products if isinstance(products, list) else []
                vuln.setdefault("tags", [])

                vulnerabilities.append(vuln)

            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Failed to parse {row.get('cve_id', 'unknown')}: {e}")
                continue

        db.close()
        return vulnerabilities

    def identify_changed_cves(self, vulnerabilities: List[Dict],
                             last_metadata: Dict) -> Tuple[List[Dict], List[str]]:
        """Identify CVEs that have changed since last generation.

        Returns:
            Tuple of (changed_cves, removed_cve_ids)
        """
        current_cve_hashes = {}
        changed_cves = []
        last_cve_hashes = last_metadata.get("cve_hashes", {})

        # Check each current CVE
        for vuln in vulnerabilities:
            cve_id = vuln["cve_id"]
            current_hash = self.calculate_cve_hash(vuln)
            current_cve_hashes[cve_id] = current_hash

            # Check if this CVE has changed
            if cve_id not in last_cve_hashes or last_cve_hashes[cve_id] != current_hash:
                changed_cves.append(vuln)
                logger.info(f"CVE {cve_id} has changed, will regenerate")

        # Identify removed CVEs
        current_cve_ids = {vuln["cve_id"] for vuln in vulnerabilities}
        last_cve_ids = set(last_cve_hashes.keys())
        removed_cve_ids = list(last_cve_ids - current_cve_ids)

        if removed_cve_ids:
            logger.info(f"Found {len(removed_cve_ids)} removed CVEs: {removed_cve_ids[:5]}...")

        return changed_cves, removed_cve_ids, current_cve_hashes

    def generate_cve_page(self, vuln: Dict) -> str:
        """Generate HTML content for a single CVE page."""
        cve_id = vuln["cve_id"]

        # Ensure default values
        description = vuln.get("description", "No description available")
        cvss_score = vuln.get("cvss_score", 0)
        epss_percentile = vuln.get("epss_percentile", 0)
        attack_vector = vuln.get("attack_vector", "Unknown")
        vendors = vuln.get("vendors", [])
        products = vuln.get("products", [])
        tags = vuln.get("tags", [])

        # Format dates
        published_date = vuln.get("published_date", "Unknown")
        if published_date and published_date != "Unknown":
            try:
                pub_dt = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
                published_formatted = pub_dt.strftime("%B %d, %Y")
            except (ValueError, AttributeError):
                published_formatted = published_date
        else:
            published_formatted = "Unknown"

        # Check KEV status
        is_kev = any(
            "kev" in tag.lower() or "known exploited" in tag.lower() for tag in tags
        )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{cve_id} - Vulnerability Details</title>
    <style>
        :root {{
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: #1e1e2a;
            --accent-primary: #00d4ff;
            --accent-danger: #ef4444;
            --accent-success: #10b981;
            --text-primary: #ffffff;
            --text-secondary: #a3a3b8;
        }}

        body {{
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}

        .header {{
            background: var(--bg-secondary);
            padding: 1rem 0;
            margin-bottom: 2rem;
        }}

        .breadcrumb {{
            margin-bottom: 2rem;
        }}

        .breadcrumb a {{
            color: var(--accent-primary);
            text-decoration: none;
        }}

        .breadcrumb a:hover {{
            text-decoration: underline;
        }}

        .cve-header {{
            background: var(--bg-card);
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
        }}

        .cve-header h1 {{
            margin: 0 0 1rem 0;
            color: var(--accent-primary);
        }}

        .badges {{
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
            margin-bottom: 1rem;
        }}

        .badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 600;
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

        .kev-badge {{
            background: var(--accent-danger);
            color: white;
        }}

        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }}

        .info-item {{
            background: rgba(255, 255, 255, 0.05);
            padding: 1rem;
            border-radius: 8px;
        }}

        .info-label {{
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}

        .info-value {{
            font-size: 1.125rem;
            font-weight: 600;
            margin-top: 0.25rem;
        }}

        .section {{
            background: var(--bg-card);
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
        }}

        .section h2 {{
            margin-top: 0;
            color: var(--accent-primary);
        }}

        .description {{
            line-height: 1.8;
            color: var(--text-secondary);
        }}

        .vendor-list, .product-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.5rem;
        }}

        .vendor-tag, .product-tag {{
            background: rgba(0, 212, 255, 0.1);
            color: var(--accent-primary);
            padding: 0.25rem 0.75rem;
            border-radius: 16px;
            font-size: 0.875rem;
        }}

        .back-link {{
            display: inline-flex;
            align-items: center;
            color: var(--accent-primary);
            text-decoration: none;
            margin-bottom: 2rem;
            gap: 0.5rem;
        }}

        .back-link:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <div class="breadcrumb">
                <a href="/vuln-bot/">Home</a> /
                <a href="/vuln-bot/#vulnerabilities">Vulnerabilities</a> /
                <span>{cve_id}</span>
            </div>
        </div>
    </div>

    <div class="container">
        <a href="/vuln-bot/" class="back-link">
            ← Back to Dashboard
        </a>

        <div class="cve-header">
            <h1>{cve_id}</h1>
            <div class="badges">
                <span class="badge severity-{vuln["severity"].lower()}">{vuln["severity"]}</span>
                {'<span class="badge kev-badge">🚨 Known Exploited</span>' if is_kev else ""}
            </div>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">CVSS Score</div>
                    <div class="info-value">{cvss_score}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">EPSS Score</div>
                    <div class="info-value">{epss_percentile}%</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Risk Score</div>
                    <div class="info-value">{vuln["risk_score"]}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Published</div>
                    <div class="info-value">{published_formatted}</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Description</h2>
            <p class="description">{description}</p>
        </div>

        <div class="section">
            <h2>Technical Details</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Attack Vector</div>
                    <div class="info-value">{str(attack_vector)}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Attack Complexity</div>
                    <div class="info-value">{str(vuln.get("attack_complexity", "Unknown"))}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Privileges Required</div>
                    <div class="info-value">{str(vuln.get("privileges_required", "Unknown"))}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">User Interaction</div>
                    <div class="info-value">{str(vuln.get("user_interaction", "Unknown"))}</div>
                </div>
            </div>
        </div>

        {f'''<div class="section">
            <h2>Affected Products</h2>
            <h3>Vendors</h3>
            <div class="vendor-list">
                {"".join(f'<span class="vendor-tag">{str(v)}</span>' for v in vendors) if vendors else '<span class="vendor-tag">Unknown</span>'}
            </div>
            <h3>Products</h3>
            <div class="product-list">
                {"".join(f'<span class="product-tag">{str(p)}</span>' for p in products) if products else '<span class="product-tag">Unknown</span>'}
            </div>
        </div>''' if vendors or products else ""}

        <div class="section">
            <h2>References</h2>
            <p>
                <a href="https://nvd.nist.gov/vuln/detail/{cve_id}" target="_blank" rel="noopener">
                    View on NVD →
                </a>
            </p>
        </div>
    </div>
</body>
</html>"""

        return html_content

    def generate_changed_cve_pages(self, changed_cves: List[Dict]) -> int:
        """Generate CVE pages only for changed vulnerabilities.

        Returns:
            Number of pages generated
        """
        if not changed_cves:
            logger.info("No CVE pages need regeneration")
            return 0

        # Ensure CVE pages directory exists
        self.cve_pages_dir.mkdir(parents=True, exist_ok=True)

        generated_count = 0
        for vuln in changed_cves:
            cve_id = vuln["cve_id"]
            cve_dir = self.cve_pages_dir / cve_id
            cve_dir.mkdir(exist_ok=True)

            try:
                html_content = self.generate_cve_page(vuln)

                with open(cve_dir / "index.html", "w", encoding="utf-8") as f:
                    f.write(html_content)

                generated_count += 1

                if generated_count % 100 == 0:
                    logger.info(f"Generated {generated_count} CVE pages...")

            except Exception as e:
                logger.error(f"Failed to generate page for {cve_id}: {e}")

        logger.info(f"Generated {generated_count} CVE pages")
        return generated_count

    def cleanup_removed_cve_pages(self, removed_cve_ids: List[str]) -> int:
        """Clean up CVE pages for removed vulnerabilities.

        Returns:
            Number of pages removed
        """
        if not removed_cve_ids:
            return 0

        removed_count = 0
        for cve_id in removed_cve_ids:
            cve_dir = self.cve_pages_dir / cve_id
            if cve_dir.exists():
                try:
                    # Remove the entire CVE directory
                    import shutil
                    shutil.rmtree(cve_dir)
                    removed_count += 1
                    logger.info(f"Removed CVE page for {cve_id}")
                except Exception as e:
                    logger.error(f"Failed to remove CVE page for {cve_id}: {e}")

        logger.info(f"Removed {removed_count} CVE pages")
        return removed_count

    def should_regenerate_dashboard(self, vulnerabilities: List[Dict],
                                   last_metadata: Dict) -> bool:
        """Check if dashboard needs regeneration based on data changes."""
        # Calculate hash of current vulnerability data
        dashboard_data = []
        for vuln in vulnerabilities:
            # Include only fields that affect the dashboard
            dashboard_entry = {
                "cve_id": vuln["cve_id"],
                "severity": vuln["severity"],
                "cvss_score": vuln["cvss_score"],
                "epss_percentile": vuln["epss_percentile"],
                "risk_score": vuln["risk_score"],
                "published_date": vuln["published_date"],
                "title": vuln.get("title", ""),
                "vendors": vuln.get("vendors", []),
            }
            dashboard_data.append(dashboard_entry)

        # Sort by risk score for consistent ordering
        dashboard_data.sort(key=lambda x: x["risk_score"], reverse=True)

        # Calculate hash
        data_str = json.dumps(dashboard_data, sort_keys=True, separators=(',', ':'))
        current_hash = hashlib.sha256(data_str.encode()).hexdigest()

        last_hash = last_metadata.get("dashboard_hash")

        if last_hash != current_hash:
            logger.info("Dashboard data has changed, will regenerate")
            return True, current_hash
        else:
            logger.info("Dashboard data unchanged, skipping regeneration")
            return False, current_hash

    def generate_incremental(self, force_all: bool = False) -> Dict:
        """Run incremental generation process.

        Args:
            force_all: If True, regenerate everything regardless of changes

        Returns:
            Dictionary with generation statistics
        """
        logger.info("Starting incremental generation...")

        # Load current vulnerabilities
        vulnerabilities = self.load_vulnerabilities_from_db()
        if not vulnerabilities:
            logger.warning("No vulnerabilities found in database")
            return {"error": "No vulnerabilities found"}

        # Get last generation metadata
        last_metadata = self.get_last_generation_metadata()

        stats = {
            "total_cves": len(vulnerabilities),
            "changed_cves": 0,
            "removed_cves": 0,
            "generated_pages": 0,
            "dashboard_regenerated": False,
            "force_all": force_all,
        }

        if force_all:
            logger.info("Force regeneration requested - will regenerate all files")
            changed_cves = vulnerabilities
            removed_cve_ids = []
            current_cve_hashes = {vuln["cve_id"]: self.calculate_cve_hash(vuln) for vuln in vulnerabilities}
        else:
            # Identify changes
            changed_cves, removed_cve_ids, current_cve_hashes = self.identify_changed_cves(
                vulnerabilities, last_metadata
            )

        stats["changed_cves"] = len(changed_cves)
        stats["removed_cves"] = len(removed_cve_ids)

        # Generate CVE pages for changed vulnerabilities
        stats["generated_pages"] = self.generate_changed_cve_pages(changed_cves)

        # Clean up removed CVE pages
        self.cleanup_removed_cve_pages(removed_cve_ids)

        # Check if dashboard needs regeneration
        should_regen, dashboard_hash = self.should_regenerate_dashboard(
            vulnerabilities, last_metadata
        )

        if should_regen or force_all:
            # Import and run the dashboard generator only if needed
            from scripts.generate_alpine_dashboard import AlpineDashboardGenerator

            logger.info("Regenerating dashboard...")
            generator = AlpineDashboardGenerator(self.db_path)
            generator.create_dashboard_html()
            generator.export_csv_data()
            stats["dashboard_regenerated"] = True

        # Save updated metadata
        new_metadata = {
            "cve_hashes": current_cve_hashes,
            "dashboard_hash": dashboard_hash,
            "generated_cves": list(current_cve_hashes.keys()),
        }
        self.save_generation_metadata(new_metadata)

        logger.info(f"Incremental generation completed: {stats}")
        return stats


def main():
    """Main entry point for incremental generation."""
    import argparse

    parser = argparse.ArgumentParser(description="Incremental CVE page and dashboard generator")
    parser.add_argument(
        "--db-path",
        type=Path,
        default=Path(".cache/vulns.db"),
        help="Path to vulnerability cache database"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("public"),
        help="Output directory for generated files"
    )
    parser.add_argument(
        "--force-all",
        action="store_true",
        help="Force regeneration of all files"
    )

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    generator = IncrementalGenerator(args.db_path, args.output_dir)
    stats = generator.generate_incremental(force_all=args.force_all)

    if "error" in stats:
        print(f"Error: {stats['error']}")
        return 1

    # Print summary
    print("\n=== Incremental Generation Summary ===")
    print(f"Total CVEs in database: {stats['total_cves']}")
    print(f"Changed CVEs: {stats['changed_cves']}")
    print(f"Removed CVEs: {stats['removed_cves']}")
    print(f"Generated pages: {stats['generated_pages']}")
    print(f"Dashboard regenerated: {stats['dashboard_regenerated']}")
    print(f"Force all: {stats['force_all']}")

    return 0


if __name__ == "__main__":
    import logging
    import sys
    sys.exit(main())
