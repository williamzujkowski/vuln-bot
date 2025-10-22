#!/usr/bin/env python3
"""
Enrich existing JSON API files with triagePriority and techCategories fields.
This script reads existing API JSON files and adds Phase 2 enrichment fields.
"""

import json
from datetime import datetime
from pathlib import Path


def calculate_triage_priority(vuln: dict) -> str:
    """Calculate triage priority based on EPSS, CVSS, and Attack Complexity
    Returns: CRITICAL-URGENT, HIGH-PRIORITY, or MONITOR
    """
    epss = vuln.get("epssPercentile", 0)
    cvss = vuln.get("cvssScore", 0)
    attack_complexity_raw = vuln.get("attackComplexity", "")
    attack_complexity = attack_complexity_raw.upper() if attack_complexity_raw else ""

    # CRITICAL-URGENT: EPSS ≥95% AND CVSS ≥9.0 AND Low Complexity
    if epss >= 95 and cvss >= 9.0 and attack_complexity == "LOW":
        return "CRITICAL-URGENT"
    # HIGH-PRIORITY: EPSS ≥80% AND CVSS ≥7.0
    elif epss >= 80 and cvss >= 7.0:
        return "HIGH-PRIORITY"
    # MONITOR: Everything else (EPSS 60-80%)
    else:
        return "MONITOR"


def detect_technology_category(vuln: dict) -> list:
    """Detect technology categories for filtering
    Returns: List of category tags
    """
    categories = []
    vendors = [v.lower() for v in vuln.get("vendors", [])]
    products = [p.lower() for p in vuln.get("products", [])]
    all_text = " ".join(vendors + products).lower()

    # Web Servers
    if any(
        keyword in all_text for keyword in ["apache", "nginx", "iis", "httpd", "tomcat"]
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
        keyword in all_text for keyword in ["wordpress", "drupal", "joomla", "typo3"]
    ):
        categories.append("cms")

    return categories


def enrich_vulnerability(vuln: dict) -> dict:
    """Add enrichment fields to a vulnerability dict"""
    # Add new fields (preserve all existing fields)
    # Use snake_case to match dashboard generator expectations
    vuln["triage_priority"] = calculate_triage_priority(vuln)
    vuln["tech_categories"] = detect_technology_category(vuln)
    return vuln


def enrich_json_file(input_path: Path, output_path: Path = None):
    """Enrich a JSON file with triagePriority and techCategories"""
    if output_path is None:
        output_path = input_path

    print(f"Enriching {input_path}...")

    # Read existing data
    with open(input_path) as f:
        data = json.load(f)

    # Enrich vulnerabilities
    if "vulnerabilities" in data:
        enriched_count = 0
        for vuln in data["vulnerabilities"]:
            # Only enrich if fields don't already exist
            if "triage_priority" not in vuln:
                enrich_vulnerability(vuln)
                enriched_count += 1

        print(f"  Enriched {enriched_count} vulnerabilities")

        # Update metadata
        data["last_updated"] = datetime.now().isoformat()

        # Write back
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)

        print(f"  ✓ Wrote enriched data to {output_path}")

        # Show enrichment stats
        priority_counts = {}
        tech_counts = {}
        for v in data["vulnerabilities"]:
            p = v.get("triage_priority", "UNKNOWN")
            priority_counts[p] = priority_counts.get(p, 0) + 1
            for cat in v.get("tech_categories", []):
                tech_counts[cat] = tech_counts.get(cat, 0) + 1

        print("\n  Enrichment Summary:")
        print("    Triage Priority Distribution:")
        for p, count in sorted(priority_counts.items()):
            print(f"      - {p}: {count}")

        if tech_counts:
            print("    Technology Categories:")
            for cat, count in sorted(
                tech_counts.items(), key=lambda x: x[1], reverse=True
            ):
                print(f"      - {cat}: {count}")

    else:
        print(f"  ⚠ No 'vulnerabilities' key found in {input_path}")


def main():
    """Main entry point"""
    print("=" * 60)
    print("JSON API Enrichment Script")
    print("Adding triagePriority and techCategories fields")
    print("=" * 60)
    print()

    # Enrich public API files
    public_api_dir = Path("public/api/vulns")
    if public_api_dir.exists():
        index_file = public_api_dir / "index.json"
        if index_file.exists():
            enrich_json_file(index_file)
        else:
            print(f"⚠ {index_file} not found")
    else:
        print(f"⚠ {public_api_dir} not found")

    print()

    # Note: src/api/vulns is only created by local dev runs with default --output-dir
    # GitHub Actions workflow uses --output-dir . which creates api/vulns
    # No need to enrich src/api since it's not used in production

    print()

    # Enrich api directory (if it exists)
    api_dir = Path("api/vulns")
    if api_dir.exists():
        index_file = api_dir / "index.json"
        if index_file.exists():
            enrich_json_file(index_file)
        else:
            print(f"⚠ {index_file} not found")

    print()
    print("=" * 60)
    print("✅ Enrichment complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
