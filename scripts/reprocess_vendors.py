#!/usr/bin/env python3
"""Re-process existing CVE JSON files to fix vendor/product extraction."""

import json
from pathlib import Path


def reprocess_cve_file(file_path: Path):
    """Reprocess a single CVE JSON file to fix vendors/products."""
    with open(file_path) as f:
        data = json.load(f)

    cves = data if isinstance(data, list) else data.get("vulnerabilities", [])

    updated_count = 0
    for cve in cves:
        # Extract description
        cve.get("description", "")
        cve.get("title", cve.get("cveId", ""))

        # Re-extract vendors/products with improved logic
        # We don't have the full CVE structure here, so we'll just update from text
        old_vendors = cve.get("vendors", [])
        old_products = cve.get("products", [])

        # For simplicity, just filter out bad vendor names from existing data
        problematic = {
            "the",
            "n/a",
            "na",
            "web",
            "file",
            "server",
            "database",
            "framework",
            "application",
            "system",
            "none",
            "unknown",
        }

        new_vendors = [
            v for v in old_vendors if v.lower() not in problematic and len(v) > 1
        ]
        new_products = [
            p for p in old_products if p.lower() not in problematic and len(p) > 1
        ]

        if new_vendors != old_vendors or new_products != old_products:
            cve["vendors"] = new_vendors
            cve["products"] = new_products
            updated_count += 1

    # Write back
    with open(file_path, "w") as f:
        if isinstance(data, list):
            json.dump(cves, f, indent=2)
        else:
            data["vulnerabilities"] = cves
            json.dump(data, f, indent=2)

    return updated_count


def main():
    api_dir = Path("api/vulns")

    print("Re-processing CVE JSON files to fix vendor/product data...")
    print("=" * 60)

    total_updated = 0
    for json_file in api_dir.glob("*.json"):
        if json_file.name in ["chunk-index.json"]:
            continue

        print(f"Processing {json_file.name}...", end=" ")
        updated = reprocess_cve_file(json_file)
        total_updated += updated
        print(f"✓ ({updated} CVEs updated)")

    print("=" * 60)
    print(f"✅ Total CVEs updated: {total_updated}")
    print("\nRe-generating dashboard...")


if __name__ == "__main__":
    main()
