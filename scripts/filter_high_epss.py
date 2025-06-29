#!/usr/bin/env python3
"""Filter existing vulnerability data to only include high EPSS scores and organize into subfolders."""

import json
import os
import shutil
from pathlib import Path


def filter_high_epss_vulns():
    """Filter vulnerabilities to only include those with EPSS >= 70% and organize into subfolders."""

    # Read from the source data
    source_index = "src/api/vulns/index.json"
    target_index = "public/api/vulns/index.json"

    # Ensure source exists
    if not os.path.exists(source_index):
        print(f"Error: {source_index} not found. Run generate-briefing first.")
        return

    with open(source_index) as f:
        data = json.load(f)

    # Filter vulnerabilities
    all_vulns = data["vulnerabilities"]
    high_epss_vulns = []

    for vuln in all_vulns:
        epss_score = vuln.get("epssScore")
        if epss_score is not None and epss_score >= 70.0:
            high_epss_vulns.append(vuln)

    print(f"Total vulnerabilities: {len(all_vulns)}")
    print(f"High EPSS vulnerabilities (>= 70%): {len(high_epss_vulns)}")

    # Create output directory
    os.makedirs("public/api/vulns", exist_ok=True)

    # Backup existing if it exists
    if os.path.exists(target_index):
        shutil.copy(target_index, f"{target_index}.backup")

    # Update the index with filtered data
    data["vulnerabilities"] = high_epss_vulns
    data["count"] = len(high_epss_vulns)

    # Write filtered index
    with open(target_index, "w") as f:
        json.dump(data, f, indent=2)

    print(
        f"\nUpdated {target_index} with {len(high_epss_vulns)} high EPSS vulnerabilities"
    )

    # Show top 10
    print("\nTop 10 by EPSS score:")
    sorted_vulns = sorted(
        high_epss_vulns, key=lambda x: x.get("epssScore", 0), reverse=True
    )
    for i, vuln in enumerate(sorted_vulns[:10], 1):
        print(
            f"{i}. {vuln['cveId']}: EPSS={vuln['epssScore']:.1f}%, CVSS={vuln.get('cvssScore', 'N/A')}, {vuln['severity']}"
        )

    # If requested, organize into subfolders
    if len(high_epss_vulns) > 1000:
        organize_into_subfolders(high_epss_vulns, "public/api/vulns")


def organize_into_subfolders(vulnerabilities, base_path, items_per_folder=1000):
    """Organize vulnerabilities into subfolders with max 1000 items each."""

    print(f"\nOrganizing {len(vulnerabilities)} vulnerabilities into subfolders...")

    # Create subfolder structure
    for i in range(0, len(vulnerabilities), items_per_folder):
        batch_num = i // items_per_folder + 1
        subfolder = Path(base_path) / f"batch_{batch_num:03d}"
        subfolder.mkdir(parents=True, exist_ok=True)

        # Get batch of vulnerabilities
        batch = vulnerabilities[i : i + items_per_folder]

        # Create index for this batch
        batch_index = {
            "batch": batch_num,
            "count": len(batch),
            "range": f"{i + 1}-{min(i + items_per_folder, len(vulnerabilities))}",
            "vulnerabilities": batch,
        }

        # Write batch index
        with open(subfolder / "index.json", "w") as f:
            json.dump(batch_index, f, indent=2)

        print(f"  Created batch {batch_num}: {len(batch)} vulnerabilities")

    # Create master index pointing to all batches
    total_batches = (len(vulnerabilities) + items_per_folder - 1) // items_per_folder
    master_index = {
        "total_count": len(vulnerabilities),
        "items_per_batch": items_per_folder,
        "total_batches": total_batches,
        "batches": [],
    }

    for i in range(total_batches):
        batch_num = i + 1
        start = i * items_per_folder
        end = min((i + 1) * items_per_folder, len(vulnerabilities))

        master_index["batches"].append(
            {
                "batch": batch_num,
                "path": f"batch_{batch_num:03d}/index.json",
                "count": end - start,
                "range": f"{start + 1}-{end}",
            }
        )

    # Write master index
    with open(Path(base_path) / "batches.json", "w") as f:
        json.dump(master_index, f, indent=2)

    print(f"\nCreated master index at {base_path}/batches.json")


if __name__ == "__main__":
    filter_high_epss_vulns()
