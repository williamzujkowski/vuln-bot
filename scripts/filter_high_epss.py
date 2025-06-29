#!/usr/bin/env python3
"""Filter existing vulnerability data to only include high EPSS scores."""

import json
import shutil


def filter_high_epss_vulns():
    """Filter vulnerabilities to only include those with EPSS >= 70%."""

    # Read the current index
    with open("public/api/vulns/index.json") as f:
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

    # Update the index with filtered data
    data["vulnerabilities"] = high_epss_vulns
    data["count"] = len(high_epss_vulns)

    # Backup original
    shutil.copy("public/api/vulns/index.json", "public/api/vulns/index.json.backup")

    # Write filtered index
    with open("public/api/vulns/index.json", "w") as f:
        json.dump(data, f, indent=2)

    print(f"\nUpdated index.json with {len(high_epss_vulns)} high EPSS vulnerabilities")

    # Show top 10
    print("\nTop 10 by EPSS score:")
    high_epss_vulns.sort(key=lambda x: x.get("epssScore", 0), reverse=True)
    for i, vuln in enumerate(high_epss_vulns[:10], 1):
        print(
            f"{i}. {vuln['cveId']}: EPSS={vuln['epssScore']:.1f}%, CVSS={vuln.get('cvssScore', 'N/A')}, {vuln['severity']}"
        )


if __name__ == "__main__":
    filter_high_epss_vulns()
