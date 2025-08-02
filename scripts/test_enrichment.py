#!/usr/bin/env python3
"""Test script for the enhanced DataEnrichmentAgent."""

import asyncio
import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.agents.enrichment_agent import DataEnrichmentAgent


async def test_enrichment():
    """Test the enrichment agent with sample CVEs."""
    agent = DataEnrichmentAgent()

    # Test CVEs with known package impacts
    test_cves = [
        {
            "cve_id": "CVE-2024-3094",  # xz utils backdoor
            "title": "XZ Utils Backdoor",
            "description": "Malicious code in xz utils",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "epss_score": 84.17,
            "vendors_list": ["xz"],
            "products_list": ["xz utils"],
            "references": ["https://github.com/advisories"],
        },
        {
            "cve_id": "CVE-2021-44228",  # Log4Shell
            "title": "Apache Log4j Remote Code Execution",
            "description": "Remote code execution in Log4j",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "epss_score": 97.0,
            "vendors_list": ["apache"],
            "products_list": ["log4j"],
            "references": ["https://logging.apache.org/log4j/2.x/security.html"],
        },
        {
            "cve_id": "CVE-2024-47660",  # Sample with potential npm packages
            "title": "Node.js Vulnerability",
            "description": "Vulnerability in Node.js",
            "severity": "HIGH",
            "cvss_score": 8.1,
            "epss_score": 75.0,
            "vendors_list": ["nodejs"],
            "products_list": ["node"],
            "references": [],
        },
    ]

    print("Testing DataEnrichmentAgent with sample CVEs...\n")

    for cve_data in test_cves:
        print(f"\n{'='*60}")
        print(f"Testing {cve_data['cve_id']}: {cve_data['title']}")
        print(f"{'='*60}")

        try:
            # Enrich the CVE data
            enriched = await agent.enrich_cve_data(cve_data)

            # Display results
            print("\nEnrichment Status:")
            print(f"- Sources: {', '.join(enriched['enrichment']['sources'])}")

            impact = enriched["enrichment"]["impact_summary"]
            print("\nImpact Summary:")
            print(f"- Total Affected Packages: {impact['total_affected_packages']}")
            print(
                f"- Affected Ecosystems: {', '.join(impact['affected_ecosystems']) if impact['affected_ecosystems'] else 'None'}"
            )
            print(f"- Has Impact Data: {impact['has_impact_data']}")

            if impact["severity_breakdown"]:
                print(
                    f"- Severity Breakdown: {json.dumps(impact['severity_breakdown'], indent=2)}"
                )

            patch_info = impact.get("patch_availability", {})
            if patch_info:
                print(
                    f"- Patch Availability: {patch_info['patched']}/{patch_info['total']} ({patch_info['percentage']}%)"
                )

            # Show package details if available
            if "package_impact" in enriched["enrichment"]:
                packages = enriched["enrichment"]["package_impact"]
                if packages:
                    print(f"\nAffected Packages ({len(packages)}):")
                    for pkg in packages[:5]:  # Show first 5
                        print(f"  - {pkg['ecosystem']}/{pkg['name']}")
                        print(f"    Version Range: {pkg['version_range']}")
                        print(f"    Severity: {pkg['severity']}")
                        print(f"    Patch Available: {pkg['patch_available']}")
                        if pkg.get("latest_safe_version"):
                            print(
                                f"    Latest Safe Version: {pkg['latest_safe_version']}"
                            )
                    if len(packages) > 5:
                        print(f"  ... and {len(packages) - 5} more packages")

            # Show exploitation intelligence
            if "exploitation_intel" in enriched["enrichment"]:
                intel = enriched["enrichment"]["exploitation_intel"]
                print("\nExploitation Intelligence:")
                print(f"- Risk Level: {intel['risk_level']}")
                print(f"- Risk Factors: {', '.join(intel['risk_factors'])}")
                print(f"- Recommendation: {intel['recommendation']}")

            # Show categorized references
            if "categorized_references" in enriched["enrichment"]:
                refs = enriched["enrichment"]["categorized_references"]
                print("\nCategorized References:")
                for category, ref_list in refs.items():
                    print(
                        f"- {category.replace('_', ' ').title()}: {len(ref_list)} references"
                    )

            # Save enriched data for inspection
            output_file = Path(f".cache/enrichment/{cve_data['cve_id']}_enriched.json")
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w") as f:
                json.dump(enriched, f, indent=2)
            print(f"\nFull enriched data saved to: {output_file}")

        except Exception as e:
            print(f"\nError enriching {cve_data['cve_id']}: {e}")
            import traceback

            traceback.print_exc()

    print(f"\n{'='*60}")
    print("Testing complete!")


if __name__ == "__main__":
    asyncio.run(test_enrichment())
