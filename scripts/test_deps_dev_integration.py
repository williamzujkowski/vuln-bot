#!/usr/bin/env python3
"""Integration test for deps.dev API - tests with real API calls."""

import asyncio
import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.agents.enrichment_agent import DataEnrichmentAgent


async def test_real_api():
    """Test the enrichment agent with real API calls to deps.dev."""
    agent = DataEnrichmentAgent()

    # Test with a known CVE that should have package data
    test_cve = {
        "cve_id": "CVE-2021-44228",  # Log4Shell - should have lots of data
        "title": "Apache Log4j Remote Code Execution",
        "description": "Remote code execution vulnerability in Apache Log4j",
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "epss_score": 97.0,
        "vendors_list": ["apache"],
        "products_list": ["log4j"],
        "references": ["https://logging.apache.org/log4j/2.x/security.html"],
        "kev_status": True
    }

    print("Testing deps.dev API integration with CVE-2021-44228 (Log4Shell)...")
    print("=" * 60)

    try:
        # Clear cache to force API call
        cache_file = agent.cache_dir / f"{test_cve['cve_id']}_deps.json"
        if cache_file.exists():
            cache_file.unlink()
            print("Cleared cache file")

        # Fetch deps.dev data
        print("\nFetching data from deps.dev API...")
        deps_data = await agent.fetch_deps_dev_data(test_cve["cve_id"])

        if deps_data:
            print("\n✅ Successfully fetched data!")
            print(f"Total affected packages: {deps_data.get('total_affected', 0)}")
            print(f"Affected ecosystems: {', '.join(deps_data.get('ecosystems', []))}")

            # Show sample packages
            packages = deps_data.get("packages", [])
            if packages:
                print("\nSample affected packages (showing first 5):")
                for i, pkg in enumerate(packages[:5]):
                    print(f"\n{i+1}. {pkg.get('ecosystem', 'Unknown')}/{pkg.get('name', 'Unknown')}")
                    print(f"   Version range: {pkg.get('version_range', 'Unknown')}")
                    print(f"   Severity: {pkg.get('severity', 'Unknown')}")
                    print(f"   Patch available: {pkg.get('patch_available', False)}")
                    if pkg.get('latest_safe_version'):
                        print(f"   Latest safe version: {pkg['latest_safe_version']}")

                if len(packages) > 5:
                    print(f"\n... and {len(packages) - 5} more packages")

            # Save full response for inspection
            output_file = Path(".cache/deps_dev_test_response.json")
            with open(output_file, 'w') as f:
                json.dump(deps_data, f, indent=2)
            print(f"\nFull response saved to: {output_file}")

        else:
            print("\n❌ No data returned from deps.dev API")
            print("This might be normal if the CVE isn't in their database yet")

        # Test full enrichment
        print("\n" + "=" * 60)
        print("Testing full CVE enrichment...")

        enriched = await agent.enrich_cve_data(test_cve)

        # Check enrichment results
        if enriched.get("enrichment"):
            print("\n✅ Enrichment successful!")
            print(f"Sources: {', '.join(enriched['enrichment']['sources'])}")

            # Check impact summary
            impact = enriched['enrichment'].get('impact_summary', {})
            if impact.get('has_impact_data'):
                print("\nImpact Summary:")
                print(f"- Total packages: {impact['total_affected_packages']}")
                print(f"- Ecosystems: {', '.join(impact['affected_ecosystems'])}")

                patch_info = impact.get('patch_availability', {})
                if patch_info:
                    print(f"- Patches: {patch_info['patched']}/{patch_info['total']} ({patch_info['percentage']}%)")

                severity_breakdown = impact.get('severity_breakdown', {})
                if severity_breakdown:
                    print(f"- Severity breakdown: {json.dumps(severity_breakdown, indent=2)}")

            # Check exploitation intelligence
            intel = enriched['enrichment'].get('exploitation_intel', {})
            if intel:
                print("\nExploitation Intelligence:")
                print(f"- Risk Level: {intel['risk_level']}")
                print(f"- Factors: {len(intel.get('risk_factors', []))} risk factors identified")
                print(f"- Recommendation: {intel['recommendation'][:100]}...")

            # Save enriched data
            output_file = Path(".cache/enriched_test_response.json")
            with open(output_file, 'w') as f:
                json.dump(enriched, f, indent=2)
            print(f"\nFull enriched data saved to: {output_file}")

        else:
            print("\n❌ Enrichment failed")

    except Exception as e:
        print(f"\n❌ Error during test: {e}")
        import traceback
        traceback.print_exc()

    print("\n" + "=" * 60)
    print("Integration test complete!")


if __name__ == "__main__":
    asyncio.run(test_real_api())
