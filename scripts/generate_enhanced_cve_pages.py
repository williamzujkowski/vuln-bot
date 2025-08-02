#!/usr/bin/env python3
"""
Generate enhanced static CVE detail pages using the StaticPageAgent with enrichment
"""

import asyncio
import sys
from pathlib import Path

# Add the scripts directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.agents.static_page_agent import StaticPageAgent


async def main():
    """Main function to generate enhanced CVE pages"""

    # Configuration
    cache_dir = Path(".cache")

    # Check if database exists
    db_path = cache_dir / "vulns.db"
    if not db_path.exists():
        print(f"Error: Database not found at {db_path}")
        print("Please run the vulnerability harvest first:")
        print("python -m scripts.main harvest --cache-dir .cache/")
        return 1

    print("🚀 Starting enhanced CVE page generation...")

    # Initialize the static page agent
    static_agent = StaticPageAgent(cache_dir=cache_dir)

    # Configure the agent
    config = {
        "output_dir": "src/cves",
        "template_format": "md",
        "max_pages_per_run": 100,  # Limit for testing
        "include_full_details": True,
        "generate_index": True,
        "enable_enrichment": True,  # Enable deps.dev enrichment
        "validate_schema": False,   # Disable schema validation due to dependency conflicts
    }

    try:
        # Execute the page generation
        results = await static_agent.execute(**config)

        print("\n✅ Enhanced CVE page generation completed!")
        print("📊 Results:")
        print(f"  - Pages generated: {results['pages_generated']}")
        print(f"  - Pages updated: {results['pages_updated']}")
        print(f"  - Pages skipped: {results['pages_skipped']}")
        print(f"  - Pages enriched: {results.get('pages_enriched', 0)}")
        print(f"  - Validation passed: {results.get('validation_passed', 0)}")
        print(f"  - Validation failed: {results.get('validation_failed', 0)}")

        if results['errors']:
            print("\n⚠️  Errors encountered:")
            for error in results['errors'][:5]:  # Show first 5 errors
                print(f"  - {error}")
            if len(results['errors']) > 5:
                print(f"  ... and {len(results['errors']) - 5} more errors")

        # Generate a summary report
        if results.get('enrichment_summary'):
            print("\n📊 Enrichment Summary:")
            summary = results['enrichment_summary']
            print(f"  - Total CVEs processed: {summary.get('total_processed', 0)}")
            print(f"  - Successfully enriched: {summary.get('successfully_enriched', 0)}")
            print(f"  - deps.dev data found: {summary.get('deps_dev_found', 0)}")
            print(f"  - CWEs extracted: {summary.get('cwes_extracted', 0)}")

        return 0 if results['success'] else 1

    except Exception as e:
        print(f"\n❌ Error during page generation: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    # Run the async main function
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
