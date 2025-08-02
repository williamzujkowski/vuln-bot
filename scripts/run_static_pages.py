#!/usr/bin/env python3
"""
Run static page generation using the agent manager
"""

import asyncio
import sys
from pathlib import Path

# Add the scripts directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.agents.agent_manager import create_agent_manager


async def main():
    """Main function to run static page generation"""

    # Configuration
    cache_dir = Path(".cache")

    # Check if database exists
    db_path = cache_dir / "vulns.db"
    if not db_path.exists():
        print(f"Error: Database not found at {db_path}")
        print("Please run the vulnerability harvest first:")
        print("python -m scripts.main harvest --cache-dir .cache/")
        return 1

    print("🚀 Starting static page generation using agent manager...")

    # Create agent manager
    manager = create_agent_manager(cache_dir=cache_dir)

    # Configuration for static page agent
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
        # Run the static page agent
        results = await manager.run_agent("static_page", force=True, **config)

        print("\n✅ Static page generation completed!")
        print("📊 Results:")
        print(f"  - Pages generated: {results.get('pages_generated', 0)}")
        print(f"  - Pages updated: {results.get('pages_updated', 0)}")
        print(f"  - Pages skipped: {results.get('pages_skipped', 0)}")
        print(f"  - Pages enriched: {results.get('enriched_count', 0)}")
        print(f"  - Validation failures: {results.get('validation_failures', 0)}")

        if results.get('errors'):
            print("\n⚠️  Errors encountered:")
            for error in results['errors'][:5]:  # Show first 5 errors
                print(f"  - {error}")
            if len(results['errors']) > 5:
                print(f"  ... and {len(results['errors']) - 5} more errors")

        return 0 if results.get('success') else 1

    except Exception as e:
        print(f"\n❌ Error during page generation: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    # Run the async main function
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
