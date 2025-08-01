#!/usr/bin/env python3
"""Demonstration of Great Expectations integration with vuln-bot."""

import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.quality.great_expectations_integration import GreatExpectationsValidator
from scripts.harvest.orchestrator import HarvestOrchestrator
from scripts.processing.cache_manager import CacheManager


def demo_great_expectations():
    """Demonstrate Great Expectations validation on vulnerability data."""
    
    print("🔍 Great Expectations Demo for Vuln-Bot\n")
    
    # Initialize components
    print("1. Initializing components...")
    cache_dir = Path(".cache")
    cache_manager = CacheManager(cache_dir=cache_dir)
    orchestrator = HarvestOrchestrator(
        cache_dir=cache_dir,
        api_keys={}
    )
    
    # Get some vulnerability data
    print("\n2. Fetching recent vulnerabilities...")
    recent_vulns = cache_manager.get_recent_vulnerabilities(limit=100)
    
    if not recent_vulns:
        print("   No cached vulnerabilities found. Please run harvest first.")
        return
        
    print(f"   Found {len(recent_vulns)} vulnerabilities")
    
    # Initialize Great Expectations validator
    print("\n3. Initializing Great Expectations validator...")
    gx_validator = GreatExpectationsValidator()
    
    if not gx_validator.context:
        print("   ⚠️  Great Expectations not installed. Install with:")
        print("   uv pip install great-expectations")
        print("\n   Running basic validation instead...")
    
    # Profile the data
    print("\n4. Profiling vulnerability data...")
    profile = gx_validator.profile_vulnerability_data(recent_vulns)
    
    if "error" in profile:
        print(f"   ⚠️  {profile['error']}")
        print("\n   To use Great Expectations, install it with:")
        print("   uv pip install great-expectations")
        return
    
    print(f"   Total records: {profile['row_count']}")
    print(f"   Total columns: {profile['column_count']}")
    
    # Show key metrics
    print("\n5. Data Quality Metrics:")
    for col in ["cve_id", "vendor", "product", "cvss_base_score", "epss_probability"]:
        if col in profile["columns"]:
            col_profile = profile["columns"][col]
            print(f"\n   {col}:")
            print(f"     - Null %: {col_profile['null_percentage']:.1f}%")
            print(f"     - Unique values: {col_profile['unique_count']}")
            
            if col == "vendor" and "top_values" in col_profile:
                unknown_count = col_profile["top_values"].get("Unknown", 0)
                unknown_pct = (unknown_count / profile["row_count"]) * 100
                print(f"     - 'Unknown' %: {unknown_pct:.1f}%")
                
    # Run validation
    print("\n6. Running data quality validation...")
    validation_results = gx_validator.validate_vulnerabilities(recent_vulns)
    
    if validation_results["validator"] == "great_expectations":
        print(f"   ✅ Validation completed using Great Expectations")
        print(f"   Success: {validation_results['success']}")
        print(f"   Total expectations: {validation_results.get('total_expectations', 0)}")
        print(f"   Passed: {validation_results.get('successful_expectations', 0)}")
        print(f"   Failed: {validation_results.get('failed_expectations', 0)}")
        
        if "data_quality_metrics" in validation_results:
            metrics = validation_results["data_quality_metrics"]
            print(f"\n   Overall Quality Score: {metrics['overall_quality_score']:.2%}")
            
            # Show completeness metrics
            if "completeness" in metrics:
                print("\n   Completeness Metrics:")
                for field, score in metrics["completeness"].items():
                    print(f"     - {field}: {score:.2%}")
                    
            # Show validity metrics
            if "validity" in metrics:
                print("\n   Validity Metrics:")
                for field, score in metrics["validity"].items():
                    print(f"     - {field}: {score:.2%}")
                    
        # Show failures if any
        if not validation_results["success"] and "failures" in validation_results:
            print("\n   ❌ Failed Expectations:")
            for failure in validation_results["failures"][:5]:  # Show first 5
                print(f"     - {failure['expectation']} on {failure.get('column', 'N/A')}")
                
    else:
        print(f"   ⚠️  Validation completed using basic validator (GX not available)")
        success_count = sum(1 for r in validation_results["results"] if r["valid"])
        print(f"   Valid records: {success_count}/{len(validation_results['results'])}")
        
    # Show suggested expectations
    if "suggested_expectations" in profile:
        print("\n7. Suggested Data Quality Rules:")
        for suggestion in profile["suggested_expectations"][:10]:  # Show first 10
            print(f"   - {suggestion['expectation']} for '{suggestion['column']}'")
            print(f"     Reason: {suggestion['reason']}")
            
    # Save results
    print("\n8. Saving results...")
    output_dir = Path("examples/output")
    output_dir.mkdir(exist_ok=True)
    
    # Save profile
    with open(output_dir / "vulnerability_profile.json", "w") as f:
        json.dump(profile, f, indent=2, default=str)
    print(f"   Profile saved to: {output_dir / 'vulnerability_profile.json'}")
    
    # Save validation results
    with open(output_dir / "validation_results.json", "w") as f:
        json.dump(validation_results, f, indent=2, default=str)
    print(f"   Validation results saved to: {output_dir / 'validation_results.json'}")
    
    print("\n✨ Demo complete!")
    
    if gx_validator.context:
        print("\nNext steps:")
        print("1. View data docs: great_expectations docs build")
        print("2. Create custom expectations for your specific needs")
        print("3. Set up automated validation in your harvest pipeline")
        print("4. Configure alerts for data quality issues")


if __name__ == "__main__":
    demo_great_expectations()