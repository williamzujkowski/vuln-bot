#!/usr/bin/env python3
"""Example of integrating Great Expectations validation into the harvest workflow."""

import sys
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.harvest.orchestrator import HarvestOrchestrator
from scripts.processing.cache_manager import CacheManager
from scripts.quality.great_expectations_integration import GreatExpectationsValidator
from scripts.quality.validator import DataQualityValidator


class HarvestWithValidation:
    """Enhanced harvest workflow with Great Expectations validation."""
    
    def __init__(self, cache_dir: Path = Path(".cache")):
        self.cache_dir = cache_dir
        self.cache_manager = CacheManager(cache_dir=cache_dir)
        self.orchestrator = HarvestOrchestrator(
            cache_dir=cache_dir,
            api_keys={}
        )
        self.gx_validator = GreatExpectationsValidator()
        self.basic_validator = DataQualityValidator()
        
    def harvest_and_validate(self):
        """Harvest vulnerabilities and validate data quality."""
        
        print("🚀 Starting Enhanced Harvest with Data Quality Validation\n")
        
        # Step 1: Harvest from all sources
        print("1. Harvesting vulnerability data...")
        start_time = datetime.now()
        
        results = self.orchestrator.harvest_all_sources()
        
        harvest_time = (datetime.now() - start_time).total_seconds()
        print(f"   ✅ Harvested {results['total_processed']} vulnerabilities in {harvest_time:.1f}s")
        print(f"   Sources: {results['sources_processed']}")
        
        # Step 2: Get harvested vulnerabilities
        print("\n2. Retrieving harvested data for validation...")
        recent_vulns = self.cache_manager.get_recent_vulnerabilities(limit=1000)
        print(f"   Found {len(recent_vulns)} vulnerabilities to validate")
        
        # Step 3: Run Great Expectations validation
        print("\n3. Running Great Expectations validation...")
        gx_results = self.gx_validator.validate_vulnerabilities(recent_vulns)
        
        if gx_results["validator"] == "great_expectations":
            print("   ✅ Great Expectations validation complete")
            self._print_gx_results(gx_results)
        else:
            print("   ⚠️  Great Expectations not available, used basic validation")
            
        # Step 4: Profile data quality trends
        print("\n4. Profiling data quality...")
        profile = self.gx_validator.profile_vulnerability_data(recent_vulns[:100])
        self._print_quality_summary(profile)
        
        # Step 5: Check for specific quality issues
        print("\n5. Checking for critical quality issues...")
        quality_issues = self._check_quality_issues(recent_vulns, profile)
        
        if quality_issues:
            print("   ⚠️  Quality issues found:")
            for issue in quality_issues:
                print(f"      - {issue}")
        else:
            print("   ✅ No critical quality issues found")
            
        # Step 6: Generate quality report
        print("\n6. Generating quality report...")
        report = self._generate_quality_report(results, gx_results, profile, quality_issues)
        
        # Save report
        report_path = Path("harvest_quality_report.json")
        with open(report_path, "w") as f:
            import json
            json.dump(report, f, indent=2, default=str)
        print(f"   Report saved to: {report_path}")
        
        return report
        
    def _print_gx_results(self, results):
        """Print Great Expectations validation results."""
        if results["success"]:
            print(f"   ✅ All {results['total_expectations']} expectations passed!")
        else:
            print(f"   ❌ {results['failed_expectations']} of {results['total_expectations']} expectations failed")
            
        if "data_quality_metrics" in results:
            metrics = results["data_quality_metrics"]
            print(f"   Overall Quality Score: {metrics['overall_quality_score']:.1%}")
            
    def _print_quality_summary(self, profile):
        """Print data quality summary from profile."""
        # Calculate key metrics
        vendor_unknown_pct = 0
        product_unknown_pct = 0
        
        if "vendor" in profile["columns"]:
            vendor_profile = profile["columns"]["vendor"]
            if "top_values" in vendor_profile:
                unknown_count = vendor_profile["top_values"].get("Unknown", 0)
                vendor_unknown_pct = (unknown_count / profile["row_count"]) * 100
                
        if "product" in profile["columns"]:
            product_profile = profile["columns"]["product"]
            if "top_values" in product_profile:
                unknown_count = product_profile["top_values"].get("Unknown", 0)
                product_unknown_pct = (unknown_count / profile["row_count"]) * 100
                
        print(f"   Vendor extraction success: {100 - vendor_unknown_pct:.1f}%")
        print(f"   Product extraction success: {100 - product_unknown_pct:.1f}%")
        
        # CVSS/EPSS completeness
        if "cvss_base_score" in profile["columns"]:
            cvss_complete = 100 - profile["columns"]["cvss_base_score"]["null_percentage"]
            print(f"   CVSS score completeness: {cvss_complete:.1f}%")
            
        if "epss_probability" in profile["columns"]:
            epss_complete = 100 - profile["columns"]["epss_probability"]["null_percentage"]
            print(f"   EPSS score completeness: {epss_complete:.1f}%")
            
    def _check_quality_issues(self, vulnerabilities, profile):
        """Check for specific quality issues."""
        issues = []
        
        # Check vendor/product quality
        if "vendor" in profile["columns"]:
            vendor_profile = profile["columns"]["vendor"]
            if "top_values" in vendor_profile:
                unknown_count = vendor_profile["top_values"].get("Unknown", 0)
                unknown_pct = (unknown_count / profile["row_count"]) * 100
                if unknown_pct > 20:
                    issues.append(f"High percentage of unknown vendors: {unknown_pct:.1f}%")
                    
        # Check for missing critical data
        critical_fields = ["cvss_base_score", "epss_probability", "severity"]
        for field in critical_fields:
            if field in profile["columns"]:
                null_pct = profile["columns"][field]["null_percentage"]
                if null_pct > 10:
                    issues.append(f"High percentage of missing {field}: {null_pct:.1f}%")
                    
        # Check for data freshness
        recent_count = sum(1 for v in vulnerabilities if v.published_date and 
                          (datetime.now(v.published_date.tzinfo) - v.published_date).days < 7)
        if recent_count < 10:
            issues.append(f"Low number of recent vulnerabilities: {recent_count} from last 7 days")
            
        return issues
        
    def _generate_quality_report(self, harvest_results, validation_results, profile, issues):
        """Generate comprehensive quality report."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "harvest_summary": {
                "total_processed": harvest_results["total_processed"],
                "sources_processed": harvest_results["sources_processed"],
                "duration_seconds": harvest_results.get("duration_seconds", 0)
            },
            "validation_summary": {
                "validator_used": validation_results["validator"],
                "success": validation_results.get("success", False),
                "total_expectations": validation_results.get("total_expectations", 0),
                "failed_expectations": validation_results.get("failed_expectations", 0)
            },
            "data_quality_metrics": validation_results.get("data_quality_metrics", {}),
            "quality_issues": issues,
            "recommendations": []
        }
        
        # Add recommendations based on issues
        if any("unknown vendors" in issue for issue in issues):
            report["recommendations"].append(
                "Improve vendor extraction logic or add more vendor patterns"
            )
            
        if any("missing cvss_base_score" in issue for issue in issues):
            report["recommendations"].append(
                "Consider fetching CVSS scores from additional sources"
            )
            
        if validation_results.get("failed_expectations", 0) > 0:
            report["recommendations"].append(
                "Review and fix data quality issues causing expectation failures"
            )
            
        return report


def main():
    """Run enhanced harvest with validation."""
    harvester = HarvestWithValidation()
    report = harvester.harvest_and_validate()
    
    print("\n✨ Enhanced harvest complete!")
    print(f"\nQuality Score: {report['data_quality_metrics'].get('overall_quality_score', 0):.1%}")
    
    if report["quality_issues"]:
        print(f"Found {len(report['quality_issues'])} quality issues to address")
    else:
        print("No quality issues found!")
        

if __name__ == "__main__":
    main()