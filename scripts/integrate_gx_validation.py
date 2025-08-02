#!/usr/bin/env python3
"""
Integrate Great Expectations validation into the vuln-bot data pipeline.
Adds validation hooks at critical points in the data flow.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

# Import with optional Great Expectations
try:
    from scripts.great_expectations_setup import (
        HAS_GREAT_EXPECTATIONS,
        VulnBotDataValidator,
    )
except ImportError:
    HAS_GREAT_EXPECTATIONS = False
    VulnBotDataValidator = None


class PipelineValidator:
    """Validates data at each stage of the vuln-bot pipeline."""

    def __init__(self, enable_validation: bool = True):
        self.enable_validation = enable_validation and HAS_GREAT_EXPECTATIONS
        self.validator = None
        self.validation_results = []

        if self.enable_validation:
            try:
                self.validator = VulnBotDataValidator()
                self.validator.setup_data_context()
            except Exception as e:
                print(f"⚠️  Could not initialize Great Expectations: {e}")
                self.enable_validation = False

    def validate_ingestion(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate raw CVE data after ingestion."""
        if not self.enable_validation:
            return {"success": True, "skipped": True}

        # Save data temporarily for validation
        temp_file = Path("temp_ingestion_data.json")
        with open(temp_file, "w") as f:
            json.dump({"vulnerabilities": data}, f)

        try:
            results = self.validator.validate_data(
                temp_file, "cve_ingestion_validation"
            )

            # Log results
            self._log_validation_result("ingestion", results)

            # Clean up
            temp_file.unlink()

            return results

        except Exception as e:
            print(f"❌ Validation error during ingestion: {e}")
            temp_file.unlink(missing_ok=True)
            return {"success": False, "error": str(e)}

    def validate_enrichment(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate enriched CVE data."""
        if not self.enable_validation:
            return {"success": True, "skipped": True}

        # Save data temporarily
        temp_file = Path("temp_enrichment_data.json")
        with open(temp_file, "w") as f:
            json.dump({"vulnerabilities": data}, f)

        try:
            results = self.validator.validate_data(
                temp_file, "cve_enrichment_validation"
            )

            # Log results
            self._log_validation_result("enrichment", results)

            # Clean up
            temp_file.unlink()

            return results

        except Exception as e:
            print(f"❌ Validation error during enrichment: {e}")
            temp_file.unlink(missing_ok=True)
            return {"success": False, "error": str(e)}

    def validate_static_pages(self, page_dir: Path) -> Dict[str, Any]:
        """Validate generated static pages."""
        if not self.enable_validation:
            return {"success": True, "skipped": True}

        # Sample validation on first 10 pages
        page_files = list(page_dir.glob("CVE-*.md"))[:10]

        all_success = True
        failed_pages = []

        for page_file in page_files:
            try:
                # Extract frontmatter
                content = page_file.read_text()
                frontmatter = self._extract_frontmatter(content)

                # Create temp JSON for validation
                temp_file = Path(f"temp_{page_file.stem}.json")
                with open(temp_file, "w") as f:
                    json.dump(frontmatter, f)

                results = self.validator.validate_data(
                    temp_file, "cve_static_page_validation"
                )

                if not results["success"]:
                    all_success = False
                    failed_pages.append(page_file.name)

                temp_file.unlink()

            except Exception as e:
                print(f"❌ Error validating {page_file}: {e}")
                all_success = False
                failed_pages.append(page_file.name)

        results = {
            "success": all_success,
            "pages_validated": len(page_files),
            "failed_pages": failed_pages,
        }

        self._log_validation_result("static_pages", results)
        return results

    def _extract_frontmatter(self, content: str) -> Dict[str, Any]:
        """Extract YAML frontmatter from markdown file."""
        import yaml

        lines = content.split("\n")
        if lines[0] != "---":
            return {}

        end_index = -1
        for i in range(1, len(lines)):
            if lines[i] == "---":
                end_index = i
                break

        if end_index == -1:
            return {}

        frontmatter_text = "\n".join(lines[1:end_index])
        return yaml.safe_load(frontmatter_text) or {}

    def _log_validation_result(self, stage: str, results: Dict[str, Any]):
        """Log validation results."""
        timestamp = datetime.now().isoformat()

        result_entry = {
            "timestamp": timestamp,
            "stage": stage,
            "success": results.get("success", False),
            "details": results,
        }

        self.validation_results.append(result_entry)

        # Print summary
        if results.get("success"):
            print(f"✅ Validation passed for {stage}")
        else:
            print(f"❌ Validation failed for {stage}")
            if "statistics" in results:
                stats = results["statistics"]
                print(
                    f"   Failed expectations: {stats.get('unsuccessful_expectations', 'N/A')}"
                )

    def generate_validation_report(self) -> str:
        """Generate a validation report."""
        report = ["# Data Validation Report", ""]
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append("")

        if not self.validation_results:
            report.append("No validation results available.")
            return "\n".join(report)

        # Summary
        total_validations = len(self.validation_results)
        successful = sum(1 for r in self.validation_results if r["success"])

        report.append("## Summary")
        report.append(f"- Total validations: {total_validations}")
        report.append(f"- Successful: {successful}")
        report.append(f"- Failed: {total_validations - successful}")
        report.append(f"- Success rate: {(successful / total_validations) * 100:.1f}%")
        report.append("")

        # Details by stage
        report.append("## Validation Details")

        for result in self.validation_results:
            report.append(f"\n### {result['stage'].title()} - {result['timestamp']}")
            report.append(
                f"**Status**: {'✅ PASSED' if result['success'] else '❌ FAILED'}"
            )

            if not result["success"] and "details" in result:
                details = result["details"]
                if "statistics" in details:
                    stats = details["statistics"]
                    report.append(
                        f"**Failed expectations**: {stats.get('unsuccessful_expectations', 'N/A')}"
                    )
                if "error" in details:
                    report.append(f"**Error**: {details['error']}")

        return "\n".join(report)


# Integration hooks for existing pipeline
def add_validation_to_orchestrator():
    """Add validation hooks to the harvest orchestrator."""
    code = """
# Add to scripts/harvest/orchestrator.py after data fetching:

from scripts.integrate_gx_validation import PipelineValidator

class HarvestOrchestrator:
    def __init__(self, ...):
        # ... existing init ...
        self.validator = PipelineValidator()

    async def harvest_all_sources(self):
        # ... existing harvest code ...

        # Validate after CVE data collection
        if self.validator.enable_validation:
            print("🔍 Validating ingested data...")
            validation_results = self.validator.validate_ingestion(all_vulnerabilities)

            if not validation_results["success"]:
                self.logger.warning("Data validation failed, continuing with warnings")

        # ... continue processing ...
"""
    return code


def add_validation_to_static_page_agent():
    """Add validation hooks to static page generation."""
    code = """
# Add to scripts/agents/static_page_agent.py after page generation:

from scripts.integrate_gx_validation import PipelineValidator

class StaticPageAgent:
    def __init__(self, ...):
        # ... existing init ...
        self.validator = PipelineValidator()

    async def execute(self, config):
        # ... existing page generation ...

        # Validate generated pages
        if self.validator.enable_validation:
            print("🔍 Validating static pages...")
            output_dir = Path(config.get("output_dir", "src/cves"))
            validation_results = self.validator.validate_static_pages(output_dir)

            if not validation_results["success"]:
                self.logger.warning(f"Page validation failed for {len(validation_results['failed_pages'])} pages")

        # Generate validation report
        report = self.validator.generate_validation_report()
        report_path = Path("validation_report.md")
        report_path.write_text(report)

        return results
"""
    return code


def main():
    """Demo validation integration."""
    print("🚀 Great Expectations Integration for Vuln-Bot")
    print("=" * 50)

    if not HAS_GREAT_EXPECTATIONS:
        print("❌ Great Expectations not installed.")
        print("   Run: pip install great-expectations")
        return

    # Initialize validator
    validator = PipelineValidator()

    # Demo validation with sample data
    sample_data = [
        {
            "cveId": "CVE-2024-12345",
            "title": "Test vulnerability",
            "severity": "CRITICAL",
            "cvssScore": 9.8,
            "epssScore": 85.5,
            "riskScore": 92,
            "publishedDate": "2024-01-01T00:00:00+00:00",
            "vendors": ["test_vendor"],
            "products": ["test_product"],
        }
    ]

    print("\n📊 Running sample validation...")
    results = validator.validate_ingestion(sample_data)

    print(f"\nValidation success: {results['success']}")

    # Show integration code
    print("\n📝 Integration Instructions:")
    print("\n1. Add to HarvestOrchestrator:")
    print(add_validation_to_orchestrator())
    print("\n2. Add to StaticPageAgent:")
    print(add_validation_to_static_page_agent())


if __name__ == "__main__":
    main()
