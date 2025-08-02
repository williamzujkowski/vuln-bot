#!/usr/bin/env python3
"""
Setup Great Expectations validation for the vuln-bot data pipeline.
Creates expectation suites for each stage of data processing.
"""

import json
from pathlib import Path
from typing import Dict, Any, List

# Make Great Expectations optional with better handling
try:
    import great_expectations as ge
    from great_expectations.core import ExpectationConfiguration, ExpectationSuite
    from great_expectations.core.batch import BatchRequest
    from great_expectations.data_context import BaseDataContext
    from great_expectations.data_context.types.base import (
        DataContextConfig,
        DatasourceConfig,
        FilesystemStoreBackendDefaults,
    )
    HAS_GREAT_EXPECTATIONS = True
except (ImportError, ValueError) as e:
    print(f"⚠️  Great Expectations not available: {e}")
    print("   Install with: pip install great-expectations")
    HAS_GREAT_EXPECTATIONS = False
    ge = None


class VulnBotDataValidator:
    """Data validation using Great Expectations for vuln-bot pipeline."""
    
    def __init__(self, project_root: Path = None):
        if not HAS_GREAT_EXPECTATIONS:
            raise ImportError("Great Expectations is required for data validation")
            
        self.project_root = project_root or Path.cwd()
        self.gx_directory = self.project_root / "great_expectations"
        self.context = None
        
    def setup_data_context(self):
        """Initialize Great Expectations data context."""
        # Create GX directory structure
        self.gx_directory.mkdir(exist_ok=True)
        
        # Configure data context
        data_context_config = DataContextConfig(
            datasources={
                "vuln_data": DatasourceConfig(
                    class_name="Datasource",
                    execution_engine={
                        "class_name": "PandasExecutionEngine",
                    },
                    data_connectors={
                        "json_connector": {
                            "class_name": "ConfiguredAssetFilesystemDataConnector",
                            "base_directory": str(self.project_root),
                            "assets": {
                                "cve_raw": {
                                    "pattern": r"api/vulns/index\.json",
                                },
                                "cve_enriched": {
                                    "pattern": r"api/vulns/vulns-.*\.json",
                                },
                                "cve_pages": {
                                    "pattern": r"src/cves/CVE-.*\.md",
                                },
                            },
                        },
                    },
                ),
            },
            stores=FilesystemStoreBackendDefaults(root_directory=str(self.gx_directory)),
        )
        
        self.context = BaseDataContext(project_config=data_context_config)
        return self.context
    
    def create_cve_ingestion_suite(self) -> ExpectationSuite:
        """Create expectation suite for raw CVE data ingestion."""
        suite_name = "cve_ingestion_validation"
        
        suite = self.context.create_expectation_suite(
            expectation_suite_name=suite_name,
            overwrite_existing=True,
        )
        
        # Core field expectations
        expectations = [
            ExpectationConfiguration(
                expectation_type="expect_column_to_exist",
                kwargs={"column": "cveId"},
            ),
            ExpectationConfiguration(
                expectation_type="expect_column_values_to_match_regex",
                kwargs={
                    "column": "cveId",
                    "regex": r"^CVE-\d{4}-\d{4,}$",
                },
            ),
            ExpectationConfiguration(
                expectation_type="expect_column_values_to_not_be_null",
                kwargs={"column": "cveId"},
            ),
            ExpectationConfiguration(
                expectation_type="expect_column_values_to_be_unique",
                kwargs={"column": "cveId"},
            ),
            # Severity validation
            ExpectationConfiguration(
                expectation_type="expect_column_values_to_be_in_set",
                kwargs={
                    "column": "severity",
                    "value_set": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
                },
            ),
            # Score validations
            ExpectationConfiguration(
                expectation_type="expect_column_values_to_be_between",
                kwargs={
                    "column": "cvssScore",
                    "min_value": 0.0,
                    "max_value": 10.0,
                    "allow_cross_type_comparisons": True,
                },
            ),
            ExpectationConfiguration(
                expectation_type="expect_column_values_to_be_between",
                kwargs={
                    "column": "epssScore",
                    "min_value": 0.0,
                    "max_value": 100.0,
                    "allow_cross_type_comparisons": True,
                },
            ),
            ExpectationConfiguration(
                expectation_type="expect_column_values_to_be_between",
                kwargs={
                    "column": "riskScore",
                    "min_value": 0,
                    "max_value": 100,
                    "allow_cross_type_comparisons": True,
                },
            ),
            # Date format validation
            ExpectationConfiguration(
                expectation_type="expect_column_values_to_match_strftime_format",
                kwargs={
                    "column": "publishedDate",
                    "strftime_format": "%Y-%m-%dT%H:%M:%S%z",
                },
            ),
            # Required fields
            ExpectationConfiguration(
                expectation_type="expect_column_to_exist",
                kwargs={"column": "title"},
            ),
            ExpectationConfiguration(
                expectation_type="expect_column_to_exist",
                kwargs={"column": "vendors"},
            ),
            ExpectationConfiguration(
                expectation_type="expect_column_to_exist",
                kwargs={"column": "products"},
            ),
        ]
        
        for expectation in expectations:
            suite.add_expectation(expectation_configuration=expectation)
        
        self.context.save_expectation_suite(suite)
        return suite
    
    def create_enrichment_suite(self) -> ExpectationSuite:
        """Create expectation suite for enriched CVE data."""
        suite_name = "cve_enrichment_validation"
        
        suite = self.context.create_expectation_suite(
            expectation_suite_name=suite_name,
            overwrite_existing=True,
        )
        
        # Additional fields from enrichment
        expectations = [
            # All base expectations from ingestion
            ExpectationConfiguration(
                expectation_type="expect_column_to_exist",
                kwargs={"column": "cveId"},
            ),
            # Enrichment-specific fields
            ExpectationConfiguration(
                expectation_type="expect_column_to_exist",
                kwargs={"column": "exploitationStatus"},
            ),
            ExpectationConfiguration(
                expectation_type="expect_column_values_to_be_in_set",
                kwargs={
                    "column": "exploitationStatus",
                    "value_set": ["ACTIVE", "POC", "UNPROVEN", "UNKNOWN"],
                },
            ),
            # Tags should be a list
            ExpectationConfiguration(
                expectation_type="expect_column_values_to_be_of_type",
                kwargs={
                    "column": "tags",
                    "type_": "list",
                },
            ),
            # References validation
            ExpectationConfiguration(
                expectation_type="expect_column_to_exist",
                kwargs={"column": "references"},
            ),
            # Affected products/vendors should be lists
            ExpectationConfiguration(
                expectation_type="expect_column_values_to_be_of_type",
                kwargs={
                    "column": "affected_vendors",
                    "type_": "list",
                },
            ),
            ExpectationConfiguration(
                expectation_type="expect_column_values_to_be_of_type",
                kwargs={
                    "column": "affected_products",
                    "type_": "list",
                },
            ),
        ]
        
        for expectation in expectations:
            suite.add_expectation(expectation_configuration=expectation)
        
        self.context.save_expectation_suite(suite)
        return suite
    
    def create_static_page_suite(self) -> ExpectationSuite:
        """Create expectation suite for static CVE pages."""
        suite_name = "cve_static_page_validation"
        
        suite = self.context.create_expectation_suite(
            expectation_suite_name=suite_name,
            overwrite_existing=True,
        )
        
        # Markdown frontmatter validation
        expectations = [
            ExpectationConfiguration(
                expectation_type="expect_column_to_exist",
                kwargs={"column": "layout"},
            ),
            ExpectationConfiguration(
                expectation_type="expect_column_values_to_equal",
                kwargs={
                    "column": "layout",
                    "value": "cve-detail",
                },
            ),
            ExpectationConfiguration(
                expectation_type="expect_column_to_exist",
                kwargs={"column": "cve_id"},
            ),
            ExpectationConfiguration(
                expectation_type="expect_column_to_exist",
                kwargs={"column": "title"},
            ),
            ExpectationConfiguration(
                expectation_type="expect_column_to_exist",
                kwargs={"column": "severity"},
            ),
            ExpectationConfiguration(
                expectation_type="expect_column_to_exist",
                kwargs={"column": "cvss_score"},
            ),
            ExpectationConfiguration(
                expectation_type="expect_column_to_exist",
                kwargs={"column": "published_date"},
            ),
            # Content validation
            ExpectationConfiguration(
                expectation_type="expect_column_values_to_not_be_null",
                kwargs={"column": "description"},
            ),
            ExpectationConfiguration(
                expectation_type="expect_column_value_lengths_to_be_between",
                kwargs={
                    "column": "description",
                    "min_value": 10,
                    "max_value": 500,  # Frontmatter truncates
                },
            ),
        ]
        
        for expectation in expectations:
            suite.add_expectation(expectation_configuration=expectation)
        
        self.context.save_expectation_suite(suite)
        return suite
    
    def validate_data(self, data_path: Path, suite_name: str) -> Dict[str, Any]:
        """Validate data against an expectation suite."""
        # Create batch request
        batch_request = BatchRequest(
            datasource_name="vuln_data",
            data_connector_name="json_connector",
            data_asset_name=self._get_asset_name(data_path),
        )
        
        # Get validator
        validator = self.context.get_validator(
            batch_request=batch_request,
            expectation_suite_name=suite_name,
        )
        
        # Run validation
        results = validator.validate()
        
        return {
            "success": results.success,
            "results": results.to_json_dict(),
            "statistics": results.statistics,
        }
    
    def _get_asset_name(self, data_path: Path) -> str:
        """Determine asset name from file path."""
        if "index.json" in str(data_path):
            return "cve_raw"
        elif "vulns-" in str(data_path):
            return "cve_enriched"
        elif data_path.suffix == ".md":
            return "cve_pages"
        else:
            raise ValueError(f"Unknown data type for path: {data_path}")
    
    def setup_all_suites(self):
        """Create all validation suites."""
        print("🔧 Setting up Great Expectations validation suites...")
        
        self.setup_data_context()
        
        # Create suites
        self.create_cve_ingestion_suite()
        print("  ✅ Created CVE ingestion validation suite")
        
        self.create_enrichment_suite()
        print("  ✅ Created CVE enrichment validation suite")
        
        self.create_static_page_suite()
        print("  ✅ Created static page validation suite")
        
        # Save checkpoint
        checkpoint_config = {
            "name": "vuln_bot_checkpoint",
            "config_version": 1,
            "class_name": "SimpleCheckpoint",
            "run_name_template": "%Y%m%d-%H%M%S-vuln-bot-validation",
            "expectation_suite_names": [
                "cve_ingestion_validation",
                "cve_enrichment_validation",
                "cve_static_page_validation",
            ],
        }
        
        self.context.add_checkpoint(**checkpoint_config)
        print("  ✅ Created validation checkpoint")
        
        print("\n✨ Great Expectations setup complete!")
        print(f"   Configuration saved to: {self.gx_directory}")


def main():
    """Setup Great Expectations for vuln-bot."""
    if not HAS_GREAT_EXPECTATIONS:
        print("❌ Great Expectations not available. Install with:")
        print("   pip install great-expectations")
        return
    
    validator = VulnBotDataValidator()
    validator.setup_all_suites()
    
    # Example validation
    print("\n📊 Example validation:")
    api_index = Path("api/vulns/index.json")
    if api_index.exists():
        results = validator.validate_data(api_index, "cve_ingestion_validation")
        print(f"   Validation success: {results['success']}")
        print(f"   Statistics: {results['statistics']}")


if __name__ == "__main__":
    main()