"""Great Expectations integration for vulnerability data quality validation."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import structlog

try:
    import great_expectations as gx
    from great_expectations.core.batch import RuntimeBatchRequest
    from great_expectations.core.expectation_configuration import ExpectationConfiguration
    
    HAS_GX = True
except ImportError:
    HAS_GX = False

from scripts.models import Vulnerability
from scripts.quality.validator import DataQualityValidator


class GreatExpectationsValidator:
    """Validates vulnerability data using Great Expectations."""
    
    def __init__(self, base_dir: Optional[Path] = None):
        """Initialize GX validator.
        
        Args:
            base_dir: Base directory for GX context (defaults to project root)
        """
        self.logger = structlog.get_logger(self.__class__.__name__)
        
        if not HAS_GX:
            self.logger.warning(
                "Great Expectations not installed. Install with: uv pip install great-expectations"
            )
            self.context = None
            return
            
        self.base_dir = base_dir or Path(__file__).parent.parent.parent
        self.gx_dir = self.base_dir / "great_expectations"
        
        # Initialize or get existing context
        self.context = self._init_context()
        
        # Create expectations suites
        self._create_expectation_suites()
        
    def _init_context(self) -> Optional[Any]:
        """Initialize Great Expectations context."""
        try:
            # Try to get existing context
            context = gx.get_context(context_root_dir=str(self.gx_dir))
            self.logger.info("Using existing GX context")
        except Exception:
            # Create new context
            try:
                context = gx.data_context.DataContext.create(
                    project_root_dir=str(self.base_dir)
                )
                self.logger.info("Created new GX context")
            except Exception as e:
                self.logger.error(f"Failed to create GX context: {e}")
                return None
                
        return context
        
    def _create_expectation_suites(self):
        """Create expectation suites for vulnerability data."""
        if not self.context:
            return
            
        # Core vulnerability expectations
        try:
            core_suite = self.context.add_or_update_expectation_suite(
                expectation_suite_name="vulnerability_core"
            )
            
            # CVE ID validation
            core_suite.add_expectation(
                ExpectationConfiguration(
                    expectation_type="expect_column_values_to_not_be_null",
                    kwargs={"column": "cve_id"}
                )
            )
            
            core_suite.add_expectation(
                ExpectationConfiguration(
                    expectation_type="expect_column_values_to_match_regex",
                    kwargs={
                        "column": "cve_id",
                        "regex": r"^CVE-\d{4}-\d{4,}$"
                    }
                )
            )
            
            # Severity validation
            core_suite.add_expectation(
                ExpectationConfiguration(
                    expectation_type="expect_column_values_to_be_in_set",
                    kwargs={
                        "column": "severity",
                        "value_set": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                    }
                )
            )
            
            # Score validation
            core_suite.add_expectation(
                ExpectationConfiguration(
                    expectation_type="expect_column_values_to_be_between",
                    kwargs={
                        "column": "cvss_base_score",
                        "min_value": 0.0,
                        "max_value": 10.0,
                        "mostly": 0.95  # Allow 5% null values
                    }
                )
            )
            
            core_suite.add_expectation(
                ExpectationConfiguration(
                    expectation_type="expect_column_values_to_be_between",
                    kwargs={
                        "column": "epss_probability",
                        "min_value": 0.0,
                        "max_value": 100.0,
                        "mostly": 0.90  # Allow 10% null values
                    }
                )
            )
            
            # Risk score validation
            core_suite.add_expectation(
                ExpectationConfiguration(
                    expectation_type="expect_column_values_to_be_between",
                    kwargs={
                        "column": "risk_score",
                        "min_value": 0,
                        "max_value": 100
                    }
                )
            )
            
            # Save suite
            self.context.save_expectation_suite(core_suite)
            self.logger.info("Created vulnerability_core expectation suite")
            
        except Exception as e:
            self.logger.error(f"Failed to create expectation suites: {e}")
            
    def validate_vulnerabilities(
        self, 
        vulnerabilities: List[Vulnerability],
        suite_name: str = "vulnerability_core"
    ) -> Dict[str, Any]:
        """Validate a list of vulnerabilities using Great Expectations.
        
        Args:
            vulnerabilities: List of vulnerabilities to validate
            suite_name: Name of expectation suite to use
            
        Returns:
            Validation results dictionary
        """
        if not self.context or not HAS_GX:
            # Fallback to basic validator
            basic_validator = DataQualityValidator()
            results = []
            for vuln in vulnerabilities:
                is_valid, errors, scores = basic_validator.validate_vulnerability(vuln)
                results.append({
                    "cve_id": vuln.cve_id,
                    "valid": is_valid,
                    "errors": errors,
                    "scores": scores
                })
            return {
                "success": all(r["valid"] for r in results),
                "results": results,
                "validator": "basic"
            }
            
        # Convert vulnerabilities to DataFrame
        data = []
        for vuln in vulnerabilities:
            data.append({
                "cve_id": vuln.cve_id,
                "severity": vuln.severity.value if vuln.severity else None,
                "cvss_base_score": vuln.cvss_base_score,
                "epss_probability": vuln.epss_probability,
                "risk_score": vuln.risk_score,
                "vendor": vuln.vendor,
                "product": vuln.product,
                "attack_vector": vuln.attack_vector,
                "attack_complexity": vuln.attack_complexity,
                "published_date": vuln.published_date.isoformat() if vuln.published_date else None,
                "description": vuln.description,
                "references": len(vuln.references) if vuln.references else 0
            })
            
        df = pd.DataFrame(data)
        
        # Create batch request
        batch_request = RuntimeBatchRequest(
            datasource_name="pandas_datasource",
            data_connector_name="runtime_data_connector",
            data_asset_name="vulnerability_batch",
            runtime_parameters={"batch_data": df},
            batch_identifiers={
                "timestamp": datetime.now().isoformat(),
                "count": len(df)
            }
        )
        
        # Get validator
        try:
            # Add datasource if it doesn't exist
            if "pandas_datasource" not in self.context.list_datasources():
                self.context.add_datasource(
                    name="pandas_datasource",
                    class_name="PandasDatasource",
                    module_name="great_expectations.datasource",
                    data_connectors={
                        "runtime_data_connector": {
                            "class_name": "RuntimeDataConnector",
                            "module_name": "great_expectations.datasource.data_connector"
                        }
                    }
                )
                
            validator = self.context.get_validator(
                batch_request=batch_request,
                expectation_suite_name=suite_name
            )
            
            # Run validation
            results = validator.validate()
            
            # Build detailed report
            report = {
                "success": results.success,
                "total_expectations": results.statistics["evaluated_expectations"],
                "successful_expectations": results.statistics["successful_expectations"],
                "failed_expectations": results.statistics["unsuccessful_expectations"],
                "validator": "great_expectations",
                "timestamp": datetime.now().isoformat(),
                "data_quality_metrics": self._calculate_quality_metrics(df, results)
            }
            
            # Add failed expectation details
            if not results.success:
                report["failures"] = []
                for result in results.results:
                    if not result.success:
                        report["failures"].append({
                            "expectation": result.expectation_config.expectation_type,
                            "column": result.expectation_config.kwargs.get("column"),
                            "details": result.result
                        })
                        
            return report
            
        except Exception as e:
            self.logger.error(f"Validation failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "validator": "great_expectations"
            }
            
    def _calculate_quality_metrics(self, df: pd.DataFrame, results: Any) -> Dict[str, float]:
        """Calculate data quality metrics from validation results."""
        metrics = {
            "completeness": {},
            "validity": {},
            "consistency": {}
        }
        
        # Completeness metrics
        for col in ["cve_id", "severity", "cvss_base_score", "epss_probability", "vendor", "product"]:
            if col in df.columns:
                metrics["completeness"][col] = 1.0 - (df[col].isna().sum() / len(df))
                
        # Validity metrics
        if "vendor" in df.columns:
            metrics["validity"]["vendor_not_unknown"] = 1.0 - ((df["vendor"] == "Unknown").sum() / len(df))
            
        if "product" in df.columns:
            metrics["validity"]["product_not_unknown"] = 1.0 - ((df["product"] == "Unknown").sum() / len(df))
            
        # Overall quality score
        all_scores = []
        for category in metrics.values():
            all_scores.extend(category.values())
            
        metrics["overall_quality_score"] = sum(all_scores) / len(all_scores) if all_scores else 0.0
        
        return metrics
        
    def create_checkpoint(self, name: str, batch_request_config: Dict[str, Any]) -> Optional[Any]:
        """Create a validation checkpoint for automated runs.
        
        Args:
            name: Checkpoint name
            batch_request_config: Configuration for batch requests
            
        Returns:
            Checkpoint object or None
        """
        if not self.context:
            return None
            
        try:
            checkpoint = self.context.add_checkpoint(
                name=name,
                config={
                    "validations": [
                        {
                            "batch_request": batch_request_config,
                            "expectation_suite_name": "vulnerability_core"
                        }
                    ],
                    "action_list": [
                        {
                            "name": "store_validation_result",
                            "action": {"class_name": "StoreValidationResultAction"}
                        },
                        {
                            "name": "update_data_docs",
                            "action": {"class_name": "UpdateDataDocsAction"}
                        }
                    ]
                }
            )
            
            self.logger.info(f"Created checkpoint: {name}")
            return checkpoint
            
        except Exception as e:
            self.logger.error(f"Failed to create checkpoint: {e}")
            return None
            
    def generate_data_docs(self):
        """Generate and open data documentation."""
        if not self.context:
            return
            
        try:
            self.context.build_data_docs()
            self.logger.info("Generated data documentation")
        except Exception as e:
            self.logger.error(f"Failed to generate data docs: {e}")
            
    def profile_vulnerability_data(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Profile vulnerability data to suggest expectations.
        
        Args:
            vulnerabilities: List of vulnerabilities to profile
            
        Returns:
            Profiling results and suggested expectations
        """
        if not HAS_GX:
            return {"error": "Great Expectations not installed"}
            
        # Convert to DataFrame
        df = pd.DataFrame([v.to_dict() for v in vulnerabilities])
        
        profile = {
            "row_count": len(df),
            "column_count": len(df.columns),
            "columns": {}
        }
        
        # Profile each column
        for col in df.columns:
            col_profile = {
                "dtype": str(df[col].dtype),
                "null_count": int(df[col].isna().sum()),
                "null_percentage": float(df[col].isna().sum() / len(df) * 100),
                "unique_count": int(df[col].nunique()),
                "unique_percentage": float(df[col].nunique() / len(df) * 100)
            }
            
            # Add statistics for numeric columns
            if df[col].dtype in ["int64", "float64"]:
                col_profile.update({
                    "min": float(df[col].min()) if not df[col].isna().all() else None,
                    "max": float(df[col].max()) if not df[col].isna().all() else None,
                    "mean": float(df[col].mean()) if not df[col].isna().all() else None,
                    "std": float(df[col].std()) if not df[col].isna().all() else None
                })
                
            # Sample values for categorical columns
            if df[col].dtype == "object":
                value_counts = df[col].value_counts().head(10)
                col_profile["top_values"] = {
                    str(k): int(v) for k, v in value_counts.items()
                }
                
            profile["columns"][col] = col_profile
            
        # Suggest expectations based on profile
        profile["suggested_expectations"] = self._suggest_expectations(df, profile)
        
        return profile
        
    def _suggest_expectations(self, df: pd.DataFrame, profile: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Suggest expectations based on data profile."""
        suggestions = []
        
        for col, col_profile in profile["columns"].items():
            # Suggest not-null expectations for low null columns
            if col_profile["null_percentage"] < 5:
                suggestions.append({
                    "column": col,
                    "expectation": "expect_column_values_to_not_be_null",
                    "reason": f"Column has only {col_profile['null_percentage']:.1f}% null values"
                })
                
            # Suggest uniqueness expectations
            if col_profile["unique_percentage"] > 95 and col in ["cve_id"]:
                suggestions.append({
                    "column": col,
                    "expectation": "expect_column_values_to_be_unique",
                    "reason": f"Column has {col_profile['unique_percentage']:.1f}% unique values"
                })
                
            # Suggest set expectations for categorical columns
            if col in ["severity", "attack_vector", "attack_complexity"] and "top_values" in col_profile:
                if len(col_profile["top_values"]) < 10:
                    suggestions.append({
                        "column": col,
                        "expectation": "expect_column_values_to_be_in_set",
                        "value_set": list(col_profile["top_values"].keys()),
                        "reason": f"Column has only {len(col_profile['top_values'])} distinct values"
                    })
                    
        return suggestions