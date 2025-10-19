"""
Data Validation Agent for ensuring data quality at all pipeline stages.
Implements validation similar to Great Expectations without the dependency.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import structlog

from scripts.agents.base_agent import BaseAgent

logger = structlog.get_logger()


class DataValidationAgent(BaseAgent):
    """Agent for comprehensive data validation throughout the pipeline."""

    def __init__(self):
        super().__init__(
            name="DataValidationAgent"
        )
        self.validation_results = {
            "passed": 0,
            "failed": 0,
            "warnings": 0,
            "validations": []
        }

    async def execute(self, **kwargs) -> Dict[str, Any]:  # noqa: ARG002
        """Execute data validation task (async compatibility)."""
        # This method is required by BaseAgent but not used in the current sync implementation
        return self.validation_results

    def get_dependencies(self) -> set:
        """Get validation dependencies."""
        # Return empty set - validation doesn't depend on specific files
        return set()

    def validate_raw_cve_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate raw CVE data at ingestion.

        Args:
            data: Raw CVE data

        Returns:
            Validation results
        """
        results = {
            "stage": "raw_ingestion",
            "timestamp": datetime.utcnow().isoformat(),
            "passed": True,
            "failures": [],
            "warnings": []
        }

        # Required fields validation
        # Note: Some data formats use 'title' instead of 'description'
        required_fields = {
            "cveId": True,  # Always required
            "publishedDate": True,  # Always required
            "severity": True,  # Always required
        }

        for field, is_required in required_fields.items():
            if is_required and (field not in data or not data[field]):
                results["failures"].append(f"Missing required field: {field}")
                results["passed"] = False

        # Check for description OR title (at least one should be present)
        if "description" not in data and "title" not in data:
            results["failures"].append("Missing both 'description' and 'title' fields")
            results["passed"] = False
        elif not data.get("description") and not data.get("title"):
            results["failures"].append("Both 'description' and 'title' fields are empty")
            results["passed"] = False

        # CVE ID format validation
        if "cveId" in data:
            cve_id = data["cveId"]
            if not self._validate_cve_id_format(cve_id):
                results["failures"].append(f"Invalid CVE ID format: {cve_id}")
                results["passed"] = False

        # Date format validation
        date_fields = ["publishedDate", "lastModifiedDate"]
        for field in date_fields:
            if field in data and data[field]:  # noqa: SIM102
                if not self._validate_date_format(data[field]):
                    results["failures"].append(f"Invalid date format for {field}: {data[field]}")
                    results["passed"] = False

        # Severity validation
        if "severity" in data:
            valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
            if data["severity"] not in valid_severities:
                results["failures"].append(f"Invalid severity: {data['severity']}")
                results["passed"] = False

        # CVSS validation
        if "cvssMetrics" in data and data["cvssMetrics"]:
            for metric in data["cvssMetrics"]:
                if "baseScore" in metric:
                    score = metric["baseScore"]
                    if not isinstance(score, (int, float)) or score < 0 or score > 10:
                        results["warnings"].append(f"Invalid CVSS score: {score}")

        self._record_validation(results)
        return results

    def validate_epss_filtered_data(self, data: Dict[str, Any], min_epss: float = 0.6) -> Dict[str, Any]:
        """
        Validate data after EPSS filtering.

        Args:
            data: Filtered vulnerability data
            min_epss: Minimum EPSS threshold

        Returns:
            Validation results
        """
        results = {
            "stage": "epss_filtering",
            "timestamp": datetime.utcnow().isoformat(),
            "passed": True,
            "failures": [],
            "warnings": []
        }

        # Validate EPSS score meets threshold
        epss_data = data.get("epss", {})
        epss_score = epss_data.get("score", 0)

        if epss_score < min_epss:
            results["failures"].append(
                f"EPSS score {epss_score} below threshold {min_epss} for {data.get('cveId')}"
            )
            results["passed"] = False

        # Validate EPSS data structure
        if not epss_data:
            results["failures"].append("Missing EPSS data")
            results["passed"] = False
        else:
            if "score" not in epss_data:
                results["failures"].append("Missing EPSS score")
                results["passed"] = False
            if "percentile" not in epss_data:
                results["warnings"].append("Missing EPSS percentile")

        # Validate risk score
        if "riskScore" in data:
            risk_score = data["riskScore"]
            if not isinstance(risk_score, (int, float)) or risk_score < 0 or risk_score > 100:
                results["warnings"].append(f"Invalid risk score: {risk_score}")

        self._record_validation(results)
        return results

    def validate_enriched_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate data after enrichment.

        Args:
            data: Enriched vulnerability data

        Returns:
            Validation results
        """
        results = {
            "stage": "enrichment",
            "timestamp": datetime.utcnow().isoformat(),
            "passed": True,
            "failures": [],
            "warnings": []
        }

        # Validate enrichments structure
        if "enrichments" in data:
            enrichments = data["enrichments"]

            # Validate CISA KEV enrichment
            if "cisa_kev" in enrichments:
                kev_data = enrichments["cisa_kev"]
                if "isKnownExploited" not in kev_data:
                    results["warnings"].append("Missing isKnownExploited in CISA KEV data")
                if "dateAdded" in kev_data and not self._validate_date_format(kev_data["dateAdded"]):
                    results["warnings"].append(f"Invalid date format in KEV dateAdded: {kev_data['dateAdded']}")

            # Validate deps.dev enrichment
            if "deps_dev" in enrichments:
                deps_data = enrichments["deps_dev"]
                if "packages" not in deps_data:
                    results["warnings"].append("Missing packages in deps.dev data")

            # Validate exploit availability
            if "exploit_availability" in enrichments:
                exploit_data = enrichments["exploit_availability"]
                if "has_exploit" not in exploit_data:
                    results["warnings"].append("Missing has_exploit flag")

        # Validate references
        if "references" in data:
            for i, ref in enumerate(data["references"]):
                if not isinstance(ref, dict):
                    results["failures"].append(f"Reference {i} is not a dictionary")
                    results["passed"] = False
                elif "url" not in ref:
                    results["warnings"].append(f"Reference {i} missing URL")
                else:
                    # Validate reference has been categorized
                    if "category" not in ref:
                        results["warnings"].append(f"Reference {i} not categorized")

        # Validate exploitation status
        if "exploitationStatus" in data:
            valid_statuses = ["UNKNOWN", "KNOWN_EXPLOITED", "EXPLOIT_AVAILABLE"]
            if data["exploitationStatus"] not in valid_statuses:
                results["warnings"].append(f"Invalid exploitation status: {data['exploitationStatus']}")

        self._record_validation(results)
        return results

    def validate_published_data(self, file_path: Path) -> Dict[str, Any]:
        """
        Validate published JSON files.

        Args:
            file_path: Path to published JSON file

        Returns:
            Validation results
        """
        results = {
            "stage": "publication",
            "timestamp": datetime.utcnow().isoformat(),
            "file": str(file_path),
            "passed": True,
            "failures": [],
            "warnings": []
        }

        try:
            with open(file_path) as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            results["failures"].append(f"Invalid JSON: {e}")
            results["passed"] = False
            self._record_validation(results)
            return results
        except Exception as e:
            results["failures"].append(f"Failed to read file: {e}")
            results["passed"] = False
            self._record_validation(results)
            return results

        # Validate structure based on file type
        if "index.json" in file_path.name:
            if "vulnerabilities" not in data:
                results["failures"].append("Missing vulnerabilities array in index")
                results["passed"] = False
            else:
                # Validate no duplicates
                cve_ids = [v.get("cveId") for v in data["vulnerabilities"] if "cveId" in v]
                if len(cve_ids) != len(set(cve_ids)):
                    results["failures"].append("Duplicate CVE IDs found in index")
                    results["passed"] = False

        elif "vulns-" in file_path.name:
            # Chunk file validation
            required_fields = ["chunk", "count", "generated", "vulnerabilities"]
            for field in required_fields:
                if field not in data:
                    results["failures"].append(f"Missing required field in chunk: {field}")
                    results["passed"] = False

            if "count" in data and "vulnerabilities" in data:  # noqa: SIM102
                if data["count"] != len(data["vulnerabilities"]):
                    results["warnings"].append(
                        f"Count mismatch: reported {data['count']}, actual {len(data['vulnerabilities'])}"
                    )

        self._record_validation(results)
        return results

    def validate_pipeline_consistency(self,
                                    raw_count: int,
                                    filtered_count: int,
                                    published_count: int) -> Dict[str, Any]:
        """
        Validate consistency across pipeline stages.

        Args:
            raw_count: Number of raw CVEs ingested
            filtered_count: Number after EPSS filtering
            published_count: Number in published data

        Returns:
            Validation results
        """
        results = {
            "stage": "pipeline_consistency",
            "timestamp": datetime.utcnow().isoformat(),
            "passed": True,
            "failures": [],
            "warnings": []
        }

        # Validate counts make sense
        if filtered_count > raw_count:
            results["failures"].append(
                f"Filtered count ({filtered_count}) exceeds raw count ({raw_count})"
            )
            results["passed"] = False

        if published_count != filtered_count:
            results["warnings"].append(
                f"Published count ({published_count}) differs from filtered count ({filtered_count})"
            )

        # Calculate reduction percentage
        if raw_count > 0:
            reduction_pct = (1 - filtered_count / raw_count) * 100
            results["metrics"] = {
                "raw_count": raw_count,
                "filtered_count": filtered_count,
                "published_count": published_count,
                "reduction_percentage": f"{reduction_pct:.1f}%"
            }

        self._record_validation(results)
        return results

    def generate_validation_report(self) -> str:
        """Generate comprehensive validation report."""
        passed = self.validation_results["passed"]
        failed = self.validation_results["failed"]
        warnings = self.validation_results["warnings"]
        total = passed + failed

        report = f"""
Data Validation Report
=====================

Summary:
--------
- Total validations: {total}
- Passed: {passed} ({(passed/total*100):.1f}%)
- Failed: {failed} ({(failed/total*100):.1f}%)
- Warnings: {warnings}

Validation Details:
------------------
"""

        # Group by stage
        stages = {}
        for validation in self.validation_results["validations"]:
            stage = validation["stage"]
            if stage not in stages:
                stages[stage] = {"passed": 0, "failed": 0, "warnings": 0}

            if validation["passed"]:
                stages[stage]["passed"] += 1
            else:
                stages[stage]["failed"] += 1
            stages[stage]["warnings"] += len(validation.get("warnings", []))

        for stage, counts in stages.items():
            report += f"\n{stage}:\n"
            report += f"  ✓ Passed: {counts['passed']}\n"
            report += f"  ✗ Failed: {counts['failed']}\n"
            report += f"  ⚠ Warnings: {counts['warnings']}\n"

        # Recent failures
        recent_failures = [
            v for v in self.validation_results["validations"][-10:]
            if not v["passed"]
        ]

        if recent_failures:
            report += "\nRecent Failures:\n"
            for failure in recent_failures:
                report += f"- {failure['stage']}: {', '.join(failure['failures'])}\n"

        report += """
Recommendations:
----------------
1. Address all validation failures before deployment
2. Investigate warnings for potential data quality issues
3. Monitor pipeline consistency metrics
4. Run validation at each pipeline stage
"""

        return report

    def _validate_cve_id_format(self, cve_id: str) -> bool:
        """Validate CVE ID format."""
        import re
        pattern = r'^CVE-\d{4}-\d{4,}$'
        return bool(re.match(pattern, cve_id))

    def _validate_date_format(self, date_str: str) -> bool:
        """Validate ISO date format."""
        try:
            datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            return True
        except Exception:
            return False

    def _record_validation(self, results: Dict[str, Any]):
        """Record validation results."""
        self.validation_results["validations"].append(results)

        if results["passed"]:
            self.validation_results["passed"] += 1
        else:
            self.validation_results["failed"] += 1

        self.validation_results["warnings"] += len(results.get("warnings", []))
