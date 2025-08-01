"""Validator agent for vulnerability data integrity and consistency."""

import structlog
from typing import Any, Dict, List, Optional, Set

from scripts.models import Vulnerability, VulnerabilityBatch


class ValidatorAgent:
    """Agent responsible for data validation and integrity checks."""

    def __init__(self):
        self.logger = structlog.get_logger(self.__class__.__name__)

    async def validate_vulnerabilities(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Validate vulnerability data structure and content.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Validation results with errors and warnings
        """
        self.logger.info(
            "Starting vulnerability validation", count=len(vulnerabilities)
        )

        errors = []
        warnings = []
        valid_vulns = []

        for idx, vuln in enumerate(vulnerabilities):
            vuln_errors = []
            vuln_warnings = []

            # Required field validation
            if not vuln.get("cve_id"):
                vuln_errors.append(f"Missing CVE ID at index {idx}")
            elif not self._is_valid_cve_id(vuln["cve_id"]):
                vuln_errors.append(f"Invalid CVE ID format: {vuln.get('cve_id')}")

            # Severity validation
            if not vuln.get("severity"):
                vuln_warnings.append(f"Missing severity for {vuln.get('cve_id', f'index {idx}')}")
            elif vuln["severity"] not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                vuln_errors.append(f"Invalid severity: {vuln['severity']} for {vuln.get('cve_id')}")

            # Score validation
            if "cvss_base_score" in vuln and vuln["cvss_base_score"] is not None:
                if not (0.0 <= vuln["cvss_base_score"] <= 10.0):
                    vuln_errors.append(f"Invalid CVSS score: {vuln['cvss_base_score']} for {vuln.get('cve_id')}")

            if "epss_probability" in vuln and vuln["epss_probability"] is not None:
                if not (0.0 <= vuln["epss_probability"] <= 100.0):
                    vuln_errors.append(f"Invalid EPSS probability: {vuln['epss_probability']} for {vuln.get('cve_id')}")

            # Collect errors and warnings
            if vuln_errors:
                errors.extend(vuln_errors)
            else:
                valid_vulns.append(vuln)
                
            if vuln_warnings:
                warnings.extend(vuln_warnings)

        result = {
            "success": len(errors) == 0,
            "total_processed": len(vulnerabilities),
            "valid_count": len(valid_vulns),
            "error_count": len(errors),
            "warning_count": len(warnings),
            "errors": errors[:10],  # Limit to first 10 errors
            "warnings": warnings[:10],  # Limit to first 10 warnings
            "valid_vulnerabilities": valid_vulns
        }

        self.logger.info(
            "Validation complete",
            valid=len(valid_vulns),
            errors=len(errors),
            warnings=len(warnings)
        )

        return result

    async def check_duplicates(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Check for duplicate vulnerabilities.

        Args:
            vulnerabilities: List of vulnerabilities to check

        Returns:
            Duplicate analysis results
        """
        seen_cves: Dict[str, List[int]] = {}
        duplicates = []

        for idx, vuln in enumerate(vulnerabilities):
            cve_id = vuln.get("cve_id")
            if cve_id:
                if cve_id in seen_cves:
                    duplicates.append({
                        "cve_id": cve_id,
                        "indices": seen_cves[cve_id] + [idx]
                    })
                    seen_cves[cve_id].append(idx)
                else:
                    seen_cves[cve_id] = [idx]

        return {
            "has_duplicates": len(duplicates) > 0,
            "duplicate_count": len(duplicates),
            "duplicates": duplicates[:10],  # Limit output
            "unique_count": len(seen_cves)
        }

    async def validate_batch_integrity(
        self, batch: VulnerabilityBatch
    ) -> Dict[str, Any]:
        """Validate integrity of a vulnerability batch.

        Args:
            batch: VulnerabilityBatch to validate

        Returns:
            Batch integrity validation results
        """
        issues = []
        
        # Check batch metadata
        if not batch.source:
            issues.append("Missing batch source")
            
        if not batch.fetched_at:
            issues.append("Missing fetch timestamp")

        # Check consistency
        actual_count = len(batch.vulnerabilities)
        if batch.count != actual_count:
            issues.append(f"Batch count mismatch: reported {batch.count}, actual {actual_count}")

        # Validate each vulnerability
        validation_result = await self.validate_vulnerabilities(
            [v.to_dict() for v in batch.vulnerabilities]
        )

        return {
            "success": len(issues) == 0 and validation_result["success"],
            "batch_issues": issues,
            "vulnerability_validation": validation_result,
            "total_issues": len(issues) + validation_result["error_count"]
        }

    def _is_valid_cve_id(self, cve_id: str) -> bool:
        """Check if CVE ID format is valid."""
        import re
        pattern = r"^CVE-\d{4}-\d{4,}$"
        return bool(re.match(pattern, cve_id))

    async def generate_validation_report(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate comprehensive validation report.

        Args:
            vulnerabilities: List of vulnerabilities to analyze

        Returns:
            Detailed validation report
        """
        # Run all validations
        structure_validation = await self.validate_vulnerabilities(vulnerabilities)
        duplicate_check = await self.check_duplicates(vulnerabilities)

        # Analyze data quality
        quality_metrics = {
            "completeness": self._calculate_completeness(vulnerabilities),
            "consistency": self._calculate_consistency(vulnerabilities),
            "validity": structure_validation["valid_count"] / len(vulnerabilities) if vulnerabilities else 0.0
        }

        return {
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "valid_vulnerabilities": structure_validation["valid_count"],
                "duplicate_vulnerabilities": duplicate_check["duplicate_count"],
                "overall_quality_score": sum(quality_metrics.values()) / len(quality_metrics)
            },
            "structure_validation": structure_validation,
            "duplicate_analysis": duplicate_check,
            "quality_metrics": quality_metrics,
            "recommendations": self._generate_recommendations(
                structure_validation, duplicate_check, quality_metrics
            )
        }

    def _calculate_completeness(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate data completeness score."""
        if not vulnerabilities:
            return 0.0

        required_fields = ["cve_id", "severity", "description", "published_date"]
        optional_fields = ["cvss_base_score", "epss_probability", "vendor", "product"]
        
        total_score = 0.0
        for vuln in vulnerabilities:
            # Required fields (weight: 0.7)
            required_present = sum(1 for field in required_fields if vuln.get(field))
            required_score = (required_present / len(required_fields)) * 0.7
            
            # Optional fields (weight: 0.3)
            optional_present = sum(1 for field in optional_fields if vuln.get(field))
            optional_score = (optional_present / len(optional_fields)) * 0.3
            
            total_score += required_score + optional_score

        return total_score / len(vulnerabilities)

    def _calculate_consistency(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate data consistency score."""
        if not vulnerabilities:
            return 0.0

        consistency_checks = 0
        total_checks = 0

        for vuln in vulnerabilities:
            # Check severity-CVSS consistency
            if vuln.get("severity") and vuln.get("cvss_base_score"):
                total_checks += 1
                expected_severity = self._get_severity_from_cvss(vuln["cvss_base_score"])
                if vuln["severity"] == expected_severity:
                    consistency_checks += 1

            # Check date consistency
            if vuln.get("published_date") and vuln.get("last_modified_date"):
                total_checks += 1
                if vuln["published_date"] <= vuln["last_modified_date"]:
                    consistency_checks += 1

        return consistency_checks / total_checks if total_checks > 0 else 1.0

    def _get_severity_from_cvss(self, cvss_score: float) -> str:
        """Get severity level from CVSS score."""
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_recommendations(
        self,
        structure_validation: Dict[str, Any],
        duplicate_check: Dict[str, Any],
        quality_metrics: Dict[str, float]
    ) -> List[str]:
        """Generate recommendations based on validation results."""
        recommendations = []

        if structure_validation["error_count"] > 0:
            recommendations.append(
                f"Fix {structure_validation['error_count']} validation errors before processing"
            )

        if duplicate_check["duplicate_count"] > 0:
            recommendations.append(
                f"Remove {duplicate_check['duplicate_count']} duplicate vulnerabilities"
            )

        if quality_metrics["completeness"] < 0.8:
            recommendations.append(
                "Improve data completeness by enriching with additional sources"
            )

        if quality_metrics["consistency"] < 0.9:
            recommendations.append(
                "Review data consistency rules and fix mismatches"
            )

        return recommendations