"""Quality assurance agent for vulnerability data validation."""

import structlog
from typing import Any, Dict, List, Optional

from scripts.models import Vulnerability
from scripts.quality.validator import DataQualityValidator


class QualityAgent:
    """Agent responsible for data quality validation and assurance."""

    def __init__(self):
        self.logger = structlog.get_logger(self.__class__.__name__)
        self.validator = DataQualityValidator()

    async def validate_batch(
        self, vulnerabilities: List[Vulnerability], fail_on_error: bool = False
    ) -> Dict[str, Any]:
        """Validate a batch of vulnerabilities.

        Args:
            vulnerabilities: List of vulnerabilities to validate
            fail_on_error: Whether to fail on validation errors

        Returns:
            Validation results dictionary
        """
        self.logger.info(
            "Starting batch validation", vulnerability_count=len(vulnerabilities)
        )

        validation_results = []
        quality_scores = []
        errors = []

        for vuln in vulnerabilities:
            is_valid, vuln_errors, scores = self.validator.validate_vulnerability(vuln)
            
            validation_results.append({
                "cve_id": vuln.cve_id,
                "is_valid": is_valid,
                "errors": vuln_errors,
                "scores": scores
            })
            
            quality_scores.append(scores["overall"])
            if vuln_errors:
                errors.extend(vuln_errors)

        # Calculate batch metrics
        avg_quality_score = sum(quality_scores) / len(quality_scores) if quality_scores else 0.0
        validation_rate = sum(1 for r in validation_results if r["is_valid"]) / len(validation_results) if validation_results else 0.0

        result = {
            "success": not fail_on_error or all(r["is_valid"] for r in validation_results),
            "total_validated": len(vulnerabilities),
            "valid_count": sum(1 for r in validation_results if r["is_valid"]),
            "validation_rate": validation_rate,
            "average_quality_score": avg_quality_score,
            "errors": errors,
            "details": validation_results
        }

        self.logger.info(
            "Batch validation complete",
            validation_rate=f"{validation_rate:.1%}",
            avg_quality_score=f"{avg_quality_score:.1%}",
            error_count=len(errors)
        )

        return result

    async def suggest_improvements(
        self, vulnerabilities: List[Vulnerability]
    ) -> List[Dict[str, Any]]:
        """Suggest improvements for vulnerability data quality.

        Args:
            vulnerabilities: List of vulnerabilities to analyze

        Returns:
            List of improvement suggestions
        """
        suggestions = []

        # Analyze patterns
        missing_cvss = sum(1 for v in vulnerabilities if not v.cvss_base_score)
        missing_epss = sum(1 for v in vulnerabilities if not v.epss_probability)
        unknown_vendors = sum(1 for v in vulnerabilities if v.vendor == "Unknown")
        
        if missing_cvss > len(vulnerabilities) * 0.1:
            suggestions.append({
                "type": "data_enrichment",
                "field": "cvss_base_score",
                "impact": "high",
                "description": f"{missing_cvss} vulnerabilities missing CVSS scores",
                "recommendation": "Enable NVD API enrichment for CVSS data"
            })

        if missing_epss > len(vulnerabilities) * 0.2:
            suggestions.append({
                "type": "data_enrichment",
                "field": "epss_probability",
                "impact": "medium",
                "description": f"{missing_epss} vulnerabilities missing EPSS scores",
                "recommendation": "Ensure EPSS API is properly configured"
            })

        if unknown_vendors > len(vulnerabilities) * 0.3:
            suggestions.append({
                "type": "data_quality",
                "field": "vendor",
                "impact": "medium",
                "description": f"{unknown_vendors} vulnerabilities have unknown vendors",
                "recommendation": "Improve vendor extraction logic or add vendor mapping"
            })

        return suggestions

    def get_quality_metrics(self) -> Dict[str, Any]:
        """Get current quality metrics.

        Returns:
            Dictionary of quality metrics
        """
        return {
            "validator_version": "1.0",
            "rules_count": len(self.validator._get_quality_score(None, [])),
            "enabled_checks": [
                "cve_id_format",
                "severity_validation",
                "score_ranges",
                "date_validation",
                "reference_validation"
            ]
        }