"""Data quality validation for vulnerability records."""

import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import structlog

from scripts.models import Vulnerability
from scripts.quality.config import DataQualityConfig


class DataQualityValidator:
    """Validates vulnerability data against quality rules."""

    def __init__(self, config: Optional[DataQualityConfig] = None):
        """Initialize validator with configuration.

        Args:
            config: Data quality configuration (uses defaults if None)
        """
        self.config = config or DataQualityConfig()
        self.logger = structlog.get_logger(self.__class__.__name__)
        self._cve_pattern = re.compile(self.config.cve_id_pattern)

        # Validate configuration on init
        config_errors = self.config.validate()
        if config_errors:
            self.logger.warning("Configuration validation errors", errors=config_errors)

    def validate_vulnerability(
        self, vuln: Vulnerability
    ) -> Tuple[bool, List[str], Dict[str, float]]:
        """Validate a single vulnerability record.

        Args:
            vuln: Vulnerability to validate

        Returns:
            Tuple of (is_valid, errors, quality_scores)
        """
        errors = []
        warnings = []
        quality_scores = {}

        # Required field validation
        for field in self.config.required_fields:
            if not getattr(vuln, field, None):
                errors.append(f"Missing required field: {field}")

        # CVE ID validation
        if vuln.cve_id:
            if not self._cve_pattern.match(vuln.cve_id):
                errors.append(f"Invalid CVE ID format: {vuln.cve_id}")
                quality_scores["valid_cve_id"] = 0.0
            else:
                quality_scores["valid_cve_id"] = 1.0
        else:
            quality_scores["valid_cve_id"] = 0.0

        # Severity validation
        if vuln.severity:
            if vuln.severity.value not in self.config.allowed_severities:
                errors.append(f"Invalid severity: {vuln.severity.value}")
            quality_scores["has_severity"] = 1.0
        else:
            quality_scores["has_severity"] = 0.0

        # Score validation
        if vuln.cvss_base_score is not None:
            if (
                not self.config.min_cvss_score
                <= vuln.cvss_base_score
                <= self.config.max_cvss_score
            ):
                errors.append(f"CVSS score {vuln.cvss_base_score} outside valid range")
            quality_scores["has_cvss"] = 1.0
        else:
            quality_scores["has_cvss"] = 0.0
            if self.config.warn_if_no_cvss:
                warnings.append("No CVSS score available")

        if vuln.epss_probability is not None:
            epss_decimal = (
                vuln.epss_probability / 100.0
            )  # Convert percentage to decimal
            # Only check that EPSS is within valid bounds (0.0-1.0), not filtering threshold
            if not 0.0 <= epss_decimal <= 1.0:
                errors.append(
                    f"EPSS score {epss_decimal} outside valid range (0.0-1.0)"
                )
            quality_scores["has_epss"] = 1.0
        else:
            quality_scores["has_epss"] = 0.0
            if self.config.warn_if_no_epss:
                warnings.append("No EPSS score available")

        if (
            vuln.risk_score is not None
            and not self.config.min_risk_score
            <= vuln.risk_score
            <= self.config.max_risk_score
        ):
            errors.append(f"Risk score {vuln.risk_score} outside valid range")

        # Text field validation
        if vuln.title:
            if len(vuln.title) > self.config.max_title_length:
                warnings.append(
                    f"Title exceeds max length ({len(vuln.title)} > {self.config.max_title_length})"
                )
            quality_scores["has_title"] = 1.0
        else:
            quality_scores["has_title"] = 0.0

        if vuln.description:
            if len(vuln.description) > self.config.max_description_length:
                warnings.append(
                    f"Description exceeds max length ({len(vuln.description)} > {self.config.max_description_length})"
                )

            # Check description quality
            word_count = len(vuln.description.split())
            if word_count < self.config.min_description_words:
                warnings.append(
                    f"Description too short ({word_count} words < {self.config.min_description_words})"
                )
                quality_scores["description_quality"] = 0.5
            else:
                quality_scores["description_quality"] = 1.0
        else:
            quality_scores["description_quality"] = 0.0

        # Date validation
        if vuln.published_date:
            year = vuln.published_date.year
            if not self.config.min_year <= year <= self.config.max_year:
                errors.append(f"Published year {year} outside allowed range")

            # Ensure datetime is timezone-aware
            published_date = vuln.published_date
            if published_date.tzinfo is None:
                published_date = published_date.replace(tzinfo=timezone.utc)

            current_time = datetime.now(timezone.utc)

            if not self.config.allow_future_dates and published_date > current_time:
                errors.append("Published date is in the future")

            # Check if recent (within last 30 days)
            days_old = (current_time - published_date).days
            quality_scores["is_recent"] = (
                1.0 if days_old <= 30 else 0.5 if days_old <= 90 else 0.0
            )

        # Collection size validation
        if len(vuln.affected_vendors) > self.config.max_vendors_per_vuln:
            warnings.append(
                f"Too many vendors ({len(vuln.affected_vendors)} > {self.config.max_vendors_per_vuln})"
            )

        if len(vuln.affected_products) > self.config.max_products_per_vuln:
            warnings.append(
                f"Too many products ({len(vuln.affected_products)} > {self.config.max_products_per_vuln})"
            )

        quality_scores["has_affected_products"] = 1.0 if vuln.affected_products else 0.0

        if len(vuln.references) > self.config.max_references_per_vuln:
            warnings.append(
                f"Too many references ({len(vuln.references)} > {self.config.max_references_per_vuln})"
            )

        quality_scores["has_references"] = 1.0 if vuln.references else 0.0
        if not vuln.references and self.config.warn_if_no_references:
            warnings.append("No references available")

        if len(vuln.tags) > self.config.max_tags_per_vuln:
            warnings.append(
                f"Too many tags ({len(vuln.tags)} > {self.config.max_tags_per_vuln})"
            )

        # Vendor/Product filtering
        blocked_vendors = set(vuln.affected_vendors) & self.config.blocked_vendors
        if blocked_vendors:
            errors.append(f"Contains blocked vendors: {blocked_vendors}")

        blocked_products = set(vuln.affected_products) & self.config.blocked_products
        if blocked_products:
            errors.append(f"Contains blocked products: {blocked_products}")

        # CPE validation
        quality_scores["has_cpe"] = 1.0 if vuln.cpe_matches else 0.0

        # Attack vector from CVSS
        quality_scores["has_attack_vector"] = 1.0 if vuln.cvss_vector else 0.0

        # Log warnings (but don't fail validation)
        if warnings:
            self.logger.debug(
                "Validation warnings", cve_id=vuln.cve_id, warnings=warnings
            )

        is_valid = len(errors) == 0
        return is_valid, errors, quality_scores

    def calculate_quality_score(
        self,
        vuln: Vulnerability,  # noqa: ARG002
        quality_scores: Dict[str, float],
    ) -> float:
        """Calculate overall quality score for a vulnerability.

        Args:
            vuln: Vulnerability record
            quality_scores: Individual quality scores from validation

        Returns:
            Overall quality score (0.0 to 1.0)
        """
        total_score = 0.0

        for metric, weight in self.config.quality_score_weights.items():
            score = quality_scores.get(metric, 0.0)
            total_score += score * weight

        return round(total_score, 3)

    def filter_vulnerabilities(
        self, vulnerabilities: List[Vulnerability]
    ) -> Tuple[List[Vulnerability], Dict[str, int]]:
        """Filter vulnerabilities based on quality rules.

        Args:
            vulnerabilities: List of vulnerabilities to filter

        Returns:
            Tuple of (filtered_vulnerabilities, filter_stats)
        """
        filtered = []
        stats = {
            "total": len(vulnerabilities),
            "passed": 0,
            "failed_validation": 0,
            "below_severity": 0,
            "below_epss": 0,
            "outside_date_range": 0,
            "duplicate": 0,
        }

        seen_cves = set()
        severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        min_severity_idx = severity_order.index(self.config.min_severity)

        for vuln in vulnerabilities:
            # Check for duplicates
            if self.config.enable_deduplication and vuln.cve_id in seen_cves:
                stats["duplicate"] += 1
                continue

            # Validate record
            is_valid, errors, quality_scores = self.validate_vulnerability(vuln)
            if not is_valid:
                stats["failed_validation"] += 1
                self.logger.debug(
                    "Vulnerability failed validation", cve_id=vuln.cve_id, errors=errors
                )
                continue

            # Check severity threshold
            if vuln.severity:
                severity_idx = severity_order.index(vuln.severity.value)
                if severity_idx < min_severity_idx:
                    stats["below_severity"] += 1
                    continue

            # Check EPSS threshold
            if vuln.epss_probability is not None:
                epss_decimal = vuln.epss_probability / 100.0
                if epss_decimal < self.config.min_epss_score:
                    stats["below_epss"] += 1
                    continue

            # Check date range
            if vuln.published_date:
                year = vuln.published_date.year
                if not self.config.min_year <= year <= self.config.max_year:
                    stats["outside_date_range"] += 1
                    continue

            # Calculate and store quality score
            vuln.quality_score = self.calculate_quality_score(vuln, quality_scores)

            # Add to filtered list
            filtered.append(vuln)
            seen_cves.add(vuln.cve_id)
            stats["passed"] += 1

        return filtered, stats

    def check_data_completeness(
        self, vulnerabilities: List[Vulnerability]
    ) -> Dict[str, float]:
        """Check overall data completeness metrics.

        Args:
            vulnerabilities: List of vulnerabilities to analyze

        Returns:
            Dictionary of completeness metrics (percentages)
        """
        if not vulnerabilities:
            return {}

        total = len(vulnerabilities)
        metrics = {
            "has_cvss": sum(
                1 for v in vulnerabilities if v.cvss_base_score is not None
            ),
            "has_epss": sum(
                1 for v in vulnerabilities if v.epss_probability is not None
            ),
            "has_references": sum(1 for v in vulnerabilities if v.references),
            "has_cpe": sum(1 for v in vulnerabilities if v.cpe_matches),
            "has_vendors": sum(1 for v in vulnerabilities if v.affected_vendors),
            "has_products": sum(1 for v in vulnerabilities if v.affected_products),
            "has_tags": sum(1 for v in vulnerabilities if v.tags),
            "has_patches": sum(
                1
                for v in vulnerabilities
                if any(r.tags and "Patch" in r.tags for r in v.references)
            ),
            "has_exploits": sum(1 for v in vulnerabilities if v.is_exploited),
            "has_attack_vector": sum(1 for v in vulnerabilities if v.cvss_vector),
        }

        # Convert counts to percentages
        return {
            metric: round(100.0 * count / total, 1) for metric, count in metrics.items()
        }

    def get_quality_report(
        self, vulnerabilities: List[Vulnerability]
    ) -> Dict[str, any]:
        """Generate a comprehensive quality report.

        Args:
            vulnerabilities: List of vulnerabilities to analyze

        Returns:
            Quality report with statistics and recommendations
        """
        # Filter and get stats
        filtered, filter_stats = self.filter_vulnerabilities(vulnerabilities)

        # Get completeness metrics
        completeness = self.check_data_completeness(filtered)

        # Calculate average quality score
        avg_quality = (
            sum(v.quality_score for v in filtered if hasattr(v, "quality_score"))
            / len(filtered)
            if filtered
            else 0.0
        )

        # Identify top issues
        issues = []
        if filter_stats["failed_validation"] > 0:
            issues.append(
                f"{filter_stats['failed_validation']} vulnerabilities failed validation"
            )
        if completeness.get("has_cvss", 100) < 80:
            issues.append(
                f"Only {completeness['has_cvss']}% of vulnerabilities have CVSS scores"
            )
        if completeness.get("has_epss", 100) < 50:
            issues.append(
                f"Only {completeness['has_epss']}% of vulnerabilities have EPSS scores"
            )

        return {
            "summary": {
                "total_processed": filter_stats["total"],
                "total_passed": filter_stats["passed"],
                "pass_rate": round(
                    100.0 * filter_stats["passed"] / filter_stats["total"], 1
                )
                if filter_stats["total"] > 0
                else 0.0,
                "average_quality_score": round(avg_quality, 3),
            },
            "filter_statistics": filter_stats,
            "data_completeness": completeness,
            "quality_issues": issues,
            "recommendations": self._generate_recommendations(
                filter_stats, completeness
            ),
        }

    def _generate_recommendations(
        self, filter_stats: Dict[str, int], completeness: Dict[str, float]
    ) -> List[str]:
        """Generate recommendations based on quality metrics."""
        recommendations = []

        # Filter-based recommendations
        if filter_stats["below_epss"] > filter_stats["total"] * 0.5:
            recommendations.append(
                f"Consider lowering EPSS threshold (currently {self.config.min_epss_score})"
            )

        if filter_stats["duplicate"] > 10:
            recommendations.append(
                "High number of duplicates detected - check deduplication logic"
            )

        # Completeness-based recommendations
        if completeness.get("has_cvss", 100) < 70:
            recommendations.append(
                "Low CVSS coverage - consider additional enrichment sources"
            )

        if completeness.get("has_references", 100) < 90:
            recommendations.append(
                "Many vulnerabilities lack references - check data sources"
            )

        return recommendations
