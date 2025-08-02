"""
EPSSFilterAgent - Filters vulnerabilities based on EPSS score threshold
"""

import os
from datetime import datetime
from typing import Any, Dict, List, Tuple

from scripts.agents.base_agent import BaseAgent


class EPSSFilterAgent(BaseAgent):
    """Agent for filtering vulnerabilities based on EPSS score threshold."""

    DEFAULT_THRESHOLD = 0.6  # 60% exploitation probability

    def __init__(self, threshold: float = None, cache_dir=None):
        """
        Initialize EPSS Filter Agent.

        Args:
            threshold: EPSS score threshold (0.0-1.0). Defaults to 0.5 (50%)
            cache_dir: Directory for caching filtered results
        """
        super().__init__(name="EPSSFilterAgent", cache_dir=cache_dir)

        # Get threshold from environment or use default
        env_threshold = os.getenv("EPSS_THRESHOLD", "").strip()
        if env_threshold:
            try:
                self.threshold = float(env_threshold)
            except ValueError:
                self.logger.warning(
                    "Invalid EPSS_THRESHOLD environment variable",
                    value=env_threshold,
                    using_default=self.DEFAULT_THRESHOLD,
                )
                self.threshold = self.DEFAULT_THRESHOLD
        else:
            self.threshold = threshold or self.DEFAULT_THRESHOLD

        # Validate threshold
        if not 0.0 <= self.threshold <= 1.0:
            raise ValueError(
                f"EPSS threshold must be between 0.0 and 1.0, got {self.threshold}"
            )

        self.logger.info(
            "EPSS Filter Agent initialized",
            threshold=self.threshold,
            threshold_percentage=f"{self.threshold * 100}%",
        )

        # Initialize counters for audit logging
        self.stats = {
            "total_processed": 0,
            "passed_filter": 0,
            "failed_filter": 0,
            "missing_epss": 0,
            "invalid_epss": 0,
        }

    def filter_vulnerabilities(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Filter vulnerabilities based on EPSS threshold.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Tuple of (filtered_vulnerabilities, filter_stats)
        """
        filtered = []

        # Reset stats for this batch
        self.stats = {
            "total_processed": len(vulnerabilities),
            "passed_filter": 0,
            "failed_filter": 0,
            "missing_epss": 0,
            "invalid_epss": 0,
            "threshold": self.threshold,
            "threshold_percentage": f"{self.threshold * 100}%",
            "filter_timestamp": datetime.utcnow().isoformat(),
        }

        for vuln in vulnerabilities:
            cve_id = vuln.get("cveId", vuln.get("cve_id", "Unknown"))

            # Extract EPSS score
            epss_score = self._extract_epss_score(vuln)

            if epss_score is None:
                self.stats["missing_epss"] += 1
                self.logger.warning("Missing EPSS score, filtering out", cve_id=cve_id)
                continue

            if epss_score < 0.0 or epss_score > 1.0:
                self.stats["invalid_epss"] += 1
                self.logger.error(
                    "Invalid EPSS score, filtering out",
                    cve_id=cve_id,
                    epss_score=epss_score,
                )
                continue

            # Apply threshold filter
            if epss_score >= self.threshold:
                self.stats["passed_filter"] += 1
                filtered.append(vuln)
                self.logger.debug(
                    "CVE passed EPSS filter", cve_id=cve_id, epss_score=epss_score
                )
            else:
                self.stats["failed_filter"] += 1
                self.logger.debug(
                    "CVE failed EPSS filter",
                    cve_id=cve_id,
                    epss_score=epss_score,
                    threshold=self.threshold,
                )

        # Log summary statistics
        self.logger.info("EPSS filtering complete", **self.stats)

        # Warn if no vulnerabilities passed the filter
        if not filtered:
            self.logger.warning(
                "No vulnerabilities passed EPSS filter",
                threshold=self.threshold,
                total_processed=len(vulnerabilities),
            )

        return filtered, self.stats

    def _extract_epss_score(self, vuln: Dict[str, Any]) -> float:
        """
        Extract EPSS score from vulnerability data.

        Handles multiple formats:
        - vuln['epssScore'] (float)
        - vuln['epss_score'] (float)
        - vuln['epssScore']['score'] (nested dict)
        - vuln['epss']['score'] (nested dict)
        - vuln['epssPercentile'] / 100 (percentile as fallback)

        Args:
            vuln: Vulnerability dictionary

        Returns:
            EPSS score as float (0.0-1.0) or None if not found
        """
        # Direct score fields
        if "epssScore" in vuln and vuln["epssScore"] is not None:
            try:
                return float(vuln["epssScore"])
            except (ValueError, TypeError):
                pass

        if "epss_score" in vuln and vuln["epss_score"] is not None:
            try:
                return float(vuln["epss_score"])
            except (ValueError, TypeError):
                pass

        # Nested score objects
        if (
            "epssScore" in vuln
            and isinstance(vuln["epssScore"], dict)
            and "score" in vuln["epssScore"]
        ):
            try:
                return float(vuln["epssScore"]["score"])
            except (ValueError, TypeError):
                pass

        if (
            "epss" in vuln
            and isinstance(vuln["epss"], dict)
            and "score" in vuln["epss"]
        ):
            try:
                return float(vuln["epss"]["score"])
            except (ValueError, TypeError):
                pass

        # Fall back to percentile / 100 if available
        if "epssPercentile" in vuln and vuln["epssPercentile"] is not None:
            try:
                percentile = float(vuln["epssPercentile"])
                # Convert percentile to score approximation
                # Note: This is an approximation since percentile != score
                return percentile / 100.0
            except (ValueError, TypeError):
                pass

        if "epss_percentile" in vuln and vuln["epss_percentile"] is not None:
            try:
                percentile = float(vuln["epss_percentile"])
                return percentile / 100.0
            except (ValueError, TypeError):
                pass

        return None

    def get_filter_report(self) -> Dict[str, Any]:
        """
        Get detailed filter statistics report.

        Returns:
            Dictionary with filter statistics and audit information
        """
        if self.stats["total_processed"] > 0:
            pass_rate = (
                self.stats["passed_filter"] / self.stats["total_processed"]
            ) * 100
            filter_rate = (
                self.stats["failed_filter"] / self.stats["total_processed"]
            ) * 100
            missing_rate = (
                self.stats["missing_epss"] / self.stats["total_processed"]
            ) * 100
        else:
            pass_rate = filter_rate = missing_rate = 0.0

        return {
            **self.stats,
            "pass_rate_percentage": f"{pass_rate:.1f}%",
            "filter_rate_percentage": f"{filter_rate:.1f}%",
            "missing_rate_percentage": f"{missing_rate:.1f}%",
            "report_generated": datetime.utcnow().isoformat(),
        }

    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process vulnerabilities through EPSS filter.

        Args:
            data: Dictionary containing 'vulnerabilities' list

        Returns:
            Dictionary with filtered vulnerabilities and statistics
        """
        vulnerabilities = data.get("vulnerabilities", [])

        # Apply filter
        filtered_vulns, stats = self.filter_vulnerabilities(vulnerabilities)

        # Generate report
        report = self.get_filter_report()

        # Log audit trail
        self.logger.info(
            "EPSS filter audit trail",
            input_count=len(vulnerabilities),
            output_count=len(filtered_vulns),
            filter_threshold=self.threshold,
            **report,
        )

        return {
            "vulnerabilities": filtered_vulns,
            "epss_filter_stats": stats,
            "epss_filter_report": report,
            "filter_applied": True,
            "threshold": self.threshold,
        }

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute EPSS filtering task.

        This method is required by BaseAgent abstract class.

        Args:
            task: Task containing 'vulnerabilities' to filter

        Returns:
            Dictionary with filtered results
        """
        return await self.process(task)

    def get_dependencies(self) -> List[str]:
        """
        Get agent dependencies.

        This method is required by BaseAgent abstract class.

        Returns:
            List of dependencies (empty for this agent)
        """
        return []
