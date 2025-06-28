"""CVE API client for fetching CVE 4.0 records."""

import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import structlog
from dateutil import parser as date_parser

from scripts.harvest.base_client import BaseAPIClient
from scripts.models import (
    CPEMatch,
    CVSSMetric,
    Reference,
    SeverityLevel,
    Vulnerability,
    VulnerabilitySource,
)


class CVEClient(BaseAPIClient):
    """Client for CVE.org API."""

    def __init__(self, api_key: Optional[str] = None, **kwargs):
        """Initialize CVE client.

        Args:
            api_key: CVE API key (optional but recommended)
            **kwargs: Additional arguments for BaseAPIClient
        """
        super().__init__(
            base_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            rate_limit_calls=5 if not api_key else 30,  # Higher limit with API key
            rate_limit_period=60.0,
            **kwargs,
        )
        self.api_key = api_key or os.getenv("CVE_API_KEY")
        self.logger = structlog.get_logger(self.__class__.__name__)

    def get_headers(self) -> Dict[str, str]:
        """Get headers for CVE API requests."""
        headers = super().get_headers()
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def fetch_recent_cves(
        self,
        days_back: int = 7,
        severity: Optional[SeverityLevel] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch recently published or modified CVEs.

        Args:
            days_back: Number of days to look back
            severity: Filter by severity level

        Returns:
            List of raw CVE records
        """
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)

        params = {
            "lastModStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.999"),
        }

        if severity and severity != SeverityLevel.NONE:
            params["cvssV3Severity"] = severity.value

        all_cves = []
        start_index = 0
        results_per_page = 2000  # Max allowed by API

        while True:
            params["startIndex"] = start_index
            params["resultsPerPage"] = results_per_page

            try:
                self.logger.info(
                    "Fetching CVEs",
                    start_index=start_index,
                    date_range=f"{start_date.date()} to {end_date.date()}",
                )

                response = self.get("/", params=params)

                vulnerabilities = response.get("vulnerabilities", [])
                all_cves.extend(vulnerabilities)

                # Check if there are more results
                total_results = response.get("totalResults", 0)
                if start_index + results_per_page >= total_results:
                    break

                start_index += results_per_page

            except Exception as e:
                self.logger.error("Failed to fetch CVEs", error=str(e))
                break

        self.logger.info("Fetched CVEs", count=len(all_cves))
        return all_cves

    def parse_cve_record(self, cve_data: Dict[str, Any]) -> Optional[Vulnerability]:
        """Parse raw CVE record into Vulnerability model.

        Args:
            cve_data: Raw CVE data from API

        Returns:
            Parsed Vulnerability object or None if parsing fails
        """
        try:
            cve = cve_data.get("cve", {})

            # Extract basic information
            cve_id = cve.get("id", "")
            if not cve_id:
                return None

            # Get descriptions (prefer English)
            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                descriptions[0]["value"]
                if descriptions
                else "No description available",
            )

            # Parse dates
            published_date = date_parser.parse(cve.get("published", ""))
            last_modified = date_parser.parse(cve.get("lastModified", ""))

            # Parse CVSS metrics
            cvss_metrics = []
            severity = SeverityLevel.NONE

            metrics = cve.get("metrics", {})

            # CVSS v3.1
            for cvss_data in metrics.get("cvssMetricV31", []):
                cvss = cvss_data.get("cvssData", {})
                metric = CVSSMetric(
                    version="3.1",
                    vector_string=cvss.get("vectorString", ""),
                    base_score=cvss.get("baseScore", 0.0),
                    base_severity=SeverityLevel(cvss.get("baseSeverity", "NONE")),
                    exploitability_score=cvss.get("exploitabilityScore"),
                    impact_score=cvss.get("impactScore"),
                )
                cvss_metrics.append(metric)
                if metric.base_severity.value > severity.value:
                    severity = metric.base_severity

            # CVSS v3.0
            for cvss_data in metrics.get("cvssMetricV30", []):
                cvss = cvss_data.get("cvssData", {})
                metric = CVSSMetric(
                    version="3.0",
                    vector_string=cvss.get("vectorString", ""),
                    base_score=cvss.get("baseScore", 0.0),
                    base_severity=SeverityLevel(cvss.get("baseSeverity", "NONE")),
                    exploitability_score=cvss.get("exploitabilityScore"),
                    impact_score=cvss.get("impactScore"),
                )
                cvss_metrics.append(metric)
                if metric.base_severity.value > severity.value:
                    severity = metric.base_severity

            # CVSS v2.0 (convert severity)
            for cvss_data in metrics.get("cvssMetricV2", []):
                cvss = cvss_data.get("cvssData", {})
                base_score = cvss.get("baseScore", 0.0)

                # Map v2 scores to v3 severity levels
                if base_score >= 9.0:
                    v2_severity = SeverityLevel.CRITICAL
                elif base_score >= 7.0:
                    v2_severity = SeverityLevel.HIGH
                elif base_score >= 4.0:
                    v2_severity = SeverityLevel.MEDIUM
                elif base_score > 0.0:
                    v2_severity = SeverityLevel.LOW
                else:
                    v2_severity = SeverityLevel.NONE

                metric = CVSSMetric(
                    version="2.0",
                    vector_string=cvss.get("vectorString", ""),
                    base_score=base_score,
                    base_severity=v2_severity,
                )
                cvss_metrics.append(metric)
                if v2_severity.value > severity.value:
                    severity = v2_severity

            # Parse configurations (CPEs)
            cpe_matches = []
            affected_vendors = set()
            affected_products = set()

            configurations = cve.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable", False):
                            cpe = CPEMatch(
                                cpe23_uri=cpe_match.get("criteria", ""),
                                version_start_including=cpe_match.get(
                                    "versionStartIncluding"
                                ),
                                version_start_excluding=cpe_match.get(
                                    "versionStartExcluding"
                                ),
                                version_end_including=cpe_match.get(
                                    "versionEndIncluding"
                                ),
                                version_end_excluding=cpe_match.get(
                                    "versionEndExcluding"
                                ),
                            )
                            cpe_matches.append(cpe)

                            # Extract vendor and product from CPE
                            parts = cpe.cpe23_uri.split(":")
                            if len(parts) >= 5:
                                affected_vendors.add(parts[3])
                                affected_products.add(parts[4])

            # Parse references
            references = []
            for ref in cve.get("references", []):
                reference = Reference(
                    url=ref.get("url", ""),
                    source=ref.get("source"),
                    tags=ref.get("tags", []),
                )
                references.append(reference)

            # Extract additional metadata
            cvss_v3_data = metrics.get("cvssMetricV31", [{}])[0].get(
                "cvssData", {}
            ) or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})

            attack_vector = None
            requires_user_interaction = None
            requires_privileges = None

            if cvss_v3_data:
                vector_string = cvss_v3_data.get("vectorString", "")
                if vector_string:
                    # Parse CVSS vector string
                    vector_parts = {
                        part.split(":")[0]: part.split(":")[1]
                        for part in vector_string.split("/")[1:]
                        if ":" in part
                    }
                    attack_vector = vector_parts.get("AV")
                    requires_user_interaction = vector_parts.get("UI") == "R"
                    requires_privileges = vector_parts.get("PR")

            # Create Vulnerability object
            vulnerability = Vulnerability(
                cve_id=cve_id,
                title=f"{cve_id}: {description[:100]}...",
                description=description,
                published_date=published_date,
                last_modified_date=last_modified,
                cvss_metrics=cvss_metrics,
                severity=severity,
                cpe_matches=cpe_matches,
                affected_vendors=list(affected_vendors),
                affected_products=list(affected_products),
                references=references,
                attack_vector=attack_vector,
                requires_user_interaction=requires_user_interaction,
                requires_privileges=requires_privileges,
                sources=[
                    VulnerabilitySource(
                        name="NVD",
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        last_modified=last_modified,
                    )
                ],
            )

            return vulnerability

        except Exception as e:
            self.logger.error(
                "Failed to parse CVE record",
                cve_id=cve_data.get("cve", {}).get("id"),
                error=str(e),
            )
            return None

    def fetch_and_parse_recent_cves(
        self,
        days_back: int = 7,
        severity: Optional[SeverityLevel] = None,
    ) -> List[Vulnerability]:
        """Fetch and parse recent CVEs into Vulnerability objects.

        Args:
            days_back: Number of days to look back
            severity: Filter by severity level

        Returns:
            List of parsed Vulnerability objects
        """
        raw_cves = self.fetch_recent_cves(days_back, severity)
        vulnerabilities = []

        for cve_data in raw_cves:
            vuln = self.parse_cve_record(cve_data)
            if vuln:
                vulnerabilities.append(vuln)

        self.logger.info(
            "Parsed vulnerabilities",
            total=len(raw_cves),
            parsed=len(vulnerabilities),
        )

        return vulnerabilities
