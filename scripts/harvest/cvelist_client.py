"""CVEProject/cvelistV5 repository client for fetching official CVE records."""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
import structlog
from git import Repo

from scripts.harvest.base_client import BaseAPIClient
from scripts.models import (
    CVSSMetric,
    ExploitationStatus,
    Reference,
    SeverityLevel,
    Vulnerability,
    VulnerabilitySource,
)


class CVEListClient(BaseAPIClient):
    """Client for CVEProject/cvelistV5 repository."""

    GITHUB_RAW_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main"
    GITHUB_API_URL = "https://api.github.com/repos/CVEProject/cvelistV5"
    CLONE_URL = "https://github.com/CVEProject/cvelistV5.git"

    def __init__(
        self,
        local_repo_path: Optional[Path] = None,
        use_github_api: bool = True,
        **kwargs,
    ):
        """Initialize CVE List client.

        Args:
            local_repo_path: Path to local clone of cvelistV5 repository
            use_github_api: Whether to use GitHub API (True) or clone repo (False)
            **kwargs: Additional arguments for BaseAPIClient
        """
        super().__init__(
            base_url=self.GITHUB_RAW_URL if use_github_api else "",
            rate_limit_calls=60,  # GitHub API rate limit
            rate_limit_period=3600,  # per hour
            **kwargs,
        )
        self.local_repo_path = local_repo_path
        self.use_github_api = use_github_api
        self.logger = structlog.get_logger(self.__class__.__name__)

        if not use_github_api and local_repo_path:
            self._ensure_local_repo()

    def get_headers(self) -> Dict[str, str]:
        """Get headers for GitHub API requests."""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "MorningVulnBriefing/1.0",
        }

        # Add GitHub token if available
        github_token = os.getenv("GITHUB_TOKEN")
        if github_token:
            headers["Authorization"] = f"token {github_token}"

        return headers

    def _ensure_local_repo(self) -> None:
        """Ensure local repository exists and is up to date."""
        if not self.local_repo_path:
            return

        if not self.local_repo_path.exists():
            self.logger.info(
                "Cloning CVEList repository", path=str(self.local_repo_path)
            )
            Repo.clone_from(self.CLONE_URL, self.local_repo_path)
        else:
            # Pull latest changes
            self.logger.info(
                "Updating CVEList repository", path=str(self.local_repo_path)
            )
            repo = Repo(self.local_repo_path)
            origin = repo.remotes.origin
            origin.pull()

    def fetch_cves_for_year(
        self, year: int, min_severity: SeverityLevel = SeverityLevel.HIGH
    ) -> List[Dict[str, Any]]:
        """Fetch all CVEs for a specific year.

        Args:
            year: Year to fetch CVEs for (e.g., 2025)
            min_severity: Minimum severity level to include

        Returns:
            List of raw CVE records
        """
        cves = []

        # Get list of subdirectories for the year
        year_path = f"cves/{year}"

        if self.use_github_api:
            # Use GitHub API to list directories
            try:
                response = requests.get(
                    f"{self.GITHUB_API_URL}/contents/{year_path}",
                    headers=self.get_headers(),
                    timeout=30,
                )
                response.raise_for_status()

                subdirs = [
                    item["name"] for item in response.json() if item["type"] == "dir"
                ]

                for subdir in subdirs:
                    cves.extend(
                        self._fetch_cves_from_directory(
                            f"{year_path}/{subdir}", min_severity
                        )
                    )

            except Exception as e:
                self.logger.error(f"Failed to fetch CVEs for year {year}", error=str(e))

        else:
            # Use local repository
            year_dir = self.local_repo_path / year_path
            if year_dir.exists():
                for subdir in year_dir.iterdir():
                    if subdir.is_dir():
                        cves.extend(
                            self._fetch_cves_from_directory(
                                str(subdir.relative_to(self.local_repo_path)),
                                min_severity,
                            )
                        )

        return cves

    def _fetch_cves_from_directory(
        self, dir_path: str, min_severity: SeverityLevel
    ) -> List[Dict[str, Any]]:
        """Fetch CVEs from a specific directory.

        Args:
            dir_path: Path to directory containing CVE JSON files
            min_severity: Minimum severity level to include

        Returns:
            List of raw CVE records
        """
        cves = []

        if self.use_github_api:
            try:
                # Get list of CVE files in directory
                response = requests.get(
                    f"{self.GITHUB_API_URL}/contents/{dir_path}",
                    headers=self.get_headers(),
                    timeout=30,
                )
                response.raise_for_status()

                # Filter for JSON files
                cve_files = [
                    item["name"]
                    for item in response.json()
                    if item["type"] == "file" and item["name"].endswith(".json")
                ]

                # Fetch each CVE file
                for filename in cve_files:
                    cve_data = self._fetch_cve_file(f"{dir_path}/{filename}")
                    if cve_data and self._meets_severity_threshold(
                        cve_data, min_severity
                    ):
                        cves.append(cve_data)

            except Exception as e:
                self.logger.error(f"Failed to fetch CVEs from {dir_path}", error=str(e))

        else:
            # Use local repository
            local_dir = self.local_repo_path / dir_path
            if local_dir.exists():
                for file_path in local_dir.glob("*.json"):
                    try:
                        with open(file_path, encoding="utf-8") as f:
                            cve_data = json.load(f)
                            if self._meets_severity_threshold(cve_data, min_severity):
                                cves.append(cve_data)
                    except Exception as e:
                        self.logger.error(f"Failed to read {file_path}", error=str(e))

        return cves

    def _fetch_cve_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Fetch a single CVE file.

        Args:
            file_path: Path to CVE JSON file

        Returns:
            CVE data or None if fetch fails
        """
        try:
            url = f"{self.GITHUB_RAW_URL}/{file_path}"
            response = requests.get(url, headers=self.get_headers(), timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to fetch {file_path}", error=str(e))
            return None

    def _meets_severity_threshold(
        self, cve_data: Dict[str, Any], min_severity: SeverityLevel
    ) -> bool:
        """Check if CVE meets minimum severity threshold.

        Args:
            cve_data: Raw CVE data
            min_severity: Minimum severity level

        Returns:
            True if CVE meets threshold
        """
        # Extract CVSS scores from all containers
        containers = cve_data.get("containers", {})
        max_severity = SeverityLevel.NONE

        # Check CNA container
        cna = containers.get("cna", {})
        for metric in cna.get("metrics", []):
            if "cvssV3_1" in metric:
                severity_str = metric["cvssV3_1"].get("baseSeverity", "").upper()
                if severity_str and hasattr(SeverityLevel, severity_str):
                    severity = SeverityLevel[severity_str]
                    if severity.value > max_severity.value:
                        max_severity = severity

        # Check ADP containers (including CISA-ADP)
        for adp in containers.get("adp", []):
            for metric in adp.get("metrics", []):
                if "cvssV3_1" in metric:
                    severity_str = metric["cvssV3_1"].get("baseSeverity", "").upper()
                    if severity_str and hasattr(SeverityLevel, severity_str):
                        severity = SeverityLevel[severity_str]
                        if severity.value > max_severity.value:
                            max_severity = severity

        # Compare with minimum threshold
        severity_order = {
            SeverityLevel.NONE: 0,
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4,
        }

        return severity_order.get(max_severity, 0) >= severity_order.get(
            min_severity, 3
        )

    def parse_cve_v5_record(self, cve_data: Dict[str, Any]) -> Optional[Vulnerability]:
        """Parse CVE Record Format v5.x into Vulnerability model.

        Args:
            cve_data: Raw CVE v5 record

        Returns:
            Parsed Vulnerability object or None if parsing fails
        """
        try:
            # Extract metadata
            cve_metadata = cve_data.get("cveMetadata", {})
            cve_id = cve_metadata.get("cveId", "")
            if not cve_id:
                return None

            # Get containers
            containers = cve_data.get("containers", {})
            cna = containers.get("cna", {})

            # Extract description
            descriptions = cna.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            # Extract title
            title = cna.get("title", f"{cve_id}: {description[:100]}...")

            # Parse dates
            published_date = datetime.fromisoformat(
                cve_metadata.get("datePublished", "").replace("Z", "+00:00")
            )
            last_modified_date = datetime.fromisoformat(
                cve_metadata.get(
                    "dateUpdated", cve_metadata.get("datePublished", "")
                ).replace("Z", "+00:00")
            )

            # Parse CVSS metrics
            cvss_metrics = []
            severity = SeverityLevel.NONE

            for metric in cna.get("metrics", []):
                cvss_metric = self._parse_cvss_metric(metric)
                if cvss_metric:
                    cvss_metrics.append(cvss_metric)
                    if cvss_metric.base_severity.value > severity.value:
                        severity = cvss_metric.base_severity

            # Parse affected products
            affected_vendors = set()
            affected_products = set()

            for affected in cna.get("affected", []):
                vendor = affected.get("vendor", "").lower()
                if vendor:
                    affected_vendors.add(vendor)
                product = affected.get("product", "").lower()
                if product:
                    affected_products.add(product)

            # Parse references
            references = []
            for ref in cna.get("references", []):
                reference = Reference(
                    url=ref.get("url", ""),
                    source=ref.get("name", ""),
                    tags=ref.get("tags", []),
                )
                references.append(reference)

            # Check for exploitation status in CISA-ADP
            exploitation_status = ExploitationStatus.UNKNOWN
            for adp in containers.get("adp", []):
                if (
                    adp.get("providerMetadata", {}).get("shortName") == "CISA-ADP"
                    and "knownExploitedVulnerability" in adp
                ):
                    exploitation_status = ExploitationStatus.ACTIVE

            # Extract problem types (CWE)
            problem_types = []
            for problem in cna.get("problemTypes", []):
                for desc in problem.get("descriptions", []):
                    if desc.get("type") == "CWE":
                        problem_types.append(desc.get("cweId", ""))

            # Create vulnerability object
            vulnerability = Vulnerability(
                cve_id=cve_id,
                title=title,
                description=description,
                published_date=published_date,
                last_modified_date=last_modified_date,
                cvss_metrics=cvss_metrics,
                severity=severity,
                affected_vendors=list(affected_vendors),
                affected_products=list(affected_products),
                references=references,
                exploitation_status=exploitation_status,
                sources=[
                    VulnerabilitySource(
                        name="CVEList",
                        url=f"https://github.com/CVEProject/cvelistV5/blob/main/cves/{cve_id.split('-')[1]}/{self._get_cve_subdir(cve_id)}/{cve_id}.json",
                        last_modified=last_modified_date,
                    )
                ],
                tags=problem_types,  # Use CWE IDs as tags
            )

            return vulnerability

        except Exception as e:
            self.logger.error(
                f"Failed to parse CVE record {cve_data.get('cveMetadata', {}).get('cveId', 'unknown')}",
                error=str(e),
            )
            return None

    def _parse_cvss_metric(self, metric_data: Dict[str, Any]) -> Optional[CVSSMetric]:
        """Parse CVSS metric from CVE v5 format.

        Args:
            metric_data: Raw metric data

        Returns:
            Parsed CVSSMetric or None
        """
        # Try CVSS v3.1
        if "cvssV3_1" in metric_data:
            cvss = metric_data["cvssV3_1"]
            return CVSSMetric(
                version="3.1",
                vector_string=cvss.get("vectorString", ""),
                base_score=cvss.get("baseScore", 0.0),
                base_severity=SeverityLevel[cvss.get("baseSeverity", "NONE").upper()],
                exploitability_score=cvss.get("exploitabilityScore"),
                impact_score=cvss.get("impactScore"),
            )

        # Try CVSS v3.0
        if "cvssV3_0" in metric_data:
            cvss = metric_data["cvssV3_0"]
            return CVSSMetric(
                version="3.0",
                vector_string=cvss.get("vectorString", ""),
                base_score=cvss.get("baseScore", 0.0),
                base_severity=SeverityLevel[cvss.get("baseSeverity", "NONE").upper()],
                exploitability_score=cvss.get("exploitabilityScore"),
                impact_score=cvss.get("impactScore"),
            )

        return None

    def _get_cve_subdir(self, cve_id: str) -> str:
        """Get subdirectory for CVE based on ID.

        Args:
            cve_id: CVE ID (e.g., CVE-2025-1234)

        Returns:
            Subdirectory name (e.g., 1xxx)
        """
        parts = cve_id.split("-")
        if len(parts) >= 3:
            number = int(parts[2])
            thousand = (number // 1000) * 1000
            return f"{thousand // 1000}xxx"
        return "0xxx"

    def harvest(
        self,
        years: List[int] = None,
        min_severity: SeverityLevel = SeverityLevel.HIGH,
        max_vulnerabilities: Optional[int] = None,
    ) -> List[Vulnerability]:
        """Harvest vulnerabilities from CVEList repository.

        Args:
            years: List of years to harvest (default: current year)
            min_severity: Minimum severity level to include
            max_vulnerabilities: Maximum number of vulnerabilities to return

        Returns:
            List of parsed Vulnerability objects
        """
        if years is None:
            years = [datetime.now().year]

        self.logger.info(
            "Harvesting CVEs",
            years=years,
            min_severity=min_severity.value,
            max_vulnerabilities=max_vulnerabilities,
        )

        vulnerabilities = []

        for year in years:
            year_cves = self.fetch_cves_for_year(year, min_severity)

            for cve_data in year_cves:
                vuln = self.parse_cve_v5_record(cve_data)
                if vuln:
                    vulnerabilities.append(vuln)

                    if (
                        max_vulnerabilities
                        and len(vulnerabilities) >= max_vulnerabilities
                    ):
                        return vulnerabilities

        self.logger.info(f"Harvested {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
