"""CVEProject/cvelistV5 repository client for fetching official CVE records."""

import base64
import json
import os
import tempfile
import zipfile
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
        use_releases: bool = True,
        cache_manager=None,
        **kwargs,
    ):
        """Initialize CVE List client.

        Args:
            local_repo_path: Path to local clone of cvelistV5 repository
            use_github_api: Whether to use GitHub API (True) or clone repo (False)
            use_releases: Whether to use release zip files (True) or individual API calls (False)
            cache_manager: Cache manager instance for incremental updates
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
        self.use_releases = use_releases
        self.cache_manager = cache_manager
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
        self,
        year: int,
        min_severity: SeverityLevel = SeverityLevel.HIGH,
        incremental: bool = False,
    ) -> List[Dict[str, Any]]:
        """Fetch all CVEs for a specific year.

        Args:
            year: Year to fetch CVEs for (e.g., 2025)
            min_severity: Minimum severity level to include
            incremental: If True, skip CVEs that haven't been updated since last harvest

        Returns:
            List of raw CVE records
        """
        if self.use_releases:
            return self._fetch_cves_from_releases(year, min_severity, incremental)

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

                # Process all subdirectories

                self.logger.info(
                    f"Processing {len(subdirs)} subdirectories for year {year}"
                )

                for i, subdir in enumerate(subdirs):
                    self.logger.info(
                        f"Processing subdirectory {i + 1}/{len(subdirs)}: {year_path}/{subdir}"
                    )
                    subdir_cves = self._fetch_cves_from_directory(
                        f"{year_path}/{subdir}", min_severity, incremental
                    )
                    cves.extend(subdir_cves)
                    self.logger.info(
                        f"Found {len(subdir_cves)} CVEs meeting criteria in {subdir}"
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
        self, dir_path: str, min_severity: SeverityLevel, incremental: bool = False
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

                # Process all CVE files

                # Fetch each CVE file
                for filename in cve_files:
                    # Extract CVE ID from filename (e.g., "CVE-2024-1234.json" -> "CVE-2024-1234")
                    cve_id = filename.replace(".json", "")

                    # Check if incremental mode and CVE hasn't been updated
                    if incremental and self._should_skip_cve(
                        cve_id, f"{dir_path}/{filename}"
                    ):
                        continue

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

        # Severity order for comparison
        severity_order = {
            SeverityLevel.NONE: 0,
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4,
        }

        # Check CNA container
        cna = containers.get("cna", {})
        for metric in cna.get("metrics", []):
            if "cvssV3_1" in metric:
                severity_str = metric["cvssV3_1"].get("baseSeverity", "").upper()
                if severity_str and hasattr(SeverityLevel, severity_str):
                    severity = SeverityLevel[severity_str]
                    if severity_order.get(severity, 0) > severity_order.get(
                        max_severity, 0
                    ):
                        max_severity = severity

        # Check ADP containers (including CISA-ADP)
        for adp in containers.get("adp", []):
            for metric in adp.get("metrics", []):
                if "cvssV3_1" in metric:
                    severity_str = metric["cvssV3_1"].get("baseSeverity", "").upper()
                    if severity_str and hasattr(SeverityLevel, severity_str):
                        severity = SeverityLevel[severity_str]
                        if severity_order.get(severity, 0) > severity_order.get(
                            max_severity, 0
                        ):
                            max_severity = severity

        # Get numeric values for comparison
        max_severity_value = severity_order.get(max_severity, 0)
        min_severity_value = severity_order.get(min_severity, 3)

        return max_severity_value >= min_severity_value

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

            # Use the same severity order
            severity_order = {
                SeverityLevel.NONE: 0,
                SeverityLevel.LOW: 1,
                SeverityLevel.MEDIUM: 2,
                SeverityLevel.HIGH: 3,
                SeverityLevel.CRITICAL: 4,
            }

            for metric in cna.get("metrics", []):
                cvss_metric = self._parse_cvss_metric(metric)
                if cvss_metric:
                    cvss_metrics.append(cvss_metric)
                    if severity_order.get(
                        cvss_metric.base_severity, 0
                    ) > severity_order.get(severity, 0):
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

    def _should_skip_cve(self, cve_id: str, file_path: str) -> bool:
        """Check if CVE should be skipped in incremental mode.

        Args:
            cve_id: CVE ID to check
            file_path: Path to CVE file on GitHub

        Returns:
            True if CVE should be skipped (no updates since last harvest)
        """
        try:
            # Skip if no cache manager available
            if not self.cache_manager:
                return False

            # Check if we have cached metadata for this CVE
            cached_vuln = self.cache_manager.get_vulnerability(cve_id)
            if not cached_vuln:
                # No cached version, need to fetch
                return False

            # Get CVE metadata from GitHub API to check dateUpdated
            api_url = f"{self.GITHUB_API_URL}/contents/{file_path}"
            response = requests.get(api_url, headers=self.get_headers(), timeout=30)
            response.raise_for_status()

            # Get the file content and decode it
            content = response.json()
            if content.get("encoding") == "base64":
                cve_content = json.loads(
                    base64.b64decode(content["content"]).decode("utf-8")
                )
            else:
                # Fallback: fetch raw content
                raw_response = requests.get(
                    f"{self.GITHUB_RAW_URL}/{file_path}",
                    headers=self.get_headers(),
                    timeout=30,
                )
                raw_response.raise_for_status()
                cve_content = raw_response.json()

            # Extract dateUpdated from CVE metadata
            cve_metadata = cve_content.get("cveMetadata", {})
            date_updated_str = cve_metadata.get("dateUpdated") or cve_metadata.get(
                "datePublished", ""
            )

            if not date_updated_str:
                # No date info, need to fetch
                return False

            # Parse the date
            date_updated = datetime.fromisoformat(
                date_updated_str.replace("Z", "+00:00")
            )

            # Compare with cached version's last_modified_date
            if (
                cached_vuln.last_modified_date
                and date_updated <= cached_vuln.last_modified_date
            ):
                self.logger.debug(f"Skipping {cve_id} - no updates since last harvest")
                return True

            return False

        except Exception as e:
            self.logger.warning(
                f"Failed to check update status for {cve_id}", error=str(e)
            )
            # On error, don't skip - better to fetch than miss updates
            return False

    def _fetch_cves_from_releases(
        self, year: int, min_severity: SeverityLevel, incremental: bool = False
    ) -> List[Dict[str, Any]]:
        """Fetch CVEs from GitHub releases (much faster than individual API calls).

        Args:
            year: Year to fetch CVEs for
            min_severity: Minimum severity level to include
            incremental: If True, use delta files for incremental updates

        Returns:
            List of raw CVE records
        """
        cves = []

        try:
            # Get latest release
            response = requests.get(
                f"{self.GITHUB_API_URL}/releases/latest",
                headers=self.get_headers(),
                timeout=30,
            )
            response.raise_for_status()
            release_data = response.json()

            self.logger.info(
                "Using release-based approach",
                release_tag=release_data["tag_name"],
                published_at=release_data["published_at"],
            )

            # Download and process the appropriate files
            if incremental and self.cache_manager:
                # For incremental updates, try delta file first
                cves.extend(self._process_delta_files(release_data, year, min_severity))

            # Always process the full midnight file for comprehensive coverage
            # (delta files may not contain all changes for the target year)
            cves.extend(
                self._process_midnight_file(
                    release_data, year, min_severity, incremental
                )
            )

            # Remove duplicates (CVE IDs)
            seen_cves = set()
            unique_cves = []
            for cve in cves:
                cve_id = cve.get("cveMetadata", {}).get("cveId")
                if cve_id and cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    unique_cves.append(cve)

            self.logger.info(
                f"Fetched {len(unique_cves)} unique CVEs for year {year} from releases"
            )

            return unique_cves

        except Exception as e:
            self.logger.error(
                f"Failed to fetch CVEs from releases for year {year}", error=str(e)
            )
            # Fallback to API-based approach
            self.logger.info("Falling back to API-based approach")
            old_use_releases = self.use_releases
            self.use_releases = False
            try:
                result = self.fetch_cves_for_year(year, min_severity, incremental)
                return result
            finally:
                self.use_releases = old_use_releases

    def _process_midnight_file(
        self,
        release_data: Dict[str, Any],
        year: int,
        min_severity: SeverityLevel,
        incremental: bool,
    ) -> List[Dict[str, Any]]:
        """Process the midnight snapshot file from a release.

        Args:
            release_data: GitHub release data
            year: Target year to filter CVEs
            min_severity: Minimum severity level
            incremental: Whether to use incremental logic

        Returns:
            List of CVE records for the target year
        """
        # Find the midnight file
        midnight_asset = None
        for asset in release_data.get("assets", []):
            if "all_CVEs_at_midnight" in asset["name"]:
                midnight_asset = asset
                break

        if not midnight_asset:
            self.logger.warning("No midnight CVE file found in release")
            return []

        self.logger.info(
            "Downloading midnight CVE snapshot",
            filename=midnight_asset["name"],
            size_mb=round(midnight_asset["size"] / (1024 * 1024), 1),
        )

        return self._download_and_process_zip(
            midnight_asset, year, min_severity, incremental
        )

    def _process_delta_files(
        self, release_data: Dict[str, Any], year: int, min_severity: SeverityLevel
    ) -> List[Dict[str, Any]]:
        """Process delta files from a release.

        Args:
            release_data: GitHub release data
            year: Target year to filter CVEs
            min_severity: Minimum severity level

        Returns:
            List of CVE records for the target year
        """
        delta_cves = []

        # Find delta files
        for asset in release_data.get("assets", []):
            if "delta_CVEs" in asset["name"]:
                self.logger.info(
                    "Processing delta file",
                    filename=asset["name"],
                    size_kb=round(asset["size"] / 1024, 1),
                )
                delta_cves.extend(
                    self._download_and_process_zip(asset, year, min_severity, False)
                )

        return delta_cves

    def _download_and_process_zip(
        self,
        asset: Dict[str, Any],
        year: int,
        min_severity: SeverityLevel,
        incremental: bool,
    ) -> List[Dict[str, Any]]:
        """Download and process a zip file from GitHub releases.

        Args:
            asset: GitHub release asset data
            year: Target year to filter CVEs
            min_severity: Minimum severity level
            incremental: Whether to apply incremental logic

        Returns:
            List of CVE records for the target year
        """
        cves = []

        try:
            # Download the zip file
            response = requests.get(
                asset["browser_download_url"],
                headers=self.get_headers(),
                timeout=300,  # 5 minutes for large files
                stream=True,
            )
            response.raise_for_status()

            # Create temporary file
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_file:
                # Download in chunks to handle large files
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        temp_file.write(chunk)
                temp_file_path = temp_file.name

            try:
                # Process the zip file (handle nested zip structure)
                with zipfile.ZipFile(temp_file_path, "r") as outer_zip:
                    # Check if this is a nested zip (like cves.zip inside the main zip)
                    zip_files = [
                        name for name in outer_zip.namelist() if name.endswith(".zip")
                    ]

                    if zip_files:
                        # Handle nested zip structure
                        self.logger.info(f"Found nested zip files: {zip_files}")
                        for nested_zip_name in zip_files:
                            # Extract the nested zip to a temp file
                            with tempfile.NamedTemporaryFile(
                                suffix=".zip", delete=False
                            ) as nested_temp:
                                with outer_zip.open(nested_zip_name) as nested_zip_data:
                                    nested_temp.write(nested_zip_data.read())
                                nested_temp_path = nested_temp.name

                            try:
                                # Process the nested zip
                                with zipfile.ZipFile(nested_temp_path, "r") as zip_file:
                                    cves.extend(
                                        self._process_zip_contents(
                                            zip_file,
                                            asset,
                                            year,
                                            min_severity,
                                            incremental,
                                        )
                                    )
                            finally:
                                os.unlink(nested_temp_path)
                    else:
                        # Direct zip file, not nested
                        cves.extend(
                            self._process_zip_contents(
                                outer_zip, asset, year, min_severity, incremental
                            )
                        )

            finally:
                # Clean up temporary file
                os.unlink(temp_file_path)

        except Exception as e:
            self.logger.error(
                f"Failed to download/process asset {asset['name']}", error=str(e)
            )

        return cves

    def _process_zip_contents(
        self,
        zip_file: zipfile.ZipFile,
        asset: Dict[str, Any],
        year: int,
        min_severity: SeverityLevel,
        incremental: bool,
    ) -> List[Dict[str, Any]]:
        """Process CVE files from a zip file.

        Args:
            zip_file: Open zipfile object
            asset: GitHub asset metadata (for logging)
            year: Target year to filter CVEs
            min_severity: Minimum severity level
            incremental: Whether to apply incremental logic

        Returns:
            List of CVE records for the target year
        """
        cves = []

        # Look for CVE files for the target year
        year_pattern = f"cves/{year}/"

        cve_files = [
            name
            for name in zip_file.namelist()
            if name.startswith(year_pattern) and name.endswith(".json")
        ]

        self.logger.info(
            f"Found {len(cve_files)} CVE files for year {year} in {asset['name']}"
        )

        processed = 0
        for cve_file in cve_files:
            try:
                # Extract CVE ID from filename
                filename = Path(cve_file).name
                cve_id = filename.replace(".json", "")

                # Apply incremental logic if requested
                if incremental and self._should_skip_cve_in_zip(
                    cve_id, zip_file, cve_file
                ):
                    continue

                # Read and parse CVE data
                with zip_file.open(cve_file) as f:
                    cve_data = json.load(f)

                # Check severity threshold
                if self._meets_severity_threshold(cve_data, min_severity):
                    cves.append(cve_data)

                processed += 1
                if processed % 1000 == 0:
                    self.logger.info(
                        f"Processed {processed}/{len(cve_files)} CVE files"
                    )

            except Exception as e:
                self.logger.warning(
                    f"Failed to process CVE file {cve_file}", error=str(e)
                )

        return cves

    def _should_skip_cve_in_zip(
        self, cve_id: str, zip_file: zipfile.ZipFile, cve_file: str
    ) -> bool:
        """Check if CVE should be skipped when processing from zip file.

        Args:
            cve_id: CVE ID to check
            zip_file: Open zipfile object
            cve_file: Path to CVE file within zip

        Returns:
            True if CVE should be skipped
        """
        try:
            if not self.cache_manager:
                return False

            # Check if we have cached version
            cached_vuln = self.cache_manager.get_vulnerability(cve_id)
            if not cached_vuln:
                return False

            # Read CVE metadata from zip
            with zip_file.open(cve_file) as f:
                cve_data = json.load(f)

            # Extract dateUpdated
            cve_metadata = cve_data.get("cveMetadata", {})
            date_updated_str = cve_metadata.get("dateUpdated") or cve_metadata.get(
                "datePublished", ""
            )

            if not date_updated_str:
                return False

            # Parse and compare dates
            date_updated = datetime.fromisoformat(
                date_updated_str.replace("Z", "+00:00")
            )

            if (
                cached_vuln.last_modified_date
                and date_updated <= cached_vuln.last_modified_date
            ):
                self.logger.debug(f"Skipping {cve_id} - no updates since last harvest")
                return True

            return False

        except Exception as e:
            self.logger.warning(
                f"Failed to check incremental status for {cve_id}", error=str(e)
            )
            return False

    def harvest(
        self,
        years: List[int] = None,
        min_severity: SeverityLevel = SeverityLevel.HIGH,
        max_vulnerabilities: Optional[int] = None,
        incremental: bool = False,
    ) -> List[Vulnerability]:
        """Harvest vulnerabilities from CVEList repository.

        Args:
            years: List of years to harvest (default: current year)
            min_severity: Minimum severity level to include
            max_vulnerabilities: Maximum number of vulnerabilities to return
            incremental: If True, skip CVEs that haven't been updated since last harvest

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
            year_cves = self.fetch_cves_for_year(year, min_severity, incremental)

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
