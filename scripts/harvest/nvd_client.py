"""National Vulnerability Database (NVD) API client for comprehensive CVE data."""

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import requests
import structlog

from scripts.harvest.base_client import BaseAPIClient
from scripts.models import (
    CVSSMetric,
    ExploitationStatus,
    Reference,
    SeverityLevel,
    Vulnerability,
    VulnerabilitySource,
)


class NVDClient(BaseAPIClient):
    """Client for NIST National Vulnerability Database API 2.0."""

    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None, **kwargs):
        """Initialize NVD client.
        
        Args:
            api_key: Optional NVD API key for higher rate limits
            **kwargs: Additional arguments for BaseAPIClient
        """
        # NVD rate limits: 
        # - Without API key: 5 requests per 30 seconds, 10,000 CVEs per request
        # - With API key: 50 requests per 30 seconds, 10,000 CVEs per request
        rate_calls = 50 if api_key else 5
        rate_period = 30  # 30 seconds
        
        super().__init__(
            base_url=self.NVD_BASE_URL,
            rate_limit_calls=rate_calls,
            rate_limit_period=rate_period,
            **kwargs,
        )
        
        self.api_key = api_key
        self.logger = structlog.get_logger(self.__class__.__name__)
        
    def get_headers(self) -> Dict[str, str]:
        """Get headers for NVD API requests."""
        headers = {
            "Accept": "application/json",
            "User-Agent": "VulnBot/1.0 (https://github.com/williamzujkowski/vuln-bot)",
        }
        
        if self.api_key:
            headers["apiKey"] = self.api_key
            
        return headers
        
    def fetch_cves_by_published_date(
        self,
        start_date: datetime,
        end_date: datetime,
        results_per_page: int = 2000,
        max_results: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch CVEs by published date range.
        
        Args:
            start_date: Start of date range
            end_date: End of date range  
            results_per_page: Number of results per API call (max 2000)
            max_results: Maximum total results to fetch
            
        Returns:
            List of CVE records from NVD API
        """
        all_cves = []
        start_index = 0
        
        # Format dates for API (ISO 8601)
        pub_start_date = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end_date = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        
        self.logger.info(
            "Fetching CVEs from NVD by published date",
            start_date=pub_start_date,
            end_date=pub_end_date,
            results_per_page=results_per_page,
        )
        
        while True:
            try:
                params = {
                    "pubStartDate": pub_start_date,
                    "pubEndDate": pub_end_date,
                    "resultsPerPage": min(results_per_page, 2000),
                    "startIndex": start_index,
                }
                
                response = self.make_request("GET", "", params=params)
                data = response.json()
                
                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break
                    
                all_cves.extend(vulnerabilities)
                self.logger.info(
                    f"Fetched {len(vulnerabilities)} CVEs, total: {len(all_cves)}"
                )
                
                # Check if we have more results
                total_results = data.get("totalResults", 0)
                if start_index + len(vulnerabilities) >= total_results:
                    break
                    
                # Check max results limit
                if max_results and len(all_cves) >= max_results:
                    all_cves = all_cves[:max_results]
                    break
                    
                start_index += len(vulnerabilities)
                
                # Rate limiting delay
                time.sleep(1)
                
            except Exception as e:
                self.logger.error(
                    f"Failed to fetch CVEs from NVD",
                    error=str(e),
                    start_index=start_index,
                )
                break
                
        self.logger.info(f"Fetched total of {len(all_cves)} CVEs from NVD")
        return all_cves
        
    def fetch_cves_by_modified_date(
        self,
        start_date: datetime,
        end_date: datetime,
        results_per_page: int = 2000,
        max_results: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch CVEs by last modified date range.
        
        Args:
            start_date: Start of date range
            end_date: End of date range
            results_per_page: Number of results per API call (max 2000)
            max_results: Maximum total results to fetch
            
        Returns:
            List of CVE records from NVD API
        """
        all_cves = []
        start_index = 0
        
        # Format dates for API (ISO 8601)
        mod_start_date = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        mod_end_date = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        
        self.logger.info(
            "Fetching CVEs from NVD by modified date",
            start_date=mod_start_date,
            end_date=mod_end_date,
            results_per_page=results_per_page,
        )
        
        while True:
            try:
                params = {
                    "lastModStartDate": mod_start_date,
                    "lastModEndDate": mod_end_date,
                    "resultsPerPage": min(results_per_page, 2000),
                    "startIndex": start_index,
                }
                
                response = self.make_request("GET", "", params=params)
                data = response.json()
                
                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break
                    
                all_cves.extend(vulnerabilities)
                self.logger.info(
                    f"Fetched {len(vulnerabilities)} CVEs, total: {len(all_cves)}"
                )
                
                # Check if we have more results
                total_results = data.get("totalResults", 0)
                if start_index + len(vulnerabilities) >= total_results:
                    break
                    
                # Check max results limit
                if max_results and len(all_cves) >= max_results:
                    all_cves = all_cves[:max_results]
                    break
                    
                start_index += len(vulnerabilities)
                
                # Rate limiting delay
                time.sleep(1)
                
            except Exception as e:
                self.logger.error(
                    f"Failed to fetch CVEs from NVD",
                    error=str(e),
                    start_index=start_index,
                )
                break
                
        self.logger.info(f"Fetched total of {len(all_cves)} CVEs from NVD")
        return all_cves
        
    def fetch_cves_by_ids(self, cve_ids: List[str]) -> List[Dict[str, Any]]:
        """Fetch specific CVEs by their IDs.
        
        Args:
            cve_ids: List of CVE IDs to fetch
            
        Returns:
            List of CVE records from NVD API
        """
        all_cves = []
        
        # NVD API doesn't support bulk CVE ID queries, so we need to fetch individually
        # or use keyword search. Let's use individual requests for accuracy.
        
        self.logger.info(f"Fetching {len(cve_ids)} specific CVEs from NVD")
        
        for i, cve_id in enumerate(cve_ids):
            try:
                params = {"cveId": cve_id}
                response = self.make_request("GET", "", params=params)
                data = response.json()
                
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    all_cves.extend(vulnerabilities)
                    
                if (i + 1) % 10 == 0:
                    self.logger.info(f"Fetched {i + 1}/{len(cve_ids)} CVEs")
                    
                # Rate limiting delay
                time.sleep(1)
                
            except Exception as e:
                self.logger.warning(
                    f"Failed to fetch CVE {cve_id} from NVD",
                    error=str(e),
                )
                continue
                
        self.logger.info(f"Successfully fetched {len(all_cves)} out of {len(cve_ids)} requested CVEs")
        return all_cves
        
    def parse_nvd_cve_record(self, cve_record: Dict[str, Any]) -> Optional[Vulnerability]:
        """Parse NVD CVE record into Vulnerability object.
        
        Args:
            cve_record: Raw CVE record from NVD API 2.0
            
        Returns:
            Parsed Vulnerability object or None if parsing fails
        """
        try:
            cve_data = cve_record.get("cve", {})
            if not cve_data:
                return None
                
            # Extract basic info
            cve_id = cve_data.get("id", "")
            if not cve_id:
                return None
                
            # Extract descriptions
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")
                
            # Create title from CVE ID and description
            title = f"{cve_id}: {description[:100]}..." if len(description) > 100 else f"{cve_id}: {description}"
            
            # Parse dates
            published_str = cve_data.get("published", "")
            modified_str = cve_data.get("lastModified", published_str)
            
            published_date = datetime.fromisoformat(published_str.replace("Z", "+00:00")) if published_str else datetime.now(timezone.utc)
            last_modified_date = datetime.fromisoformat(modified_str.replace("Z", "+00:00")) if modified_str else published_date
            
            # Parse CVSS metrics and determine severity
            cvss_metrics = []
            severity = SeverityLevel.NONE
            attack_vector = "Unknown"
            attack_complexity = "Unknown" 
            privileges_required = "Unknown"
            user_interaction = "Unknown"
            
            metrics_data = cve_data.get("metrics", {})
            
            # Process CVSS v3.1 metrics
            for cvss_v31 in metrics_data.get("cvssMetricV31", []):
                cvss_data = cvss_v31.get("cvssData", {})
                if cvss_data:
                    cvss_metric = CVSSMetric(
                        version="3.1",
                        vector_string=cvss_data.get("vectorString", ""),
                        base_score=cvss_data.get("baseScore", 0.0),
                        base_severity=SeverityLevel[cvss_data.get("baseSeverity", "NONE").upper()],
                        exploitability_score=cvss_data.get("exploitabilityScore"),
                        impact_score=cvss_data.get("impactScore"),
                    )
                    cvss_metrics.append(cvss_metric)
                    
                    # Extract attack vector details from the first (primary) CVSS metric
                    if len(cvss_metrics) == 1:
                        attack_vector = cvss_data.get("attackVector", "Unknown")
                        attack_complexity = cvss_data.get("attackComplexity", "Unknown")
                        privileges_required = cvss_data.get("privilegesRequired", "Unknown")
                        user_interaction = cvss_data.get("userInteraction", "Unknown")
                    
                    # Update severity to highest found
                    if self._severity_order(cvss_metric.base_severity) > self._severity_order(severity):
                        severity = cvss_metric.base_severity
                        
            # Process CVSS v3.0 metrics if no v3.1 found
            if not cvss_metrics:
                for cvss_v30 in metrics_data.get("cvssMetricV30", []):
                    cvss_data = cvss_v30.get("cvssData", {})
                    if cvss_data:
                        cvss_metric = CVSSMetric(
                            version="3.0",
                            vector_string=cvss_data.get("vectorString", ""),
                            base_score=cvss_data.get("baseScore", 0.0),
                            base_severity=SeverityLevel[cvss_data.get("baseSeverity", "NONE").upper()],
                            exploitability_score=cvss_data.get("exploitabilityScore"),
                            impact_score=cvss_data.get("impactScore"),
                        )
                        cvss_metrics.append(cvss_metric)
                        
                        # Extract attack vector details from the first (primary) CVSS metric
                        if len(cvss_metrics) == 1:
                            attack_vector = cvss_data.get("attackVector", "Unknown")
                            attack_complexity = cvss_data.get("attackComplexity", "Unknown")
                            privileges_required = cvss_data.get("privilegesRequired", "Unknown")
                            user_interaction = cvss_data.get("userInteraction", "Unknown")
                        
                        if self._severity_order(cvss_metric.base_severity) > self._severity_order(severity):
                            severity = cvss_metric.base_severity
                            
            # Parse vendor and product information from configurations
            affected_vendors = set()
            affected_products = set()
            
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cpe_name = cpe_match.get("criteria", "")
                        if cpe_name:
                            # Parse CPE name: cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
                            cpe_parts = cpe_name.split(":")
                            if len(cpe_parts) >= 5:
                                vendor = cpe_parts[3].replace("_", " ").strip()
                                product = cpe_parts[4].replace("_", " ").strip()
                                
                                if vendor and vendor != "*":
                                    affected_vendors.add(vendor.lower())
                                if product and product != "*":
                                    affected_products.add(product.lower())
                                    
            # Parse references
            references = []
            for ref in cve_data.get("references", []):
                reference = Reference(
                    url=ref.get("url", ""),
                    source=ref.get("source", ""),
                    tags=ref.get("tags", []),
                )
                references.append(reference)
                
            # Check for exploitation status (look for exploit references)
            exploitation_status = ExploitationStatus.UNKNOWN
            exploit_tags = ["Exploit", "Third Party Advisory", "VDB Entry"]
            for ref in references:
                if any(tag in ref.tags for tag in exploit_tags):
                    exploitation_status = ExploitationStatus.POC
                    break
                    
            # Extract CWE information
            problem_types = []
            weaknesses = cve_data.get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        problem_types.extend(desc.get("value", "").split(", "))
                        
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
                attack_vector=attack_vector,
                attack_complexity=attack_complexity,
                privileges_required=privileges_required,
                user_interaction=user_interaction,
                sources=[
                    VulnerabilitySource(
                        name="NVD",
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        last_modified=last_modified_date,
                    )
                ],
                tags=problem_types,
            )
            
            return vulnerability
            
        except Exception as e:
            self.logger.error(
                f"Failed to parse NVD CVE record {cve_record.get('cve', {}).get('id', 'unknown')}",
                error=str(e),
            )
            return None
            
    def _severity_order(self, severity: SeverityLevel) -> int:
        """Get numeric order for severity comparison."""
        order = {
            SeverityLevel.NONE: 0,
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4,
        }
        return order.get(severity, 0)
        
    def harvest(
        self, 
        years: List[int],
        min_severity: SeverityLevel = SeverityLevel.HIGH,
        max_vulnerabilities: Optional[int] = None,
    ) -> List[Vulnerability]:
        """Harvest vulnerabilities from NVD API.
        
        Args:
            years: List of years to harvest
            min_severity: Minimum severity level to include
            max_vulnerabilities: Maximum number of vulnerabilities to return
            
        Returns:
            List of parsed Vulnerability objects
        """
        all_vulnerabilities = []
        
        self.logger.info(
            "Harvesting CVEs from NVD",
            years=years,
            min_severity=min_severity.value,
            max_vulnerabilities=max_vulnerabilities,
        )
        
        for year in years:
            # Define date range for the year
            start_date = datetime(year, 1, 1, tzinfo=timezone.utc)
            end_date = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
            
            # Fetch CVEs for the year
            year_cves = self.fetch_cves_by_published_date(
                start_date=start_date,
                end_date=end_date,
                max_results=max_vulnerabilities - len(all_vulnerabilities) if max_vulnerabilities else None,
            )
            
            # Parse and filter CVEs
            for cve_record in year_cves:
                vulnerability = self.parse_nvd_cve_record(cve_record)
                if vulnerability and self._meets_severity_threshold(vulnerability, min_severity):
                    all_vulnerabilities.append(vulnerability)
                    
                    if max_vulnerabilities and len(all_vulnerabilities) >= max_vulnerabilities:
                        break
                        
            self.logger.info(
                f"Harvested {len([v for v in all_vulnerabilities if v.published_date.year == year])} vulnerabilities for year {year}"
            )
            
            if max_vulnerabilities and len(all_vulnerabilities) >= max_vulnerabilities:
                break
                
        self.logger.info(f"Total harvested: {len(all_vulnerabilities)} vulnerabilities from NVD")
        return all_vulnerabilities
        
    def _meets_severity_threshold(self, vulnerability: Vulnerability, min_severity: SeverityLevel) -> bool:
        """Check if vulnerability meets minimum severity threshold."""
        return self._severity_order(vulnerability.severity) >= self._severity_order(min_severity)