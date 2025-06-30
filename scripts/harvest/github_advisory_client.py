"""GitHub Security Advisory database client for fetching vulnerability data."""

import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import structlog
from requests.exceptions import RequestException

from scripts.harvest.base_client import BaseAPIClient
from scripts.models import (
    CVSSMetric,
    ExploitationStatus,
    Reference,
    SeverityLevel,
    Vulnerability,
    VulnerabilitySource,
)


class GitHubAdvisoryClient(BaseAPIClient):
    """Client for GitHub Security Advisory database API."""

    GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"

    def __init__(self, **kwargs):
        """Initialize GitHub Advisory client.

        Args:
            **kwargs: Additional arguments for BaseAPIClient
        """
        super().__init__(
            base_url=self.GITHUB_GRAPHQL_URL,
            rate_limit_calls=5000,  # GitHub GraphQL API rate limit
            rate_limit_period=3600,  # per hour
            **kwargs,
        )
        self.logger = structlog.get_logger(self.__class__.__name__)

    def get_headers(self) -> Dict[str, str]:
        """Get headers for GitHub API requests."""
        headers = {
            "Accept": "application/vnd.github.v4+json",
            "User-Agent": "MorningVulnBriefing/1.0",
        }

        # Add GitHub token if available
        github_token = os.getenv("GITHUB_TOKEN")
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"
        else:
            self.logger.warning(
                "No GITHUB_TOKEN found, API rate limits will be restricted"
            )

        return headers

    def _construct_query(
        self,
        severity: Optional[str] = None,
        ecosystem: Optional[str] = None,
        after_cursor: Optional[str] = None,
        first: int = 100,
    ) -> str:
        """Construct GraphQL query for fetching advisories.

        Args:
            severity: Filter by severity (CRITICAL, HIGH, MODERATE, LOW)
            ecosystem: Filter by ecosystem (e.g., PIP, NPM, MAVEN)
            after_cursor: Pagination cursor
            first: Number of results to fetch

        Returns:
            GraphQL query string
        """
        filters = []
        if severity:
            filters.append(f"severity: {severity}")
        if ecosystem:
            filters.append(f"ecosystem: {ecosystem}")

        filter_string = f"({', '.join(filters)})" if filters else ""
        after_string = f', after: "{after_cursor}"' if after_cursor else ""

        return f"""
        {{
          securityAdvisories{filter_string}(first: {first}{after_string}) {{
            pageInfo {{
              endCursor
              hasNextPage
            }}
            nodes {{
              ghsaId
              summary
              description
              severity
              publishedAt
              updatedAt
              identifiers {{
                type
                value
              }}
              references {{
                url
              }}
              vulnerabilities(first: 10) {{
                nodes {{
                  package {{
                    ecosystem
                    name
                  }}
                  vulnerableVersionRange
                  firstPatchedVersion {{
                    identifier
                  }}
                }}
              }}
              cvss {{
                score
                vectorString
              }}
              cwes(first: 5) {{
                nodes {{
                  cweId
                  name
                }}
              }}
            }}
          }}
        }}
        """

    def fetch_advisories(
        self,
        severity: Optional[str] = None,
        ecosystem: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch security advisories from GitHub.

        Args:
            severity: Filter by severity (CRITICAL, HIGH, MODERATE, LOW)
            ecosystem: Filter by ecosystem
            limit: Maximum number of advisories to fetch

        Returns:
            List of raw advisory data
        """
        advisories = []
        cursor = None

        while True:
            try:
                query = self._construct_query(
                    severity=severity,
                    ecosystem=ecosystem,
                    after_cursor=cursor,
                    first=min(100, limit - len(advisories)) if limit else 100,
                )

                response = self.post("", json_data={"query": query})

                if "errors" in response:
                    self.logger.error("GraphQL errors", errors=response["errors"])
                    break

                data = response.get("data", {}).get("securityAdvisories", {})
                nodes = data.get("nodes", [])
                advisories.extend(nodes)

                # Check pagination
                page_info = data.get("pageInfo", {})
                if not page_info.get("hasNextPage") or (
                    limit and len(advisories) >= limit
                ):
                    break

                cursor = page_info.get("endCursor")

            except RequestException as e:
                self.logger.error("Failed to fetch advisories", error=str(e))
                break

        return advisories[:limit] if limit else advisories

    def parse_advisory(self, advisory_data: Dict[str, Any]) -> Optional[Vulnerability]:
        """Parse GitHub Security Advisory into Vulnerability model.

        Args:
            advisory_data: Raw advisory data from GraphQL

        Returns:
            Parsed Vulnerability object or None if parsing fails
        """
        try:
            # Extract identifiers
            ghsa_id = advisory_data.get("ghsaId", "")
            cve_id = None

            for identifier in advisory_data.get("identifiers", []):
                if identifier.get("type") == "CVE":
                    cve_id = identifier.get("value")
                    break

            # Skip if no CVE ID (we focus on CVE-tracked vulnerabilities)
            if not cve_id:
                return None

            # Parse dates
            published_date = datetime.fromisoformat(
                advisory_data.get("publishedAt", "").replace("Z", "+00:00")
            )
            last_modified_date = datetime.fromisoformat(
                advisory_data.get("updatedAt", "").replace("Z", "+00:00")
            )

            # Parse severity
            severity_map = {
                "CRITICAL": SeverityLevel.CRITICAL,
                "HIGH": SeverityLevel.HIGH,
                "MODERATE": SeverityLevel.MEDIUM,
                "LOW": SeverityLevel.LOW,
            }
            severity = severity_map.get(
                advisory_data.get("severity", "").upper(), SeverityLevel.NONE
            )

            # Parse CVSS
            cvss_metrics = []
            cvss_data = advisory_data.get("cvss", {})
            if cvss_data and cvss_data.get("score"):
                # GitHub uses CVSS 3.1 by default
                cvss_metric = CVSSMetric(
                    version="3.1",
                    vector_string=cvss_data.get("vectorString", ""),
                    base_score=float(cvss_data.get("score", 0)),
                    base_severity=severity,
                )
                cvss_metrics.append(cvss_metric)

            # Extract affected packages
            affected_vendors = set()
            affected_products = set()

            for vuln in advisory_data.get("vulnerabilities", {}).get("nodes", []):
                package = vuln.get("package", {})
                ecosystem = package.get("ecosystem", "").lower()
                name = package.get("name", "").lower()

                if ecosystem:
                    affected_vendors.add(ecosystem)
                if name:
                    affected_products.add(name)

            # Parse references
            references = []
            for ref in advisory_data.get("references", []):
                url = ref.get("url", "")
                if url:
                    references.append(
                        Reference(
                            url=url,
                            source="GitHub Advisory",
                            tags=["advisory"],
                        )
                    )

            # Add GitHub advisory URL
            references.append(
                Reference(
                    url=f"https://github.com/advisories/{ghsa_id}",
                    source="GitHub Advisory",
                    tags=["primary", "advisory"],
                )
            )

            # Extract CWE tags
            tags = []
            for cwe in advisory_data.get("cwes", {}).get("nodes", []):
                cwe_id = cwe.get("cweId", "")
                if cwe_id:
                    tags.append(cwe_id)

            # Create vulnerability object
            vulnerability = Vulnerability(
                cve_id=cve_id,
                title=advisory_data.get("summary", f"{cve_id}: {ghsa_id}"),
                description=advisory_data.get("description", ""),
                published_date=published_date,
                last_modified_date=last_modified_date,
                cvss_metrics=cvss_metrics,
                severity=severity,
                affected_vendors=list(affected_vendors),
                affected_products=list(affected_products),
                references=references,
                exploitation_status=ExploitationStatus.UNKNOWN,
                sources=[
                    VulnerabilitySource(
                        name="GitHub Advisory",
                        url=f"https://github.com/advisories/{ghsa_id}",
                        last_modified=last_modified_date,
                    )
                ],
                tags=tags,
                github_advisory_id=ghsa_id,  # Store GHSA ID as additional metadata
            )

            return vulnerability

        except Exception as e:
            self.logger.error(
                f"Failed to parse advisory {advisory_data.get('ghsaId', 'unknown')}",
                error=str(e),
            )
            return None

    def harvest(
        self,
        min_severity: SeverityLevel = SeverityLevel.HIGH,
        ecosystems: Optional[List[str]] = None,
        max_vulnerabilities: Optional[int] = None,
    ) -> List[Vulnerability]:
        """Harvest vulnerabilities from GitHub Security Advisory database.

        Args:
            min_severity: Minimum severity level to include
            ecosystems: List of ecosystems to filter (e.g., ["PIP", "NPM"])
            max_vulnerabilities: Maximum number of vulnerabilities to return

        Returns:
            List of parsed Vulnerability objects
        """
        self.logger.info(
            "Harvesting GitHub advisories",
            min_severity=min_severity.value,
            ecosystems=ecosystems,
            max_vulnerabilities=max_vulnerabilities,
        )

        # Map severity levels to GitHub GraphQL values
        severity_map = {
            SeverityLevel.CRITICAL: "CRITICAL",
            SeverityLevel.HIGH: "HIGH",
            SeverityLevel.MEDIUM: "MODERATE",
            SeverityLevel.LOW: "LOW",
        }

        vulnerabilities = []

        # Fetch for each severity level >= min_severity
        severity_order = [
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
        ]

        for severity in severity_order:
            if severity.value < min_severity.value:
                continue

            graphql_severity = severity_map.get(severity)
            if not graphql_severity:
                continue

            # Fetch advisories for this severity
            if ecosystems:
                # Fetch for each ecosystem
                for ecosystem in ecosystems:
                    advisories = self.fetch_advisories(
                        severity=graphql_severity,
                        ecosystem=ecosystem,
                        limit=max_vulnerabilities - len(vulnerabilities)
                        if max_vulnerabilities
                        else None,
                    )

                    for advisory in advisories:
                        vuln = self.parse_advisory(advisory)
                        if vuln:
                            vulnerabilities.append(vuln)

                            if (
                                max_vulnerabilities
                                and len(vulnerabilities) >= max_vulnerabilities
                            ):
                                return vulnerabilities
            else:
                # Fetch all ecosystems
                advisories = self.fetch_advisories(
                    severity=graphql_severity,
                    limit=max_vulnerabilities - len(vulnerabilities)
                    if max_vulnerabilities
                    else None,
                )

                for advisory in advisories:
                    vuln = self.parse_advisory(advisory)
                    if vuln:
                        vulnerabilities.append(vuln)

                        if (
                            max_vulnerabilities
                            and len(vulnerabilities) >= max_vulnerabilities
                        ):
                            return vulnerabilities

        self.logger.info(
            f"Harvested {len(vulnerabilities)} vulnerabilities from GitHub advisories"
        )
        return vulnerabilities
