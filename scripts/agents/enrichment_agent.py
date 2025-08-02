"""
DataEnrichmentAgent - Enriches CVE data with external sources like deps.dev
"""

import asyncio
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import quote

import aiohttp

from scripts.agents.base_agent import BaseAgent


class DataEnrichmentAgent(BaseAgent):
    """Agent for enriching CVE data with external sources."""

    # Supported ecosystems with their deps.dev system names
    ECOSYSTEM_MAPPING = {
        "npm": "npm",
        "pypi": "pypi",
        "maven": "maven",
        "nuget": "nuget",
        "cargo": "cargo",
        "go": "go",
        "rubygems": "rubygems",
        "packagist": "packagist",  # PHP Composer
        "pub": "pub",  # Dart/Flutter
        "hex": "hex",  # Erlang/Elixir
        "hackage": "hackage",  # Haskell
        "cran": "cran",  # R
        "cocoapods": "cocoapods",  # iOS/macOS
        "swift": "swift",  # Swift Package Manager
        "github": "github",  # GitHub Actions
        "docker": "docker",  # Docker Hub
    }

    def __init__(self, cache_dir: Path = None):
        super().__init__(name="DataEnrichmentAgent", cache_dir=cache_dir)
        self.deps_dev_base_url = "https://api.deps.dev/v3alpha"
        self.cache_dir = Path(".cache/enrichment")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = timedelta(hours=24)

        # Rate limiting configuration
        self.rate_limit_delay = 0.2  # 200ms between requests (5 req/sec)
        self.last_request_time = 0
        self.max_retries = 3
        self.retry_delay = 1.0  # Initial retry delay in seconds

    async def _apply_rate_limit(self):
        """Apply rate limiting between API requests."""
        current_time = asyncio.get_event_loop().time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - time_since_last)
        self.last_request_time = asyncio.get_event_loop().time()

    async def _make_request_with_retry(
        self, session: aiohttp.ClientSession, url: str
    ) -> Optional[Dict[str, Any]]:
        """Make HTTP request with retry logic."""
        for attempt in range(self.max_retries):
            try:
                await self._apply_rate_limit()

                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=30),
                    headers={"Accept": "application/json"},
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    elif response.status == 404:
                        # Not found is not an error for retry
                        return None
                    elif response.status == 429:
                        # Rate limited - wait longer
                        retry_after = int(response.headers.get("Retry-After", 60))
                        self.logger.warning(f"Rate limited, waiting {retry_after}s")
                        await asyncio.sleep(retry_after)
                        continue
                    else:
                        self.logger.warning(f"API returned status {response.status}")
                        if attempt < self.max_retries - 1:
                            await asyncio.sleep(self.retry_delay * (2**attempt))
                            continue
                        return None

            except asyncio.TimeoutError:
                self.logger.warning(f"Timeout on attempt {attempt + 1}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (2**attempt))
                    continue
                return None
            except Exception as e:
                self.logger.error(f"Request error: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (2**attempt))
                    continue
                return None

        return None

    async def fetch_deps_dev_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch affected packages from deps.dev API for a given CVE."""
        try:
            # Check cache first
            cache_file = self.cache_dir / f"{cve_id}_deps.json"
            if cache_file.exists():
                # Check if cache is still valid
                cache_time = datetime.fromtimestamp(cache_file.stat().st_mtime)
                if datetime.now() - cache_time < self.cache_ttl:
                    with open(cache_file) as f:
                        self.logger.debug(f"Using cached deps.dev data for {cve_id}")
                        return json.load(f)

            # Query deps.dev API - use the query endpoint to search for CVE
            # The deps.dev API v3alpha uses a different structure
            async with aiohttp.ClientSession() as session:
                # First, search for packages affected by this CVE
                query_url = f"{self.deps_dev_base_url}/query?q={quote(cve_id)}"

                search_result = await self._make_request_with_retry(session, query_url)
                if not search_result:
                    self.logger.debug(f"No deps.dev query results for {cve_id}")
                    # Try alternative: get known advisories
                    return await self._fetch_via_osv(session, cve_id)

                # Process search results to find affected packages
                affected_packages = await self._process_search_results(
                    session, search_result, cve_id
                )

                # Cache the result
                if affected_packages and affected_packages["total_affected"] > 0:
                    with open(cache_file, "w") as f:
                        json.dump(affected_packages, f, indent=2)

                return affected_packages

        except Exception as e:
            self.logger.error(f"Error in fetch_deps_dev_data for {cve_id}: {e}")
            return None

    async def _fetch_via_osv(
        self, session: aiohttp.ClientSession, cve_id: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch vulnerability data via OSV (Open Source Vulnerabilities) format."""
        try:
            # Try OSV endpoint which deps.dev supports
            osv_url = f"https://api.osv.dev/v1/vulns/{quote(cve_id)}"

            osv_data = await self._make_request_with_retry(session, osv_url)
            if osv_data and "affected" in osv_data:
                return self._process_osv_response(osv_data)

            return None
        except Exception as e:
            self.logger.error(f"Error fetching OSV data: {e}")
            return None

    async def _process_search_results(
        self, session: aiohttp.ClientSession, search_data: Dict[str, Any], cve_id: str
    ) -> Dict[str, Any]:
        """Process search results and fetch detailed package information."""
        affected_packages = {
            "packages": [],
            "total_affected": 0,
            "ecosystems": set(),
            "severity_breakdown": {},
            "dependency_chains": [],
        }

        # Extract results from search
        results = search_data.get("results", [])

        for result in results[:50]:  # Limit to avoid too many requests
            if result.get("type") == "package":
                package_key = result.get("package", {})
                ecosystem = package_key.get("system", "")
                name = package_key.get("name", "")

                if ecosystem and name:
                    # Fetch detailed package info
                    package_info = await self._fetch_package_details(
                        session, ecosystem, name, cve_id
                    )
                    if package_info:
                        affected_packages["packages"].append(package_info)
                        affected_packages["ecosystems"].add(ecosystem)

        # Convert set to list and calculate totals
        affected_packages["ecosystems"] = list(affected_packages["ecosystems"])
        affected_packages["total_affected"] = len(affected_packages["packages"])

        # Calculate severity breakdown
        for pkg in affected_packages["packages"]:
            severity = pkg.get("severity", "UNKNOWN")
            affected_packages["severity_breakdown"][severity] = (
                affected_packages["severity_breakdown"].get(severity, 0) + 1
            )

        return affected_packages

    async def _fetch_package_details(
        self, session: aiohttp.ClientSession, ecosystem: str, name: str, cve_id: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch detailed package information including versions and dependencies."""
        try:
            # Get package info
            package_url = f"{self.deps_dev_base_url}/systems/{quote(ecosystem)}/packages/{quote(name)}"

            package_data = await self._make_request_with_retry(session, package_url)
            if not package_data:
                return None

            # Get version info and advisories
            versions_url = f"{package_url}/versions"
            versions_data = await self._make_request_with_retry(session, versions_url)

            # Process package information
            package_info = {
                "ecosystem": ecosystem,
                "name": name,
                "description": package_data.get("description", ""),
                "homepage": package_data.get("homepage", ""),
                "repository": package_data.get("repository", ""),
                "affected_versions": [],
                "fixed_versions": [],
                "severity": "UNKNOWN",
                "dependency_count": 0,
                "version_range": "",
                "patch_available": False,
            }

            # Analyze versions for vulnerability info
            if versions_data:
                package_info.update(self._analyze_versions(versions_data, cve_id))

            return package_info

        except Exception as e:
            self.logger.error(
                f"Error fetching package details for {ecosystem}/{name}: {e}"
            )
            return None

    def _analyze_versions(
        self, versions_data: Dict[str, Any], cve_id: str
    ) -> Dict[str, Any]:
        """Analyze version data to find affected and fixed versions."""
        analysis = {
            "affected_versions": [],
            "fixed_versions": [],
            "version_range": "",
            "patch_available": False,
            "latest_safe_version": None,
        }

        versions = versions_data.get("versions", [])
        affected_found = False

        for version in versions:
            version_key = version.get("versionKey", {})
            version_name = version_key.get("version", "")

            # Check advisories for this version
            advisories = version.get("advisories", [])
            is_affected = any(adv.get("id") == cve_id for adv in advisories)

            if is_affected:
                affected_found = True
                analysis["affected_versions"].append(version_name)
            elif affected_found:
                # Version after affected ones might be fixed
                analysis["fixed_versions"].append(version_name)
                if not analysis["latest_safe_version"]:
                    analysis["latest_safe_version"] = version_name
                    analysis["patch_available"] = True

        # Create version range string
        if analysis["affected_versions"]:
            if len(analysis["affected_versions"]) == 1:
                analysis["version_range"] = f"= {analysis['affected_versions'][0]}"
            else:
                analysis["version_range"] = (
                    f">= {analysis['affected_versions'][0]} <= {analysis['affected_versions'][-1]}"
                )

        return analysis

    def _process_osv_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process OSV (Open Source Vulnerabilities) response format."""
        affected_packages = {
            "packages": [],
            "total_affected": 0,
            "ecosystems": set(),
            "severity_breakdown": {},
            "dependency_chains": [],
        }

        # Extract severity information
        severity = "UNKNOWN"
        if "severity" in data:
            for sev in data["severity"]:
                if sev.get("type") == "CVSS_V3":
                    score = sev.get("score", 0)
                    if score >= 9.0:
                        severity = "CRITICAL"
                    elif score >= 7.0:
                        severity = "HIGH"
                    elif score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                    break

        # Extract affected packages from OSV format
        if "affected" in data:
            for affected in data["affected"]:
                package = affected.get("package", {})
                ecosystem = package.get("ecosystem", "").lower()
                name = package.get("name", "")

                if ecosystem and name:
                    # Map ecosystem names to deps.dev format
                    ecosystem_mapped = self._map_ecosystem_name(ecosystem)

                    package_info = {
                        "ecosystem": ecosystem_mapped,
                        "name": name,
                        "severity": severity,
                        "affected_versions": [],
                        "fixed_versions": [],
                        "version_range": "",
                        "patch_available": False,
                        "database_specific": affected.get("database_specific", {}),
                    }

                    # Process version ranges
                    for range_info in affected.get("ranges", []):
                        events = range_info.get("events", [])

                        introduced = None
                        fixed = None

                        for event in events:
                            if "introduced" in event:
                                introduced = event["introduced"]
                                if introduced and introduced != "0":
                                    package_info["affected_versions"].append(introduced)
                            elif "fixed" in event:
                                fixed = event["fixed"]
                                if fixed:
                                    package_info["fixed_versions"].append(fixed)
                                    package_info["patch_available"] = True

                        # Build version range string
                        if introduced and fixed:
                            package_info["version_range"] = f">= {introduced} < {fixed}"
                        elif introduced:
                            package_info["version_range"] = f">= {introduced}"

                    # Also check specific versions
                    versions = affected.get("versions", [])
                    if versions:
                        package_info["affected_versions"].extend(versions)
                        if not package_info["version_range"]:
                            package_info["version_range"] = (
                                f"in [{', '.join(versions)}]"
                            )

                    affected_packages["packages"].append(package_info)
                    affected_packages["ecosystems"].add(ecosystem_mapped)

        # Convert set to list and calculate totals
        affected_packages["ecosystems"] = list(affected_packages["ecosystems"])
        affected_packages["total_affected"] = len(affected_packages["packages"])

        # Calculate severity breakdown
        for pkg in affected_packages["packages"]:
            pkg_severity = pkg.get("severity", "UNKNOWN")
            affected_packages["severity_breakdown"][pkg_severity] = (
                affected_packages["severity_breakdown"].get(pkg_severity, 0) + 1
            )

        return affected_packages

    def _map_ecosystem_name(self, ecosystem: str) -> str:
        """Map various ecosystem names to deps.dev standard names."""
        ecosystem_lower = ecosystem.lower()

        # Direct mappings
        if ecosystem_lower in self.ECOSYSTEM_MAPPING:
            return self.ECOSYSTEM_MAPPING[ecosystem_lower]

        # Common variations
        variations = {
            "npm": ["node", "nodejs", "javascript"],
            "pypi": ["python", "pip"],
            "maven": ["java", "mvn"],
            "nuget": ["dotnet", ".net", "csharp"],
            "cargo": ["rust", "crates", "crates.io"],
            "go": ["golang"],
            "rubygems": ["ruby", "gem"],
            "packagist": ["php", "composer"],
            "hex": ["elixir", "erlang"],
            "docker": ["container", "dockerhub"],
        }

        for standard, alts in variations.items():
            if ecosystem_lower in alts:
                return standard

        # Return original if no mapping found
        return ecosystem

    async def enrich_cve_data(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich CVE data with external sources."""
        # Try both camelCase and snake_case keys
        cve_id = cve_data.get("cveId", cve_data.get("cve_id", ""))

        # Start with original data
        enriched_data = cve_data.copy()

        # Add enrichment metadata
        enriched_data["enrichment"] = {
            "timestamp": datetime.now().isoformat(),
            "sources": [],
        }

        # Fetch deps.dev data
        deps_data = await self.fetch_deps_dev_data(cve_id)
        if deps_data and deps_data["total_affected"] > 0:
            enriched_data["enrichment"]["deps_dev"] = deps_data
            enriched_data["enrichment"]["sources"].append("deps.dev")

            # Add summary statistics
            enriched_data["enrichment"]["impact_summary"] = {
                "total_affected_packages": deps_data["total_affected"],
                "affected_ecosystems": deps_data["ecosystems"],
                "has_impact_data": True,
                "severity_breakdown": deps_data.get("severity_breakdown", {}),
                "patch_availability": self._calculate_patch_availability(deps_data),
            }

            # Add formatted package impact for display
            enriched_data["enrichment"]["package_impact"] = self._format_package_impact(
                deps_data
            )

            # Also add to top-level for static page generator compatibility
            enriched_data["has_deps_data"] = True
            enriched_data["total_affected_packages"] = deps_data["total_affected"]
            enriched_data["affected_ecosystems"] = deps_data["ecosystems"]
        else:
            enriched_data["enrichment"]["impact_summary"] = {
                "total_affected_packages": 0,
                "affected_ecosystems": [],
                "has_impact_data": False,
                "severity_breakdown": {},
                "patch_availability": {"total": 0, "patched": 0, "percentage": 0},
            }

            # Top-level compatibility
            enriched_data["has_deps_data"] = False
            enriched_data["total_affected_packages"] = 0
            enriched_data["affected_ecosystems"] = []

        # Extract CWE/Problem types from the original data
        problem_types = self._extract_problem_types(cve_data)
        if problem_types:
            enriched_data["enrichment"]["problem_types"] = problem_types
            enriched_data["enrichment"]["sources"].append("cve_schema")

            # Add CWE IDs to top-level if not already present
            if "cwe_ids" not in enriched_data:
                enriched_data["cwe_ids"] = [
                    pt["id"] for pt in problem_types if pt["type"] == "CWE"
                ]

        # Extract structured affected versions
        structured_affected = self._extract_structured_affected(cve_data)
        if structured_affected:
            enriched_data["enrichment"]["structured_affected"] = structured_affected

        # Extract all references from all containers
        all_references = self._extract_all_references(cve_data)
        if all_references:
            enriched_data["enrichment"]["all_references"] = all_references

            # Categorize references for better display
            enriched_data["enrichment"]["categorized_references"] = (
                self._categorize_references(all_references)
            )

        # Add exploitation intelligence
        enriched_data["enrichment"]["exploitation_intel"] = (
            self._analyze_exploitation_risk(enriched_data)
        )

        return enriched_data

    def _calculate_patch_availability(
        self, deps_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate patch availability statistics."""
        total = 0
        patched = 0

        for package in deps_data.get("packages", []):
            total += 1
            if package.get("patch_available", False):
                patched += 1

        percentage = (patched / total * 100) if total > 0 else 0

        return {"total": total, "patched": patched, "percentage": round(percentage, 1)}

    def _format_package_impact(self, deps_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format package impact information for display."""
        formatted_packages = []

        for package in deps_data.get("packages", []):
            formatted = {
                "ecosystem": package["ecosystem"],
                "name": package["name"],
                "version_range": package.get("version_range", "Unknown"),
                "severity": package.get("severity", "UNKNOWN"),
                "patch_available": package.get("patch_available", False),
                "fixed_versions": package.get("fixed_versions", []),
                "latest_safe_version": package.get("latest_safe_version"),
                "repository": package.get("repository", ""),
                "affected_version_count": len(package.get("affected_versions", [])),
            }
            formatted_packages.append(formatted)

        # Sort by severity and ecosystem
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        formatted_packages.sort(
            key=lambda x: (
                severity_order.get(x["severity"], 4),
                x["ecosystem"],
                x["name"],
            )
        )

        return formatted_packages

    def _categorize_references(
        self, references: List[Dict[str, str]]
    ) -> Dict[str, List[Dict[str, str]]]:
        """Categorize references by type for better organization."""
        categories = {
            "vendor_advisories": [],
            "patches": [],
            "exploits": [],
            "technical_details": [],
            "media_coverage": [],
            "other": [],
        }

        for ref in references:
            tags = ref.get("tags", [])
            url = ref.get("url", "")

            if "Vendor Advisory" in tags:
                categories["vendor_advisories"].append(ref)
            elif "Patch" in tags:
                categories["patches"].append(ref)
            elif "Exploit" in tags:
                categories["exploits"].append(ref)
            elif "Media Coverage" in tags:
                categories["media_coverage"].append(ref)
            elif any(
                tech in url.lower()
                for tech in ["blog", "analysis", "writeup", "research"]
            ):
                categories["technical_details"].append(ref)
            else:
                categories["other"].append(ref)

        # Remove empty categories
        return {k: v for k, v in categories.items() if v}

    def _analyze_exploitation_risk(
        self, enriched_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze exploitation risk based on available data."""
        risk_factors = []
        risk_level = "LOW"

        # Check EPSS score
        epss_score = enriched_data.get("epss_score", 0)
        if epss_score > 70:
            risk_factors.append(f"High EPSS score ({epss_score}%)")
            risk_level = "HIGH"
        elif epss_score > 30:
            risk_factors.append(f"Moderate EPSS score ({epss_score}%)")
            if risk_level == "LOW":
                risk_level = "MEDIUM"

        # Check for exploit references
        refs = enriched_data.get("enrichment", {}).get("all_references", [])
        exploit_refs = [r for r in refs if "Exploit" in r.get("tags", [])]
        if exploit_refs:
            risk_factors.append(
                f"Known exploits available ({len(exploit_refs)} references)"
            )
            risk_level = "HIGH"

        # Check KEV status
        if enriched_data.get("kev_status", False):
            risk_factors.append("Listed in CISA KEV catalog")
            risk_level = "CRITICAL"

        # Check package impact
        total_affected = enriched_data.get("total_affected_packages", 0)
        if total_affected > 100:
            risk_factors.append(
                f"Widespread impact ({total_affected} packages affected)"
            )
            if risk_level in ["LOW", "MEDIUM"]:
                risk_level = "HIGH"
        elif total_affected > 10:
            risk_factors.append(
                f"Significant impact ({total_affected} packages affected)"
            )
            if risk_level == "LOW":
                risk_level = "MEDIUM"

        # Check for popular ecosystems
        ecosystems = enriched_data.get("affected_ecosystems", [])
        popular_ecosystems = ["npm", "pypi", "maven", "nuget"]
        affected_popular = [e for e in ecosystems if e in popular_ecosystems]
        if affected_popular:
            risk_factors.append(
                f"Affects popular ecosystems: {', '.join(affected_popular)}"
            )

        return {
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "recommendation": self._get_risk_recommendation(risk_level, enriched_data),
        }

    def _get_risk_recommendation(self, risk_level: str, data: Dict[str, Any]) -> str:
        """Get risk-based recommendation."""
        patch_info = (
            data.get("enrichment", {})
            .get("impact_summary", {})
            .get("patch_availability", {})
        )
        patch_percentage = patch_info.get("percentage", 0)

        if risk_level == "CRITICAL":
            return "IMMEDIATE ACTION REQUIRED: This vulnerability is actively exploited. Apply patches immediately or implement compensating controls."
        elif risk_level == "HIGH":
            if patch_percentage > 50:
                return "HIGH PRIORITY: Patches are available for most affected packages. Update affected systems within 24-48 hours."
            else:
                return "HIGH PRIORITY: Limited patches available. Implement workarounds and monitor for patch releases."
        elif risk_level == "MEDIUM":
            return "MODERATE PRIORITY: Schedule patching within your normal maintenance window. Monitor for exploitation activity."
        else:
            return "LOW PRIORITY: Monitor for changes in exploitation status. Plan patching with regular updates."

    def _extract_problem_types(self, cve_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract CWE and problem type information from CVE data."""
        problem_types = []

        # Look for CWE patterns in description and tags
        description = cve_data.get("description", "")
        tags = cve_data.get("tags", [])

        # Extract CWE IDs from description
        import re

        cwe_pattern = r"CWE-(\d+)"
        cwe_matches = re.findall(cwe_pattern, description)
        for cwe_id in cwe_matches:
            problem_types.append(
                {
                    "type": "CWE",
                    "id": f"CWE-{cwe_id}",
                    "description": self._get_cwe_description(cwe_id),
                }
            )

        # Also check tags for CWE references
        for tag in tags:
            if tag.startswith("CWE-"):
                cwe_id = tag.replace("CWE-", "")
                if not any(pt["id"] == tag for pt in problem_types):
                    problem_types.append(
                        {
                            "type": "CWE",
                            "id": tag,
                            "description": self._get_cwe_description(cwe_id),
                        }
                    )

        return problem_types

    def _get_cwe_description(self, cwe_id: str) -> str:
        """Get CWE description (could be expanded with a CWE database)."""
        # Common CWE descriptions (can be expanded)
        cwe_descriptions = {
            "79": "Cross-site Scripting (XSS)",
            "89": "SQL Injection",
            "78": "OS Command Injection",
            "22": "Path Traversal",
            "287": "Improper Authentication",
            "285": "Improper Authorization",
            "20": "Improper Input Validation",
            "200": "Information Exposure",
            "119": "Buffer Overflow",
            "416": "Use After Free",
            "476": "NULL Pointer Dereference",
            "190": "Integer Overflow",
            "352": "Cross-Site Request Forgery (CSRF)",
            "434": "Unrestricted Upload of File with Dangerous Type",
            "611": "Improper Restriction of XML External Entity Reference",
            "918": "Server-Side Request Forgery (SSRF)",
        }
        return cwe_descriptions.get(cwe_id, f"CWE-{cwe_id}")

    def _extract_structured_affected(
        self, cve_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Extract structured affected product and version information."""
        structured_affected = []

        # Extract from vendors_list and products_list
        vendors = cve_data.get("vendors_list", [])
        products = cve_data.get("products_list", [])

        # Create structured entries
        for i, vendor in enumerate(vendors):
            product = products[i] if i < len(products) else "Unknown"

            affected_entry = {
                "vendor": vendor,
                "product": product,
                "versions": self._extract_versions_from_title(
                    cve_data.get("title", "")
                ),
                "platforms": [],
                "default_status": "affected",
            }

            structured_affected.append(affected_entry)

        return structured_affected

    def _extract_versions_from_title(self, title: str) -> List[Dict[str, str]]:
        """Extract version information from title."""
        versions = []

        # Common version patterns
        import re

        patterns = [
            r"before\s+(\d+(?:\.\d+)*)",
            r"prior\s+to\s+(\d+(?:\.\d+)*)",
            r"through\s+(\d+(?:\.\d+)*)",
            r"(\d+(?:\.\d+)*)\s+and\s+earlier",
            r"versions?\s+(\d+(?:\.\d+)*)",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, title, re.IGNORECASE)
            for match in matches:
                versions.append(
                    {"version": match, "status": "affected", "version_type": "semver"}
                )

        return versions if versions else [{"version": "Unknown", "status": "affected"}]

    def _extract_all_references(self, cve_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract all references from CVE data."""
        references = []
        seen_urls = set()

        # Extract from references field
        for ref in cve_data.get("references", []):
            url = ref if isinstance(ref, str) else ref.get("url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                references.append(
                    {
                        "url": url,
                        "source": "references",
                        "tags": self._classify_reference(url),
                    }
                )

        # Check description for URLs
        description = cve_data.get("description", "")
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls_in_desc = re.findall(url_pattern, description)
        for url in urls_in_desc:
            if url not in seen_urls:
                seen_urls.add(url)
                references.append(
                    {
                        "url": url,
                        "source": "description",
                        "tags": self._classify_reference(url),
                    }
                )

        return references

    def _classify_reference(self, url: str) -> List[str]:
        """Classify reference URL by type."""
        tags = []

        if "github.com" in url:
            if "/commit/" in url:
                tags.append("Patch")
            elif "/issues/" in url:
                tags.append("Issue Tracking")
            elif "/security/" in url:
                tags.append("Vendor Advisory")
            else:
                tags.append("Third Party Advisory")
        elif "cve.mitre.org" in url:
            tags.append("CVE Record")
        elif any(
            vendor in url
            for vendor in ["microsoft.com", "oracle.com", "cisco.com", "apache.org"]
        ):
            tags.append("Vendor Advisory")
        elif "exploit-db.com" in url or "metasploit" in url:
            tags.append("Exploit")
        elif "youtube.com" in url or "vimeo.com" in url:
            tags.append("Media Coverage")
        else:
            tags.append("Third Party Advisory")

        return tags

    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process enrichment request."""
        try:
            cve_list = data.get("vulnerabilities", [])
            enriched_vulns = []

            # Process CVEs in batches to avoid overwhelming the API
            batch_size = 10
            for i in range(0, len(cve_list), batch_size):
                batch = cve_list[i : i + batch_size]

                # Process batch concurrently
                tasks = [self.enrich_cve_data(cve) for cve in batch]
                batch_results = await asyncio.gather(*tasks)
                enriched_vulns.extend(batch_results)

                # Small delay between batches
                if i + batch_size < len(cve_list):
                    await asyncio.sleep(1)

            return {
                "success": True,
                "data": {"vulnerabilities": enriched_vulns},
                "message": f"Enriched {len(enriched_vulns)} CVEs with external data",
            }

        except Exception as e:
            self.logger.error(f"Error in enrichment process: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to enrich CVE data",
            }

    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute enrichment for a single CVE or batch.

        This is mainly used when the agent is run independently.
        Usually, enrich_cve_data is called directly.
        """
        cve_data = kwargs.get("cve_data")
        if not cve_data:
            return {"success": False, "error": "No CVE data provided"}

        if isinstance(cve_data, dict):
            # Single CVE
            enriched = await self.enrich_cve_data(cve_data)
            return {"success": True, "data": enriched}
        elif isinstance(cve_data, list):
            # Batch
            enriched_list = []
            for cve in cve_data:
                enriched = await self.enrich_cve_data(cve)
                enriched_list.append(enriched)
            return {"success": True, "data": enriched_list}
        else:
            return {"success": False, "error": "Invalid CVE data format"}

    def get_dependencies(self) -> Set[str]:
        """Get dependencies for change detection."""
        return set()  # This agent doesn't have file dependencies
