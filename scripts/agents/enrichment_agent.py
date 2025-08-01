"""
DataEnrichmentAgent - Enriches CVE data with external sources like deps.dev
"""

import asyncio
import json
import logging
import re
from typing import Dict, List, Optional, Any, Set
from pathlib import Path
import aiohttp
from datetime import datetime, timedelta

from scripts.agents.base_agent import BaseAgent


class DataEnrichmentAgent(BaseAgent):
    """Agent for enriching CVE data with external sources."""
    
    def __init__(self, cache_dir: Path = None):
        super().__init__(name="DataEnrichmentAgent", cache_dir=cache_dir)
        self.deps_dev_base_url = "https://api.deps.dev/v3"
        self.cache_dir = Path(".cache/enrichment")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = timedelta(hours=24)
        
    async def fetch_deps_dev_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch affected packages from deps.dev API for a given CVE."""
        try:
            # Check cache first
            cache_file = self.cache_dir / f"{cve_id}_deps.json"
            if cache_file.exists():
                # Check if cache is still valid
                cache_time = datetime.fromtimestamp(cache_file.stat().st_mtime)
                if datetime.now() - cache_time < self.cache_ttl:
                    with open(cache_file, 'r') as f:
                        self.logger.debug(f"Using cached deps.dev data for {cve_id}")
                        return json.load(f)
            
            # Query deps.dev API
            # The API endpoint for advisory/vulnerability information
            url = f"{self.deps_dev_base_url}/advisories/{cve_id}"
            
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            # Process the response to extract affected packages
                            affected_packages = self._process_deps_dev_response(data)
                            
                            # Cache the result
                            with open(cache_file, 'w') as f:
                                json.dump(affected_packages, f, indent=2)
                            
                            return affected_packages
                        elif response.status == 404:
                            self.logger.debug(f"No deps.dev data found for {cve_id}")
                            return None
                        else:
                            self.logger.warning(f"deps.dev API returned status {response.status} for {cve_id}")
                            return None
                except asyncio.TimeoutError:
                    self.logger.warning(f"Timeout fetching deps.dev data for {cve_id}")
                    return None
                except Exception as e:
                    self.logger.error(f"Error fetching deps.dev data for {cve_id}: {e}")
                    return None
                    
        except Exception as e:
            self.logger.error(f"Error in fetch_deps_dev_data for {cve_id}: {e}")
            return None
    
    def _process_deps_dev_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process deps.dev API response to extract relevant information."""
        affected_packages = {
            "packages": [],
            "total_affected": 0,
            "ecosystems": set()
        }
        
        # Extract affected packages from the advisory data
        if "affected" in data:
            for affected in data["affected"]:
                package_info = {
                    "ecosystem": affected.get("package", {}).get("ecosystem", ""),
                    "name": affected.get("package", {}).get("name", ""),
                    "versions": affected.get("versions", []),
                    "severity": affected.get("severity", []),
                    "database_specific": affected.get("database_specific", {})
                }
                
                if package_info["ecosystem"] and package_info["name"]:
                    affected_packages["packages"].append(package_info)
                    affected_packages["ecosystems"].add(package_info["ecosystem"])
        
        # Convert set to list for JSON serialization
        affected_packages["ecosystems"] = list(affected_packages["ecosystems"])
        affected_packages["total_affected"] = len(affected_packages["packages"])
        
        return affected_packages
    
    async def enrich_cve_data(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich CVE data with external sources."""
        # Try both camelCase and snake_case keys
        cve_id = cve_data.get("cveId", cve_data.get("cve_id", ""))
        
        # Start with original data
        enriched_data = cve_data.copy()
        
        # Add enrichment metadata
        enriched_data["enrichment"] = {
            "timestamp": datetime.now().isoformat(),
            "sources": []
        }
        
        # Fetch deps.dev data
        deps_data = await self.fetch_deps_dev_data(cve_id)
        if deps_data:
            enriched_data["enrichment"]["deps_dev"] = deps_data
            enriched_data["enrichment"]["sources"].append("deps.dev")
            
            # Add summary statistics
            enriched_data["enrichment"]["impact_summary"] = {
                "total_affected_packages": deps_data["total_affected"],
                "affected_ecosystems": deps_data["ecosystems"],
                "has_impact_data": True
            }
        else:
            enriched_data["enrichment"]["impact_summary"] = {
                "total_affected_packages": 0,
                "affected_ecosystems": [],
                "has_impact_data": False
            }
        
        # Extract CWE/Problem types from the original data
        problem_types = self._extract_problem_types(cve_data)
        if problem_types:
            enriched_data["enrichment"]["problem_types"] = problem_types
            enriched_data["enrichment"]["sources"].append("cve_schema")
        
        # Extract structured affected versions
        structured_affected = self._extract_structured_affected(cve_data)
        if structured_affected:
            enriched_data["enrichment"]["structured_affected"] = structured_affected
        
        # Extract all references from all containers
        all_references = self._extract_all_references(cve_data)
        if all_references:
            enriched_data["enrichment"]["all_references"] = all_references
        
        return enriched_data
    
    def _extract_problem_types(self, cve_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract CWE and problem type information from CVE data."""
        problem_types = []
        
        # Look for CWE patterns in description and tags
        description = cve_data.get("description", "")
        tags = cve_data.get("tags", [])
        
        # Extract CWE IDs from description
        import re
        cwe_pattern = r'CWE-(\d+)'
        cwe_matches = re.findall(cwe_pattern, description)
        for cwe_id in cwe_matches:
            problem_types.append({
                "type": "CWE",
                "id": f"CWE-{cwe_id}",
                "description": self._get_cwe_description(cwe_id)
            })
        
        # Also check tags for CWE references
        for tag in tags:
            if tag.startswith("CWE-"):
                cwe_id = tag.replace("CWE-", "")
                if not any(pt["id"] == tag for pt in problem_types):
                    problem_types.append({
                        "type": "CWE",
                        "id": tag,
                        "description": self._get_cwe_description(cwe_id)
                    })
        
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
    
    def _extract_structured_affected(self, cve_data: Dict[str, Any]) -> List[Dict[str, Any]]:
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
                "versions": self._extract_versions_from_title(cve_data.get("title", "")),
                "platforms": [],
                "default_status": "affected"
            }
            
            structured_affected.append(affected_entry)
        
        return structured_affected
    
    def _extract_versions_from_title(self, title: str) -> List[Dict[str, str]]:
        """Extract version information from title."""
        versions = []
        
        # Common version patterns
        import re
        patterns = [
            r'before\s+(\d+(?:\.\d+)*)',
            r'prior\s+to\s+(\d+(?:\.\d+)*)',
            r'through\s+(\d+(?:\.\d+)*)',
            r'(\d+(?:\.\d+)*)\s+and\s+earlier',
            r'versions?\s+(\d+(?:\.\d+)*)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, title, re.IGNORECASE)
            for match in matches:
                versions.append({
                    "version": match,
                    "status": "affected",
                    "version_type": "semver"
                })
        
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
                references.append({
                    "url": url,
                    "source": "references",
                    "tags": self._classify_reference(url)
                })
        
        # Check description for URLs
        description = cve_data.get("description", "")
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls_in_desc = re.findall(url_pattern, description)
        for url in urls_in_desc:
            if url not in seen_urls:
                seen_urls.add(url)
                references.append({
                    "url": url,
                    "source": "description",
                    "tags": self._classify_reference(url)
                })
        
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
        elif any(vendor in url for vendor in ["microsoft.com", "oracle.com", "cisco.com", "apache.org"]):
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
                batch = cve_list[i:i + batch_size]
                
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
                "message": f"Enriched {len(enriched_vulns)} CVEs with external data"
            }
            
        except Exception as e:
            self.logger.error(f"Error in enrichment process: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to enrich CVE data"
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