#!/usr/bin/env python3
"""
DepsDevEnrichmentAgent - Enriches vulnerability data with deps.dev package impact information.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from scripts.agents.base_agent import BaseAgent


class DepsDevEnrichmentAgent(BaseAgent):
    """Agent for enriching vulnerabilities with deps.dev package impact data."""

    def __init__(self, cache_dir: Optional[Path] = None):
        """
        Initialize DepsDevEnrichmentAgent.

        Args:
            cache_dir: Directory for caching enriched data
        """
        super().__init__(name="DepsDevEnrichmentAgent", cache_dir=cache_dir)

        self.ecosystem_mappings = {
            "npm": "npm",
            "pypi": "pypi",
            "pip": "pypi",
            "maven": "maven",
            "rubygems": "rubygems",
            "nuget": "nuget",
            "packagist": "packagist",
            "cargo": "cargo",
            "go": "go",
            "golang": "go",
            "crates.io": "cargo",
            "hex": "hex",
            "pub": "pub",
            "cocoapods": "cocoapods"
        }

        self.logger.info("DepsDevEnrichmentAgent initialized")

    def extract_package_info(self, vulnerability: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract package information from vulnerability data.

        Args:
            vulnerability: Vulnerability dictionary

        Returns:
            List of package info dictionaries with ecosystem, name, and versions
        """
        packages = []

        # Check various fields for package information
        # 1. Check affected products/packages
        affected = vulnerability.get("affected", [])
        if isinstance(affected, list):
            for item in affected:
                if isinstance(item, dict):
                    package_info = self._extract_from_affected_item(item)
                    if package_info:
                        packages.extend(package_info)

        # 2. Check vendor/product fields
        vendors = vulnerability.get("vendors", [])
        products = vulnerability.get("products", [])

        for vendor in vendors:
            for product in products:
                package_info = self._infer_package_from_vendor_product(vendor, product)
                if package_info:
                    packages.append(package_info)

        # 3. Check description for package mentions
        description = vulnerability.get("description", "")
        title = vulnerability.get("title", "")

        desc_packages = self._extract_packages_from_text(description + " " + title)
        packages.extend(desc_packages)

        # 4. Check references for package URLs
        references = vulnerability.get("references", [])
        for ref in references:
            if isinstance(ref, dict):
                url = ref.get("url", "")
                ref_packages = self._extract_packages_from_url(url)
                packages.extend(ref_packages)

        # Deduplicate packages
        unique_packages = []
        seen = set()

        for pkg in packages:
            key = f"{pkg['ecosystem']}:{pkg['name']}"
            if key not in seen:
                seen.add(key)
                unique_packages.append(pkg)

        return unique_packages

    def _extract_from_affected_item(self, affected_item: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract package info from an affected item."""
        packages = []

        # Check for package field
        package = affected_item.get("package")
        if package:
            ecosystem = package.get("ecosystem", "").lower()
            name = package.get("name", "")

            if ecosystem and name:
                # Map to deps.dev ecosystem
                deps_ecosystem = self.ecosystem_mappings.get(ecosystem, ecosystem)

                package_info = {
                    "ecosystem": deps_ecosystem,
                    "name": name,
                    "versions": []
                }

                # Extract versions
                versions = affected_item.get("versions", [])
                ranges = affected_item.get("ranges", [])

                if versions:
                    package_info["versions"] = versions
                elif ranges:
                    # Extract version info from ranges
                    for range_item in ranges:
                        if isinstance(range_item, dict):
                            events = range_item.get("events", [])
                            for event in events:
                                if isinstance(event, dict):
                                    if event.get("introduced"):
                                        package_info["versions"].append(f">={event['introduced']}")
                                    if event.get("fixed"):
                                        package_info["versions"].append(f"<{event['fixed']}")

                packages.append(package_info)

        return packages

    def _infer_package_from_vendor_product(self, vendor: str, product: str) -> Optional[Dict[str, Any]]:
        """Infer package information from vendor/product combination."""
        # Common vendor/product to package mappings
        known_packages = {
            ("wordpress", "wordpress"): {"ecosystem": "packagist", "name": "wordpress/wordpress"},
            ("microsoft", "typescript"): {"ecosystem": "npm", "name": "typescript"},
            ("facebook", "react"): {"ecosystem": "npm", "name": "react"},
            ("angular", "angular"): {"ecosystem": "npm", "name": "@angular/core"},
            ("vuejs", "vue"): {"ecosystem": "npm", "name": "vue"},
            ("django", "django"): {"ecosystem": "pypi", "name": "django"},
            ("flask", "flask"): {"ecosystem": "pypi", "name": "flask"},
            ("rails", "rails"): {"ecosystem": "rubygems", "name": "rails"},
            ("kubernetes", "kubernetes"): {"ecosystem": "go", "name": "k8s.io/kubernetes"},
            ("docker", "docker"): {"ecosystem": "go", "name": "github.com/docker/docker"},
        }

        key = (vendor.lower(), product.lower())
        if key in known_packages:
            return known_packages[key].copy()

        # Try to infer NPM packages
        if product.lower() in ["npm", "node", "nodejs"]:
            return None

        # Check if product looks like a package name
        if "/" in product or "@" in product:
            # Likely an npm scoped package
            return {"ecosystem": "npm", "name": product, "versions": []}

        return None

    def _extract_packages_from_text(self, text: str) -> List[Dict[str, Any]]:
        """Extract package mentions from text."""
        packages = []

        # NPM package patterns
        npm_patterns = [
            r'npm\s+package\s+["`]?([a-zA-Z0-9@\-/._]+)["`]?',
            r'@[a-zA-Z0-9\-]+/[a-zA-Z0-9\-._]+',  # Scoped packages
            r'package\.json.*["`]([a-zA-Z0-9\-._]+)["`]',
        ]

        for pattern in npm_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                packages.append({
                    "ecosystem": "npm",
                    "name": match,
                    "versions": []
                })

        # PyPI package patterns
        pypi_patterns = [
            r'pip\s+install\s+([a-zA-Z0-9\-._]+)',
            r'pypi\.org/project/([a-zA-Z0-9\-._]+)',
            r'python\s+package\s+["`]?([a-zA-Z0-9\-._]+)["`]?',
        ]

        for pattern in pypi_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                packages.append({
                    "ecosystem": "pypi",
                    "name": match,
                    "versions": []
                })

        # Maven/Java patterns
        maven_patterns = [
            r'groupId["\s:]+([a-zA-Z0-9\-.]+)["\s]+artifactId["\s:]+([a-zA-Z0-9\-._]+)',
            r'([a-zA-Z0-9\-.]+):([a-zA-Z0-9\-._]+):[0-9\-.]+',  # Maven coordinates
        ]

        for pattern in maven_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if isinstance(match, tuple) and len(match) == 2:
                    packages.append({
                        "ecosystem": "maven",
                        "name": f"{match[0]}:{match[1]}",
                        "versions": []
                    })

        return packages

    def _extract_packages_from_url(self, url: str) -> List[Dict[str, Any]]:
        """Extract package information from reference URLs."""
        packages = []

        # NPM registry URLs
        if "npmjs.com/package/" in url:
            match = re.search(r'npmjs\.com/package/([a-zA-Z0-9@\-/._]+)', url)
            if match:
                packages.append({
                    "ecosystem": "npm",
                    "name": match.group(1),
                    "versions": []
                })

        # PyPI URLs
        if "pypi.org/project/" in url:
            match = re.search(r'pypi\.org/project/([a-zA-Z0-9\-._]+)', url)
            if match:
                packages.append({
                    "ecosystem": "pypi",
                    "name": match.group(1),
                    "versions": []
                })

        # RubyGems URLs
        if "rubygems.org/gems/" in url:
            match = re.search(r'rubygems\.org/gems/([a-zA-Z0-9\-._]+)', url)
            if match:
                packages.append({
                    "ecosystem": "rubygems",
                    "name": match.group(1),
                    "versions": []
                })

        # Maven Central URLs
        if "mvnrepository.com/artifact/" in url:
            match = re.search(r'mvnrepository\.com/artifact/([a-zA-Z0-9\-.]+)/([a-zA-Z0-9\-._]+)', url)
            if match:
                packages.append({
                    "ecosystem": "maven",
                    "name": f"{match.group(1)}:{match.group(2)}",
                    "versions": []
                })

        # Packagist (PHP) URLs
        if "packagist.org/packages/" in url:
            match = re.search(r'packagist\.org/packages/([a-zA-Z0-9\-/._]+)', url)
            if match:
                packages.append({
                    "ecosystem": "packagist",
                    "name": match.group(1),
                    "versions": []
                })

        return packages

    def generate_deps_dev_links(self, packages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate deps.dev links for packages.

        Args:
            packages: List of package info dictionaries

        Returns:
            List of deps.dev link dictionaries
        """
        deps_links = []

        for package in packages:
            ecosystem = package.get("ecosystem", "")
            name = package.get("name", "")
            versions = package.get("versions", [])

            if ecosystem and name:
                # Base URL for deps.dev
                base_url = f"https://deps.dev/{ecosystem}/{quote(name, safe='')}"

                deps_link = {
                    "ecosystem": ecosystem,
                    "package": name,
                    "url": base_url,
                    "title": f"View {name} on deps.dev",
                    "type": "package_impact"
                }

                # Add version-specific links if available
                if versions and len(versions) == 1:
                    version = versions[0]
                    # Clean version string
                    version = version.replace(">=", "").replace("<", "").replace("=", "")
                    deps_link["url"] = f"{base_url}/{quote(version, safe='')}"
                    deps_link["title"] = f"View {name}@{version} on deps.dev"
                    deps_link["version"] = version

                deps_links.append(deps_link)

        return deps_links

    def enrich_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a vulnerability with deps.dev package impact data.

        Args:
            vulnerability: Vulnerability dictionary

        Returns:
            Enriched vulnerability dictionary
        """
        # Extract package information
        packages = self.extract_package_info(vulnerability)

        if packages:
            # Generate deps.dev links
            deps_links = self.generate_deps_dev_links(packages)

            # Add to vulnerability
            if "enrichments" not in vulnerability:
                vulnerability["enrichments"] = {}

            vulnerability["enrichments"]["deps_dev"] = {
                "packages": packages,
                "links": deps_links
            }

            # Also add to references for display
            if "references" not in vulnerability:
                vulnerability["references"] = []

            # Add deps.dev links to references
            for link in deps_links:
                vulnerability["references"].append({
                    "url": link["url"],
                    "source": "deps.dev",
                    "title": link["title"],
                    "type": "Package Impact Analysis",
                    "tags": ["package", "dependency", "impact"]
                })

            self.logger.info(
                "Enriched vulnerability with deps.dev data",
                cve_id=vulnerability.get("cve_id", "Unknown"),
                packages_found=len(packages)
            )

        return vulnerability

    def enrich_batch(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enrich a batch of vulnerabilities.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            List of enriched vulnerabilities
        """
        enriched = []
        enriched_count = 0

        for vuln in vulnerabilities:
            enriched_vuln = self.enrich_vulnerability(vuln.copy())

            if enriched_vuln.get("enrichments", {}).get("deps_dev"):
                enriched_count += 1

            enriched.append(enriched_vuln)

        self.logger.info(
            "Batch enrichment completed",
            total_vulnerabilities=len(vulnerabilities),
            enriched_with_deps_dev=enriched_count
        )

        return enriched

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute deps.dev enrichment task.

        Args:
            task: Task containing 'vulnerabilities' to enrich

        Returns:
            Dictionary with enrichment results
        """
        vulnerabilities = task.get("vulnerabilities", [])

        if not vulnerabilities:
            return {
                "success": False,
                "error": "No vulnerabilities provided"
            }

        # Enrich vulnerabilities
        enriched_vulnerabilities = self.enrich_batch(vulnerabilities)

        # Calculate statistics
        total_enriched = sum(
            1 for v in enriched_vulnerabilities
            if v.get("enrichments", {}).get("deps_dev")
        )

        total_packages = sum(
            len(v.get("enrichments", {}).get("deps_dev", {}).get("packages", []))
            for v in enriched_vulnerabilities
        )

        return {
            "success": True,
            "vulnerabilities": enriched_vulnerabilities,
            "statistics": {
                "total_vulnerabilities": len(vulnerabilities),
                "enriched_with_deps_dev": total_enriched,
                "total_packages_found": total_packages,
                "enrichment_rate": (total_enriched / len(vulnerabilities) * 100) if vulnerabilities else 0
            }
        }

    def get_dependencies(self) -> List[str]:
        """Get agent dependencies."""
        return []
