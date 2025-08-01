#!/usr/bin/env python3
"""Enrichment agent for enhancing vulnerability data with additional context."""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import structlog

from scripts.processing.risk_scorer import RiskScorer
from scripts.processing.vendor_product_extractor import VendorProductExtractor
from scripts.processing.cvss_parser import CVSSVectorParser
from scripts.harvest.epss_client import EPSSClient
from scripts.processing.normalizer import VulnerabilityNormalizer


class EnrichmentAgent:
    """Agent responsible for enriching vulnerability data."""
    
    def __init__(
        self,
        cache_dir: Path = Path(".cache"),
        api_keys: Optional[Dict[str, str]] = None
    ):
        """Initialize enrichment agent.
        
        Args:
            cache_dir: Directory for caching
            api_keys: API keys for enrichment services
        """
        self.logger = structlog.get_logger(self.__class__.__name__)
        self.cache_dir = cache_dir
        self.api_keys = api_keys or {}
        
        # Initialize components
        self.risk_scorer = RiskScorer()
        self.vendor_extractor = VendorProductExtractor()
        self.cvss_parser = CVSSVectorParser()
        self.normalizer = VulnerabilityNormalizer()
        
        # EPSS client for score enrichment
        self.epss_client = EPSSClient(
            api_key=self.api_keys.get("epss_api_key"),
            cache_dir=self.cache_dir / "api_cache"
        )
        
    async def enrich_batch(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Enrich a batch of vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            List of enriched vulnerability dictionaries
        """
        self.logger.info(f"Enriching batch of {len(vulnerabilities)} vulnerabilities")
        
        # Group by enrichment type for efficiency
        enriched_vulns = []
        
        # Process in chunks for better performance
        chunk_size = 100
        for i in range(0, len(vulnerabilities), chunk_size):
            chunk = vulnerabilities[i:i + chunk_size]
            
            # Enrich chunk
            enriched_chunk = await self._enrich_chunk(chunk)
            enriched_vulns.extend(enriched_chunk)
            
        self.logger.info(f"Enrichment complete: {len(enriched_vulns)} vulnerabilities")
        return enriched_vulns
        
    async def _enrich_chunk(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Enrich a chunk of vulnerabilities."""
        # Extract CVE IDs for bulk operations
        cve_ids = [v["cve_id"] for v in vulnerabilities if v.get("cve_id")]
        
        # Fetch EPSS scores in bulk if needed
        epss_scores = await self._fetch_epss_scores(cve_ids)
        
        # Enrich each vulnerability
        enriched = []
        for vuln in vulnerabilities:
            enriched_vuln = await self._enrich_single(vuln, epss_scores)
            enriched.append(enriched_vuln)
            
        return enriched
        
    async def _enrich_single(
        self,
        vuln: Dict[str, Any],
        epss_scores: Dict[str, Dict[str, float]]
    ) -> Dict[str, Any]:
        """Enrich a single vulnerability."""
        # Make a copy to avoid modifying original
        enriched = vuln.copy()
        
        # 1. Extract vendor/product if missing
        if not enriched.get("vendor") or enriched.get("vendor") == "Unknown":
            vendors, products = self.vendor_extractor.extract_vendors_products(
                cve_data=enriched,
                description=enriched.get("description", ""),
                title=enriched.get("title", "")
            )
            
            if vendors:
                enriched["vendor"] = vendors[0]
            if products:
                enriched["product"] = products[0]
                
        # 2. Parse CVSS vector if available
        if enriched.get("cvss_vector_string"):
            cvss_details = self.cvss_parser.parse_cvss_vector(
                enriched["cvss_vector_string"]
            )
            enriched.update(cvss_details)
            
        # 3. Add/update EPSS score
        cve_id = enriched.get("cve_id")
        if cve_id and cve_id in epss_scores:
            enriched["epss_probability"] = epss_scores[cve_id].get("epss", 0) * 100
            enriched["epss_percentile"] = epss_scores[cve_id].get("percentile", 0) * 100
            
        # 4. Calculate risk score
        enriched["risk_score"] = self._calculate_risk_score(enriched)
        
        # 5. Add enrichment metadata
        enriched["enrichment_metadata"] = {
            "enriched_at": datetime.now(timezone.utc).isoformat(),
            "enrichment_version": "1.0",
            "vendor_extracted": enriched.get("vendor") != vuln.get("vendor"),
            "product_extracted": enriched.get("product") != vuln.get("product"),
            "epss_added": "epss_probability" in enriched and "epss_probability" not in vuln,
            "cvss_parsed": "attack_vector" in enriched and "attack_vector" not in vuln
        }
        
        # 6. Add infrastructure tags
        enriched["tags"] = self._generate_tags(enriched)
        
        return enriched
        
    async def _fetch_epss_scores(
        self,
        cve_ids: List[str]
    ) -> Dict[str, Dict[str, float]]:
        """Fetch EPSS scores for CVEs that need them."""
        if not cve_ids:
            return {}
            
        try:
            return self.epss_client.fetch_epss_scores_bulk(cve_ids)
        except Exception as e:
            self.logger.warning(f"Failed to fetch EPSS scores: {str(e)}")
            return {}
            
    def _calculate_risk_score(self, vuln: Dict[str, Any]) -> int:
        """Calculate risk score for a vulnerability."""
        # Use existing risk scorer logic
        from scripts.models import Vulnerability, SeverityLevel
        
        # Create temporary Vulnerability object for scoring
        severity_map = {
            "CRITICAL": SeverityLevel.CRITICAL,
            "HIGH": SeverityLevel.HIGH,
            "MEDIUM": SeverityLevel.MEDIUM,
            "LOW": SeverityLevel.LOW
        }
        
        temp_vuln = Vulnerability(
            cve_id=vuln.get("cve_id", ""),
            severity=severity_map.get(vuln.get("severity", "MEDIUM"), SeverityLevel.MEDIUM),
            cvss_base_score=vuln.get("cvss_base_score"),
            epss_probability=vuln.get("epss_probability"),
            published_date=datetime.fromisoformat(vuln["published_date"]) if vuln.get("published_date") else None,
            vendor=vuln.get("vendor"),
            product=vuln.get("product"),
            description=vuln.get("description", "")
        )
        
        return self.risk_scorer.calculate_risk_score(temp_vuln)
        
    def _generate_tags(self, vuln: Dict[str, Any]) -> List[str]:
        """Generate tags for a vulnerability."""
        tags = []
        
        # Infrastructure tags
        description = (vuln.get("description", "") + " " + 
                      vuln.get("vendor", "") + " " + 
                      vuln.get("product", "")).lower()
        
        infrastructure_keywords = {
            "network": ["network", "router", "switch", "firewall", "vpn"],
            "web": ["web", "http", "apache", "nginx", "tomcat"],
            "database": ["database", "sql", "mysql", "postgresql", "oracle"],
            "cloud": ["cloud", "aws", "azure", "gcp", "kubernetes"],
            "container": ["docker", "container", "kubernetes", "k8s"],
            "iot": ["iot", "embedded", "firmware", "device"],
            "mobile": ["android", "ios", "mobile", "app"],
            "windows": ["windows", "microsoft", "active directory"],
            "linux": ["linux", "ubuntu", "debian", "redhat", "centos"]
        }
        
        for tag, keywords in infrastructure_keywords.items():
            if any(keyword in description for keyword in keywords):
                tags.append(tag)
                
        # Exploitation tags
        if vuln.get("epss_probability", 0) > 90:
            tags.append("high-exploitation-risk")
        if vuln.get("epss_probability", 0) > 95:
            tags.append("critical-exploitation-risk")
            
        # Attack vector tags
        attack_vector = vuln.get("attack_vector", "").upper()
        if attack_vector == "NETWORK":
            tags.append("remote-exploitable")
        elif attack_vector == "LOCAL":
            tags.append("local-access-required")
            
        # Severity tags
        if vuln.get("severity") == "CRITICAL":
            tags.append("critical-severity")
        elif vuln.get("cvss_base_score", 0) >= 9.0:
            tags.append("high-impact")
            
        return list(set(tags))  # Remove duplicates
        
    async def enrich_with_external_data(
        self,
        vulnerabilities: List[Dict[str, Any]],
        sources: List[str] = None
    ) -> List[Dict[str, Any]]:
        """Enrich with additional external data sources.
        
        Args:
            vulnerabilities: List of vulnerabilities to enrich
            sources: External sources to use (future expansion)
            
        Returns:
            Enriched vulnerabilities
        """
        # This method is a placeholder for future external enrichment sources
        # such as:
        # - Exploit databases
        # - Threat intelligence feeds
        # - Patch availability information
        # - Attack patterns and techniques (MITRE ATT&CK)
        
        self.logger.info("External enrichment not yet implemented")
        return vulnerabilities


# CLI interface
async def main():
    """Main CLI entry point."""
    import argparse
    import json
    import os
    
    parser = argparse.ArgumentParser(description="Enrich vulnerability data")
    parser.add_argument("input", type=Path, help="Input JSON file with vulnerabilities")
    parser.add_argument("--output", type=Path, help="Output file path")
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache"))
    
    args = parser.parse_args()
    
    # Load input data
    with open(args.input) as f:
        data = json.load(f)
        
    # Extract vulnerabilities from input
    if isinstance(data, list):
        vulnerabilities = data
    elif isinstance(data, dict) and "vulnerabilities" in data:
        vulnerabilities = data["vulnerabilities"]
    else:
        print("Error: Input must be a list of vulnerabilities or contain 'vulnerabilities' key")
        return
        
    # Get API keys from environment
    api_keys = {
        "epss_api_key": os.getenv("EPSS_API_KEY")
    }
    
    # Create agent and enrich
    agent = EnrichmentAgent(cache_dir=args.cache_dir, api_keys=api_keys)
    enriched = await agent.enrich_batch(vulnerabilities)
    
    # Output results
    output_data = {
        "vulnerabilities": enriched,
        "enrichment_metadata": {
            "total_processed": len(enriched),
            "enriched_at": datetime.now(timezone.utc).isoformat(),
            "enrichment_version": "1.0"
        }
    }
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2, default=str)
        print(f"Enriched data saved to {args.output}")
    else:
        print(json.dumps(output_data, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())