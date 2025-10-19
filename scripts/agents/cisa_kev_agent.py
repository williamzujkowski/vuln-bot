"""
CISA Known Exploited Vulnerabilities (KEV) Agent.
Fetches and enriches vulnerabilities with CISA KEV catalog data.
"""

import json
from datetime import datetime
from typing import Any, Dict, List

import requests
import structlog

from scripts.agents.base_agent import BaseAgent

logger = structlog.get_logger()


class CISAKEVAgent(BaseAgent):
    """Agent for enriching vulnerabilities with CISA KEV data."""

    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    CACHE_DURATION_HOURS = 24

    def __init__(self):
        super().__init__(
            name="CISAKEVAgent",
            role="threat_intelligence",
            goal="Enrich vulnerabilities with CISA Known Exploited Vulnerabilities data",
            backstory="Identifies vulnerabilities actively exploited in the wild per CISA",
        )
        self.kev_cache = None
        self.kev_cache_time = None
        self.stats = {"kev_enriched": 0, "total_processed": 0, "kev_catalog_size": 0}

    def fetch_kev_catalog(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Fetch the CISA KEV catalog.

        Args:
            force_refresh: Force fetching even if cache is valid

        Returns:
            Dictionary mapping CVE IDs to KEV entries
        """
        # Check cache
        if not force_refresh and self._is_cache_valid():
            logger.info(
                "Using cached KEV catalog",
                entries=len(self.kev_cache),
                cache_age_hours=self._get_cache_age_hours(),
            )
            return self.kev_cache

        logger.info("Fetching CISA KEV catalog", url=self.CISA_KEV_URL)

        try:
            response = requests.get(self.CISA_KEV_URL, timeout=30)
            response.raise_for_status()

            data = response.json()

            # Convert to dictionary keyed by CVE ID
            kev_dict = {}
            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cveID")
                if cve_id:
                    kev_dict[cve_id] = {
                        "vendorProject": vuln.get("vendorProject"),
                        "product": vuln.get("product"),
                        "vulnerabilityName": vuln.get("vulnerabilityName"),
                        "dateAdded": vuln.get("dateAdded"),
                        "shortDescription": vuln.get("shortDescription"),
                        "requiredAction": vuln.get("requiredAction"),
                        "dueDate": vuln.get("dueDate"),
                        "notes": vuln.get("notes"),
                        "knownRansomwareCampaignUse": vuln.get(
                            "knownRansomwareCampaignUse", "Unknown"
                        ),
                    }

            # Update cache
            self.kev_cache = kev_dict
            self.kev_cache_time = datetime.utcnow()
            self.stats["kev_catalog_size"] = len(kev_dict)

            logger.info(
                "KEV catalog fetched successfully",
                total_entries=len(kev_dict),
                catalog_version=data.get("catalogVersion"),
                date_released=data.get("dateReleased"),
            )

            return kev_dict

        except requests.RequestException as e:
            logger.error("Failed to fetch KEV catalog", error=str(e))
            # Return empty dict on error
            return {}
        except json.JSONDecodeError as e:
            logger.error("Failed to parse KEV catalog JSON", error=str(e))
            return {}

    def enrich_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a single vulnerability with KEV data.

        Args:
            vulnerability: Vulnerability dictionary

        Returns:
            Enriched vulnerability dictionary
        """
        cve_id = vulnerability.get("cveId")
        if not cve_id:
            return vulnerability

        # Ensure KEV catalog is loaded
        kev_catalog = self.fetch_kev_catalog()

        # Check if CVE is in KEV catalog
        if cve_id in kev_catalog:
            kev_entry = kev_catalog[cve_id]

            # Add KEV enrichment
            if "enrichments" not in vulnerability:
                vulnerability["enrichments"] = {}

            vulnerability["enrichments"]["cisa_kev"] = {
                "isKnownExploited": True,
                "dateAdded": kev_entry["dateAdded"],
                "vulnerabilityName": kev_entry["vulnerabilityName"],
                "requiredAction": kev_entry["requiredAction"],
                "dueDate": kev_entry["dueDate"],
                "knownRansomwareCampaignUse": kev_entry["knownRansomwareCampaignUse"],
                "notes": kev_entry.get("notes"),
            }

            # Update exploitation status
            vulnerability["exploitationStatus"] = "KNOWN_EXPLOITED"

            # Add KEV reference
            if "references" not in vulnerability:
                vulnerability["references"] = []

            # Check if KEV reference already exists
            kev_ref_exists = any(
                ref.get("url", "").startswith(
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                )
                for ref in vulnerability["references"]
            )

            if not kev_ref_exists:
                vulnerability["references"].append(
                    {
                        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                        "source": "CISA KEV",
                        "tags": ["exploit", "kev"],
                        "category": "exploit",
                        "rel": "noopener noreferrer",
                        "target": "_blank",
                        "domain": "cisa.gov",
                        "icon": "🔥",
                        "title": "CISA Known Exploited Vulnerabilities Catalog",
                    }
                )

            # Add tags
            if "metadata" not in vulnerability:
                vulnerability["metadata"] = {}
            if "tags" not in vulnerability["metadata"]:
                vulnerability["metadata"]["tags"] = []

            if "CISA-KEV" not in vulnerability["metadata"]["tags"]:
                vulnerability["metadata"]["tags"].append("CISA-KEV")

            if kev_entry["knownRansomwareCampaignUse"] == "Known":  # noqa: SIM102
                if "RANSOMWARE" not in vulnerability["metadata"]["tags"]:
                    vulnerability["metadata"]["tags"].append("RANSOMWARE")

            self.stats["kev_enriched"] += 1

            logger.info(
                "Enriched vulnerability with KEV data",
                cve_id=cve_id,
                date_added=kev_entry["dateAdded"],
                ransomware=kev_entry["knownRansomwareCampaignUse"],
            )

        self.stats["total_processed"] += 1
        return vulnerability

    def enrich_batch(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Enrich a batch of vulnerabilities with KEV data.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            List of enriched vulnerabilities
        """
        logger.info("Starting batch KEV enrichment", count=len(vulnerabilities))

        # Reset stats for this batch
        self.stats["kev_enriched"] = 0
        self.stats["total_processed"] = 0

        # Fetch KEV catalog once for the batch
        self.fetch_kev_catalog()

        # Process vulnerabilities
        enriched_vulns = []
        for vuln in vulnerabilities:
            enriched_vuln = self.enrich_vulnerability(vuln)
            enriched_vulns.append(enriched_vuln)

        logger.info(
            "Batch KEV enrichment completed",
            total=self.stats["total_processed"],
            enriched=self.stats["kev_enriched"],
            enrichment_rate=f"{(self.stats['kev_enriched'] / self.stats['total_processed'] * 100):.1f}%"
            if self.stats["total_processed"] > 0
            else "0%",
        )

        return enriched_vulns

    def get_kev_statistics(self) -> Dict[str, Any]:
        """Get statistics about KEV enrichment."""
        kev_catalog = self.fetch_kev_catalog()

        stats = {
            "catalog_size": len(kev_catalog),
            "last_updated": self.kev_cache_time.isoformat()
            if self.kev_cache_time
            else None,
            "cache_age_hours": self._get_cache_age_hours(),
            "enrichment_stats": {
                "total_processed": self.stats["total_processed"],
                "kev_enriched": self.stats["kev_enriched"],
                "enrichment_rate": f"{(self.stats['kev_enriched'] / self.stats['total_processed'] * 100):.1f}%"
                if self.stats["total_processed"] > 0
                else "0%",
            },
        }

        # Get some catalog insights
        if kev_catalog:
            # Count by year added
            year_counts = {}
            ransomware_count = 0

            for _cve_id, entry in kev_catalog.items():
                # Extract year from dateAdded
                date_added = entry.get("dateAdded", "")
                if date_added and len(date_added) >= 4:
                    year = date_added[:4]
                    year_counts[year] = year_counts.get(year, 0) + 1

                # Count ransomware
                if entry.get("knownRansomwareCampaignUse") == "Known":
                    ransomware_count += 1

            stats["catalog_insights"] = {
                "entries_by_year": dict(sorted(year_counts.items(), reverse=True)),
                "known_ransomware_count": ransomware_count,
                "ransomware_percentage": f"{(ransomware_count / len(kev_catalog) * 100):.1f}%",
            }

        return stats

    def _is_cache_valid(self) -> bool:
        """Check if the KEV cache is still valid."""
        if not self.kev_cache or not self.kev_cache_time:
            return False

        age_hours = self._get_cache_age_hours()
        return age_hours < self.CACHE_DURATION_HOURS

    def _get_cache_age_hours(self) -> float:
        """Get the age of the cache in hours."""
        if not self.kev_cache_time:
            return float("inf")

        age = datetime.utcnow() - self.kev_cache_time
        return age.total_seconds() / 3600
