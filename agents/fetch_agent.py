#!/usr/bin/env python3
"""Fetch agent for retrieving vulnerability data from multiple sources."""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import structlog

from scripts.harvest.cvelist_client import CVEListClient
from scripts.harvest.epss_client import EPSSClient
from scripts.harvest.github_advisory_client import GitHubAdvisoryClient
from scripts.harvest.nvd_client import NVDClient
from scripts.processing.cache_manager import CacheManager


class FetchAgent:
    """Agent responsible for fetching vulnerability data from various sources."""

    def __init__(
        self,
        cache_dir: Path = Path(".cache"),
        api_keys: Optional[Dict[str, str]] = None
    ):
        """Initialize fetch agent.
        
        Args:
            cache_dir: Directory for caching
            api_keys: API keys for data sources
        """
        self.logger = structlog.get_logger(self.__class__.__name__)
        self.cache_dir = cache_dir
        self.api_keys = api_keys or {}
        self.cache_manager = CacheManager(cache_dir)

        # Initialize clients
        self._init_clients()

    def _init_clients(self):
        """Initialize data source clients."""
        # CVEList client
        self.cvelist_client = CVEListClient(
            cache_dir=self.cache_dir / "api_cache",
            use_github_api=True,
            use_releases=True,
            cache_manager=self.cache_manager
        )

        # NVD client
        self.nvd_client = NVDClient(
            api_key=self.api_keys.get("nvd_api_key"),
            cache_dir=self.cache_dir / "api_cache",
            cache_manager=self.cache_manager
        )

        # GitHub Advisory client
        self.github_advisory_client = GitHubAdvisoryClient(
            github_token=self.api_keys.get("github_token"),
            cache_dir=self.cache_dir / "api_cache"
        )

        # EPSS client
        self.epss_client = EPSSClient(
            api_key=self.api_keys.get("epss_api_key"),
            cache_dir=self.cache_dir / "api_cache"
        )

    async def fetch_from_source(self, source: str) -> Dict[str, Any]:
        """Fetch data from a specific source.
        
        Args:
            source: Source name (cvelist, nvd, github_advisory, epss)
            
        Returns:
            Fetch results with vulnerabilities and metadata
        """
        start_time = datetime.now(timezone.utc)

        try:
            if source == "cvelist":
                result = await self._fetch_cvelist()
            elif source == "nvd":
                result = await self._fetch_nvd()
            elif source == "github_advisory":
                result = await self._fetch_github_advisory()
            elif source == "epss":
                result = await self._fetch_epss()
            else:
                raise ValueError(f"Unknown source: {source}")

            duration = (datetime.now(timezone.utc) - start_time).total_seconds()

            return {
                "source": source,
                "vulnerabilities": result["vulnerabilities"],
                "metadata": result.get("metadata", {}),
                "duration": duration,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            self.logger.error(f"Failed to fetch from {source}: {str(e)}")
            raise

    async def _fetch_cvelist(self) -> Dict[str, Any]:
        """Fetch from CVEList (CVE.org)."""
        self.logger.info("Fetching from CVEList")

        # Use harvest method which handles years and severity filtering
        vulnerabilities = self.cvelist_client.harvest(
            years=[2024, 2025],
            min_severity="HIGH",
            min_epss=0.7
        )

        # Convert to standard format
        formatted_vulns = []
        for vuln in vulnerabilities:
            formatted_vulns.append({
                "cve_id": vuln.cve_id,
                "severity": vuln.severity.value if vuln.severity else "UNKNOWN",
                "cvss_base_score": vuln.cvss_base_score,
                "epss_probability": vuln.epss_probability,
                "vendor": vuln.vendor,
                "product": vuln.product,
                "attack_vector": vuln.attack_vector,
                "published_date": vuln.published_date.isoformat() if vuln.published_date else None,
                "description": vuln.description,
                "references": vuln.references,
                "source": "cvelist"
            })

        return {
            "vulnerabilities": formatted_vulns,
            "metadata": {
                "total_fetched": len(formatted_vulns),
                "years": [2024, 2025],
                "min_severity": "HIGH"
            }
        }

    async def _fetch_nvd(self) -> Dict[str, Any]:
        """Fetch from NVD (NIST)."""
        self.logger.info("Fetching from NVD")

        # Use harvest method
        vulnerabilities = self.nvd_client.harvest(
            years=[2024, 2025],
            min_severity="HIGH",
            min_epss=0.7
        )

        # Convert to standard format
        formatted_vulns = []
        for vuln in vulnerabilities:
            formatted_vulns.append({
                "cve_id": vuln.cve_id,
                "severity": vuln.severity.value if vuln.severity else "UNKNOWN",
                "cvss_base_score": vuln.cvss_base_score,
                "epss_probability": vuln.epss_probability,
                "vendor": vuln.vendor,
                "product": vuln.product,
                "attack_vector": vuln.attack_vector,
                "published_date": vuln.published_date.isoformat() if vuln.published_date else None,
                "description": vuln.description,
                "references": vuln.references,
                "source": "nvd"
            })

        return {
            "vulnerabilities": formatted_vulns,
            "metadata": {
                "total_fetched": len(formatted_vulns),
                "api_version": "2.0"
            }
        }

    async def _fetch_github_advisory(self) -> Dict[str, Any]:
        """Fetch from GitHub Security Advisory Database."""
        self.logger.info("Fetching from GitHub Advisory")

        # Use harvest method
        vulnerabilities = self.github_advisory_client.harvest(
            min_severity="HIGH",
            published_since=datetime(2024, 1, 1, tzinfo=timezone.utc),
            limit=1000
        )

        # Convert to standard format
        formatted_vulns = []
        for vuln in vulnerabilities:
            formatted_vulns.append({
                "cve_id": vuln.cve_id,
                "severity": vuln.severity.value if vuln.severity else "UNKNOWN",
                "cvss_base_score": vuln.cvss_base_score,
                "epss_probability": vuln.epss_probability,
                "vendor": vuln.vendor,
                "product": vuln.product,
                "attack_vector": vuln.attack_vector,
                "published_date": vuln.published_date.isoformat() if vuln.published_date else None,
                "description": vuln.description,
                "references": vuln.references,
                "source": "github_advisory"
            })

        return {
            "vulnerabilities": formatted_vulns,
            "metadata": {
                "total_fetched": len(formatted_vulns),
                "database": "GitHub Security Advisory"
            }
        }

    async def _fetch_epss(self) -> Dict[str, Any]:
        """Fetch EPSS scores for known CVEs."""
        self.logger.info("Fetching EPSS scores")

        # Get CVEs that need EPSS scores
        recent_vulns = self.cache_manager.get_recent_vulnerabilities(limit=1000)
        cve_ids = [v.cve_id for v in recent_vulns if v.cve_id]

        if not cve_ids:
            return {"vulnerabilities": [], "metadata": {"updated": 0}}

        # Fetch EPSS scores in bulk
        epss_data = self.epss_client.fetch_epss_scores_bulk(cve_ids)

        # Format as vulnerability updates
        formatted_vulns = []
        for cve_id, score_data in epss_data.items():
            if score_data:
                formatted_vulns.append({
                    "cve_id": cve_id,
                    "epss_probability": score_data.get("epss", 0) * 100,  # Convert to percentage
                    "epss_percentile": score_data.get("percentile", 0) * 100,
                    "source": "epss"
                })

        return {
            "vulnerabilities": formatted_vulns,
            "metadata": {
                "total_updated": len(formatted_vulns),
                "total_requested": len(cve_ids)
            }
        }

    async def fetch_all_sources(self) -> Dict[str, Any]:
        """Fetch from all configured sources concurrently."""
        sources = ["cvelist", "nvd", "github_advisory", "epss"]

        # Create tasks for concurrent execution
        tasks = []
        for source in sources:
            task = asyncio.create_task(self.fetch_from_source(source))
            tasks.append((source, task))

        # Wait for all tasks to complete
        results = {}
        all_vulnerabilities = []

        for source, task in tasks:
            try:
                result = await task
                results[source] = {
                    "success": True,
                    "count": len(result["vulnerabilities"]),
                    "duration": result["duration"]
                }
                all_vulnerabilities.extend(result["vulnerabilities"])
            except Exception as e:
                self.logger.error(f"Failed to fetch from {source}: {str(e)}")
                results[source] = {
                    "success": False,
                    "error": str(e)
                }

        return {
            "vulnerabilities": all_vulnerabilities,
            "source_results": results,
            "total_fetched": len(all_vulnerabilities),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


# CLI interface
async def main():
    """Main CLI entry point."""
    import argparse
    import os

    parser = argparse.ArgumentParser(description="Fetch vulnerability data")
    parser.add_argument(
        "source",
        choices=["cvelist", "nvd", "github_advisory", "epss", "all"],
        help="Data source to fetch from"
    )
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache"))
    parser.add_argument("--output", type=Path, help="Output file path")

    args = parser.parse_args()

    # Get API keys from environment
    api_keys = {
        "github_token": os.getenv("GITHUB_TOKEN"),
        "nvd_api_key": os.getenv("NVD_API_KEY"),
        "epss_api_key": os.getenv("EPSS_API_KEY")
    }

    agent = FetchAgent(cache_dir=args.cache_dir, api_keys=api_keys)

    if args.source == "all":
        result = await agent.fetch_all_sources()
    else:
        result = await agent.fetch_from_source(args.source)

    # Output results
    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"Results saved to {args.output}")
    else:
        print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
