"""Main orchestrator for vulnerability harvesting from multiple sources."""

import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

import structlog

from scripts.harvest.cve_client import CVEClient
from scripts.harvest.epss_client import EPSSClient
from scripts.models import Vulnerability, VulnerabilityBatch
from scripts.processing.cache_manager import CacheManager
from scripts.processing.normalizer import VulnerabilityNormalizer
from scripts.processing.risk_scorer import RiskScorer


class HarvestOrchestrator:
    """Orchestrate vulnerability harvesting from multiple sources."""

    def __init__(
        self,
        cache_dir: Path,
        api_keys: Optional[Dict[str, str]] = None,
        max_workers: int = 4,
    ):
        """Initialize harvest orchestrator.
        
        Args:
            cache_dir: Directory for caching
            api_keys: Dictionary of API keys
            max_workers: Maximum concurrent workers
        """
        self.cache_dir = cache_dir
        self.api_keys = api_keys or {}
        self.max_workers = max_workers
        self.logger = structlog.get_logger(self.__class__.__name__)
        
        # Initialize components
        self.cache_manager = CacheManager(cache_dir)
        self.normalizer = VulnerabilityNormalizer()
        self.risk_scorer = RiskScorer()
        
        # Initialize clients
        self.cve_client = CVEClient(
            api_key=self.api_keys.get("CVE_API_KEY"),
            cache_dir=cache_dir / "api_cache",
        )
        self.epss_client = EPSSClient(
            cache_dir=cache_dir / "api_cache",
        )

    def harvest_cve_data(self, days_back: int = 7) -> List[Vulnerability]:
        """Harvest CVE data from NVD.
        
        Args:
            days_back: Number of days to look back
            
        Returns:
            List of vulnerabilities from CVE/NVD
        """
        self.logger.info("Harvesting CVE data", days_back=days_back)
        
        try:
            vulnerabilities = self.cve_client.fetch_and_parse_recent_cves(
                days_back=days_back
            )
            self.logger.info("Harvested CVE data", count=len(vulnerabilities))
            return vulnerabilities
        except Exception as e:
            self.logger.error("Failed to harvest CVE data", error=str(e))
            return []

    def enrich_with_epss(self, vulnerabilities: List[Vulnerability]) -> None:
        """Enrich vulnerabilities with EPSS scores.
        
        Args:
            vulnerabilities: List of vulnerabilities to enrich
        """
        if not vulnerabilities:
            return
        
        self.logger.info("Enriching with EPSS scores", count=len(vulnerabilities))
        
        # Extract CVE IDs
        cve_ids = [v.cve_id for v in vulnerabilities]
        
        try:
            # Fetch EPSS scores in bulk
            epss_scores = self.epss_client.fetch_epss_scores_bulk(cve_ids)
            
            # Apply scores to vulnerabilities
            enriched_count = 0
            for vuln in vulnerabilities:
                if vuln.cve_id in epss_scores:
                    vuln.epss_score = epss_scores[vuln.cve_id]
                    enriched_count += 1
            
            self.logger.info(
                "Enriched with EPSS scores",
                total=len(vulnerabilities),
                enriched=enriched_count,
            )
        except Exception as e:
            self.logger.error("Failed to enrich with EPSS scores", error=str(e))

    def harvest_all_sources(
        self,
        days_back: int = 7,
        include_sources: Optional[Set[str]] = None,
    ) -> VulnerabilityBatch:
        """Harvest vulnerabilities from all configured sources.
        
        Args:
            days_back: Number of days to look back
            include_sources: Set of sources to include (None = all)
            
        Returns:
            Batch of harvested and processed vulnerabilities
        """
        start_time = datetime.utcnow()
        self.logger.info(
            "Starting vulnerability harvest",
            days_back=days_back,
            sources=include_sources or "all",
        )
        
        # Clean up expired cache entries
        self.cache_manager.cleanup_expired()
        
        all_vulnerabilities = []
        harvest_metadata = {
            "days_back": days_back,
            "start_time": start_time.isoformat(),
            "sources": [],
        }
        
        # Define harvest tasks
        harvest_tasks = []
        
        if not include_sources or "cve" in include_sources:
            harvest_tasks.append(("CVE/NVD", self.harvest_cve_data, days_back))
        
        # TODO: Add more sources here (GitHub Advisory, OSV, etc.)
        
        # Execute harvest tasks concurrently
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_source = {}
            
            for source_name, harvest_func, *args in harvest_tasks:
                future = executor.submit(harvest_func, *args)
                future_to_source[future] = source_name
            
            for future in as_completed(future_to_source):
                source_name = future_to_source[future]
                try:
                    vulnerabilities = future.result()
                    all_vulnerabilities.extend(vulnerabilities)
                    harvest_metadata["sources"].append({
                        "name": source_name,
                        "count": len(vulnerabilities),
                        "status": "success",
                    })
                    self.logger.info(
                        "Completed harvest",
                        source=source_name,
                        count=len(vulnerabilities),
                    )
                except Exception as e:
                    self.logger.error(
                        "Failed to harvest",
                        source=source_name,
                        error=str(e),
                    )
                    harvest_metadata["sources"].append({
                        "name": source_name,
                        "count": 0,
                        "status": "failed",
                        "error": str(e),
                    })
        
        # Deduplicate vulnerabilities
        unique_vulnerabilities = self.normalizer.deduplicate_vulnerabilities(
            all_vulnerabilities
        )
        
        # Enrich with EPSS scores
        self.enrich_with_epss(unique_vulnerabilities)
        
        # Calculate risk scores
        self.risk_scorer.score_batch(unique_vulnerabilities)
        
        # Sort by risk score
        unique_vulnerabilities.sort(key=lambda v: v.risk_score, reverse=True)
        
        # Create batch
        end_time = datetime.utcnow()
        harvest_metadata["end_time"] = end_time.isoformat()
        harvest_metadata["duration_seconds"] = (end_time - start_time).total_seconds()
        harvest_metadata["total_vulnerabilities"] = len(all_vulnerabilities)
        harvest_metadata["unique_vulnerabilities"] = len(unique_vulnerabilities)
        
        batch = VulnerabilityBatch(
            vulnerabilities=unique_vulnerabilities,
            metadata=harvest_metadata,
            generated_at=start_time,
        )
        
        # Cache the batch
        self.cache_manager.cache_batch(batch)
        
        # Log summary
        self.logger.info(
            "Harvest completed",
            duration_seconds=harvest_metadata["duration_seconds"],
            total_vulnerabilities=len(all_vulnerabilities),
            unique_vulnerabilities=len(unique_vulnerabilities),
            sources=len(harvest_metadata["sources"]),
        )
        
        # Log risk distribution
        risk_distribution = {
            "critical": len([v for v in unique_vulnerabilities if v.risk_score >= 90]),
            "high": len([v for v in unique_vulnerabilities if 70 <= v.risk_score < 90]),
            "medium": len([v for v in unique_vulnerabilities if 40 <= v.risk_score < 70]),
            "low": len([v for v in unique_vulnerabilities if v.risk_score < 40]),
        }
        self.logger.info("Risk distribution", **risk_distribution)
        
        return batch

    def get_high_priority_vulnerabilities(
        self,
        batch: VulnerabilityBatch,
        limit: int = 50,
        min_risk_score: int = 70,
    ) -> List[Vulnerability]:
        """Get high-priority vulnerabilities from a batch.
        
        Args:
            batch: Vulnerability batch
            limit: Maximum number to return
            min_risk_score: Minimum risk score
            
        Returns:
            List of high-priority vulnerabilities
        """
        high_priority = [
            v for v in batch.vulnerabilities
            if v.risk_score >= min_risk_score
        ][:limit]
        
        self.logger.info(
            "Selected high-priority vulnerabilities",
            total=batch.count,
            selected=len(high_priority),
            min_risk_score=min_risk_score,
        )
        
        return high_priority

    async def harvest_async(
        self,
        days_back: int = 7,
        include_sources: Optional[Set[str]] = None,
    ) -> VulnerabilityBatch:
        """Asynchronous version of harvest_all_sources.
        
        Args:
            days_back: Number of days to look back
            include_sources: Set of sources to include (None = all)
            
        Returns:
            Batch of harvested and processed vulnerabilities
        """
        # Run the synchronous harvest in an executor
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.harvest_all_sources,
            days_back,
            include_sources,
        )