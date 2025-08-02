"""Main orchestrator for vulnerability harvesting from multiple sources."""

import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

import structlog
import yaml

from scripts.agents.epss_filter_agent import EPSSFilterAgent
from scripts.harvest.cvelist_client import CVEListClient
from scripts.harvest.epss_client import EPSSClient
from scripts.harvest.github_advisory_client import GitHubAdvisoryClient
from scripts.harvest.nvd_client import NVDClient
from scripts.metrics import MetricsCollector
from scripts.models import Vulnerability, VulnerabilityBatch
from scripts.processing.cache_manager import CacheManager
from scripts.processing.normalizer import VulnerabilityNormalizer
from scripts.processing.risk_scorer import RiskScorer
from scripts.quality import DataQualityConfig, DataQualityValidator


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
        self.metrics = MetricsCollector(cache_dir / "metrics.db")
        self.epss_filter_agent = EPSSFilterAgent(cache_dir=cache_dir)

        # Load data quality configuration
        self.quality_config = self._load_quality_config()
        self.quality_validator = DataQualityValidator(self.quality_config)

        # Initialize clients
        self.cvelist_client = CVEListClient(
            cache_dir=cache_dir / "api_cache",
            use_github_api=True,
            use_releases=True,  # Use new release-based approach by default
            cache_manager=self.cache_manager,
        )
        self.nvd_client = NVDClient(
            api_key=self.api_keys.get("NVD_API_KEY"),
            cache_dir=cache_dir / "api_cache",
        )
        self.epss_client = EPSSClient(
            cache_dir=cache_dir / "api_cache",
        )
        self.github_advisory_client = GitHubAdvisoryClient(
            cache_dir=cache_dir / "api_cache",
        )

    def _load_quality_config(self) -> DataQualityConfig:
        """Load data quality configuration from file."""
        config_path = Path(__file__).parent.parent.parent / "config" / "quality.yaml"

        if config_path.exists():
            try:
                with open(config_path) as f:
                    config_dict = yaml.safe_load(f)
                    return DataQualityConfig.from_dict(config_dict)
            except Exception as e:
                self.logger.warning(
                    "Failed to load quality config, using defaults", error=str(e)
                )

        return DataQualityConfig()  # Use defaults

    def harvest_cve_data(
        self,
        years: Optional[List[int]] = None,
        min_severity: str = "HIGH",
        incremental: bool = False,
    ) -> List[Vulnerability]:
        """Harvest CVE data from CVEProject/cvelistV5.

        Args:
            years: List of years to harvest (default: [2025])
            min_severity: Minimum severity level (HIGH or CRITICAL)
            incremental: If True, skip CVEs that haven't been updated since last harvest

        Returns:
            List of vulnerabilities from CVEList
        """
        if years is None:
            years = [2024, 2025]  # Default to 2024 and 2025

        self.logger.info("Harvesting CVE data", years=years, min_severity=min_severity)

        try:
            from scripts.models import SeverityLevel

            severity_enum = SeverityLevel[min_severity.upper()]

            vulnerabilities = self.cvelist_client.harvest(
                years=years,
                min_severity=severity_enum,
                incremental=incremental,
            )
            self.logger.info("Harvested CVE data", count=len(vulnerabilities))
            return vulnerabilities
        except Exception as e:
            self.logger.error("Failed to harvest CVE data", error=str(e))
            return []

    def harvest_github_advisory_data(
        self,
        min_severity: str = "HIGH",
        ecosystems: Optional[List[str]] = None,
    ) -> List[Vulnerability]:
        """Harvest vulnerability data from GitHub Security Advisory database.

        Args:
            min_severity: Minimum severity level (HIGH or CRITICAL)
            ecosystems: List of ecosystems to filter (e.g., ["PIP", "NPM"])

        Returns:
            List of vulnerabilities from GitHub Advisory
        """
        self.logger.info(
            "Harvesting GitHub Advisory data",
            min_severity=min_severity,
            ecosystems=ecosystems,
        )

        try:
            from scripts.models import SeverityLevel

            severity_enum = SeverityLevel[min_severity.upper()]

            vulnerabilities = self.github_advisory_client.harvest(
                min_severity=severity_enum,
                ecosystems=ecosystems,
            )
            self.logger.info(
                "Harvested GitHub Advisory data", count=len(vulnerabilities)
            )
            return vulnerabilities
        except Exception as e:
            self.logger.error("Failed to harvest GitHub Advisory data", error=str(e))
            return []

    def harvest_nvd_data(
        self,
        years: Optional[List[int]] = None,
        min_severity: str = "HIGH",
        max_vulnerabilities: Optional[int] = None,
    ) -> List[Vulnerability]:
        """Harvest vulnerability data from NIST National Vulnerability Database.

        Args:
            years: List of years to harvest (default: [2024, 2025])
            min_severity: Minimum severity level (HIGH or CRITICAL)
            max_vulnerabilities: Maximum number of vulnerabilities to return

        Returns:
            List of vulnerabilities from NVD
        """
        if years is None:
            years = [2024, 2025]

        self.logger.info(
            "Harvesting NVD data",
            years=years,
            min_severity=min_severity,
            max_vulnerabilities=max_vulnerabilities,
        )

        try:
            from scripts.models import SeverityLevel

            severity_enum = SeverityLevel[min_severity.upper()]

            vulnerabilities = self.nvd_client.harvest(
                years=years,
                min_severity=severity_enum,
                max_vulnerabilities=max_vulnerabilities,
            )
            self.logger.info("Harvested NVD data", count=len(vulnerabilities))
            return vulnerabilities
        except Exception as e:
            self.logger.error("Failed to harvest NVD data", error=str(e))
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
        years: Optional[List[int]] = None,
        include_sources: Optional[Set[str]] = None,
        min_epss_score: float = 0.5,  # 50% threshold (EPSS ≥ 0.5)
        min_severity: str = "HIGH",
        incremental: bool = False,
    ) -> VulnerabilityBatch:
        """Harvest vulnerabilities from all configured sources.

        Args:
            years: List of years to harvest (default: [2025])
            include_sources: Set of sources to include (None = all)
            min_epss_score: Minimum EPSS score threshold (0.0-1.0)
            min_severity: Minimum severity level (HIGH or CRITICAL)
            incremental: If True, skip CVEs that haven't been updated since last harvest

        Returns:
            Batch of harvested and processed vulnerabilities
        """
        if years is None:
            years = [2024, 2025]  # Default to 2024 and 2025

        start_time = datetime.now(timezone.utc)
        self.logger.info(
            "Starting vulnerability harvest",
            years=years,
            min_epss_score=min_epss_score,
            min_severity=min_severity,
            sources=include_sources or "all",
        )

        # Start metrics collection
        harvest_id = self.metrics.start_harvest(
            {
                "years": years,
                "min_epss_score": min_epss_score,
                "min_severity": min_severity,
                "include_sources": list(include_sources) if include_sources else None,
            }
        )

        # Clean up expired cache entries
        self.cache_manager.cleanup_expired()

        all_vulnerabilities = []
        harvest_metadata = {
            "harvest_id": str(harvest_id),
            "years": years,
            "min_epss_score": min_epss_score,
            "min_severity": min_severity,
            "start_time": start_time.isoformat(),
            "sources": [],
        }

        # Define harvest tasks
        harvest_tasks = []

        # Use CVEList as primary source since we don't have NVD API key
        if not include_sources or "cve" in include_sources:
            harvest_tasks.append(
                ("CVEList", self.harvest_cve_data, years, min_severity, incremental)
            )

        # Keep NVD as fallback source (limited by rate limits without API key)
        # Only use NVD if we have an API key or explicitly requested
        if (not include_sources or "nvd" in include_sources) and (
            self.api_keys.get("NVD_API_KEY") or "nvd" in (include_sources or set())
        ):
            harvest_tasks.append(
                ("NVD", self.harvest_nvd_data, years, min_severity, None)
            )

        if not include_sources or "github" in include_sources:
            harvest_tasks.append(
                (
                    "GitHub Advisory",
                    self.harvest_github_advisory_data,
                    min_severity,
                    None,
                )
            )

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
                    harvest_metadata["sources"].append(
                        {
                            "name": source_name,
                            "count": len(vulnerabilities),
                            "status": "success",
                        }
                    )
                    self.logger.info(
                        "Completed harvest",
                        source=source_name,
                        count=len(vulnerabilities),
                    )

                    # Record metrics for source
                    self.metrics.record_metric(
                        f"source_{source_name}_count",
                        len(vulnerabilities),
                        {"source": source_name},
                    )
                except Exception as e:
                    self.logger.error(
                        "Failed to harvest",
                        source=source_name,
                        error=str(e),
                    )
                    harvest_metadata["sources"].append(
                        {
                            "name": source_name,
                            "count": 0,
                            "status": "failed",
                            "error": str(e),
                        }
                    )

                    # Record error
                    self.metrics.record_error(
                        "harvest_error", str(e), {"source": source_name}
                    )

        # Deduplicate vulnerabilities
        unique_vulnerabilities = self.normalizer.deduplicate_vulnerabilities(
            all_vulnerabilities
        )

        # Record deduplication metrics
        self.metrics.record_metric(
            "deduplication_rate",
            (len(all_vulnerabilities) - len(unique_vulnerabilities))
            / max(len(all_vulnerabilities), 1)
            * 100,
            {"before": len(all_vulnerabilities), "after": len(unique_vulnerabilities)},
        )

        # Apply data quality validation
        self.logger.info("Applying data quality validation")
        validated_vulnerabilities, quality_stats = (
            self.quality_validator.filter_vulnerabilities(unique_vulnerabilities)
        )

        # Record quality metrics
        self.metrics.record_metric(
            "quality_pass_rate",
            quality_stats["passed"] / max(quality_stats["total"], 1) * 100,
            quality_stats,
        )

        # Log quality report
        quality_report = self.quality_validator.get_quality_report(
            unique_vulnerabilities
        )
        self.logger.info(
            "Data quality report",
            summary=quality_report["summary"],
            issues=quality_report["quality_issues"],
        )

        unique_vulnerabilities = validated_vulnerabilities

        # Enrich with EPSS scores
        self.enrich_with_epss(unique_vulnerabilities)

        # Apply EPSS filtering using EPSSFilterAgent
        # Update the agent's threshold if different from default
        if min_epss_score != self.epss_filter_agent.threshold:
            self.epss_filter_agent.threshold = min_epss_score
            self.logger.info(
                "Updated EPSS filter threshold",
                new_threshold=min_epss_score,
                threshold_percentage=f"{min_epss_score * 100}%",
            )

        # Convert vulnerabilities to dict format for the agent
        vuln_dicts = []
        for vuln in unique_vulnerabilities:
            vuln_dict = vuln.to_dict()
            # Ensure EPSS score is at the top level
            if hasattr(vuln, "epss_probability") and vuln.epss_probability is not None:
                vuln_dict["epssScore"] = (
                    vuln.epss_probability / 100.0
                )  # Convert percentage to decimal
            vuln_dicts.append(vuln_dict)

        # Apply EPSS filter
        filtered_vuln_dicts, filter_stats = (
            self.epss_filter_agent.filter_vulnerabilities(vuln_dicts)
        )

        # Convert back to Vulnerability objects
        filtered_vulnerabilities = []
        for vuln_dict in filtered_vuln_dicts:
            # Find the original vulnerability object
            for vuln in unique_vulnerabilities:
                if vuln.cve_id == vuln_dict.get("cveId", vuln_dict.get("cve_id")):
                    filtered_vulnerabilities.append(vuln)
                    break

        # Update unique_vulnerabilities to only include filtered ones
        unique_vulnerabilities = filtered_vulnerabilities

        # Log filter statistics
        self.logger.info(
            "EPSS filtering completed",
            original_count=filter_stats["total_processed"],
            filtered_count=filter_stats["passed_filter"],
            removed_count=filter_stats["failed_filter"],
            missing_epss=filter_stats["missing_epss"],
            threshold=filter_stats["threshold"],
        )

        # Calculate risk scores
        self.risk_scorer.score_batch(unique_vulnerabilities)

        # Record individual vulnerability metrics
        for vuln in unique_vulnerabilities:
            self.metrics.record_vulnerability(vuln)

        # Sort by risk score
        unique_vulnerabilities.sort(key=lambda v: v.risk_score, reverse=True)

        # Create batch
        end_time = datetime.now(timezone.utc)
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
            "medium": len(
                [v for v in unique_vulnerabilities if 40 <= v.risk_score < 70]
            ),
            "low": len([v for v in unique_vulnerabilities if v.risk_score < 40]),
        }
        self.logger.info("Risk distribution", **risk_distribution)

        # End metrics collection
        self.metrics.end_harvest(
            status="completed",
            summary={
                "risk_distribution": risk_distribution,
                "sources_processed": len(harvest_metadata["sources"]),
                "cache_hit_rate": getattr(self.cache_manager, "_cache_hit_rate", 0),
            },
        )

        return batch

    def get_high_priority_vulnerabilities(
        self,
        batch: VulnerabilityBatch,
        limit: int = 50,
        min_risk_score: int = 50,
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
            v for v in batch.vulnerabilities if v.risk_score >= min_risk_score
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
        years: Optional[List[int]] = None,
        include_sources: Optional[Set[str]] = None,
        min_epss_score: float = 0.5,
        min_severity: str = "HIGH",
    ) -> VulnerabilityBatch:
        """Asynchronous version of harvest_all_sources.

        Args:
            years: List of years to harvest (default: [2025])
            include_sources: Set of sources to include (None = all)
            min_epss_score: Minimum EPSS score threshold (0.0-1.0)
            min_severity: Minimum severity level (HIGH or CRITICAL)

        Returns:
            Batch of harvested and processed vulnerabilities
        """
        # Run the synchronous harvest in an executor
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.harvest_all_sources,
            years,
            include_sources,
            min_epss_score,
            min_severity,
        )
