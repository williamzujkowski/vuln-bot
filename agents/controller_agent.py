#!/usr/bin/env python3
"""Controller agent for orchestrating the CVE data pipeline with Great Expectations validation."""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

from agents.enrichment_agent import EnrichmentAgent
from agents.fetch_agent import FetchAgent
from agents.quality_agent import QualityAgent
from agents.static_page_agent import StaticPageAgent
from agents.validator_agent import ValidatorAgent
from scripts.processing.cache_manager import CacheManager


class ControllerAgent:
    """Main orchestrator for the CVE data pipeline."""

    def __init__(
        self,
        cache_dir: Path = Path(".cache"),
        api_keys: Optional[Dict[str, str]] = None,
        enable_validation: bool = True
    ):
        """Initialize controller agent.
        
        Args:
            cache_dir: Directory for caching
            api_keys: API keys for data sources
            enable_validation: Enable Great Expectations validation
        """
        self.logger = structlog.get_logger(self.__class__.__name__)
        self.cache_dir = cache_dir
        self.api_keys = api_keys or {}
        self.enable_validation = enable_validation

        # Initialize sub-agents
        self.fetch_agent = FetchAgent(cache_dir, api_keys)
        self.validator_agent = ValidatorAgent() if enable_validation else None
        self.enrichment_agent = EnrichmentAgent(cache_dir, api_keys)
        self.static_page_agent = StaticPageAgent(cache_dir)
        self.quality_agent = QualityAgent(cache_dir)
        self.cache_manager = CacheManager(cache_dir)

        # Pipeline state
        self.pipeline_state = {
            "started_at": None,
            "completed_at": None,
            "status": "idle",
            "steps_completed": [],
            "errors": [],
            "metrics": {}
        }

    async def run_pipeline(
        self,
        sources: List[str] = None,
        validate: bool = True,
        checkpoint: str = "harvest_checkpoint",
        fail_on_validation_error: bool = False
    ) -> Dict[str, Any]:
        """Run the complete CVE data pipeline.
        
        Args:
            sources: List of sources to fetch from
            validate: Run Great Expectations validation
            checkpoint: GX checkpoint to use
            fail_on_validation_error: Fail pipeline on validation errors
            
        Returns:
            Pipeline execution results
        """
        self.pipeline_state["started_at"] = datetime.now()
        self.pipeline_state["status"] = "running"

        try:
            # Step 1: Fetch data from sources
            self.logger.info("Starting data fetch from sources")
            fetch_results = await self._fetch_data(sources)
            self.pipeline_state["steps_completed"].append("fetch")
            self.pipeline_state["metrics"]["fetched_cves"] = fetch_results["total_fetched"]

            # Step 2: Validate with Great Expectations
            if validate and self.validator_agent:
                self.logger.info("Running Great Expectations validation")
                validation_results = await self._validate_data(
                    fetch_results["vulnerabilities"],
                    checkpoint,
                    fail_on_validation_error
                )
                self.pipeline_state["steps_completed"].append("validate")
                self.pipeline_state["metrics"]["validation"] = validation_results

            # Step 3: Enrich data
            self.logger.info("Enriching vulnerability data")
            enriched_data = await self._enrich_data(fetch_results["vulnerabilities"])
            self.pipeline_state["steps_completed"].append("enrich")
            self.pipeline_state["metrics"]["enriched_cves"] = len(enriched_data)

            # Step 4: Generate static pages
            self.logger.info("Generating static pages")
            page_results = await self._generate_pages(enriched_data)
            self.pipeline_state["steps_completed"].append("generate_pages")
            self.pipeline_state["metrics"]["pages_generated"] = page_results["pages_generated"]

            # Step 5: Generate quality report
            self.logger.info("Generating quality report")
            quality_report = await self._generate_quality_report()
            self.pipeline_state["steps_completed"].append("quality_report")
            self.pipeline_state["metrics"]["quality_score"] = quality_report["summary"]["overall_quality_score"]

            # Mark pipeline complete
            self.pipeline_state["status"] = "completed"
            self.pipeline_state["completed_at"] = datetime.now()

            return {
                "success": True,
                "pipeline_state": self.pipeline_state,
                "quality_report": quality_report
            }

        except Exception as e:
            self.logger.error(f"Pipeline failed: {str(e)}")
            self.pipeline_state["status"] = "failed"
            self.pipeline_state["errors"].append(str(e))
            self.pipeline_state["completed_at"] = datetime.now()

            return {
                "success": False,
                "pipeline_state": self.pipeline_state,
                "error": str(e)
            }

    async def _fetch_data(self, sources: Optional[List[str]] = None) -> Dict[str, Any]:
        """Fetch data from configured sources."""
        if not sources:
            sources = ["cvelist", "nvd", "github_advisory", "epss"]

        vulnerabilities = []
        fetch_metrics = {}

        for source in sources:
            try:
                self.logger.info(f"Fetching from {source}")
                result = await self.fetch_agent.fetch_from_source(source)
                vulnerabilities.extend(result["vulnerabilities"])
                fetch_metrics[source] = {
                    "count": len(result["vulnerabilities"]),
                    "duration": result.get("duration"),
                    "success": True
                }
            except Exception as e:
                self.logger.error(f"Failed to fetch from {source}: {str(e)}")
                fetch_metrics[source] = {
                    "count": 0,
                    "error": str(e),
                    "success": False
                }

        return {
            "vulnerabilities": vulnerabilities,
            "total_fetched": len(vulnerabilities),
            "metrics": fetch_metrics
        }

    async def _validate_data(
        self,
        vulnerabilities: List[Dict[str, Any]],
        checkpoint: str,  # noqa: ARG002
        fail_on_error: bool
    ) -> Dict[str, Any]:
        """Validate data with Great Expectations."""
        if not self.validator_agent:
            return {"skipped": True, "reason": "Validation disabled"}

        # Convert to format expected by validator
        cve_data = []
        for vuln in vulnerabilities:
            cve_data.append({
                "cveId": vuln.get("cve_id"),
                "state": "PUBLISHED",
                "cvss_base_score": vuln.get("cvss_base_score"),
                "severity": vuln.get("severity"),
                "vendor": vuln.get("vendor"),
                "product": vuln.get("product"),
                "published_date": vuln.get("published_date")
            })

        # Run validation
        validation_result = self.validator_agent.validate_cve_batch(
            cve_data,
            source="pipeline"
        )

        # Check if we should fail
        if not validation_result["success"] and fail_on_error:
            raise ValueError(f"Validation failed: {validation_result['failed_expectations']} failures")

        return validation_result

    async def _enrich_data(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich vulnerability data."""
        return await self.enrichment_agent.enrich_batch(vulnerabilities)

    async def _generate_pages(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate static pages."""
        return await self.static_page_agent.generate_all(vulnerabilities)

    async def _generate_quality_report(self) -> Dict[str, Any]:
        """Generate data quality report."""
        return self.quality_agent.collect_quality_metrics()

    def get_pipeline_status(self) -> Dict[str, Any]:
        """Get current pipeline status."""
        return self.pipeline_state


# CLI interface
async def main():
    """Main CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="CVE Pipeline Controller")
    parser.add_argument(
        "command",
        choices=["harvest", "validate", "status"],
        help="Command to execute"
    )
    parser.add_argument("--sources", nargs="+", help="Data sources to use")
    parser.add_argument("--with-validation", action="store_true", help="Enable validation")
    parser.add_argument("--checkpoint", default="harvest_checkpoint", help="GX checkpoint")
    parser.add_argument("--fail-on-validation-error", action="store_true", help="Fail on validation errors")
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache"), help="Cache directory")

    args = parser.parse_args()

    # Get API keys from environment
    import os
    api_keys = {
        "github_token": os.getenv("GITHUB_TOKEN"),
        "nvd_api_key": os.getenv("NVD_API_KEY")
    }

    controller = ControllerAgent(
        cache_dir=args.cache_dir,
        api_keys=api_keys,
        enable_validation=args.with_validation
    )

    if args.command == "harvest":
        result = await controller.run_pipeline(
            sources=args.sources,
            validate=args.with_validation,
            checkpoint=args.checkpoint,
            fail_on_validation_error=args.fail_on_validation_error
        )

        if result["success"]:
            print("✅ Pipeline completed successfully!")
            print(f"Total CVEs processed: {result['pipeline_state']['metrics']['fetched_cves']}")
            print(f"Quality score: {result['quality_report']['summary']['overall_quality_score']:.1%}")
        else:
            print("❌ Pipeline failed!")
            print(f"Error: {result['error']}")

    elif args.command == "status":
        status = controller.get_pipeline_status()
        print(json.dumps(status, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
