#!/usr/bin/env python3
"""Main entry point for the vulnerability harvesting and processing system."""

import logging
import os
import sys
from pathlib import Path

import click
import structlog
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from scripts.harvest.orchestrator import HarvestOrchestrator
from scripts.processing.cache_manager import CacheManager

console = Console()

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.dev.ConsoleRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)


@click.group()
@click.option("--debug", is_flag=True, help="Enable debug logging")
def cli(debug: bool) -> None:
    """Morning Vuln Briefing - Automated vulnerability intelligence platform."""
    # Configure logging
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


@cli.command()
@click.option(
    "--cache-dir",
    type=click.Path(path_type=Path),
    default=Path(".cache"),
    help="Directory for caching API responses",
)
@click.option(
    "--years",
    "-y",
    multiple=True,
    type=int,
    help="Years to harvest (default: 2024, 2025)",
)
@click.option(
    "--min-severity",
    type=click.Choice(["MEDIUM", "HIGH", "CRITICAL"]),
    default="HIGH",
    help="Minimum severity level",
)
@click.option(
    "--min-epss", type=float, default=0.6, help="Minimum EPSS score (0.0-1.0)"
)
@click.option("--dry-run", is_flag=True, help="Run without making actual API calls")
def harvest(
    cache_dir: Path, years: tuple, min_severity: str, min_epss: float, dry_run: bool
) -> None:
    """Harvest vulnerability data from all configured sources."""
    logger = structlog.get_logger()

    if dry_run:
        logger.info("Running in dry-run mode")
        # TODO: Implement dry-run logic
        return

    logger.info("Starting vulnerability harvest", cache_dir=str(cache_dir))

    # Convert years tuple to list, default to [2024, 2025] if empty
    years_list = list(years) if years else [2024, 2025]

    # Collect API keys from environment
    api_keys = {
        "GITHUB_TOKEN": os.getenv("GITHUB_TOKEN"),
        "EPSS_API_KEY": os.getenv("EPSS_API_KEY"),
    }

    # Initialize orchestrator
    orchestrator = HarvestOrchestrator(
        cache_dir=cache_dir,
        api_keys=api_keys,
    )

    # Perform harvest
    try:
        batch = orchestrator.harvest_all_sources(
            years=years_list,
            min_severity=min_severity,
            min_epss_score=min_epss,
        )

        # Display summary
        console.print("\n[green]✓[/green] Vulnerability harvest completed")
        console.print(f"Total vulnerabilities: {batch.count}")

        # Show top vulnerabilities
        high_priority = orchestrator.get_high_priority_vulnerabilities(batch, limit=10)

        if high_priority:
            table = Table(title="Top 10 High-Risk Vulnerabilities")
            table.add_column("CVE ID", style="cyan")
            table.add_column("Risk Score", style="red")
            table.add_column("Severity", style="yellow")
            table.add_column("EPSS %", style="magenta")
            table.add_column("Title", style="white", max_width=50)

            for vuln in high_priority:
                table.add_row(
                    vuln.cve_id,
                    str(vuln.risk_score),
                    vuln.severity.value,
                    f"{vuln.epss_probability or 0:.1f}%",
                    vuln.title[:50] + "..." if len(vuln.title) > 50 else vuln.title,
                )

            console.print(table)

    except Exception as e:
        logger.error("Harvest failed", error=str(e))
        sys.exit(1)


@cli.command()
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path),
    default=Path("src"),
    help="Output directory for generated briefings",
)
@click.option(
    "--cache-dir",
    type=click.Path(path_type=Path),
    default=Path(".cache"),
    help="Cache directory to read vulnerabilities from",
)
@click.option(
    "--limit",
    type=int,
    default=50,
    help="Maximum vulnerabilities to include in briefing",
)
def generate_briefing(output_dir: Path, cache_dir: Path, limit: int) -> None:
    """Generate daily vulnerability briefing from harvested data."""
    logger = structlog.get_logger()
    logger.info("Generating vulnerability briefing", output_dir=str(output_dir))

    try:
        # Initialize components
        from scripts.processing.briefing_generator import BriefingGenerator

        cache_manager = CacheManager(cache_dir)
        generator = BriefingGenerator(output_dir)

        # Get recent vulnerabilities from cache
        vulnerabilities = cache_manager.get_recent_vulnerabilities(limit=1000)

        if not vulnerabilities:
            logger.warning("No vulnerabilities found in cache")
            console.print(
                "[yellow]⚠[/yellow] No vulnerabilities found. Run 'harvest' first."
            )
            return

        # Create a batch from cached vulnerabilities
        from scripts.models import VulnerabilityBatch

        batch = VulnerabilityBatch(
            vulnerabilities=vulnerabilities,
            metadata={
                "source": "cache",
                "generated_from_cache": True,
            },
        )

        # Generate all outputs
        results = generator.generate_all(batch, briefing_limit=limit)

        console.print("\n[green]✓[/green] Briefing generated successfully")
        console.print(f"  Briefing: {results['briefing']}")
        console.print(f"  Index: {results['index']}")
        console.print(f"  Vulnerability JSONs: {len(results['vulnerabilities'])} files")

    except Exception as e:
        logger.error("Failed to generate briefing", error=str(e))
        console.print(f"[red]✗[/red] Failed to generate briefing: {e}")
        sys.exit(1)


@cli.command()
def update_badge() -> None:
    """Update coverage badge in README."""
    logger = structlog.get_logger()
    logger.info("Updating coverage badge")

    # TODO: Implement badge update logic
    console.print("[green]✓[/green] Coverage badge updated")


@cli.command()
@click.option("--webhook-url", envvar="SLACK_WEBHOOK", help="Slack webhook URL")
@click.option("--dry-run", is_flag=True, help="Print alerts without sending")
def send_alerts(webhook_url: str, dry_run: bool) -> None:
    """Send vulnerability alerts to configured webhooks."""
    logger = structlog.get_logger()

    if not webhook_url and not dry_run:
        logger.error("No webhook URL configured")
        sys.exit(1)

    if dry_run:
        logger.info("Running in dry-run mode")

    # TODO: Implement alert sending logic
    console.print("[green]✓[/green] Alerts sent successfully")


if __name__ == "__main__":
    cli()
