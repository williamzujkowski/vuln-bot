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
    default="MEDIUM",
    help="Minimum severity level",
)
@click.option(
    "--min-epss", type=float, default=0.001, help="Minimum EPSS score (0.0-1.0)"
)
@click.option(
    "--incremental",
    is_flag=True,
    help="Skip CVEs that haven't been updated since last harvest",
)
@click.option(
    "--use-releases/--no-use-releases",
    default=True,
    help="Use GitHub releases (faster) instead of individual API calls",
)
@click.option("--dry-run", is_flag=True, help="Run without making actual API calls")
def harvest(
    cache_dir: Path,
    years: tuple,
    min_severity: str,
    min_epss: float,
    incremental: bool,
    use_releases: bool,
    dry_run: bool,
) -> None:
    """Harvest vulnerability data from all configured sources."""
    logger = structlog.get_logger()

    if dry_run:
        logger.info("Running in dry-run mode")

        # Simulate harvest operation without API calls
        years_list = list(years) if years else [2024, 2025]

        console.print(
            "\n[yellow]🔍 DRY RUN MODE - Simulating harvest operation[/yellow]"
        )
        console.print("Parameters:")
        console.print(f"  Cache directory: {cache_dir}")
        console.print(f"  Years: {years_list}")
        console.print(f"  Minimum severity: {min_severity}")
        console.print(f"  Minimum EPSS score: {min_epss}")
        console.print(f"  Incremental: {incremental}")
        console.print(f"  Use releases: {use_releases}")

        # Simulate what would be fetched
        console.print("\n[blue]📊 Simulated harvest results:[/blue]")

        # Estimate based on typical harvest results
        estimated_total = 0
        for year in years_list:
            if year == 2024:
                estimated_total += 3000  # Approximate CVEs for 2024
            elif year == 2025:
                estimated_total += 500  # Approximate CVEs for 2025 so far
            else:
                estimated_total += 1000  # Default estimate for other years

        # Apply severity filtering (rough estimates)
        if min_severity == "CRITICAL":
            estimated_total = int(estimated_total * 0.15)
        elif min_severity == "HIGH":
            estimated_total = int(estimated_total * 0.45)
        else:  # MEDIUM
            estimated_total = int(estimated_total * 0.75)

        # Apply EPSS filtering
        if min_epss >= 0.7:
            estimated_total = int(estimated_total * 0.1)
        elif min_epss >= 0.3:
            estimated_total = int(estimated_total * 0.3)
        else:
            estimated_total = int(estimated_total * 0.8)

        console.print(f"  Estimated vulnerabilities: ~{estimated_total}")
        console.print(
            f"  EPSS enrichment: Would query EPSS API for {estimated_total} CVEs"
        )
        console.print(
            "  Risk scoring: Would calculate risk scores for all vulnerabilities"
        )

        # Show what files would be created/updated
        console.print("\n[green]📝 Files that would be affected:[/green]")
        console.print(f"  ✓ Cache database: {cache_dir}/cache.db")
        console.print(f"  ✓ Metrics database: {cache_dir}/metrics.db")
        console.print(f"  ✓ API response cache: {cache_dir}/api_cache/")

        # Show simulated API endpoints
        console.print("\n[cyan]🌐 API endpoints that would be called:[/cyan]")
        if use_releases:
            console.print("  ✓ GitHub API: CVEProject/cvelistV5 releases")
        else:
            console.print("  ✓ GitHub API: CVEProject/cvelistV5 repository browsing")
        console.print("  ✓ EPSS API: Exploit Prediction Scoring System")

        console.print(
            "\n[green]✅ Dry run completed - no actual data was fetched[/green]"
        )
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

    # Update CVE client to use specified approach
    orchestrator.cvelist_client.use_releases = use_releases

    # Perform harvest
    try:
        batch = orchestrator.harvest_all_sources(
            years=years_list,
            min_severity=min_severity,
            min_epss_score=min_epss,
            incremental=incremental,
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
    """Generate vulnerability briefing from harvested data."""
    logger = structlog.get_logger()
    logger.info("Generating vulnerability briefing", output_dir=str(output_dir))

    try:
        # Initialize components
        from scripts.processing.briefing_generator import BriefingGenerator

        cache_manager = CacheManager(cache_dir)
        generator = BriefingGenerator(output_dir)

        # Get recent vulnerabilities from cache
        # Use a very high limit to get all available vulnerabilities
        vulnerabilities = cache_manager.get_recent_vulnerabilities(limit=50000)

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
@click.option(
    "--coverage-file",
    type=click.Path(exists=True, path_type=Path),
    default=Path("coverage.xml"),
    help="Path to coverage XML file",
)
@click.option(
    "--readme-file",
    type=click.Path(exists=True, path_type=Path),
    default=Path("README.md"),
    help="Path to README file",
)
@click.option(
    "--dry-run", is_flag=True, help="Show what would be updated without making changes"
)
def update_badge(coverage_file: Path, readme_file: Path, dry_run: bool) -> None:
    """Update coverage badge in README."""
    logger = structlog.get_logger()
    logger.info(
        "Updating coverage badge",
        coverage_file=str(coverage_file),
        readme_file=str(readme_file),
    )

    try:
        import re
        import xml.etree.ElementTree as ET

        # Parse coverage XML
        tree = ET.parse(coverage_file)
        root = tree.getroot()

        # Extract coverage percentage
        line_rate = float(root.get("line-rate", "0"))
        coverage_percentage = int(line_rate * 100)

        logger.info(f"Current coverage: {coverage_percentage}%")

        # Determine badge color based on coverage
        if coverage_percentage >= 90:
            color = "brightgreen"
        elif coverage_percentage >= 80:
            color = "green"
        elif coverage_percentage >= 70:
            color = "yellowgreen"
        elif coverage_percentage >= 60:
            color = "yellow"
        elif coverage_percentage >= 50:
            color = "orange"
        else:
            color = "red"

        # Create new badge URL
        new_badge_url = (
            f"https://img.shields.io/badge/coverage-{coverage_percentage}%25-{color}"
        )

        # Read README content
        readme_content = readme_file.read_text()

        # Find and replace coverage badge
        # Look for pattern: ![Coverage](https://img.shields.io/badge/coverage-XX%-color)
        badge_pattern = (
            r"!\[Coverage\]\(https://img\.shields\.io/badge/coverage-\d+%25-\w+\)"
        )
        new_badge = f"![Coverage]({new_badge_url})"

        # Check if badge exists
        if not re.search(badge_pattern, readme_content):
            logger.warning("Coverage badge not found in README")
            console.print("[yellow]⚠[/yellow] Coverage badge not found in README")
            return

        # Replace the badge
        updated_content = re.sub(badge_pattern, new_badge, readme_content)

        # Check if content changed
        if updated_content == readme_content:
            logger.info("Coverage badge is already up to date")
            console.print(
                f"[green]✓[/green] Coverage badge already shows {coverage_percentage}%"
            )
            return

        if dry_run:
            # Show what would be changed
            old_badge_match = re.search(badge_pattern, readme_content)
            if old_badge_match:
                old_badge = old_badge_match.group(0)
                console.print(
                    "\n[yellow]🔍 DRY RUN MODE - Would update coverage badge[/yellow]"
                )
                console.print(f"  Current: {old_badge}")
                console.print(f"  New:     {new_badge}")
                console.print(f"  Coverage: {coverage_percentage}% (color: {color})")
        else:
            # Write updated content
            readme_file.write_text(updated_content)
            logger.info(f"Updated coverage badge to {coverage_percentage}%")
            console.print(
                f"[green]✓[/green] Coverage badge updated to {coverage_percentage}% (color: {color})"
            )

    except ET.ParseError as e:
        logger.error("Failed to parse coverage XML", error=str(e))
        console.print(f"[red]✗[/red] Failed to parse coverage XML: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error("Failed to update coverage badge", error=str(e))
        console.print(f"[red]✗[/red] Failed to update coverage badge: {e}")
        sys.exit(1)


@cli.command()
@click.option("--webhook-url", envvar="SLACK_WEBHOOK", help="Slack webhook URL")
@click.option(
    "--teams-webhook", envvar="TEAMS_WEBHOOK", help="Microsoft Teams webhook URL"
)
@click.option(
    "--risk-threshold",
    type=int,
    default=80,
    help="Minimum risk score for alerts (0-100)",
)
@click.option("--dry-run", is_flag=True, help="Print alerts without sending")
def send_alerts(
    webhook_url: str, teams_webhook: str, risk_threshold: int, dry_run: bool
) -> None:
    """Send vulnerability alerts to configured webhooks."""
    logger = structlog.get_logger()

    webhooks = []
    if webhook_url:
        webhooks.append(("Slack", webhook_url))
    if teams_webhook:
        webhooks.append(("Teams", teams_webhook))

    if not webhooks and not dry_run:
        logger.error("No webhook URLs configured")
        console.print(
            "[red]✗[/red] No webhook URLs configured. Set SLACK_WEBHOOK or TEAMS_WEBHOOK environment variables."
        )
        sys.exit(1)

    if dry_run:
        logger.info("Running in dry-run mode")

    # Get recent high-priority vulnerabilities from cache
    cache_manager = CacheManager(Path(".cache"))
    vulnerabilities = cache_manager.get_recent_vulnerabilities(limit=100)

    if not vulnerabilities:
        logger.warning("No vulnerabilities found in cache")
        console.print(
            "[yellow]⚠[/yellow] No vulnerabilities found. Run 'harvest' first."
        )
        return

    # Filter for high-risk vulnerabilities using configurable threshold
    high_risk_vulns = [
        v for v in vulnerabilities if (v.risk_score or 0) >= risk_threshold
    ]

    if not high_risk_vulns:
        logger.info("No high-risk vulnerabilities found")
        console.print(
            f"[green]ℹ[/green] No high-risk vulnerabilities (score >= {risk_threshold}) found."
        )
        return

    if dry_run:
        logger.info("Running in dry-run mode - showing alerts without sending")
        console.print(
            f"\n[yellow]🔍 DRY RUN MODE - Would send {len(high_risk_vulns)} alerts[/yellow]"
        )

        # Show what would be sent
        table = Table(title="High-Risk Vulnerabilities (Would be sent as alerts)")
        table.add_column("CVE ID", style="cyan")
        table.add_column("Risk Score", style="red")
        table.add_column("Severity", style="yellow")
        table.add_column("EPSS %", style="magenta")
        table.add_column("Title", style="white", max_width=40)

        for vuln in high_risk_vulns[:10]:  # Show top 10
            table.add_row(
                vuln.cve_id,
                str(vuln.risk_score),
                vuln.severity.value,
                f"{(vuln.epss_probability or 0):.1f}%",
                (vuln.title[:40] + "...") if len(vuln.title) > 40 else vuln.title,
            )

        console.print(table)
        console.print("\n[blue]📤 Webhook destinations:[/blue]")
        if webhook_url:
            console.print(
                f"  • Slack: {webhook_url[:50]}{'...' if len(webhook_url) > 50 else ''}"
            )
        if teams_webhook:
            console.print(
                f"  • Teams: {teams_webhook[:50]}{'...' if len(teams_webhook) > 50 else ''}"
            )
        if not webhooks:
            console.print("  • No webhooks configured")
        console.print(f"  • Risk threshold: >= {risk_threshold}/100")
        console.print("  • Format: JSON payload with vulnerability details")
        return

    # Send actual alerts
    from datetime import datetime

    import requests

    logger.info(
        "Sending vulnerability alerts",
        count=len(high_risk_vulns),
        webhooks=len(webhooks),
    )

    def create_slack_payload(vulns, threshold):
        """Create Slack-compatible webhook payload."""
        return {
            "text": f"🚨 {len(vulns)} High-Risk Vulnerabilities Detected",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*🚨 Vuln-Bot Alert: {len(vulns)} High-Risk Vulnerabilities*\n"
                        + f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                        + f"Risk threshold: ≥{threshold}/100",
                    },
                },
                {"type": "divider"},
            ],
        }

    def create_teams_payload(vulns, threshold):
        """Create Microsoft Teams-compatible webhook payload."""
        facts = []
        for i, vuln in enumerate(vulns[:5], 1):
            facts.append(
                {
                    "name": f"{i}. {vuln.cve_id}",
                    "value": f"Risk: {vuln.risk_score}/100 | Severity: {vuln.severity.value} | EPSS: {(vuln.epss_probability or 0):.1f}%",
                }
            )

        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF6B35",
            "summary": f"🚨 {len(vulns)} High-Risk Vulnerabilities Detected",
            "sections": [
                {
                    "activityTitle": "🚨 Vuln-Bot Alert",
                    "activitySubtitle": f"{len(vulns)} High-Risk Vulnerabilities",
                    "activityImage": "",
                    "facts": [
                        {
                            "name": "Generated",
                            "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
                        },
                        {"name": "Risk Threshold", "value": f"≥{threshold}/100"},
                        {"name": "Total Found", "value": str(len(vulns))},
                    ],
                    "markdown": True,
                },
                {
                    "activityTitle": "Top Vulnerabilities",
                    "facts": facts,
                    "markdown": True,
                },
            ],
        }

    # Send alerts to all configured webhooks
    success_count = 0
    failed_webhooks = []

    for webhook_type, webhook_url in webhooks:
        try:
            # Create appropriate payload for the webhook type
            if webhook_type == "Slack":
                payload = create_slack_payload(high_risk_vulns, risk_threshold)
                # Add vulnerability details for Slack
                for i, vuln in enumerate(high_risk_vulns[:5], 1):
                    payload["blocks"].append(
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"*{i}. {vuln.cve_id}* (Risk: {vuln.risk_score}/100)\n"
                                + f"📊 Severity: {vuln.severity.value} | "
                                + f"🎯 EPSS: {(vuln.epss_probability or 0):.1f}%\n"
                                + f"📝 {vuln.title[:100]}{'...' if len(vuln.title) > 100 else ''}",
                            },
                        }
                    )

                if len(high_risk_vulns) > 5:
                    payload["blocks"].append(
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"_...and {len(high_risk_vulns) - 5} more high-risk vulnerabilities._",
                            },
                        }
                    )

                # Add footer
                payload["blocks"].extend(
                    [
                        {"type": "divider"},
                        {
                            "type": "context",
                            "elements": [
                                {
                                    "type": "mrkdwn",
                                    "text": "🤖 Vuln-Bot | High-Risk CVE Intelligence Platform",
                                }
                            ],
                        },
                    ]
                )

            elif webhook_type == "Teams":
                payload = create_teams_payload(high_risk_vulns, risk_threshold)

            # Send the webhook
            response = requests.post(
                webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            response.raise_for_status()

            logger.info(
                f"{webhook_type} alert sent successfully",
                status_code=response.status_code,
                webhook=webhook_url[:50] + "..."
                if len(webhook_url) > 50
                else webhook_url,
            )

            console.print(
                f"[green]✓[/green] {webhook_type}: Alert sent successfully (status: {response.status_code})"
            )
            success_count += 1

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send {webhook_type} alert", error=str(e))
            console.print(f"[red]✗[/red] {webhook_type}: Failed to send alert - {e}")
            failed_webhooks.append((webhook_type, str(e)))
        except Exception as e:
            logger.error(f"Unexpected error sending {webhook_type} alert", error=str(e))
            console.print(f"[red]✗[/red] {webhook_type}: Unexpected error - {e}")
            failed_webhooks.append((webhook_type, str(e)))

    # Summary
    console.print("\n[blue]📊 Alert Summary:[/blue]")
    console.print(
        f"  Vulnerabilities: {len(high_risk_vulns)} (risk >= {risk_threshold})"
    )
    console.print(f"  Webhooks: {success_count}/{len(webhooks)} successful")

    if failed_webhooks:
        console.print("[yellow]⚠[/yellow] Failed webhooks:")
        for webhook_type, error in failed_webhooks:
            console.print(f"  • {webhook_type}: {error}")
        sys.exit(1)

    console.print("[green]🚀 All alerts sent successfully![/green]")


if __name__ == "__main__":
    cli()
