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
    "--min-epss",
    type=float,
    default=0.6,
    help="Minimum EPSS score (0.0-1.0, default: 0.6 for 60%)",
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
        "NVD_API_KEY": os.getenv("NVD_API_KEY"),
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
@click.option(
    "--storage-strategy",
    type=click.Choice(["severity-year", "size-chunks", "single-file"]),
    default="severity-year",
    help="Storage strategy for vulnerability data (default: severity-year)",
)
def generate_briefing(
    output_dir: Path, cache_dir: Path, limit: int, storage_strategy: str
) -> None:
    """Generate vulnerability briefing from harvested data."""
    logger = structlog.get_logger()
    logger.info(
        "Generating vulnerability briefing",
        output_dir=str(output_dir),
        storage_strategy=storage_strategy,
    )

    try:
        # Initialize components
        from scripts.processing.optimized_briefing_generator import (
            OptimizedBriefingGenerator,
        )

        cache_manager = CacheManager(cache_dir)
        generator = OptimizedBriefingGenerator(output_dir, storage_strategy)

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
        console.print(f"  Storage strategy: {storage_strategy}")
        if "chunks" in results and results["chunks"]:
            console.print(f"  Data chunks: {len(results['chunks'])} files")
            if results.get("chunk_index"):
                console.print(f"  Chunk index: {results['chunk_index']}")

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
        # nosec B314 - coverage.xml is a trusted local file generated by pytest
        tree = ET.parse(coverage_file)  # nosec
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
                webhook=(
                    webhook_url[:50] + "..." if len(webhook_url) > 50 else webhook_url
                ),
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


@cli.command()
@click.option(
    "--cache-dir",
    type=click.Path(path_type=Path),
    default=Path(".cache"),
    help="Directory containing cached vulnerability data",
)
@click.option(
    "--api-dir",
    type=click.Path(path_type=Path),
    default=Path("api"),
    help="Directory containing API files to validate",
)
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path),
    default=Path("reports"),
    help="Directory for report output",
)
@click.option(
    "--min-epss",
    type=float,
    default=0.6,
    help="Minimum EPSS threshold (0.0-1.0, default: 0.6 for 60%)",
)
@click.option(
    "--fail-on-violations",
    is_flag=True,
    help="Exit with error code if threshold violations are found",
)
def validate_threshold_compliance(
    cache_dir: Path, api_dir: Path, output_dir: Path, min_epss: float, fail_on_violations: bool
) -> None:
    """Validate EPSS threshold compliance for CI/CD gating."""
    logger = structlog.get_logger()

    try:
        logger.info(
            "Validating threshold compliance",
            min_epss=min_epss,
            min_epss_percentage=int(min_epss * 100)
        )

        from scripts.agents.threshold_compliance_agent import ThresholdComplianceAgent
        from scripts.processing.cache_manager import CacheManager

        # Initialize compliance agent
        compliance_agent = ThresholdComplianceAgent(
            cache_dir=cache_dir,
            min_epss_threshold=min_epss
        )

        validation_result = None

        # First try to validate API files if they exist
        if api_dir.exists() and (api_dir / "vulns").exists():
            logger.info("Validating API files", api_dir=api_dir)
            validation_result = compliance_agent.validate_api_files(api_dir)
        else:
            # Fall back to cache validation
            logger.info("API files not found, validating cached data", cache_dir=cache_dir)
            cache_manager = CacheManager(cache_dir)
            cached_vulns = cache_manager.get_recent_vulnerabilities(limit=50000)

            if cached_vulns:
                # Convert to dict format for validation
                vulnerabilities = [vuln.to_summary_dict() for vuln in cached_vulns]
                validation_result = compliance_agent.validate_vulnerability_compliance(vulnerabilities)
            else:
                logger.error("No data found for validation")
                console.print("[red]✗[/red] No vulnerability data found. Run 'harvest' and 'generate-briefing' first.")
                sys.exit(1)

        if not validation_result:
            logger.error("Validation failed to run")
            sys.exit(1)

        # Save reports
        json_path, txt_path = compliance_agent.save_compliance_report(validation_result, output_dir)

        # Display results
        report_text = compliance_agent.generate_compliance_report(validation_result)
        console.print(report_text)

        # Show file paths
        console.print("\n📄 Reports saved:")
        console.print(f"  JSON: {json_path}")
        console.print(f"  Text: {txt_path}")

        # Exit with appropriate code
        if validation_result["passed"]:
            console.print("\n[green]🎉 EPSS threshold compliance validation PASSED![/green]")
            sys.exit(0)
        else:
            violations_count = len(validation_result.get("violations", []))
            console.print("\n[red]❌ EPSS threshold compliance validation FAILED![/red]")
            console.print(f"[red]Found {violations_count} violations of ≥{int(min_epss * 100)}% EPSS threshold[/red]")

            if fail_on_violations:
                sys.exit(1)
            else:
                console.print("[yellow]⚠ Warning: --fail-on-violations not set, continuing with exit code 0[/yellow]")
                sys.exit(0)

    except Exception as e:
        logger.error("Failed to validate threshold compliance", error=str(e))
        console.print(f"[red]✗[/red] Failed to validate threshold compliance: {e}")
        sys.exit(1)


@cli.command()
@click.option(
    "--cache-dir",
    type=click.Path(path_type=Path),
    default=Path(".cache"),
    help="Directory for caching API responses",
)
@click.option(
    "--enable-osv/--disable-osv",
    default=True,
    help="Enable OSV.dev enrichment (cross-referencing and aliases)",
)
@click.option(
    "--enable-deps-dev/--disable-deps-dev",
    default=True,
    help="Enable deps.dev enrichment (package impact analysis)",
)
@click.option(
    "--enable-registry-stats/--disable-registry-stats",
    default=False,
    help="Enable package registry statistics (download metrics)",
)
@click.option(
    "--parallel/--sequential",
    default=True,
    help="Run enrichment sources in parallel (default: parallel)",
)
@click.option(
    "--limit",
    type=int,
    default=None,
    help="Maximum vulnerabilities to enrich (default: all)",
)
def enrich_multi_source(
    cache_dir: Path,
    enable_osv: bool,
    enable_deps_dev: bool,
    enable_registry_stats: bool,
    parallel: bool,
    limit: int,
) -> None:
    """Enrich cached vulnerabilities with multi-source data (OSV, deps.dev, registries)."""
    logger = structlog.get_logger()
    logger.info(
        "Starting multi-source enrichment",
        cache_dir=str(cache_dir),
        sources={
            "osv": enable_osv,
            "deps_dev": enable_deps_dev,
            "registry_stats": enable_registry_stats,
        },
        parallel=parallel,
    )

    try:
        from scripts.harvest.multi_source_harvester import MultiSourceHarvester
        from scripts.processing.cache_manager import CacheManager

        # Initialize components
        cache_manager = CacheManager(cache_dir)
        harvester = MultiSourceHarvester(
            cache_dir=cache_dir,
            cache_manager=cache_manager,
        )

        # Get vulnerabilities from cache
        vulnerabilities = cache_manager.get_recent_vulnerabilities(limit=limit or 50000)

        if not vulnerabilities:
            logger.warning("No vulnerabilities found in cache")
            console.print(
                "[yellow]⚠[/yellow] No vulnerabilities found. Run 'harvest' first."
            )
            return

        # Apply limit if specified
        if limit:
            vulnerabilities = vulnerabilities[:limit]
            logger.info("Limited enrichment", max_vulnerabilities=limit)

        # Perform enrichment
        enriched_batch = harvester.harvest_all_sources(
            vulnerabilities=vulnerabilities,
            enable_osv=enable_osv,
            enable_deps_dev=enable_deps_dev,
            enable_registry_stats=enable_registry_stats,
            parallel_enrichment=parallel,
        )

        # Display summary
        console.print("\n[green]✓[/green] Multi-source enrichment completed")
        console.print(f"Total vulnerabilities: {len(enriched_batch.vulnerabilities)}")

        # Show enrichment statistics
        stats = enriched_batch.metadata.get("enrichment_statistics", {})
        console.print("\n[blue]📊 Enrichment Statistics:[/blue]")
        console.print(f"  Sources attempted: {stats.get('sources_attempted', 0)}")
        console.print(f"  Sources succeeded: {stats.get('sources_succeeded', 0)}")
        console.print(f"  Sources failed: {stats.get('sources_failed', 0)}")

        enrichment_types = stats.get("enrichment_types", {})
        if enrichment_types:
            console.print("\n[cyan]🔍 Enrichment by Type:[/cyan]")
            for source, count in enrichment_types.items():
                console.print(f"  {source}: {count} vulnerabilities enriched")

        # Show duration
        duration = enriched_batch.metadata.get("duration_seconds", 0)
        console.print(f"\n⏱  Duration: {duration:.2f} seconds")

        # Update cache with enriched data
        logger.info("Updating cache with enriched data")
        cache_manager.cache_batch(enriched_batch)

        console.print("[green]✅ Enriched data cached successfully[/green]")

    except Exception as e:
        logger.error("Multi-source enrichment failed", error=str(e))
        console.print(f"[red]✗[/red] Failed to enrich vulnerabilities: {e}")
        sys.exit(1)


@cli.command()
@click.option(
    "--cache-dir",
    type=click.Path(path_type=Path),
    default=Path(".cache"),
    help="Directory containing cached vulnerability data",
)
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path),
    default=Path("reports"),
    help="Directory for report output",
)
@click.option(
    "--format",
    type=click.Choice(["json", "html", "both"]),
    default="both",
    help="Report output format",
)
def generate_quality_report(cache_dir: Path, output_dir: Path, format: str) -> None:
    """Generate comprehensive data quality report with EPSS filtering statistics."""
    logger = structlog.get_logger()

    try:
        logger.info("Generating data quality report", cache_dir=cache_dir, output_dir=output_dir)

        # Get vulnerabilities from cache or API data
        vulnerabilities = []
        harvest_metadata = {}

        # Try to load from cache first
        cache_manager = CacheManager(cache_dir)
        cached_vulns = cache_manager.get_recent_vulnerabilities(limit=50000)

        if cached_vulns:
            logger.info("Loading vulnerabilities from cache", count=len(cached_vulns))
            # Convert to dict format for analysis
            vulnerabilities = [vuln.to_summary_dict() for vuln in cached_vulns]
            harvest_metadata = {
                "source": "cache",
                "last_harvest": "unknown"
            }
        else:
            # Try to load from API files
            api_index_path = Path("api/vulns/index.json")
            if api_index_path.exists():
                logger.info("Loading vulnerabilities from API index")
                import json
                with open(api_index_path) as f:
                    api_data = json.load(f)
                    vulnerabilities = api_data.get("vulnerabilities", [])
                    harvest_metadata = {
                        "source": "api_files",
                        "generated": api_data.get("generated"),
                        "count": api_data.get("count")
                    }

        if not vulnerabilities:
            logger.warning("No vulnerabilities found")
            console.print("[yellow]⚠[/yellow] No vulnerabilities found. Run 'harvest' and 'generate-briefing' first.")
            return

        # Initialize report agent
        from scripts.agents.data_quality_report_agent import DataQualityReportAgent
        report_agent = DataQualityReportAgent(output_dir=output_dir)

        # Generate report
        report = report_agent.generate_quality_report(vulnerabilities, harvest_metadata)

        # Save in requested formats
        files_saved = []

        if format in ["json", "both"]:
            json_path = report_agent.save_report_json(report, "epss-quality-daily.json")
            files_saved.append(str(json_path))

        if format in ["html", "both"]:
            html_path = report_agent.save_report_html(report, "epss-quality-daily.html")
            files_saved.append(str(html_path))

        # Display summary
        summary = report["quality_summary"]
        console.print("\n[green]✓[/green] Data quality report generated successfully")
        console.print(f"  Total vulnerabilities: {report['report_metadata']['total_vulnerabilities']:,}")
        console.print(f"  EPSS coverage: {summary['data_completeness']['epss_coverage']:.1f}%")
        console.print(f"  EPSS ≥60% compliance: {summary['epss_threshold_compliance']['compliance_rate']:.1f}%")
        console.print(f"  CVSS coverage: {summary['data_completeness']['cvss_coverage']:.1f}%")
        console.print(f"  Vendor identification: {summary['data_completeness']['vendor_identification']:.1f}%")

        for file_path in files_saved:
            console.print(f"  Report: {file_path}")

        # Highlight any quality issues
        if summary['epss_threshold_compliance']['compliance_rate'] < 100:
            console.print(
                f"[yellow]⚠[/yellow] EPSS threshold compliance issue: "
                f"{summary['epss_threshold_compliance']['compliant_vulnerabilities']} of "
                f"{report['report_metadata']['total_vulnerabilities']} vulnerabilities meet ≥60% threshold"
            )

        if summary['data_completeness']['epss_coverage'] < 95:
            console.print(f"[yellow]⚠[/yellow] Low EPSS coverage: {summary['data_completeness']['epss_coverage']:.1f}%")

    except Exception as e:
        logger.error("Failed to generate quality report", error=str(e))
        console.print(f"[red]✗[/red] Failed to generate quality report: {e}")
        sys.exit(1)


if __name__ == "__main__":
    cli()
