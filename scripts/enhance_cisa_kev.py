#!/usr/bin/env python3
"""
Script to enhance vulnerability data with CISA KEV information.
"""

import json
from pathlib import Path

import click
import structlog

from scripts.agents.cisa_kev_agent import CISAKEVAgent

logger = structlog.get_logger()


@click.command()
@click.option(
    "--api-dir",
    type=click.Path(path_type=Path),
    default=Path("api/vulns"),
    help="Directory containing API JSON files",
)
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path),
    default=Path("api/vulns"),
    help="Output directory for enhanced files",
)
@click.option("--force-refresh", is_flag=True, help="Force refresh of CISA KEV catalog")
def enhance_cisa_kev(api_dir: Path, output_dir: Path, force_refresh: bool):
    """Enhance vulnerability data with CISA KEV information."""

    logger.info(
        "Starting CISA KEV enhancement",
        api_dir=api_dir,
        output_dir=output_dir,
        force_refresh=force_refresh,
    )

    # Initialize KEV agent
    agent = CISAKEVAgent()

    # Force refresh if requested
    if force_refresh:
        agent.fetch_kev_catalog(force_refresh=True)

    # Process index file
    index_file = api_dir / "index.json"
    if index_file.exists():
        logger.info("Processing index file", path=index_file)

        with open(index_file) as f:
            data = json.load(f)

        vulnerabilities = data.get("vulnerabilities", [])
        enriched_vulns = agent.enrich_batch(vulnerabilities)

        # Update data
        data["vulnerabilities"] = enriched_vulns

        # Save enhanced file
        output_file = output_dir / "index.json"
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)

        logger.info("Enhanced index file", vulnerabilities=len(vulnerabilities))

    # Process chunk files
    chunk_index_file = api_dir / "chunk-index.json"
    if chunk_index_file.exists():
        with open(chunk_index_file) as f:
            chunk_index = json.load(f)

        for chunk in chunk_index.get("chunks", []):
            chunk_file = chunk.get("file")
            if chunk_file:
                chunk_path = api_dir / chunk_file
                if chunk_path.exists():
                    logger.info("Processing chunk file", path=chunk_path)

                    with open(chunk_path) as f:
                        chunk_data = json.load(f)

                    vulnerabilities = chunk_data.get("vulnerabilities", [])
                    enriched_vulns = agent.enrich_batch(vulnerabilities)

                    # Update data
                    chunk_data["vulnerabilities"] = enriched_vulns

                    # Save enhanced file
                    output_file = output_dir / chunk_file
                    with open(output_file, "w") as f:
                        json.dump(chunk_data, f, indent=2)

                    logger.info(
                        "Enhanced chunk file",
                        file=chunk_file,
                        vulnerabilities=len(vulnerabilities),
                    )

    # Get and display statistics
    stats = agent.get_kev_statistics()

    click.echo("\n✅ CISA KEV Enhancement Summary:")
    click.echo(f"  KEV Catalog Size: {stats['catalog_size']} entries")
    click.echo(
        f"  Vulnerabilities Processed: {stats['enrichment_stats']['total_processed']}"
    )
    click.echo(f"  KEV Matches Found: {stats['enrichment_stats']['kev_enriched']}")
    click.echo(f"  Enrichment Rate: {stats['enrichment_stats']['enrichment_rate']}")

    if "catalog_insights" in stats:
        insights = stats["catalog_insights"]
        click.echo("\n📊 KEV Catalog Insights:")
        click.echo(
            f"  Known Ransomware: {insights['known_ransomware_count']} ({insights['ransomware_percentage']})"
        )
        click.echo("  Recent Entries (by year):")
        for year, count in list(insights["entries_by_year"].items())[:5]:
            click.echo(f"    {year}: {count} entries")


if __name__ == "__main__":
    enhance_cisa_kev()
