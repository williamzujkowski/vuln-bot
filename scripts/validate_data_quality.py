#!/usr/bin/env python3
"""
Script to validate data quality at various pipeline stages.
"""

import json
from datetime import datetime
from pathlib import Path

import click
import structlog

from scripts.agents.data_validation_agent import DataValidationAgent

logger = structlog.get_logger()


@click.command()
@click.option(
    "--stage",
    type=click.Choice(["raw", "filtered", "enriched", "published"]),
    required=True,
    help="Pipeline stage to validate"
)
@click.option(
    "--api-dir",
    type=click.Path(path_type=Path),
    default=Path("api"),
    help="Directory containing API data"
)
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path),
    default=Path("reports"),
    help="Output directory for validation reports"
)
def validate_data_quality(stage: str, api_dir: Path, output_dir: Path):
    """Validate data quality at specified pipeline stage."""

    logger.info("Starting data validation", stage=stage, api_dir=api_dir)

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Initialize validation agent
    agent = DataValidationAgent()

    # Load vulnerabilities
    vulnerabilities = []
    index_file = api_dir / "vulns" / "index.json"

    if index_file.exists():
        with open(index_file) as f:
            data = json.load(f)
            vulnerabilities = data.get("vulnerabilities", [])

    # Perform validation based on stage
    validation_count = 0

    if stage == "raw":
        for vuln in vulnerabilities:
            agent.validate_raw_cve_data(vuln)
            validation_count += 1

    elif stage == "filtered":
        for vuln in vulnerabilities:
            agent.validate_epss_filtered_data(vuln)
            validation_count += 1

    elif stage == "enriched":
        for vuln in vulnerabilities:
            agent.validate_enriched_data(vuln)
            validation_count += 1

    elif stage == "published":
        # Validate all JSON files
        json_files = list((api_dir / "vulns").glob("*.json"))
        for json_file in json_files:
            agent.validate_published_data(json_file)
            validation_count += 1

    # Generate report
    report = agent.generate_validation_report()

    # Save reports
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    # Save text report
    text_report_path = output_dir / f"data_validation_{stage}_{timestamp}.txt"
    with open(text_report_path, 'w') as f:
        f.write(report)

    # Save JSON report
    json_report_path = output_dir / f"data_validation_{stage}_{timestamp}.json"
    with open(json_report_path, 'w') as f:
        json.dump({
            "stage": stage,
            "timestamp": datetime.utcnow().isoformat(),
            "validation_count": validation_count,
            "results": agent.validation_results
        }, f, indent=2)

    # Display summary
    click.echo(report)

    # Exit with error if validations failed
    if agent.validation_results["failed"] > 0:
        click.echo(f"\n❌ {agent.validation_results['failed']} validations failed!")
        raise click.ClickException("Data validation failed")
    else:
        click.echo(f"\n✅ All {agent.validation_results['passed']} validations passed!")


if __name__ == "__main__":
    validate_data_quality()
