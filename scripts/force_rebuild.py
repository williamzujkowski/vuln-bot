#!/usr/bin/env python3
"""
Force rebuild script to fix stale data issues on production.
This script performs a complete cleanup and rebuild to ensure no stale files remain.
"""

import sys
from pathlib import Path

import click
import structlog

from scripts.agents.build_deploy_agent import BuildDeployAgent
from scripts.agents.repo_audit_agent import RepoAuditAgent

logger = structlog.get_logger()


@click.command()
@click.option("--audit-only", is_flag=True, help="Only run audit without rebuilding")
@click.option(
    "--expected-count",
    type=int,
    default=295,
    help="Expected number of CVEs (for validation)",
)
@click.option("--min-epss", type=float, default=0.6, help="Minimum EPSS threshold")
def force_rebuild(audit_only: bool, expected_count: int, min_epss: float):
    """Force a complete rebuild to fix stale data issues."""

    # Initialize agents
    build_agent = BuildDeployAgent()
    audit_agent = RepoAuditAgent()

    # Paths
    build_dir = Path("_site")
    public_dir = Path("public")
    api_dir = Path("api")

    # Get valid CVE IDs
    valid_ids = set()
    index_file = api_dir / "vulns" / "index.json"
    if index_file.exists():
        import json

        with open(index_file) as f:
            data = json.load(f)
        for vuln in data.get("vulnerabilities", []):
            if vuln.get("epss", {}).get("score", 0) >= min_epss:
                valid_ids.add(vuln["cveId"])

    click.echo(f"Found {len(valid_ids)} valid CVEs with EPSS >= {min_epss * 100}%")

    if audit_only:
        # Run audit only
        click.echo("\n📊 Running repository audit...")

        for directory in [build_dir, public_dir]:
            if directory.exists():
                click.echo(f"\nAuditing {directory}...")
                results = audit_agent.audit_build_directory(
                    directory, valid_ids, expected_count
                )

                # Display report
                report = audit_agent.generate_audit_report()
                click.echo(report)

                # Show critical findings
                if results["recommendations"]:
                    click.echo("\n⚠️  Critical Findings:")
                    for rec in results["recommendations"]:
                        if rec["severity"] in ["CRITICAL", "HIGH"]:
                            click.echo(f"  [{rec['severity']}] {rec['issue']}")
                            click.echo(f"    → {rec['action']}")
    else:
        # Run full rebuild
        click.echo("\n🔨 Starting forced rebuild...")

        results = build_agent.force_full_rebuild(
            build_dir=build_dir,
            api_dir=api_dir,
            public_dir=public_dir,
            min_epss=min_epss,
        )

        # Display report
        report = build_agent.generate_build_report(results)
        click.echo(report)

        # Check for errors
        if results["errors"]:
            click.echo("\n❌ Build completed with errors:")
            for error in results["errors"]:
                click.echo(f"  - {error}")
            sys.exit(1)

        # Generate deployment script
        if results["status"] == "completed":
            click.echo("\n📦 Preparing GitHub Pages deployment...")

            deploy_results = build_agent.prepare_gh_pages_deployment()

            if deploy_results["status"] == "prepared":
                click.echo("\n✅ Deployment script created!")
                click.echo("\nNext steps:")
                for instruction in deploy_results["instructions"]:
                    click.echo(f"  → {instruction}")
            else:
                click.echo(
                    f"\n❌ Deployment preparation failed: {deploy_results['errors']}"
                )

    click.echo("\n✨ Done!")


if __name__ == "__main__":
    force_rebuild()
