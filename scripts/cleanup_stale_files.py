#!/usr/bin/env python3
"""
Script to clean up stale files before building the site.
"""

from pathlib import Path

import click
import structlog

from scripts.agents.cleanup_agent import CleanupAgent

logger = structlog.get_logger()


@click.command()
@click.option(
    "--build-dir",
    type=click.Path(path_type=Path),
    default=Path("_site"),
    help="Build directory to clean",
)
@click.option(
    "--api-dir",
    type=click.Path(path_type=Path),
    default=Path("api"),
    help="API directory containing vulnerability data",
)
@click.option(
    "--posts-dir",
    type=click.Path(path_type=Path),
    default=Path("src/_posts"),
    help="Posts directory containing CVE markdown files",
)
@click.option(
    "--min-epss", type=float, default=0.6, help="Minimum EPSS threshold for valid CVEs"
)
@click.option(
    "--verify-only", is_flag=True, help="Only verify for stale files without cleaning"
)
@click.option(
    "--force-purge", is_flag=True, help="Force complete removal of build directories"
)
@click.option(
    "--safe-mode",
    is_flag=True,
    help="Audit-only mode: list files that would be deleted without removing them",
)
def cleanup_stale_files(
    build_dir: Path,
    api_dir: Path,
    posts_dir: Path,
    min_epss: float,
    verify_only: bool,
    force_purge: bool,
    safe_mode: bool,
):
    """Clean up stale CVE files before building the site."""

    agent = CleanupAgent()

    if safe_mode:
        # Audit-only mode: show what would be deleted
        click.echo("🔍 Running in SAFE MODE (audit-only)...\n")

        valid_ids = agent._get_valid_cve_ids(api_dir, min_epss)
        from scripts.agents.repo_audit_agent import RepoAuditAgent

        audit_agent = RepoAuditAgent()

        # Audit each directory
        total_to_delete = 0
        for directory in [build_dir, posts_dir]:
            if directory.exists():
                vestigial_files = audit_agent.find_vestigial_files(
                    directory, api_dir, min_epss
                )
                if vestigial_files:
                    click.echo(f"\n📁 {directory}:")
                    click.echo(f"  Would delete {len(vestigial_files)} files:")
                    for file in vestigial_files[:10]:
                        click.echo(f"    - {file}")
                    if len(vestigial_files) > 10:
                        click.echo(f"    ... and {len(vestigial_files) - 10} more")
                    total_to_delete += len(vestigial_files)

        click.echo(f"\n📊 Total files that would be deleted: {total_to_delete}")
        click.echo("\n💡 To actually delete these files, run without --safe-mode")

    elif verify_only:
        # Get valid CVE IDs
        valid_ids = agent._get_valid_cve_ids(api_dir, min_epss)

        # Verify no stale files
        results = agent.verify_no_stale_files(build_dir, valid_ids)

        if results["verification_passed"]:
            click.echo("✅ No stale files found")
        else:
            click.echo(f"❌ Found {len(results['stale_files_found'])} stale files")
            for file in results["stale_files_found"][:10]:
                click.echo(f"  - {file}")
            if len(results["stale_files_found"]) > 10:
                click.echo(f"  ... and {len(results['stale_files_found']) - 10} more")

            # Exit with error code
            raise click.ClickException("Stale files detected")
    else:
        # Perform cleanup
        if force_purge:
            click.echo(
                "🔥 FORCE PURGE mode enabled - will completely remove directories\n"
            )

        stats = agent.clean_before_build(
            build_dir=build_dir,
            api_dir=api_dir,
            posts_dir=posts_dir,
            min_epss_threshold=min_epss,
            force_purge=force_purge,
        )

        # Display report
        report = agent.generate_cleanup_report()
        click.echo(report)

        # Show summary
        click.echo("\n✅ Cleanup completed:")
        click.echo(f"  - Removed {stats['files_removed']} files")
        click.echo(f"  - Freed {agent._format_bytes(stats['bytes_freed'])}")
        click.echo(f"  - Found {stats['stale_cves_found']} stale CVEs")

        if force_purge:
            click.echo(
                f"  - Force purged {stats.get('directories_cleaned', 0)} directories"
            )

        # Log metrics
        logger.info(
            "Cleanup metrics",
            files_removed=stats["files_removed"],
            bytes_freed=stats["bytes_freed"],
            stale_cves=stats["stale_cves_found"],
            force_purge=force_purge,
        )


if __name__ == "__main__":
    cleanup_stale_files()
