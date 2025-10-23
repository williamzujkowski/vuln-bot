#!/usr/bin/env python3
"""
Comprehensive CI/CD gatecheck script to prevent deployment of incorrect data.
This script implements strict thresholds to catch issues like the 15,000+ CVE problem.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import click
import structlog
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

logger = structlog.get_logger()
console = Console()


class CIGatecheck:
    """Comprehensive gatecheck validation for CI/CD pipeline."""

    def __init__(self):
        self.errors = []
        self.warnings = []
        self.metrics = {}

    def add_error(self, message: str, details: Optional[str] = None):
        """Add a critical error that should fail the build."""
        self.errors.append({"message": message, "details": details})
        logger.error(message, details=details)

    def add_warning(self, message: str, details: Optional[str] = None):
        """Add a warning that should be noted but not fail the build."""
        self.warnings.append({"message": message, "details": details})
        logger.warning(message, details=details)

    def validate_cve_count_threshold(
        self,
        api_dir: Path,
        max_count: int = 1000,
        expected_count: int = 298,
        min_baseline: int = 298,
    ):
        """
        Critical validation: Ensure CVE count is within reasonable bounds.
        This is the primary check to prevent the 15,000+ CVE issue.

        Args:
            api_dir: Directory containing API data
            max_count: Maximum CVE count (prevents stale data issue)
            expected_count: Expected CVE count for this harvest
            min_baseline: Minimum baseline count (count should NEVER go below this)
        """
        console.print("\n[bold blue]🔍 Validating CVE Count Thresholds[/bold blue]")

        # Check main index file
        index_file = api_dir / "vulns" / "index.json"
        total_cves = 0

        if index_file.exists():
            with open(index_file) as f:
                data = json.load(f)
                total_cves = len(data.get("vulnerabilities", []))

        self.metrics["total_cves"] = total_cves
        self.metrics["min_baseline"] = min_baseline
        self.metrics["expected_count"] = expected_count

        # CRITICAL: Check for excessive CVE count (15,000+ issue)
        if total_cves > max_count:
            self.add_error(
                f"CRITICAL: Excessive CVE count detected: {total_cves} > {max_count}",
                f"This indicates stale data is present. Expected ~{expected_count} CVEs after EPSS filtering.",
            )
            return False

        # CRITICAL: Enforce minimum baseline (count should NEVER decrease)
        if total_cves < min_baseline:
            self.add_error(
                f"CRITICAL: CVE count regression detected: {total_cves} < {min_baseline} (baseline)",
                f"Count dropped from baseline of {min_baseline}. This indicates harvest is missing CVEs that should be included.",
            )
            return False

        # Check if count is reasonable for our filtering criteria (warning only)
        tolerance = 0.5  # 50% tolerance for expected count (not baseline)
        max_acceptable = int(expected_count * (1 + tolerance))

        if total_cves > max_acceptable:
            self.add_warning(
                f"CVE count higher than expected: {total_cves} > {max_acceptable}",
                f"Expected ~{expected_count}. This might indicate new CVEs meeting criteria or threshold changes.",
            )

        console.print(
            f"✅ CVE count validation passed: {total_cves} CVEs (baseline: ≥{min_baseline}, expected: ~{expected_count})"
        )
        return True

    def validate_epss_threshold_compliance(self, api_dir: Path, min_epss: float = 0.6):
        """Validate that all CVEs meet the minimum EPSS threshold."""
        console.print(
            f"\n[bold blue]🎯 Validating EPSS Threshold Compliance (≥{min_epss * 100}%)[/bold blue]"
        )

        violations = []
        total_checked = 0

        # Check main index file
        # NOTE: index.json uses flattened structure with epssScore (percentage)
        # while chunk files use nested epss.score (decimal)
        index_file = api_dir / "vulns" / "index.json"
        if index_file.exists():
            with open(index_file) as f:
                data = json.load(f)
                for vuln in data.get("vulnerabilities", []):
                    total_checked += 1
                    # Index file uses epssScore field as percentage (90.99)
                    epss_score_pct = vuln.get("epssScore", 0)
                    epss_score = epss_score_pct / 100.0  # Convert to decimal

                    if epss_score < min_epss:
                        violations.append(
                            {
                                "cveId": vuln.get("cveId"),
                                "epss": epss_score * 100,
                                "severity": vuln.get("severity"),
                            }
                        )

        # Check chunk files for consistency
        chunk_violations = []
        vulns_dir = api_dir / "vulns"
        if vulns_dir.exists():
            for chunk_file in vulns_dir.glob("vulns-*.json"):
                with open(chunk_file) as f:
                    chunk_data = json.load(f)
                    for vuln in chunk_data.get("vulnerabilities", []):
                        # Try legacy format first (epss.score)
                        epss_score = vuln.get("epss", {}).get("score", 0)

                        # If not found, try CVE 5.0 format (containers.adp[].enrichments.epss.score)
                        if epss_score == 0 and "containers" in vuln:
                            for adp in vuln.get("containers", {}).get("adp", []):
                                epss_data = adp.get("enrichments", {}).get("epss", {})
                                if epss_data.get("score"):
                                    epss_score = epss_data["score"]
                                    break

                        if epss_score < min_epss:
                            chunk_violations.append(
                                {
                                    "file": chunk_file.name,
                                    "cveId": vuln.get("cveId"),
                                    "epss": epss_score * 100,
                                }
                            )

        self.metrics["epss_violations"] = len(violations) + len(chunk_violations)
        self.metrics["total_checked_epss"] = total_checked

        if violations or chunk_violations:
            self.add_error(
                f"EPSS threshold violations found: {len(violations)} in index, {len(chunk_violations)} in chunks",
                f"Sample violations: {(violations + chunk_violations)[:5]}",
            )
            return False

        console.print(
            f"✅ EPSS threshold compliance passed: {total_checked} CVEs checked"
        )
        return True

    def validate_chunk_file_consistency(self, api_dir: Path):
        """Validate that chunk files are consistent and not oversized."""
        console.print("\n[bold blue]📦 Validating Chunk File Consistency[/bold blue]")

        chunk_index_file = api_dir / "vulns" / "chunk-index.json"
        if not chunk_index_file.exists():
            self.add_warning("Chunk index file not found - using direct file discovery")
            return True

        with open(chunk_index_file) as f:
            chunk_index = json.load(f)

        total_in_chunks = 0
        oversized_chunks = []

        for chunk_info in chunk_index.get("chunks", []):
            chunk_file = api_dir / "vulns" / chunk_info["file"]

            if not chunk_file.exists():
                self.add_error(f"Chunk file missing: {chunk_info['file']}")
                continue

            with open(chunk_file) as f:
                chunk_data = json.load(f)
                chunk_count = len(chunk_data.get("vulnerabilities", []))
                total_in_chunks += chunk_count

                # Check for oversized chunks (likely indicates stale data)
                if chunk_count > 1000:
                    oversized_chunks.append(
                        {"file": chunk_info["file"], "count": chunk_count}
                    )

        self.metrics["total_in_chunks"] = total_in_chunks
        self.metrics["oversized_chunks"] = len(oversized_chunks)

        if oversized_chunks:
            self.add_error(
                f"Oversized chunks detected: {len(oversized_chunks)} files",
                f"Oversized chunks: {oversized_chunks}",
            )
            return False

        console.print(
            f"✅ Chunk consistency validated: {total_in_chunks} CVEs across chunks"
        )
        return True

    def validate_api_structure(self, api_dir: Path):
        """Validate the API structure and required files."""
        console.print("\n[bold blue]📋 Validating API Structure[/bold blue]")

        required_files = ["vulns/index.json", "vulns/chunk-index.json"]

        missing_files = []
        for file_path in required_files:
            full_path = api_dir / file_path
            if not full_path.exists():
                missing_files.append(file_path)

        if missing_files:
            self.add_error(
                f"Required API files missing: {missing_files}",
                "This indicates incomplete build or generation failure",
            )
            return False

        console.print("✅ API structure validation passed")
        return True

    def validate_data_freshness(self, api_dir: Path, max_age_hours: int = 8):
        """Validate that data appears fresh and not stale."""
        console.print(
            f"\n[bold blue]🕒 Validating Data Freshness (max {max_age_hours}h)[/bold blue]"
        )

        index_file = api_dir / "vulns" / "index.json"
        if not index_file.exists():
            self.add_error("Index file missing for freshness check")
            return False

        # Check file modification time
        file_age_hours = (
            datetime.now().timestamp() - index_file.stat().st_mtime
        ) / 3600

        self.metrics["data_age_hours"] = file_age_hours

        if file_age_hours > max_age_hours:
            self.add_error(
                f"CRITICAL: Data is stale: {file_age_hours:.1f} hours old > {max_age_hours}h",
                "Re-run harvest with --force-refresh or investigate harvest pipeline failures",
            )

        console.print(f"✅ Data freshness validated: {file_age_hours:.1f} hours old")
        return True

    def check_for_known_stale_patterns(self, api_dir: Path):
        """Check for patterns that indicate stale data presence."""
        console.print("\n[bold blue]🔍 Checking for Stale Data Patterns[/bold blue]")

        stale_indicators = []

        # Check for year-based chunk files that shouldn't exist
        vulns_dir = api_dir / "vulns"
        if vulns_dir.exists():
            for chunk_file in vulns_dir.glob("vulns-202[0-3]-*.json"):
                # Files from 2020-2023 shouldn't exist with our current filtering
                stale_indicators.append(f"Old year chunk file: {chunk_file.name}")

        # Check for low EPSS files that shouldn't exist
        if vulns_dir.exists():
            for chunk_file in vulns_dir.glob("vulns-*-LOW.json"):
                stale_indicators.append(f"Low severity chunk file: {chunk_file.name}")

        self.metrics["stale_indicators"] = len(stale_indicators)

        if stale_indicators:
            self.add_error(
                f"Stale data patterns detected: {len(stale_indicators)} indicators",
                f"Indicators: {stale_indicators[:5]}",
            )
            return False

        console.print("✅ No stale data patterns detected")
        return True

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive validation report."""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "PASSED" if len(self.errors) == 0 else "FAILED",
            "errors": self.errors,
            "warnings": self.warnings,
            "metrics": self.metrics,
            "summary": {
                "total_errors": len(self.errors),
                "total_warnings": len(self.warnings),
                "critical_checks_passed": len(self.errors) == 0,
            },
        }

    def display_results(self):
        """Display validation results in a formatted table."""

        # Status panel
        status = "✅ PASSED" if len(self.errors) == 0 else "❌ FAILED"
        status_color = "green" if len(self.errors) == 0 else "red"

        console.print(
            Panel(
                f"[bold {status_color}]Gatecheck Status: {status}[/bold {status_color}]\n"
                f"Errors: {len(self.errors)} | Warnings: {len(self.warnings)}",
                title="CI/CD Gatecheck Results",
            )
        )

        # Errors table
        if self.errors:
            console.print("\n[bold red]❌ Critical Errors (Build Failure)[/bold red]")
            error_table = Table()
            error_table.add_column("Error", style="red")
            error_table.add_column("Details", style="dim")

            for error in self.errors:
                error_table.add_row(error["message"], error.get("details", ""))
            console.print(error_table)

        # Warnings table
        if self.warnings:
            console.print(
                "\n[bold yellow]⚠️  Warnings (Review Recommended)[/bold yellow]"
            )
            warning_table = Table()
            warning_table.add_column("Warning", style="yellow")
            warning_table.add_column("Details", style="dim")

            for warning in self.warnings:
                warning_table.add_row(warning["message"], warning.get("details", ""))
            console.print(warning_table)

        # Metrics table
        if self.metrics:
            console.print("\n[bold blue]📊 Validation Metrics[/bold blue]")
            metrics_table = Table()
            metrics_table.add_column("Metric", style="blue")
            metrics_table.add_column("Value", style="green")

            for key, value in self.metrics.items():
                metrics_table.add_row(key.replace("_", " ").title(), str(value))
            console.print(metrics_table)


@click.command()
@click.option(
    "--api-dir",
    type=click.Path(path_type=Path),
    default=Path("public/api"),
    help="Directory containing API data to validate",
)
@click.option(
    "--cache-dir",
    type=click.Path(path_type=Path),
    default=Path(".cache"),
    help="Cache directory for temporary data",
)
@click.option(
    "--max-cve-count",
    type=int,
    default=100,
    help="Maximum allowed CVE count (prevents 15,000+ issue)",
)
@click.option(
    "--expected-cve-count",
    type=int,
    default=298,
    help="Expected CVE count for reasonable validation (updated from 60 to 298)",
)
@click.option(
    "--min-baseline",
    type=int,
    default=298,
    help="Minimum baseline CVE count (count should NEVER go below this)",
)
@click.option(
    "--min-epss", type=float, default=0.6, help="Minimum EPSS threshold (0.0-1.0)"
)
@click.option(
    "--output-report",
    type=click.Path(path_type=Path),
    help="Output file for JSON report",
)
@click.option(
    "--fail-on-warnings", is_flag=True, help="Fail the check if warnings are present"
)
@click.option(
    "--fail-on-violations", is_flag=True, help="Fail immediately on any data violations"
)
@click.option(
    "--force-purge", is_flag=True, help="Force purge directories before validation"
)
def main(
    api_dir: Path,
    cache_dir: Path,  # noqa: ARG001
    max_cve_count: int,
    expected_cve_count: int,
    min_baseline: int,
    min_epss: float,
    output_report: Optional[Path],
    fail_on_warnings: bool,
    fail_on_violations: bool,
    force_purge: bool,
):
    """
    Comprehensive CI/CD gatecheck validation.

    This script performs critical validations to prevent deployment of incorrect data,
    specifically designed to catch issues like the 15,000+ CVE problem.
    """
    console.print("[bold green]🚀 Starting CI/CD Gatecheck Validation[/bold green]")

    # Handle force purge if requested
    if force_purge:
        console.print("[bold yellow]🧹 Force purging directories...[/bold yellow]")
        import shutil

        purge_dirs = [api_dir.parent, Path("_site"), Path("public"), Path("dist")]
        for purge_dir in purge_dirs:
            if purge_dir.exists():
                shutil.rmtree(purge_dir)
                console.print(f"   Purged: {purge_dir}")
        console.print("✅ Force purge completed")

    # Check if API directory exists, create friendly error if missing
    if not api_dir.exists():
        console.print(f"[bold red]❌ API directory not found: {api_dir}[/bold red]")
        console.print(
            "[yellow]💡 Tip: Run 'npm run build' first to generate API data[/yellow]"
        )
        if not fail_on_violations:
            console.print("[yellow]⚠️  Continuing with limited validation...[/yellow]")
        else:
            console.print("[red]🚫 Exiting due to --fail-on-violations flag[/red]")
            sys.exit(1)

    gatecheck = CIGatecheck()

    # Run all validations
    validations = [
        (
            "CVE Count Threshold",
            lambda: gatecheck.validate_cve_count_threshold(
                api_dir, max_cve_count, expected_cve_count, min_baseline
            ),
        ),
        (
            "EPSS Threshold Compliance",
            lambda: gatecheck.validate_epss_threshold_compliance(api_dir, min_epss),
        ),
        (
            "Chunk File Consistency",
            lambda: gatecheck.validate_chunk_file_consistency(api_dir),
        ),
        ("API Structure", lambda: gatecheck.validate_api_structure(api_dir)),
        ("Data Freshness", lambda: gatecheck.validate_data_freshness(api_dir)),
        (
            "Stale Data Patterns",
            lambda: gatecheck.check_for_known_stale_patterns(api_dir),
        ),
    ]

    console.print(
        f"\n[bold blue]Running {len(validations)} validation checks...[/bold blue]"
    )

    for name, validation_func in validations:
        try:
            validation_func()
        except Exception as e:
            gatecheck.add_error(f"Validation '{name}' failed with exception", str(e))

    # Display results
    gatecheck.display_results()

    # Generate and save report
    report = gatecheck.generate_report()

    if output_report:
        output_report.parent.mkdir(parents=True, exist_ok=True)
        with open(output_report, "w") as f:
            json.dump(report, f, indent=2)
        console.print(f"\n📄 Report saved to: {output_report}")

    # Determine exit code
    has_failures = len(gatecheck.errors) > 0
    has_warnings = len(gatecheck.warnings) > 0

    if has_failures:
        console.print(
            f"\n[bold red]❌ Gatecheck FAILED with {len(gatecheck.errors)} errors[/bold red]"
        )
        sys.exit(1)
    elif fail_on_warnings and has_warnings:
        console.print(
            f"\n[bold yellow]⚠️  Gatecheck FAILED due to {len(gatecheck.warnings)} warnings (--fail-on-warnings)[/bold yellow]"
        )
        sys.exit(1)
    else:
        console.print(
            "\n[bold green]✅ Gatecheck PASSED - All validations successful[/bold green]"
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
