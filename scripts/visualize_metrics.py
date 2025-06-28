#!/usr/bin/env python3
"""
Generate metrics visualization and summary for vulnerability harvesting.
"""

import json
import sys
from pathlib import Path
from typing import Dict

from scripts.metrics import MetricsCollector


def format_duration(seconds: float) -> str:
    """Format duration in human-readable format."""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    else:
        return f"{seconds / 3600:.1f} hours"


def print_harvest_summary(summary: Dict):
    """Print a formatted harvest summary."""
    print("\n" + "=" * 50)
    print("VULNERABILITY HARVEST METRICS SUMMARY")
    print("=" * 50)

    # Basic info
    print(f"\nHarvest ID: {summary['harvest_id']}")
    print(f"Status: {summary['status']}")
    print(f"Duration: {format_duration(summary['duration_seconds'])}")
    print(f"Start Time: {summary['start_time']}")
    print(f"End Time: {summary['end_time']}")

    # Vulnerability counts
    print(f"\nTotal Vulnerabilities Found: {summary['total_vulnerabilities']}")

    # Risk distribution
    print("\nRisk Distribution:")
    risk_dist = summary["risk_distribution"]
    total = sum(risk_dist.values())
    for level, count in risk_dist.items():
        percentage = (count / total * 100) if total > 0 else 0
        bar = "█" * int(percentage / 2)
        print(f"  {level.capitalize():8s}: {count:4d} ({percentage:5.1f}%) {bar}")

    # Statistics
    stats = summary["statistics"]
    print("\nStatistics:")
    print(f"  Average Risk Score: {stats['avg_risk_score']:.1f}")
    print(f"  Risk Score Range: {stats['min_risk_score']} - {stats['max_risk_score']}")
    print(f"  Average CVSS Score: {stats['avg_cvss_score']:.1f}")
    print(f"  Average EPSS Score: {stats['avg_epss_score']:.1f}%")
    print(f"  KEV Vulnerabilities: {stats['kev_count']}")
    print(f"  SSVC Vulnerabilities: {stats['ssvc_count']}")

    # Errors
    if summary["errors"]:
        print("\nErrors:")
        for error_type, count in summary["errors"].items():
            print(f"  {error_type}: {count}")
    else:
        print("\nNo errors encountered during harvest.")

    # Metadata
    metadata = summary["metadata"]
    if metadata:
        print("\nHarvest Configuration:")
        if "years" in metadata:
            print(f"  Years: {', '.join(map(str, metadata['years']))}")
        if "min_epss_score" in metadata:
            print(f"  Min EPSS Score: {metadata['min_epss_score']}")
        if "min_severity" in metadata:
            print(f"  Min Severity: {metadata['min_severity']}")


def generate_github_summary(summary: Dict) -> str:
    """Generate a GitHub Actions summary in Markdown format."""
    md = []

    # Header
    md.append("## 📊 Vulnerability Harvest Metrics\n")

    # Status badge
    status_emoji = "✅" if summary["status"] == "completed" else "❌"
    md.append(f"{status_emoji} **Status:** {summary['status']}")
    md.append(f"⏱️ **Duration:** {format_duration(summary['duration_seconds'])}")
    md.append(f"🔢 **Total Vulnerabilities:** {summary['total_vulnerabilities']}\n")

    # Risk distribution table
    md.append("### Risk Distribution\n")
    md.append("| Risk Level | Count | Percentage |")
    md.append("|------------|-------|------------|")

    risk_dist = summary["risk_distribution"]
    total = sum(risk_dist.values())
    for level in ["critical", "high", "medium", "low"]:
        count = risk_dist.get(level, 0)
        percentage = (count / total * 100) if total > 0 else 0
        md.append(f"| {level.capitalize()} | {count} | {percentage:.1f}% |")

    # Key statistics
    stats = summary["statistics"]
    md.append("\n### Key Statistics\n")
    md.append(f"- **Average Risk Score:** {stats['avg_risk_score']:.1f}/100")
    md.append(f"- **Average CVSS Score:** {stats['avg_cvss_score']:.1f}/10")
    md.append(f"- **Average EPSS Score:** {stats['avg_epss_score']:.1f}%")
    md.append(f"- **Known Exploited (KEV):** {stats['kev_count']}")
    md.append(f"- **SSVC Decisions:** {stats['ssvc_count']}")

    # Errors if any
    if summary["errors"]:
        md.append("\n### ⚠️ Errors Encountered\n")
        for error_type, count in summary["errors"].items():
            md.append(f"- {error_type}: {count}")

    return "\n".join(md)


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Visualize vulnerability harvest metrics"
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        help="Path to metrics database",
        default=Path(".cache/metrics.db"),
    )
    parser.add_argument(
        "--harvest-id",
        type=int,
        help="Specific harvest ID to visualize (default: latest)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "github", "json"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "--export",
        type=Path,
        help="Export detailed metrics to JSON file",
    )
    parser.add_argument(
        "--recent",
        type=int,
        help="Show summaries for N recent harvests",
    )

    args = parser.parse_args()

    # Initialize metrics collector
    metrics = MetricsCollector(args.db_path)

    # Handle recent harvests
    if args.recent:
        harvests = metrics.get_recent_harvests(args.recent)

        if args.format == "json":
            print(json.dumps(harvests, indent=2, default=str))
        else:
            for i, summary in enumerate(harvests):
                if i > 0:
                    print("\n" + "-" * 50)
                print_harvest_summary(summary)

        return

    # Get specific harvest or latest
    if args.harvest_id:
        summary = metrics.get_harvest_summary(args.harvest_id)
    else:
        # Get the latest harvest
        recent = metrics.get_recent_harvests(1)
        if not recent:
            print("No harvest data found", file=sys.stderr)
            sys.exit(1)
        summary = recent[0]

    # Export if requested
    if args.export:
        metrics.export_metrics(args.export, summary["harvest_id"])
        print(f"Detailed metrics exported to: {args.export}")

    # Output in requested format
    if args.format == "text":
        print_harvest_summary(summary)
    elif args.format == "github":
        print(generate_github_summary(summary))
    elif args.format == "json":
        print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
