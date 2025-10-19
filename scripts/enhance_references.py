#!/usr/bin/env python3
"""
Script to enhance and categorize reference links for vulnerabilities.
"""

import json
from pathlib import Path
from typing import Any, Dict
from urllib.parse import urlparse

import click
import structlog

logger = structlog.get_logger()


def categorize_reference(ref: Dict[str, Any]) -> str:
    """
    Categorize a reference link based on URL patterns and metadata.

    Returns: Category like 'advisory', 'patch', 'exploit', 'technical', 'vendor', 'other'
    """
    url = ref.get("url", "").lower()
    title = ref.get("title", "").lower()
    tags = ref.get("tags", [])

    # Exploit indicators
    exploit_patterns = [
        "exploit", "poc", "proof-of-concept", "metasploit",
        "nuclei", "exploit-db", "0day", "packetstorm"
    ]
    for pattern in exploit_patterns:
        if pattern in url or pattern in title:
            return "exploit"

    # Patch/Fix indicators
    patch_patterns = [
        "patch", "fix", "commit", "pull/", "releases/tag",
        "diff", "changeset", "update", "hotfix"
    ]
    for pattern in patch_patterns:
        if pattern in url or pattern in title:
            return "patch"

    # Advisory indicators
    advisory_patterns = [
        "advisory", "bulletin", "announcement", "disclosure",
        "security.txt", "cve.mitre", "nvd.nist", "cert.", "kb.cert"
    ]
    for pattern in advisory_patterns:
        if pattern in url or pattern in title:
            return "advisory"

    # Vendor indicators
    vendor_patterns = [
        "microsoft.com/security", "oracle.com/security", "cisco.com/security",
        "redhat.com/security", "ubuntu.com/security", "debian.org/security",
        "support.", "kb.", "technet", "docs."
    ]
    for pattern in vendor_patterns:
        if pattern in url:
            return "vendor"

    # Technical/Research indicators
    technical_patterns = [
        "github.com", "gitlab.com", "bitbucket", "sourceforge",
        "blog", "research", "analysis", "writeup", "article"
    ]
    for pattern in technical_patterns:
        if pattern in url:
            return "technical"

    # Check tags
    if "package" in tags or "dependency" in tags:
        return "dependency"

    return "other"


def enhance_reference(ref: Dict[str, Any]) -> Dict[str, Any]:
    """Enhance a reference with additional metadata."""
    enhanced_ref = ref.copy()

    # Add category if not present
    if "category" not in enhanced_ref:
        enhanced_ref["category"] = categorize_reference(ref)

    # Add security attributes for external links
    url = enhanced_ref.get("url", "")
    if url.startswith(("http://", "https://")):
        if "rel" not in enhanced_ref:
            enhanced_ref["rel"] = "noopener noreferrer"
        if "target" not in enhanced_ref:
            enhanced_ref["target"] = "_blank"

    # Extract domain for display
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain:
            enhanced_ref["domain"] = domain.replace("www.", "")
    except Exception:
        pass

    # Add icon based on category
    category_icons = {
        "exploit": "🔥",
        "patch": "🔧",
        "advisory": "📋",
        "vendor": "🏢",
        "technical": "📚",
        "dependency": "📦",
        "other": "🔗"
    }
    enhanced_ref["icon"] = category_icons.get(enhanced_ref["category"], "🔗")

    return enhanced_ref


def enhance_vulnerability_references(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """Enhance all references for a vulnerability."""
    references = vuln.get("references", [])

    if not references:
        return vuln

    enhanced_refs = []
    categories_found = set()

    for ref in references:
        if isinstance(ref, dict):
            enhanced_ref = enhance_reference(ref)
            enhanced_refs.append(enhanced_ref)
            categories_found.add(enhanced_ref["category"])
        elif isinstance(ref, str):
            # Convert string reference to dict
            enhanced_ref = enhance_reference({"url": ref})
            enhanced_refs.append(enhanced_ref)
            categories_found.add(enhanced_ref["category"])

    # Sort references by category priority
    category_priority = {
        "exploit": 1,
        "patch": 2,
        "advisory": 3,
        "vendor": 4,
        "dependency": 5,
        "technical": 6,
        "other": 7
    }

    enhanced_refs.sort(key=lambda x: category_priority.get(x.get("category", "other"), 7))

    vuln["references"] = enhanced_refs
    vuln["reference_categories"] = list(categories_found)

    return vuln


@click.command()
@click.option(
    "--api-dir",
    type=click.Path(path_type=Path),
    default=Path("api/vulns"),
    help="Directory containing API JSON files"
)
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path),
    default=Path("api/vulns"),
    help="Output directory for enhanced files"
)
def enhance_references_cli(api_dir: Path, output_dir: Path):
    """Enhance and categorize vulnerability references."""

    logger.info("Starting reference enhancement", api_dir=api_dir, output_dir=output_dir)

    stats = {
        "files_processed": 0,
        "vulnerabilities_processed": 0,
        "references_enhanced": 0,
        "categories": {}
    }

    # Process index file
    index_file = api_dir / "index.json"
    if index_file.exists():
        logger.info("Processing index file", path=index_file)

        with open(index_file) as f:
            data = json.load(f)

        vulnerabilities = data.get("vulnerabilities", [])
        enhanced_vulns = []

        for vuln in vulnerabilities:
            enhanced_vuln = enhance_vulnerability_references(vuln)
            enhanced_vulns.append(enhanced_vuln)

            # Update stats
            refs = enhanced_vuln.get("references", [])
            stats["references_enhanced"] += len(refs)

            for ref in refs:
                category = ref.get("category", "other")
                stats["categories"][category] = stats["categories"].get(category, 0) + 1

        data["vulnerabilities"] = enhanced_vulns
        stats["vulnerabilities_processed"] += len(vulnerabilities)
        stats["files_processed"] += 1

        # Save enhanced file
        output_file = output_dir / "index.json"
        with open(output_file, 'w') as f:
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
                    enhanced_vulns = []

                    for vuln in vulnerabilities:
                        enhanced_vuln = enhance_vulnerability_references(vuln)
                        enhanced_vulns.append(enhanced_vuln)

                        # Update stats
                        refs = enhanced_vuln.get("references", [])
                        stats["references_enhanced"] += len(refs)

                        for ref in refs:
                            category = ref.get("category", "other")
                            stats["categories"][category] = stats["categories"].get(category, 0) + 1

                    chunk_data["vulnerabilities"] = enhanced_vulns
                    stats["vulnerabilities_processed"] += len(vulnerabilities)
                    stats["files_processed"] += 1

                    # Save enhanced file
                    output_file = output_dir / chunk_file
                    with open(output_file, 'w') as f:
                        json.dump(chunk_data, f, indent=2)

                    logger.info("Enhanced chunk file", file=chunk_file, vulnerabilities=len(vulnerabilities))

    # Display summary
    click.echo("\n✅ Reference Enhancement Summary:")
    click.echo(f"  Files processed: {stats['files_processed']}")
    click.echo(f"  Vulnerabilities processed: {stats['vulnerabilities_processed']}")
    click.echo(f"  References enhanced: {stats['references_enhanced']}")
    click.echo("\n📊 Reference Categories:")

    for category, count in sorted(stats["categories"].items()):
        icon = {
            "exploit": "🔥",
            "patch": "🔧",
            "advisory": "📋",
            "vendor": "🏢",
            "technical": "📚",
            "dependency": "📦",
            "other": "🔗"
        }.get(category, "🔗")
        click.echo(f"  {icon} {category.capitalize()}: {count}")


if __name__ == "__main__":
    enhance_references_cli()
