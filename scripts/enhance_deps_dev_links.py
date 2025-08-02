#!/usr/bin/env python3
"""
Script to enhance existing vulnerability data with deps.dev links.
"""

import json
from pathlib import Path

import click
import structlog

from scripts.agents.deps_dev_enrichment_agent import DepsDevEnrichmentAgent

logger = structlog.get_logger()


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
def enhance_deps_dev_links(api_dir: Path, output_dir: Path):
    """Enhance vulnerability data with deps.dev package impact links."""
    
    logger.info("Starting deps.dev enhancement", api_dir=api_dir, output_dir=output_dir)
    
    # Initialize enrichment agent
    agent = DepsDevEnrichmentAgent()
    
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
                    enriched_vulns = agent.enrich_batch(vulnerabilities)
                    
                    # Update data
                    chunk_data["vulnerabilities"] = enriched_vulns
                    
                    # Save enhanced file
                    output_file = output_dir / chunk_file
                    with open(output_file, 'w') as f:
                        json.dump(chunk_data, f, indent=2)
                    
                    logger.info("Enhanced chunk file", file=chunk_file, vulnerabilities=len(vulnerabilities))
    
    # Generate summary report
    logger.info("Deps.dev enhancement complete")
    
    # Show statistics
    stats = {
        "files_processed": 0,
        "vulnerabilities_processed": 0,
        "deps_dev_links_added": 0
    }
    
    # Re-read files to count enhancements
    for json_file in output_dir.glob("*.json"):
        if json_file.name == "chunk-index.json":
            continue
            
        with open(json_file) as f:
            data = json.load(f)
        
        vulns = data.get("vulnerabilities", [])
        stats["files_processed"] += 1
        stats["vulnerabilities_processed"] += len(vulns)
        
        for vuln in vulns:
            if vuln.get("enrichments", {}).get("deps_dev"):
                stats["deps_dev_links_added"] += 1
    
    click.echo("\n✅ Enhancement Summary:")
    click.echo(f"  Files processed: {stats['files_processed']}")
    click.echo(f"  Vulnerabilities processed: {stats['vulnerabilities_processed']}")
    click.echo(f"  Deps.dev links added: {stats['deps_dev_links_added']}")
    click.echo(f"  Coverage: {stats['deps_dev_links_added'] / stats['vulnerabilities_processed'] * 100:.1f}%")


if __name__ == "__main__":
    enhance_deps_dev_links()