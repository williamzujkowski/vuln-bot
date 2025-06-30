#!/usr/bin/env python3
"""Optimized briefing generator that uses chunked storage instead of individual files."""

import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

import structlog

from scripts.models import VulnerabilityBatch
from scripts.processing.briefing_generator import BriefingGenerator


class OptimizedBriefingGenerator(BriefingGenerator):
    """Enhanced briefing generator with optimized storage strategies."""

    def __init__(self, output_dir: Path, storage_strategy: str = "severity-year"):
        """Initialize optimized generator.

        Args:
            output_dir: Directory for output files
            storage_strategy: Storage strategy to use
        """
        super().__init__(output_dir)
        self.storage_strategy = storage_strategy
        self.logger = structlog.get_logger()

    def generate_all(
        self, batch: VulnerabilityBatch, briefing_limit: int = 50
    ) -> Dict[str, any]:
        """Generate all outputs with optimized storage.

        Args:
            batch: Vulnerability batch to process
            briefing_limit: Maximum vulnerabilities in briefing

        Returns:
            Dictionary with paths to generated files
        """
        generated_files = {
            "briefing": None,
            "index": None,
            "chunks": [],
            "chunk_index": None,
        }

        # Generate briefing post (unchanged)
        try:
            generated_files["briefing"] = str(
                self.generate_briefing_post(batch, limit=briefing_limit)
            )
        except Exception as e:
            self.logger.error("Failed to generate briefing", error=str(e))

        # Generate search index (unchanged)
        try:
            generated_files["index"] = str(self.generate_search_index(batch))
        except Exception as e:
            self.logger.error("Failed to generate index", error=str(e))

        # Generate chunked storage instead of individual files
        if self.storage_strategy == "severity-year":
            generated_files["chunks"], generated_files["chunk_index"] = (
                self._generate_severity_year_chunks(batch)
            )
        elif self.storage_strategy == "size-chunks":
            generated_files["chunks"], generated_files["chunk_index"] = (
                self._generate_size_chunks(batch, chunk_size=1000)
            )
        elif self.storage_strategy == "single-file":
            generated_files["chunks"] = [self._generate_single_file(batch)]
        else:
            # Fallback to original behavior if needed
            self.logger.warning(
                "Unknown storage strategy, skipping individual files",
                strategy=self.storage_strategy,
            )

        self.logger.info(
            "Optimized generation complete",
            briefing=generated_files["briefing"] is not None,
            index=generated_files["index"] is not None,
            chunks=len(generated_files["chunks"]),
            strategy=self.storage_strategy,
        )

        return generated_files

    def _generate_severity_year_chunks(
        self, batch: VulnerabilityBatch
    ) -> tuple[List[str], str]:
        """Generate chunks organized by severity and year.

        Returns:
            Tuple of (chunk_files, chunk_index_file)
        """
        chunks = defaultdict(list)
        chunk_files = []

        # Group vulnerabilities
        for vuln in batch.vulnerabilities:
            year = vuln.published_date.year if vuln.published_date else "unknown"
            severity = vuln.severity.value
            chunk_key = f"{year}-{severity}"
            chunks[chunk_key].append(vuln.to_detail_dict())

        # Write chunk files
        for chunk_key, chunk_vulns in sorted(chunks.items()):
            chunk_file = self.api_dir / f"vulns-{chunk_key}.json"
            chunk_data = {
                "chunk": chunk_key,
                "count": len(chunk_vulns),
                "generated": batch.generated_at.isoformat(),
                "vulnerabilities": chunk_vulns,
            }

            with open(chunk_file, "w", encoding="utf-8") as f:
                json.dump(chunk_data, f, indent=2, ensure_ascii=False)

            chunk_files.append(str(chunk_file))
            self.logger.info(
                "Generated chunk",
                chunk=chunk_key,
                count=len(chunk_vulns),
                size_mb=chunk_file.stat().st_size / 1024 / 1024,
            )

        # Create chunk index
        chunk_index = {
            "strategy": "severity-year",
            "generated": batch.generated_at.isoformat(),
            "total_count": batch.count,
            "chunks": [
                {
                    "key": chunk_key,
                    "file": f"vulns-{chunk_key}.json",
                    "count": len(chunk_vulns),
                }
                for chunk_key, chunk_vulns in sorted(chunks.items())
            ],
        }

        chunk_index_file = self.api_dir / "chunk-index.json"
        with open(chunk_index_file, "w", encoding="utf-8") as f:
            json.dump(chunk_index, f, indent=2, ensure_ascii=False)

        return chunk_files, str(chunk_index_file)

    def _generate_size_chunks(
        self, batch: VulnerabilityBatch, chunk_size: int = 1000
    ) -> tuple[List[str], str]:
        """Generate fixed-size chunks.

        Returns:
            Tuple of (chunk_files, chunk_index_file)
        """
        chunk_files = []
        chunks_info = []

        vulnerabilities = list(batch.vulnerabilities)

        for i in range(0, len(vulnerabilities), chunk_size):
            chunk_num = i // chunk_size + 1
            chunk_vulns = vulnerabilities[i : i + chunk_size]

            chunk_file = self.api_dir / f"vulns-chunk-{chunk_num:03d}.json"
            chunk_data = {
                "chunk": chunk_num,
                "count": len(chunk_vulns),
                "generated": batch.generated_at.isoformat(),
                "vulnerabilities": [v.to_detail_dict() for v in chunk_vulns],
            }

            with open(chunk_file, "w", encoding="utf-8") as f:
                json.dump(chunk_data, f, indent=2, ensure_ascii=False)

            chunk_files.append(str(chunk_file))
            chunks_info.append(
                {
                    "chunk": chunk_num,
                    "file": chunk_file.name,
                    "count": len(chunk_vulns),
                    "range": f"{i + 1}-{min(i + chunk_size, len(vulnerabilities))}",
                }
            )

        # Create chunk index
        chunk_index = {
            "strategy": "size-chunks",
            "chunk_size": chunk_size,
            "generated": batch.generated_at.isoformat(),
            "total_count": batch.count,
            "chunks": chunks_info,
        }

        chunk_index_file = self.api_dir / "chunk-index.json"
        with open(chunk_index_file, "w", encoding="utf-8") as f:
            json.dump(chunk_index, f, indent=2, ensure_ascii=False)

        return chunk_files, str(chunk_index_file)

    def _generate_single_file(self, batch: VulnerabilityBatch) -> str:
        """Generate a single file with all vulnerability details.

        Returns:
            Path to the generated file
        """
        filepath = self.api_dir / "vulns-complete.json"

        data = {
            "generated": batch.generated_at.isoformat(),
            "count": batch.count,
            "storage_strategy": "single-file",
            "includes_full_details": True,
            "vulnerabilities": [v.to_detail_dict() for v in batch.vulnerabilities],
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        self.logger.info(
            "Generated single file",
            count=batch.count,
            size_mb=filepath.stat().st_size / 1024 / 1024,
        )

        return str(filepath)

    def _generate_markdown(self, data: Dict[str, any]) -> str:
        """Generate markdown content for the briefing with updated links.

        Overrides parent method to change CVE links to use modal instead of JSON files.
        """
        lines = []

        # Front matter
        lines.extend(
            [
                "---",
                f"title: Morning Vulnerability Briefing - {data['date_str']}",
                f"date: {data['generated_at']}",
                "layout: layouts/post.njk",
                "tags: [vulnerability, briefing, security]",
                f"vulnerabilityCount: {data['total_count']}",
                f"criticalCount: {data['severity_distribution']['CRITICAL']}",
                f"highCount: {data['severity_distribution']['HIGH']}",
                "---",
                "",
            ]
        )

        # Summary
        lines.extend(
            [
                f"# Morning Vulnerability Briefing - {data['date_str']}",
                "",
                f"Today's briefing covers **{data['total_count']} vulnerabilities** from {len(data['sources'])} sources.",
                "",
                "## Risk Distribution",
                "",
                f"- 🔴 **Critical Risk**: {data['risk_distribution']['critical']} vulnerabilities",
                f"- 🟠 **High Risk**: {data['risk_distribution']['high']} vulnerabilities",
                f"- 🟡 **Medium Risk**: {data['risk_distribution']['medium']} vulnerabilities",
                f"- 🟢 **Low Risk**: {data['risk_distribution']['low']} vulnerabilities",
                "",
                "## Top Vulnerabilities",
                "",
            ]
        )

        # Vulnerability details with updated links
        for i, vuln in enumerate(data["vulnerabilities"], 1):
            # Change the link to use a JavaScript click handler instead of direct JSON link
            lines.extend(
                [
                    f'### {i}. [{vuln["cve_id"]}](javascript:void(0)) {{: .cve-link data-cve-id="{vuln["cve_id"]}" onclick="window.cveModal && window.cveModal.openModal(\'{vuln["cve_id"]}\')" }}',
                    "",
                    f"**Risk Score**: {vuln['risk_score']}/100 | ",
                    f"**Severity**: {vuln['severity']} | ",
                    f"**CVSS**: {vuln['cvss_score'] or 'N/A'} | ",
                    f"**EPSS**: {vuln['epss_score'] or 0:.1f}%",
                    "",
                    f"**Summary**: {vuln['description']}",
                    "",
                ]
            )

            if vuln["risk_factors"]:
                lines.extend(
                    [
                        "**Risk Factors**:",
                        "",
                    ]
                )
                for factor in vuln["risk_factors"]:
                    lines.append(f"- {factor}")
                lines.append("")

            if vuln["vendors"]:
                lines.append(f"**Affected Vendors**: {', '.join(vuln['vendors'])}")
                lines.append("")

            if vuln["tags"]:
                lines.append(
                    f"**Tags**: {', '.join(f'`{tag}`' for tag in vuln['tags'])}"
                )
                lines.append("")

            if vuln["references"]:
                lines.extend(
                    [
                        "**References**:",
                        "",
                    ]
                )
                for ref in vuln["references"]:
                    lines.append(f"- [{ref}]({ref})")
                lines.append("")

            lines.append("---")
            lines.append("")

        # Footer
        lines.extend(
            [
                "## Data Sources",
                "",
                "This briefing was generated from the following sources:",
                "",
            ]
        )

        for source in data["sources"]:
            status = "✅" if source["status"] == "success" else "❌"
            lines.append(
                f"- {status} {source['name']}: {source['count']} vulnerabilities"
            )

        lines.extend(
            [
                "",
                "## About This Briefing",
                "",
                "This automated briefing highlights vulnerabilities with:",
                "- CVSS scores ≥ 7.0 (High/Critical severity)",
                "- EPSS probability ≥ 70% (high exploitation likelihood)",
                "- Published or updated within the last 30 days",
                "",
                f"Generated: {data['date_str']}",
                "",
            ]
        )

        return "\n".join(lines)
