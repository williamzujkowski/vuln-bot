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
