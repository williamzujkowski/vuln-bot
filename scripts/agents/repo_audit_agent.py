"""
Repository Audit Agent for scanning and identifying stale files.
Detects vestigial CVE pages and data files that shouldn't exist.
"""

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set

import structlog

from scripts.agents.base_agent import BaseAgent

logger = structlog.get_logger()


class RepoAuditAgent(BaseAgent):
    """Agent for auditing repository for stale and unexpected files."""

    def __init__(self):
        super().__init__(name="RepoAuditAgent")
        self.audit_results = {
            "stale_files": [],
            "unexpected_cves": [],
            "file_counts": {},
            "size_analysis": {},
            "timestamp_analysis": [],
            "recommendations": []
        }

    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute repository audit."""
        build_dir = kwargs.get('build_dir', Path('_site'))
        valid_cve_ids = kwargs.get('valid_cve_ids', set())
        expected_count = kwargs.get('expected_count', 60)
        return self.audit_build_directory(build_dir, valid_cve_ids, expected_count)

    def get_dependencies(self) -> set:
        """Get dependencies for change detection."""
        return {
            "_site",
            "public",
            "api/vulns",
            "src/_posts"
        }

    def audit_build_directory(self,
                            build_dir: Path,
                            valid_cve_ids: Set[str],
                            expected_count: int = 60) -> Dict[str, Any]:
        """
        Comprehensive audit of build directory.

        Args:
            build_dir: Path to build directory
            valid_cve_ids: Set of valid CVE IDs that should exist
            expected_count: Expected number of CVEs

        Returns:
            Detailed audit results
        """
        logger.info("Starting repository audit",
                   build_dir=build_dir,
                   valid_cves=len(valid_cve_ids),
                   expected=expected_count)

        if not build_dir.exists():
            logger.warning("Build directory does not exist", path=build_dir)
            return self.audit_results

        # Reset results
        self.audit_results = {
            "stale_files": [],
            "unexpected_cves": [],
            "file_counts": {},
            "size_analysis": {},
            "timestamp_analysis": [],
            "recommendations": []
        }

        # Audit CVE HTML pages
        self._audit_cve_pages(build_dir, valid_cve_ids)

        # Audit API JSON files
        self._audit_api_files(build_dir, valid_cve_ids)

        # Audit chunk files
        self._audit_chunk_files(build_dir, valid_cve_ids)

        # Analyze file timestamps
        self._analyze_timestamps(build_dir)

        # Count all files
        self._count_all_files(build_dir)

        # Generate recommendations
        self._generate_recommendations(expected_count)

        return self.audit_results

    def find_vestigial_files(self, directory: Path, api_dir: Path, min_epss: float) -> List[str]:
        """
        Find vestigial/stale files that should be removed.

        Args:
            directory: Directory to scan for stale files
            api_dir: API directory containing valid data
            min_epss: Minimum EPSS threshold

        Returns:
            List of file paths that should be removed
        """
        if not directory.exists():
            return []

        # Get valid CVE IDs from API data
        valid_cve_ids = set()
        index_file = api_dir / "vulns" / "index.json"

        if index_file.exists():
            try:
                with open(index_file) as f:
                    data = json.load(f)

                for vuln in data.get("vulnerabilities", []):
                    epss_score = vuln.get("epss", {}).get("score", 0)
                    if epss_score >= min_epss:
                        valid_cve_ids.add(vuln["cveId"])
            except Exception as e:
                logger.error("Failed to load index file", error=str(e))

        vestigial_files = []

        # Check for CVE HTML pages
        cve_pages = list(directory.glob("**/CVE-*/index.html"))
        for page in cve_pages:
            cve_id = page.parent.name
            if cve_id not in valid_cve_ids:
                vestigial_files.append(str(page))

        # Check for CVE directories
        cve_dirs = [d for d in directory.glob("**/CVE-*") if d.is_dir()]
        for cve_dir in cve_dirs:
            cve_id = cve_dir.name
            if cve_id not in valid_cve_ids:
                vestigial_files.append(str(cve_dir))

        # Check for CVE JSON files
        cve_jsons = list(directory.glob("**/CVE-*.json"))
        for json_file in cve_jsons:
            cve_id = json_file.stem
            if cve_id not in valid_cve_ids:
                vestigial_files.append(str(json_file))

        # Check for CVE markdown files
        cve_mds = list(directory.glob("**/CVE-*.md"))
        for md_file in cve_mds:
            cve_id = md_file.stem
            if cve_id not in valid_cve_ids:
                vestigial_files.append(str(md_file))

        return vestigial_files

    def _audit_cve_pages(self, build_dir: Path, valid_cve_ids: Set[str]):
        """Audit CVE HTML pages."""
        cve_pages = list(build_dir.glob("cves/CVE-*/index.html"))
        logger.info("Found CVE pages", count=len(cve_pages))

        self.audit_results["file_counts"]["cve_html_pages"] = len(cve_pages)

        for page in cve_pages:
            cve_id = page.parent.name
            if cve_id not in valid_cve_ids:
                self.audit_results["stale_files"].append({
                    "path": str(page),
                    "type": "cve_html",
                    "cve_id": cve_id,
                    "size": page.stat().st_size,
                    "modified": datetime.fromtimestamp(page.stat().st_mtime, tz=timezone.utc).isoformat()
                })
                self.audit_results["unexpected_cves"].append(cve_id)

    def _audit_api_files(self, build_dir: Path, valid_cve_ids: Set[str]):
        """Audit API JSON files."""
        api_dir = build_dir / "api"
        if not api_dir.exists():
            return

        # Check individual CVE JSON files
        cve_jsons = list(api_dir.glob("cves/CVE-*.json"))
        self.audit_results["file_counts"]["cve_json_files"] = len(cve_jsons)

        for json_file in cve_jsons:
            cve_id = json_file.stem
            if cve_id not in valid_cve_ids:
                self.audit_results["stale_files"].append({
                    "path": str(json_file),
                    "type": "cve_json",
                    "cve_id": cve_id,
                    "size": json_file.stat().st_size,
                    "modified": datetime.fromtimestamp(json_file.stat().st_mtime, tz=timezone.utc).isoformat()
                })

        # Check index.json
        index_file = api_dir / "vulns" / "index.json"
        if index_file.exists():
            try:
                with open(index_file) as f:
                    data = json.load(f)
                vulns = data.get("vulnerabilities", [])
                self.audit_results["file_counts"]["index_json_count"] = len(vulns)

                # Check for unexpected CVEs in index
                for vuln in vulns:
                    if vuln.get("cveId") not in valid_cve_ids:
                        self.audit_results["unexpected_cves"].append(vuln.get("cveId"))

            except Exception as e:
                logger.error("Failed to parse index.json", error=str(e))

    def _audit_chunk_files(self, build_dir: Path, valid_cve_ids: Set[str]):
        """Audit chunk JSON files."""
        chunk_files = list((build_dir / "api" / "vulns").glob("vulns-*.json"))
        self.audit_results["file_counts"]["chunk_files"] = len(chunk_files)

        total_in_chunks = 0
        chunk_analysis = []

        for chunk_file in chunk_files:
            try:
                with open(chunk_file) as f:
                    data = json.load(f)

                vulns = data.get("vulnerabilities", [])
                chunk_info = {
                    "file": chunk_file.name,
                    "count": len(vulns),
                    "reported_count": data.get("count", 0),
                    "unexpected_cves": []
                }

                total_in_chunks += len(vulns)

                # Check for unexpected CVEs
                for vuln in vulns:
                    cve_id = vuln.get("cveId")
                    if cve_id and cve_id not in valid_cve_ids:
                        chunk_info["unexpected_cves"].append(cve_id)
                        self.audit_results["unexpected_cves"].append(cve_id)

                if chunk_info["unexpected_cves"]:
                    chunk_analysis.append(chunk_info)

            except Exception as e:
                logger.error("Failed to parse chunk file", file=chunk_file, error=str(e))

        self.audit_results["file_counts"]["total_cves_in_chunks"] = total_in_chunks
        self.audit_results["chunk_analysis"] = chunk_analysis

    def _analyze_timestamps(self, build_dir: Path):
        """Analyze file timestamps to identify old files."""
        now = datetime.now(timezone.utc)
        old_files = []

        # Check all JSON and HTML files
        for pattern in ["**/*.json", "**/*.html"]:
            for file in build_dir.glob(pattern):
                if file.is_file():
                    mtime = datetime.fromtimestamp(file.stat().st_mtime, tz=timezone.utc)
                    age_hours = (now - mtime).total_seconds() / 3600

                    # Flag files older than 24 hours
                    if age_hours > 24:
                        old_files.append({
                            "path": str(file.relative_to(build_dir)),
                            "age_hours": round(age_hours, 1),
                            "modified": mtime.isoformat()
                        })

        # Sort by age
        old_files.sort(key=lambda x: x["age_hours"], reverse=True)
        self.audit_results["timestamp_analysis"] = old_files[:20]  # Top 20 oldest

    def _count_all_files(self, build_dir: Path):
        """Count all files by type."""
        counts = defaultdict(int)
        total_size = 0

        for file in build_dir.rglob("*"):
            if file.is_file():
                ext = file.suffix.lower()
                counts[ext] += 1
                total_size += file.stat().st_size

        self.audit_results["file_counts"]["by_extension"] = dict(counts)
        self.audit_results["size_analysis"]["total_size_mb"] = round(total_size / 1024 / 1024, 2)

    def _generate_recommendations(self, expected_count: int):
        """Generate actionable recommendations."""
        recommendations = []

        # Check for massive discrepancy
        total_cves = max(
            self.audit_results["file_counts"].get("cve_html_pages", 0),
            self.audit_results["file_counts"].get("total_cves_in_chunks", 0),
            self.audit_results["file_counts"].get("index_json_count", 0)
        )

        if total_cves > expected_count * 10:
            recommendations.append({
                "severity": "CRITICAL",
                "issue": f"Found {total_cves} CVEs, expected ~{expected_count}",
                "action": "Force full rebuild with complete directory purge"
            })

        if self.audit_results["stale_files"]:
            recommendations.append({
                "severity": "HIGH",
                "issue": f"Found {len(self.audit_results['stale_files'])} stale files",
                "action": "Run enhanced cleanup agent with force purge"
            })

        if self.audit_results["unexpected_cves"]:
            unique_unexpected = len(set(self.audit_results["unexpected_cves"]))
            recommendations.append({
                "severity": "HIGH",
                "issue": f"Found {unique_unexpected} unexpected CVE IDs",
                "action": "Verify EPSS threshold is being applied correctly"
            })

        old_files = self.audit_results["timestamp_analysis"]
        if old_files and old_files[0]["age_hours"] > 168:  # 1 week
            recommendations.append({
                "severity": "MEDIUM",
                "issue": "Found files older than 1 week",
                "action": "Consider full site rebuild to ensure freshness"
            })

        self.audit_results["recommendations"] = recommendations

    def generate_audit_report(self) -> str:
        """Generate human-readable audit report."""
        report = """
Repository Audit Report
======================

File Counts:
------------
"""
        counts = self.audit_results["file_counts"]
        for key, value in counts.items():
            if isinstance(value, (int, float)):
                report += f"- {key}: {value:,}\n"
            else:
                report += f"- {key}: {value}\n"

        if self.audit_results["stale_files"]:
            report += f"\nStale Files Found: {len(self.audit_results['stale_files'])}\n"
            report += "Sample stale files:\n"
            for file in self.audit_results["stale_files"][:10]:
                report += f"  - {file['cve_id']}: {file['path']}\n"

        if self.audit_results["unexpected_cves"]:
            unique_unexpected = sorted(set(self.audit_results["unexpected_cves"]))
            report += f"\nUnexpected CVEs: {len(unique_unexpected)}\n"
            report += "Sample unexpected CVE IDs:\n"
            for cve_id in unique_unexpected[:10]:
                report += f"  - {cve_id}\n"

        if self.audit_results["timestamp_analysis"]:
            report += "\nOldest Files:\n"
            for file in self.audit_results["timestamp_analysis"][:5]:
                report += f"  - {file['path']} ({file['age_hours']:.1f} hours old)\n"

        report += "\nRecommendations:\n"
        report += "----------------\n"
        for rec in self.audit_results["recommendations"]:
            report += f"[{rec['severity']}] {rec['issue']}\n"
            report += f"  → {rec['action']}\n\n"

        return report

    def generate_stale_files_report(self, output_path: Path) -> Dict[str, Any]:
        """Generate detailed stale files report in JSON and Markdown."""
        # Prepare report data
        report_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "total_stale_files": len(self.audit_results["stale_files"]),
                "unexpected_cves": len(set(self.audit_results["unexpected_cves"])),
                "total_cve_pages": self.audit_results["file_counts"].get("cve_html_pages", 0),
                "total_cve_jsons": self.audit_results["file_counts"].get("cve_json_files", 0),
                "total_in_chunks": self.audit_results["file_counts"].get("total_cves_in_chunks", 0)
            },
            "stale_files": self.audit_results["stale_files"],
            "unexpected_cve_ids": sorted(set(self.audit_results["unexpected_cves"])),
            "recommendations": self.audit_results["recommendations"],
            "file_age_analysis": self.audit_results["timestamp_analysis"][:20]
        }

        # Save JSON report
        json_path = output_path.with_suffix('.json')
        with open(json_path, 'w') as f:
            json.dump(report_data, f, indent=2)

        # Generate Markdown report
        md_content = f"""# Stale Files Audit Report

**Generated**: {report_data['timestamp']}

## Summary

- **Total Stale Files**: {report_data['summary']['total_stale_files']:,}
- **Unexpected CVE IDs**: {report_data['summary']['unexpected_cves']:,}
- **Total CVE HTML Pages**: {report_data['summary']['total_cve_pages']:,}
- **Total CVE JSON Files**: {report_data['summary']['total_cve_jsons']:,}
- **Total CVEs in Chunks**: {report_data['summary']['total_in_chunks']:,}

## Critical Findings

"""

        # Add critical recommendations
        critical_recs = [r for r in report_data['recommendations'] if r['severity'] in ['CRITICAL', 'HIGH']]
        if critical_recs:
            md_content += "### Immediate Actions Required\n\n"
            for rec in critical_recs:
                md_content += f"**[{rec['severity']}]** {rec['issue']}\n"
                md_content += f"- Action: {rec['action']}\n\n"

        # Add stale file samples
        if report_data['stale_files']:
            md_content += "\n## Stale Files (Sample)\n\n"
            md_content += "| CVE ID | File Path | Size | Last Modified |\n"
            md_content += "|--------|-----------|------|---------------|\n"
            for file in report_data['stale_files'][:20]:
                size_kb = file['size'] / 1024
                md_content += f"| {file['cve_id']} | {file['path']} | {size_kb:.1f} KB | {file['modified']} |\n"

        # Add unexpected CVE list
        if report_data['unexpected_cve_ids']:
            md_content += "\n## Unexpected CVE IDs\n\n"
            md_content += "These CVEs should not exist based on current EPSS threshold:\n\n"
            for i in range(0, min(50, len(report_data['unexpected_cve_ids'])), 5):
                batch = report_data['unexpected_cve_ids'][i:i+5]
                md_content += "- " + ", ".join(batch) + "\n"

        # Save Markdown report
        md_path = output_path.with_suffix('.md')
        with open(md_path, 'w') as f:
            f.write(md_content)

        logger.info("Generated stale files reports", json_path=json_path, md_path=md_path)

        return report_data

    def _get_valid_cve_ids(self, source_dir: Path, min_epss: float) -> Set[str]:
        """Get valid CVE IDs from source data."""
        valid_ids = set()

        # Check index.json
        index_file = source_dir / "vulns" / "index.json"
        if index_file.exists():
            try:
                with open(index_file) as f:
                    data = json.load(f)
                for vuln in data.get("vulnerabilities", []):
                    epss_score = vuln.get("epss", {}).get("score", 0)
                    if epss_score >= min_epss:
                        valid_ids.add(vuln["cveId"])
            except Exception as e:
                logger.error("Failed to load source index", error=str(e))

        return valid_ids
