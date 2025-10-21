"""
Cleanup Agent for removing stale CVE pages and data files.
Ensures only current threshold-compliant data remains in the build.
"""

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Set

import structlog

from scripts.agents.base_agent import BaseAgent

logger = structlog.get_logger()


class CleanupAgent(BaseAgent):
    """Agent responsible for cleaning up stale files from previous builds."""

    def __init__(self):
        super().__init__(name="CleanupAgent")
        self.stats = {
            "directories_cleaned": 0,
            "files_removed": 0,
            "bytes_freed": 0,
            "stale_cves_found": 0,
        }

    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute cleanup operations."""
        build_dir = kwargs.get("build_dir", Path("_site"))
        api_dir = kwargs.get("api_dir", Path("api"))
        posts_dir = kwargs.get("posts_dir", Path("src/_posts"))
        min_epss_threshold = kwargs.get("min_epss_threshold", 0.6)
        force_purge = kwargs.get("force_purge", False)

        return self.clean_before_build(
            build_dir=build_dir,
            api_dir=api_dir,
            posts_dir=posts_dir,
            min_epss_threshold=min_epss_threshold,
            force_purge=force_purge,
        )

    def get_dependencies(self) -> set:
        """Get dependencies for change detection."""
        return {"_site", "public", "src/_posts", "api/vulns"}

    def clean_build_directory(
        self, build_dir: Path, force_purge: bool = True
    ) -> Dict[str, Any]:
        """
        Clean the build directory before regeneration.

        Args:
            build_dir: Path to the build directory (e.g., _site)
            force_purge: If True, completely removes directory. If False, selective cleanup.

        Returns:
            Dictionary with cleanup statistics
        """
        logger.info(
            "Starting build directory cleanup",
            directory=build_dir,
            force_purge=force_purge,
        )

        if build_dir.exists():
            # Calculate size before cleanup
            size_before = self._calculate_directory_size(build_dir)

            if force_purge:
                # Remove the entire directory
                try:
                    shutil.rmtree(build_dir)
                    self.stats["directories_cleaned"] += 1
                    self.stats["bytes_freed"] += size_before
                    logger.info(
                        "Force purged build directory",
                        path=build_dir,
                        size_freed=size_before,
                    )
                except Exception as e:
                    logger.error(
                        "Failed to remove build directory", path=build_dir, error=str(e)
                    )
                    raise
            else:
                # Selective cleanup - remove only CVE-related files
                self._selective_cleanup(build_dir)

        return self.stats

    def clean_api_directory(
        self, api_dir: Path, valid_cve_ids: Set[str]
    ) -> Dict[str, Any]:
        """
        Clean API directory of stale CVE data files.

        Args:
            api_dir: Path to the API directory
            valid_cve_ids: Set of valid CVE IDs that should be kept

        Returns:
            Dictionary with cleanup statistics
        """
        logger.info(
            "Cleaning API directory", directory=api_dir, valid_cves=len(valid_cve_ids)
        )

        if not api_dir.exists():
            logger.warning("API directory does not exist", path=api_dir)
            return self.stats

        # Clean individual CVE JSON files
        cve_files = list(api_dir.glob("cves/CVE-*.json"))
        for cve_file in cve_files:
            cve_id = cve_file.stem
            if cve_id not in valid_cve_ids:
                self._remove_file(cve_file)
                self.stats["stale_cves_found"] += 1

        # Clean vulnerability chunk files that might contain stale data
        self._clean_chunk_files(api_dir, valid_cve_ids)

        return self.stats

    def clean_posts_directory(
        self, posts_dir: Path, valid_cve_ids: Set[str]
    ) -> Dict[str, Any]:
        """
        Clean posts directory of stale CVE markdown files.

        Args:
            posts_dir: Path to the posts directory
            valid_cve_ids: Set of valid CVE IDs that should be kept

        Returns:
            Dictionary with cleanup statistics
        """
        logger.info(
            "Cleaning posts directory",
            directory=posts_dir,
            valid_cves=len(valid_cve_ids),
        )

        if not posts_dir.exists():
            logger.warning("Posts directory does not exist", path=posts_dir)
            return self.stats

        # Clean CVE markdown files
        cve_posts = list(posts_dir.glob("cves/CVE-*.md"))
        for post_file in cve_posts:
            # Extract CVE ID from filename (e.g., CVE-2024-12345.md)
            cve_id = post_file.stem
            if cve_id not in valid_cve_ids:
                self._remove_file(post_file)
                self.stats["stale_cves_found"] += 1

        return self.stats

    def clean_before_build(
        self,
        build_dir: Path,
        api_dir: Path,
        posts_dir: Path,
        min_epss_threshold: float = 0.6,
        force_purge: bool = True,
    ) -> Dict[str, Any]:
        """
        Comprehensive cleanup before building the site.

        Args:
            build_dir: Path to the build directory
            api_dir: Path to the API directory
            posts_dir: Path to the posts directory
            min_epss_threshold: Minimum EPSS threshold for valid CVEs
            force_purge: If True, completely removes build directory

        Returns:
            Dictionary with comprehensive cleanup statistics
        """
        logger.info(
            "Starting comprehensive pre-build cleanup",
            min_epss=min_epss_threshold,
            force_purge=force_purge,
        )

        start_time = datetime.utcnow()

        # Get list of valid CVE IDs from current data
        valid_cve_ids = self._get_valid_cve_ids(api_dir, min_epss_threshold)

        # Clean build directory (complete removal by default)
        self.clean_build_directory(build_dir, force_purge=force_purge)

        # Clean API directory (selective removal)
        self.clean_api_directory(api_dir, valid_cve_ids)

        # Clean posts directory (selective removal)
        self.clean_posts_directory(posts_dir, valid_cve_ids)

        # Add timing information
        self.stats["cleanup_duration_seconds"] = (
            datetime.utcnow() - start_time
        ).total_seconds()
        self.stats["valid_cves_retained"] = len(valid_cve_ids)

        # Log summary
        logger.info(
            "Cleanup completed",
            files_removed=self.stats["files_removed"],
            bytes_freed=self.stats["bytes_freed"],
            stale_cves=self.stats["stale_cves_found"],
            duration=self.stats["cleanup_duration_seconds"],
        )

        return self.stats

    def verify_no_stale_files(
        self, build_dir: Path, valid_cve_ids: Set[str]
    ) -> Dict[str, Any]:
        """
        Verify that no stale files remain after build.

        Args:
            build_dir: Path to the build directory
            valid_cve_ids: Set of valid CVE IDs

        Returns:
            Dictionary with verification results
        """
        logger.info("Verifying no stale files remain", directory=build_dir)

        verification_results = {"stale_files_found": [], "verification_passed": True}

        if not build_dir.exists():
            logger.warning("Build directory does not exist for verification")
            return verification_results

        # Check for CVE pages
        cve_pages = list(build_dir.glob("cves/CVE-*/index.html"))
        for page in cve_pages:
            cve_id = page.parent.name
            if cve_id not in valid_cve_ids:
                verification_results["stale_files_found"].append(str(page))
                verification_results["verification_passed"] = False

        # Check for CVE JSON files
        cve_jsons = list(build_dir.glob("api/cves/CVE-*.json"))
        for json_file in cve_jsons:
            cve_id = json_file.stem
            if cve_id not in valid_cve_ids:
                verification_results["stale_files_found"].append(str(json_file))
                verification_results["verification_passed"] = False

        if verification_results["stale_files_found"]:
            logger.error(
                "Stale files found after build",
                count=len(verification_results["stale_files_found"]),
                files=verification_results["stale_files_found"][:10],
            )  # Log first 10
        else:
            logger.info("No stale files found - verification passed")

        return verification_results

    def _get_valid_cve_ids(self, api_dir: Path, min_epss_threshold: float) -> Set[str]:
        """Get set of valid CVE IDs that meet the EPSS threshold."""
        valid_ids = set()

        # Read from index.json if it exists
        index_file = api_dir / "vulns" / "index.json"
        if index_file.exists():
            try:
                with open(index_file) as f:
                    data = json.load(f)

                for vuln in data.get("vulnerabilities", []):
                    epss_score = vuln.get("epss", {}).get("score", 0)
                    if epss_score >= min_epss_threshold:
                        valid_ids.add(vuln["cveId"])

                logger.info("Loaded valid CVE IDs from index", count=len(valid_ids))
            except Exception as e:
                logger.error("Failed to load index file", error=str(e))

        # Also check chunk files
        chunk_files = list((api_dir / "vulns").glob("vulns-*.json"))
        for chunk_file in chunk_files:
            try:
                with open(chunk_file) as f:
                    chunk_data = json.load(f)

                for vuln in chunk_data.get("vulnerabilities", []):
                    epss_score = vuln.get("epss", {}).get("score", 0)
                    if epss_score >= min_epss_threshold:
                        valid_ids.add(vuln["cveId"])
            except Exception as e:
                logger.error("Failed to load chunk file", file=chunk_file, error=str(e))

        return valid_ids

    def _clean_chunk_files(self, api_dir: Path, valid_cve_ids: Set[str]):
        """Clean chunk files to remove stale vulnerabilities."""
        chunk_files = list((api_dir / "vulns").glob("vulns-*.json"))

        for chunk_file in chunk_files:
            try:
                with open(chunk_file) as f:
                    chunk_data = json.load(f)

                original_count = len(chunk_data.get("vulnerabilities", []))

                # Filter vulnerabilities
                filtered_vulns = [
                    vuln
                    for vuln in chunk_data.get("vulnerabilities", [])
                    if vuln["cveId"] in valid_cve_ids
                ]

                if len(filtered_vulns) < original_count:
                    # Update the chunk file
                    chunk_data["vulnerabilities"] = filtered_vulns
                    chunk_data["count"] = len(filtered_vulns)

                    with open(chunk_file, "w") as f:
                        json.dump(chunk_data, f, indent=2)

                    removed = original_count - len(filtered_vulns)
                    logger.info(
                        "Cleaned chunk file",
                        file=chunk_file.name,
                        removed=removed,
                        remaining=len(filtered_vulns),
                    )
                    self.stats["stale_cves_found"] += removed

            except Exception as e:
                logger.error(
                    "Failed to clean chunk file", file=chunk_file, error=str(e)
                )

    def _remove_file(self, file_path: Path):
        """Remove a file and update statistics."""
        try:
            size = file_path.stat().st_size
            file_path.unlink()
            self.stats["files_removed"] += 1
            self.stats["bytes_freed"] += size
            logger.debug("Removed file", path=file_path, size=size)
        except Exception as e:
            logger.error("Failed to remove file", path=file_path, error=str(e))

    def _calculate_directory_size(self, directory: Path) -> int:
        """Calculate total size of a directory in bytes."""
        total_size = 0
        for item in directory.rglob("*"):
            if item.is_file():
                total_size += item.stat().st_size
        return total_size

    def generate_cleanup_report(self) -> str:
        """Generate a human-readable cleanup report."""
        report = f"""
Cleanup Agent Report
===================

Summary:
--------
- Directories cleaned: {self.stats["directories_cleaned"]}
- Files removed: {self.stats["files_removed"]}
- Storage freed: {self._format_bytes(self.stats["bytes_freed"])}
- Stale CVEs found: {self.stats["stale_cves_found"]}
- Valid CVEs retained: {self.stats.get("valid_cves_retained", 0)}
- Cleanup duration: {self.stats.get("cleanup_duration_seconds", 0):.2f} seconds

Actions Taken:
--------------
1. Removed entire build directory for clean regeneration
2. Cleaned stale CVE files from API directory
3. Cleaned stale CVE posts from posts directory
4. Updated chunk files to remove non-compliant vulnerabilities

Verification:
-------------
Run verify_no_stale_files() after build to ensure cleanup effectiveness.
"""
        return report

    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes into human-readable format."""
        for unit in ["B", "KB", "MB", "GB"]:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} TB"

    def _selective_cleanup(self, build_dir: Path):
        """Perform selective cleanup of CVE-related files."""
        patterns = [
            "cves/CVE-*",
            "api/cves/CVE-*.json",
            "api/vulns/*.json",
            "*.html",  # All HTML files that might contain CVE data
        ]

        for pattern in patterns:
            for file in build_dir.glob(pattern):
                if file.is_file():
                    self._remove_file(file)
                elif file.is_dir():
                    try:
                        shutil.rmtree(file)
                        self.stats["directories_cleaned"] += 1
                        logger.debug("Removed directory", path=file)
                    except Exception as e:
                        logger.error(
                            "Failed to remove directory", path=file, error=str(e)
                        )

    def force_purge_and_verify(
        self, build_dir: Path, api_dir: Path, expected_count: int = 295
    ) -> Dict[str, Any]:
        """
        Force purge build directory and verify results.

        Args:
            build_dir: Build directory to purge
            api_dir: API directory with source data
            expected_count: Expected number of CVEs

        Returns:
            Purge and verification results
        """
        results = {
            "purge_successful": False,
            "verification_passed": False,
            "issues_found": [],
        }

        # Force purge
        logger.info("Force purging build directory", path=build_dir)
        if build_dir.exists():
            try:
                shutil.rmtree(build_dir)
                results["purge_successful"] = True
                logger.info("Successfully purged build directory")
            except Exception as e:
                results["issues_found"].append(f"Failed to purge: {e}")
                logger.error("Purge failed", error=str(e))
                return results

        # Verify API data
        valid_ids = self._get_valid_cve_ids(api_dir, min_epss_threshold=0.6)
        actual_count = len(valid_ids)

        if actual_count > expected_count * 1.5:
            results["issues_found"].append(
                f"API data contains {actual_count} CVEs, expected ~{expected_count}"
            )
        else:
            results["verification_passed"] = True

        results["cve_count"] = actual_count
        results["expected_count"] = expected_count

        return results
