"""
Build and Deploy Agent for managing full site rebuilds.
Ensures clean builds when EPSS thresholds change.
"""

import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import structlog

from scripts.agents.base_agent import BaseAgent
from scripts.agents.cleanup_agent import CleanupAgent
from scripts.agents.repo_audit_agent import RepoAuditAgent

logger = structlog.get_logger()


class BuildDeployAgent(BaseAgent):
    """Agent responsible for clean builds and deployments."""

    def __init__(self):
        super().__init__(name="BuildDeployAgent")
        self.cleanup_agent = CleanupAgent()
        self.audit_agent = RepoAuditAgent()

    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute a force full rebuild."""
        return self.force_full_rebuild(**kwargs)

    def get_dependencies(self) -> set:
        """Get dependencies for change detection."""
        return {"api/vulns/index.json", "src/_posts", "_site", "public"}

    def force_full_rebuild(
        self,
        build_dir: Path = Path("_site"),
        api_dir: Path = Path("api"),
        posts_dir: Path = Path("src/_posts"),
        public_dir: Path = Path("public"),
        min_epss: float = 0.6,
    ) -> Dict[str, Any]:
        """
        Force a complete rebuild with full cleanup.

        Args:
            build_dir: Build output directory
            api_dir: API data directory
            posts_dir: Posts directory
            public_dir: Public directory for GitHub Pages
            min_epss: Minimum EPSS threshold

        Returns:
            Build results and statistics
        """
        logger.info("Starting forced full rebuild", min_epss=min_epss)

        results = {
            "status": "started",
            "start_time": datetime.utcnow().isoformat(),
            "steps_completed": [],
            "errors": [],
            "statistics": {},
        }

        try:
            # Step 1: Pre-build audit
            logger.info("Step 1: Running pre-build audit")
            valid_cve_ids = self._get_valid_cve_ids(api_dir, min_epss)
            audit_results = self.audit_agent.audit_build_directory(
                build_dir, valid_cve_ids, expected_count=295
            )
            results["statistics"]["pre_audit"] = {
                "stale_files": len(audit_results["stale_files"]),
                "unexpected_cves": len(set(audit_results["unexpected_cves"])),
            }
            results["steps_completed"].append("pre_build_audit")

            # Step 2: Force purge all build directories
            logger.info("Step 2: Force purging build directories")
            for directory in [build_dir, public_dir]:
                if directory.exists():
                    logger.info(f"Purging directory: {directory}")
                    shutil.rmtree(directory)
                    directory.mkdir(parents=True, exist_ok=True)
            results["steps_completed"].append("force_purge")

            # Step 3: Clean source directories
            logger.info("Step 3: Cleaning source directories")
            cleanup_stats = self.cleanup_agent.clean_before_build(
                build_dir=build_dir,
                api_dir=api_dir,
                posts_dir=posts_dir,
                min_epss_threshold=min_epss,
                force_purge=True,
            )
            results["statistics"]["cleanup"] = cleanup_stats
            results["steps_completed"].append("source_cleanup")

            # Step 4: Run 11ty build (if available) - FORCE NON-INCREMENTAL
            if self._is_11ty_available():
                logger.info("Step 4: Running 11ty build (FULL BUILD - non-incremental)")
                build_result = self._run_11ty_build(
                    build_dir, force_non_incremental=True
                )
                if not build_result["success"]:
                    results["errors"].append(
                        f"11ty build failed: {build_result['error']}"
                    )
                else:
                    results["steps_completed"].append("11ty_build")
                    results["statistics"]["11ty_files_created"] = build_result.get(
                        "file_count", 0
                    )

            # Step 5: Copy to public directory
            logger.info("Step 5: Copying to public directory")
            if build_dir.exists() and build_dir != public_dir:
                if public_dir.exists():
                    shutil.rmtree(public_dir)
                shutil.copytree(build_dir, public_dir)
                results["steps_completed"].append("copy_to_public")

            # Step 6: Post-build audit
            logger.info("Step 6: Running post-build audit")
            post_audit_results = self.audit_agent.audit_build_directory(
                public_dir, valid_cve_ids, expected_count=295
            )
            results["statistics"]["post_audit"] = {
                "total_files": post_audit_results["file_counts"].get(
                    "cve_html_pages", 0
                ),
                "stale_files": len(post_audit_results["stale_files"]),
                "unexpected_cves": len(set(post_audit_results["unexpected_cves"])),
            }
            results["steps_completed"].append("post_build_audit")

            # Step 7: Verify success
            if post_audit_results["recommendations"]:
                for rec in post_audit_results["recommendations"]:
                    if rec["severity"] == "CRITICAL":
                        results["errors"].append(rec["issue"])

            results["status"] = (
                "completed" if not results["errors"] else "completed_with_errors"
            )

        except Exception as e:
            logger.error("Force rebuild failed", error=str(e))
            results["status"] = "failed"
            results["errors"].append(str(e))

        results["end_time"] = datetime.utcnow().isoformat()
        return results

    def prepare_gh_pages_deployment(
        self, source_dir: Path = Path("public"), branch: str = "gh-pages"
    ) -> Dict[str, Any]:
        """
        Prepare for GitHub Pages deployment with proper git commands.

        Args:
            source_dir: Directory containing built site
            branch: Target branch for deployment

        Returns:
            Deployment preparation results
        """
        results = {"status": "started", "commands_executed": [], "errors": []}

        try:
            # Ensure we're in a git repository
            if not Path(".git").exists():
                results["errors"].append("Not in a git repository")
                results["status"] = "failed"
                return results

            # Get current branch
            current_branch = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True,
                text=True,
            ).stdout.strip()

            # Create deployment script with force overwrite
            deploy_script = f"""#!/bin/bash
set -e

echo "Preparing GitHub Pages deployment with FORCE OVERWRITE..."

# Save current branch
CURRENT_BRANCH="{current_branch}"

# Ensure source directory exists
if [ ! -d "{source_dir}" ]; then
    echo "Error: Source directory {source_dir} does not exist"
    exit 1
fi

# Create temporary directory for deployment
TEMP_DIR=$(mktemp -d)
cp -r {source_dir}/* $TEMP_DIR/

# Fetch latest gh-pages to ensure we're up to date
git fetch origin {branch}:{branch} || true

# Switch to gh-pages branch
git checkout {branch} || git checkout -b {branch}

# CRITICAL: Remove ALL existing files (except .git)
# This ensures no stale files remain
echo "Removing all existing files from gh-pages branch..."
find . -mindepth 1 -maxdepth 1 ! -name '.git' -exec rm -rf {{}} +

# Verify directory is clean
FILE_COUNT=$(find . -mindepth 1 ! -path './.git*' | wc -l)
echo "Files remaining after cleanup: $FILE_COUNT (should be 0)"

# Copy new files
echo "Copying fresh build files..."
cp -r $TEMP_DIR/* .

# Touch .nojekyll to ensure GitHub Pages processes correctly
touch .nojekyll

# Add all files (including deletions)
git add -A .

# Show what will be committed
echo "Files to be committed:"
git status --short

# Check if there are changes
if git diff --cached --quiet; then
    echo "No changes to deploy"
else
    # Commit changes with descriptive message
    TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
    git commit -m "chore: force full site rebuild - complete overwrite ($TIMESTAMP)

This commit completely replaces all files in gh-pages branch to ensure
no stale CVE pages remain. All files have been regenerated from scratch.

[skip ci]"
fi

# Clean up
rm -rf $TEMP_DIR

# Return to original branch
git checkout $CURRENT_BRANCH

echo "Deployment preparation complete!"
echo "Next step: git push origin {branch} --force-with-lease"
"""

            # Write deployment script
            deploy_script_path = Path("deploy_gh_pages.sh")
            with open(deploy_script_path, "w") as f:
                f.write(deploy_script)

            # Make executable
            os.chmod(deploy_script_path, 0o755)  # nosec B103 - Legitimate deploy script permissions

            results["commands_executed"].append("Created deployment script")
            results["deployment_script"] = str(deploy_script_path)
            results["status"] = "prepared"

            # Add instructions
            results["instructions"] = [
                f"Run './{deploy_script_path}' to prepare gh-pages branch",
                f"Then push with: git push origin {branch} --force-with-lease",
                "This will completely replace the gh-pages branch contents",
            ]

        except Exception as e:
            logger.error("Deployment preparation failed", error=str(e))
            results["status"] = "failed"
            results["errors"].append(str(e))

        return results

    def _is_11ty_available(self) -> bool:
        """Check if 11ty is available."""
        try:
            result = subprocess.run(
                ["npx", "eleventy", "--version"], capture_output=True, text=True
            )
            return result.returncode == 0
        except Exception:
            return False

    def _run_11ty_build(
        self, output_dir: Path, force_non_incremental: bool = True
    ) -> Dict[str, Any]:
        """Run 11ty build process WITHOUT incremental mode."""
        try:
            # Clean output directory first
            if output_dir.exists():
                logger.info("Removing existing output directory for clean build")
                shutil.rmtree(output_dir)

            # Ensure parent directory exists
            output_dir.parent.mkdir(parents=True, exist_ok=True)

            # Build command - explicitly avoid --incremental flag
            cmd = ["npx", "eleventy"]

            # Add output directory
            cmd.extend(["--output", str(output_dir)])

            # Add quiet flag to reduce noise
            cmd.append("--quiet")

            # IMPORTANT: Do NOT add --incremental flag
            if force_non_incremental:
                logger.info("Running 11ty with FULL BUILD (non-incremental) mode")
                # Some versions of 11ty might have --incremental=false option
                # but generally just omitting the flag ensures full build

            # Run 11ty build
            logger.info(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=Path.cwd(),  # Ensure we're in project root
            )

            if result.returncode != 0:
                logger.error("11ty build failed", stderr=result.stderr)
                return {"success": False, "error": result.stderr}

            # Verify output was created
            if not output_dir.exists():
                return {"success": False, "error": "Output directory was not created"}

            # Count files created
            file_count = sum(1 for _ in output_dir.rglob("*") if _.is_file())
            logger.info(f"11ty build completed, created {file_count} files")

            return {"success": True, "output": result.stdout, "file_count": file_count}

        except Exception as e:
            logger.error("Exception during 11ty build", error=str(e))
            return {"success": False, "error": str(e)}

    def _get_valid_cve_ids(self, api_dir: Path, min_epss: float) -> set:
        """Get valid CVE IDs from API data."""
        valid_ids = set()

        index_file = api_dir / "vulns" / "index.json"
        if index_file.exists():
            try:
                import json

                with open(index_file) as f:
                    data = json.load(f)

                for vuln in data.get("vulnerabilities", []):
                    epss_score = vuln.get("epss", {}).get("score", 0)
                    if epss_score >= min_epss:
                        valid_ids.add(vuln["cveId"])

            except Exception as e:
                logger.error("Failed to load valid CVE IDs", error=str(e))

        return valid_ids

    def generate_build_report(self, results: Dict[str, Any]) -> str:
        """Generate human-readable build report."""
        report = f"""
Build & Deploy Agent Report
==========================

Status: {results.get("status", "Unknown")}
Duration: {self._calculate_duration(results)}

Steps Completed:
----------------
"""
        for step in results.get("steps_completed", []):
            report += f"✓ {step.replace('_', ' ').title()}\n"

        if results.get("errors"):
            report += "\nErrors Encountered:\n"
            report += "-------------------\n"
            for error in results["errors"]:
                report += f"✗ {error}\n"

        stats = results.get("statistics", {})
        if stats:
            report += "\nStatistics:\n"
            report += "-----------\n"

            if "pre_audit" in stats:
                report += (
                    f"Pre-build stale files: {stats['pre_audit']['stale_files']}\n"
                )
                report += f"Pre-build unexpected CVEs: {stats['pre_audit']['unexpected_cves']}\n"

            if "cleanup" in stats:
                cleanup = stats["cleanup"]
                report += f"Files removed: {cleanup.get('files_removed', 0)}\n"
                report += f"Storage freed: {self._format_bytes(cleanup.get('bytes_freed', 0))}\n"

            if "post_audit" in stats:
                report += (
                    f"Post-build total files: {stats['post_audit']['total_files']}\n"
                )
                report += (
                    f"Post-build stale files: {stats['post_audit']['stale_files']}\n"
                )

        return report

    def _calculate_duration(self, results: Dict[str, Any]) -> str:
        """Calculate build duration."""
        try:
            start = datetime.fromisoformat(results["start_time"])
            end = datetime.fromisoformat(results["end_time"])
            duration = (end - start).total_seconds()
            return f"{duration:.1f} seconds"
        except Exception:
            return "Unknown"

    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human-readable."""
        for unit in ["B", "KB", "MB", "GB"]:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} TB"
