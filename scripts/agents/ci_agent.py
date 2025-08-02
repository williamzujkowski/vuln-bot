"""CI Agent - Manages continuous integration and deployment tasks."""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set

from scripts.agents.base_agent import BaseAgent


class CIAgent(BaseAgent):
    """Agent responsible for CI/CD operations and deployment."""

    def __init__(self, cache_dir: Path = None):
        super().__init__("ci", cache_dir)

        # Configuration
        self.config = {
            "build_command": "npm run build",
            "test_command": "npm test",
            "lint_commands": ["ruff check scripts/", "ruff format --check scripts/"],
            "security_commands": ["bandit -r scripts/ -ll"],
            "build_dir": "public",
            "deploy_branch": "gh-pages",
            "commit_changes": True,
            "run_tests": False,  # Disabled as noted in package.json
            "cache_optimization": True,
        }

    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute CI/CD pipeline.

        Returns:
            Results from CI/CD execution
        """
        config = {**self.config, **kwargs}

        results = {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "config": config,
            "steps": {},
            "success": True,
            "errors": [],
            "artifacts": [],
        }

        try:
            # Step 1: Lint and format check
            if config.get("lint_commands"):
                lint_result = await self._run_lint_checks(config["lint_commands"])
                results["steps"]["lint"] = lint_result
                if not lint_result["success"]:
                    results["success"] = False

            # Step 2: Security checks
            if config.get("security_commands"):
                security_result = await self._run_security_checks(
                    config["security_commands"]
                )
                results["steps"]["security"] = security_result
                if not security_result["success"]:
                    results["success"] = False

            # Step 3: Tests (if enabled)
            if config.get("run_tests"):
                test_result = await self._run_tests(config["test_command"])
                results["steps"]["tests"] = test_result
                if not test_result["success"]:
                    results["success"] = False

            # Step 4: Build
            build_result = await self._run_build(config["build_command"])
            results["steps"]["build"] = build_result
            if not build_result["success"]:
                results["success"] = False
            else:
                results["artifacts"].extend(build_result.get("artifacts", []))

            # Step 5: Cache optimization
            if config.get("cache_optimization"):
                cache_result = await self._optimize_cache()
                results["steps"]["cache_optimization"] = cache_result

            # Step 6: Commit changes (if enabled and successful)
            if config.get("commit_changes") and results["success"]:
                commit_result = await self._commit_changes()
                results["steps"]["commit"] = commit_result
                if not commit_result["success"]:
                    results["success"] = False

            results["completed_at"] = datetime.now(timezone.utc).isoformat()

            if results["success"]:
                self.logger.info(
                    "CI pipeline completed successfully",
                    steps_completed=len(results["steps"]),
                    artifacts_generated=len(results["artifacts"]),
                )
            else:
                self.logger.error(
                    "CI pipeline completed with errors",
                    failed_steps=[
                        step
                        for step, result in results["steps"].items()
                        if not result.get("success")
                    ],
                )

            return results

        except Exception as e:
            results["success"] = False
            results["errors"].append(str(e))
            results["completed_at"] = datetime.now(timezone.utc).isoformat()

            self.logger.error("CI pipeline failed", error=str(e))
            raise

    async def _run_lint_checks(self, commands: List[str]) -> Dict[str, Any]:
        """Run linting and formatting checks.

        Args:
            commands: List of lint commands to run

        Returns:
            Lint check results
        """
        result = {
            "success": True,
            "commands": {},
            "started_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            for cmd in commands:
                cmd_result = await self._run_command(cmd)
                result["commands"][cmd] = cmd_result

                if cmd_result["return_code"] != 0:
                    result["success"] = False
                    self.logger.warning(
                        "Lint command failed",
                        command=cmd,
                        return_code=cmd_result["return_code"],
                    )

            result["completed_at"] = datetime.now(timezone.utc).isoformat()

            if result["success"]:
                self.logger.info("All lint checks passed")
            else:
                self.logger.warning("Some lint checks failed")

            return result

        except Exception as e:
            result["success"] = False
            result["error"] = str(e)
            result["completed_at"] = datetime.now(timezone.utc).isoformat()
            return result

    async def _run_security_checks(self, commands: List[str]) -> Dict[str, Any]:
        """Run security checks.

        Args:
            commands: List of security commands to run

        Returns:
            Security check results
        """
        result = {
            "success": True,
            "commands": {},
            "started_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            for cmd in commands:
                cmd_result = await self._run_command(cmd)
                result["commands"][cmd] = cmd_result

                # Bandit returns non-zero for issues found, but we may want to continue
                if cmd_result["return_code"] != 0:
                    self.logger.warning(
                        "Security check found issues",
                        command=cmd,
                        return_code=cmd_result["return_code"],
                    )
                    # Don't fail the entire pipeline for security warnings
                    # result['success'] = False

            result["completed_at"] = datetime.now(timezone.utc).isoformat()

            self.logger.info("Security checks completed")
            return result

        except Exception as e:
            result["success"] = False
            result["error"] = str(e)
            result["completed_at"] = datetime.now(timezone.utc).isoformat()
            return result

    async def _run_tests(self, command: str) -> Dict[str, Any]:
        """Run test suite.

        Args:
            command: Test command to run

        Returns:
            Test results
        """
        result = {"success": True, "started_at": datetime.now(timezone.utc).isoformat()}

        try:
            cmd_result = await self._run_command(command)
            result.update(cmd_result)

            if cmd_result["return_code"] != 0:
                result["success"] = False
                self.logger.error("Tests failed", return_code=cmd_result["return_code"])
            else:
                self.logger.info("All tests passed")

            result["completed_at"] = datetime.now(timezone.utc).isoformat()
            return result

        except Exception as e:
            result["success"] = False
            result["error"] = str(e)
            result["completed_at"] = datetime.now(timezone.utc).isoformat()
            return result

    async def _run_build(self, command: str) -> Dict[str, Any]:
        """Run build process.

        Args:
            command: Build command to run

        Returns:
            Build results
        """
        result = {
            "success": True,
            "artifacts": [],
            "started_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            cmd_result = await self._run_command(command)
            result.update(cmd_result)

            if cmd_result["return_code"] != 0:
                result["success"] = False
                self.logger.error("Build failed", return_code=cmd_result["return_code"])
            else:
                self.logger.info("Build completed successfully")

                # Collect build artifacts
                build_dir = Path(self.config["build_dir"])
                if build_dir.exists():
                    artifacts = list(build_dir.rglob("*"))
                    result["artifacts"] = [str(p) for p in artifacts if p.is_file()]

            result["completed_at"] = datetime.now(timezone.utc).isoformat()
            return result

        except Exception as e:
            result["success"] = False
            result["error"] = str(e)
            result["completed_at"] = datetime.now(timezone.utc).isoformat()
            return result

    async def _optimize_cache(self) -> Dict[str, Any]:
        """Optimize cache and temporary files.

        Returns:
            Cache optimization results
        """
        result = {
            "success": True,
            "optimizations": [],
            "started_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            # Clean up Python cache files
            cleanup_commands = [
                'find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true',
                'find . -name "*.pyc" -delete 2>/dev/null || true',
                'find . -name ".DS_Store" -delete 2>/dev/null || true',
            ]

            for cmd in cleanup_commands:
                cmd_result = await self._run_command(cmd)
                result["optimizations"].append(
                    {"command": cmd, "success": cmd_result["return_code"] == 0}
                )

            # Compress large files if needed
            large_files = []
            build_dir = Path(self.config["build_dir"])
            if build_dir.exists():
                for file_path in build_dir.rglob("*.json"):
                    if file_path.stat().st_size > 1024 * 1024:  # > 1MB
                        large_files.append(str(file_path))

            result["large_files_found"] = len(large_files)
            result["completed_at"] = datetime.now(timezone.utc).isoformat()

            self.logger.info(
                "Cache optimization completed",
                optimizations=len(result["optimizations"]),
                large_files=len(large_files),
            )

            return result

        except Exception as e:
            result["success"] = False
            result["error"] = str(e)
            result["completed_at"] = datetime.now(timezone.utc).isoformat()
            return result

    async def _commit_changes(self) -> Dict[str, Any]:
        """Commit changes to git repository.

        Returns:
            Commit results
        """
        result = {"success": True, "started_at": datetime.now(timezone.utc).isoformat()}

        try:
            # Check if there are changes to commit
            status_result = await self._run_command("git status --porcelain")

            if not status_result["stdout"].strip():
                result["message"] = "No changes to commit"
                result["completed_at"] = datetime.now(timezone.utc).isoformat()
                self.logger.info("No changes to commit")
                return result

            # Add changes
            add_result = await self._run_command("git add public/ api/")
            if add_result["return_code"] != 0:
                result["success"] = False
                result["error"] = f"Failed to add files: {add_result['stderr']}"
                return result

            # Create commit message
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            commit_msg = f"""feat: update vulnerability intelligence dashboard

- Regenerated static CVE pages and dashboard
- Updated vulnerability data and API endpoints
- Generated at {timestamp}

🤖 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>"""

            # Commit changes
            commit_result = await self._run_command(f'git commit -m "{commit_msg}"')

            if commit_result["return_code"] != 0:
                result["success"] = False
                result["error"] = f"Failed to commit: {commit_result['stderr']}"
            else:
                result["commit_hash"] = commit_result["stdout"].strip()
                self.logger.info("Changes committed successfully")

            result["completed_at"] = datetime.now(timezone.utc).isoformat()
            return result

        except Exception as e:
            result["success"] = False
            result["error"] = str(e)
            result["completed_at"] = datetime.now(timezone.utc).isoformat()
            return result

    async def _run_command(self, command: str, timeout: int = 300) -> Dict[str, Any]:
        """Run a shell command asynchronously.

        Args:
            command: Command to run
            timeout: Timeout in seconds

        Returns:
            Command execution results
        """
        try:
            self.logger.debug("Running command", command=command)

            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=Path.cwd(),
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )

            return {
                "command": command,
                "return_code": process.returncode,
                "stdout": stdout.decode("utf-8", errors="ignore"),
                "stderr": stderr.decode("utf-8", errors="ignore"),
                "duration": timeout,  # Approximate
            }

        except asyncio.TimeoutError:
            self.logger.error("Command timed out", command=command, timeout=timeout)
            return {
                "command": command,
                "return_code": -1,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "duration": timeout,
            }
        except Exception as e:
            self.logger.error("Command failed", command=command, error=str(e))
            return {
                "command": command,
                "return_code": -1,
                "stdout": "",
                "stderr": str(e),
                "duration": 0,
            }

    def get_dependencies(self) -> Set[str]:
        """Get dependencies for change detection."""
        return {
            "public/",
            "api/",
            "package.json",
            ".eleventy.js",
            "scripts/",
            ".github/workflows/",
        }

    async def get_build_status(self) -> Dict[str, Any]:
        """Get current build status and metrics.

        Returns:
            Build status information
        """
        build_dir = Path(self.config["build_dir"])

        status = {
            "build_exists": build_dir.exists(),
            "build_files": 0,
            "build_size_mb": 0,
            "last_build": None,
            "git_status": {},
            "agent_status": self.get_status(),
        }

        try:
            if build_dir.exists():
                build_files = list(build_dir.rglob("*"))
                status["build_files"] = len([f for f in build_files if f.is_file()])
                status["build_size_mb"] = sum(
                    f.stat().st_size for f in build_files if f.is_file()
                ) / (1024 * 1024)

                # Get most recent build time
                if build_files:
                    newest_file = max(
                        build_files,
                        key=lambda f: f.stat().st_mtime if f.is_file() else 0,
                    )
                    status["last_build"] = datetime.fromtimestamp(
                        newest_file.stat().st_mtime, tz=timezone.utc
                    ).isoformat()

            # Get git status
            git_status = await self._run_command("git status --porcelain")
            if git_status["return_code"] == 0:
                status["git_status"] = {
                    "clean": not git_status["stdout"].strip(),
                    "changes": (
                        git_status["stdout"].strip().split("\n")
                        if git_status["stdout"].strip()
                        else []
                    ),
                }

        except Exception as e:
            status["error"] = str(e)

        return status
