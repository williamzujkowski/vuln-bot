"""Base agent class for the vulnerability processing system.

NIST-IG Compliance:
- SA-8: Security Engineering Principles - Modular agent architecture
- SI-10: Information Input Validation - Data validation in process method
- AU-12: Audit Generation - Comprehensive logging throughout
- CM-2: Baseline Configuration - Change detection via state hashing
"""

import abc
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Set

import structlog


class BaseAgent(abc.ABC):
    """Abstract base class for all agents in the system."""

    def __init__(self, name: str, cache_dir: Optional[Path] = None):
        """Initialize base agent.

        Args:
            name: Agent name/identifier
            cache_dir: Directory for agent cache files
        """
        self.name = name
        self.logger = structlog.get_logger(self.__class__.__name__, agent=name)
        self.cache_dir = cache_dir or Path('.cache/agents')
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Agent state
        self.is_running = False
        self.last_run = None
        self.run_count = 0
        self.errors = []

        # Change detection
        self._last_state_hash = None
        self._dependencies = set()

    @abc.abstractmethod
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute the agent's main task.

        Returns:
            Dict containing execution results and metadata
        """
        pass

    @abc.abstractmethod
    def get_dependencies(self) -> Set[str]:
        """Get list of file/data dependencies for change detection.

        Returns:
            Set of file paths or data keys this agent depends on
        """
        pass

    async def run(self, force: bool = False, **kwargs) -> Dict[str, Any]:
        """Run the agent with change detection and caching.

        Args:
            force: Force execution even if no changes detected
            **kwargs: Arguments passed to execute()

        Returns:
            Execution results
        """
        self.is_running = True
        start_time = time.time()

        try:
            # Check if execution is needed
            if not force and not await self._should_execute():
                self.logger.info("No changes detected, skipping execution")
                return await self._load_cached_result()

            self.logger.info("Starting agent execution")

            # Execute the agent
            result = await self.execute(**kwargs)

            # Update state tracking
            execution_time = time.time() - start_time
            self._update_run_metadata(success=True)

            # Cache the result
            await self._cache_result(result)

            self.logger.info(
                "Agent execution completed",
                execution_time=f"{execution_time:.2f}s",
                run_count=self.run_count,
            )

            return result

        except Exception as e:
            execution_time = time.time() - start_time
            self._update_run_metadata(success=False, error=str(e))
            self.logger.error(
                "Agent execution failed",
                error=str(e),
                execution_time=f"{execution_time:.2f}s",
            )
            raise

        finally:
            self.is_running = False

    async def _should_execute(self) -> bool:
        """Check if agent should execute based on change detection."""
        try:
            # Get current state hash
            current_hash = await self._calculate_state_hash()

            # Compare with last known hash
            if self._last_state_hash is None:
                # First run
                self._last_state_hash = current_hash
                return True

            if current_hash != self._last_state_hash:
                self.logger.debug("State change detected",
                                old_hash=self._last_state_hash,
                                new_hash=current_hash)
                self._last_state_hash = current_hash
                return True

            return False

        except Exception as e:
            self.logger.warning("Change detection failed, forcing execution", error=str(e))
            return True

    async def _calculate_state_hash(self) -> str:
        """Calculate hash of current state based on dependencies."""
        import hashlib

        hasher = hashlib.sha256()

        # Hash file dependencies
        dependencies = self.get_dependencies()
        for dep in sorted(dependencies):
            dep_path = Path(dep)
            if dep_path.exists():
                if dep_path.is_file():
                    # Hash file content and modification time
                    hasher.update(dep.encode())
                    hasher.update(str(dep_path.stat().st_mtime).encode())
                    # For small files, hash content too
                    if dep_path.stat().st_size < 1024 * 1024:  # 1MB
                        hasher.update(dep_path.read_bytes())
                else:
                    # Hash directory modification time
                    hasher.update(dep.encode())
                    hasher.update(str(dep_path.stat().st_mtime).encode())
            else:
                # Missing dependency - hash the path anyway
                hasher.update(dep.encode())

        return hasher.hexdigest()

    async def _load_cached_result(self) -> Dict[str, Any]:
        """Load cached result from previous run."""
        cache_file = self.cache_dir / f"{self.name}_result.json"

        try:
            if cache_file.exists():
                data = json.loads(cache_file.read_text())
                self.logger.debug("Loaded cached result", cache_file=str(cache_file))
                return data.get('result', {})
        except Exception as e:
            self.logger.warning("Failed to load cached result", error=str(e))

        return {}

    async def _cache_result(self, result: Dict[str, Any]) -> None:
        """Cache execution result."""
        cache_file = self.cache_dir / f"{self.name}_result.json"

        try:
            cache_data = {
                'result': result,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'agent': self.name,
                'run_count': self.run_count,
                'state_hash': self._last_state_hash,
            }

            cache_file.write_text(json.dumps(cache_data, indent=2))
            self.logger.debug("Cached result", cache_file=str(cache_file))

        except Exception as e:
            self.logger.warning("Failed to cache result", error=str(e))

    def _update_run_metadata(self, success: bool, error: Optional[str] = None) -> None:
        """Update agent run metadata."""
        self.last_run = datetime.now(timezone.utc)
        self.run_count += 1

        if not success and error:
            self.errors.append({
                'timestamp': self.last_run.isoformat(),
                'error': error,
                'run_count': self.run_count,
            })
            # Keep only last 10 errors
            self.errors = self.errors[-10:]

    def get_status(self) -> Dict[str, Any]:
        """Get agent status information."""
        return {
            'name': self.name,
            'is_running': self.is_running,
            'last_run': self.last_run.isoformat() if self.last_run else None,
            'run_count': self.run_count,
            'error_count': len(self.errors),
            'recent_errors': self.errors[-3:],  # Last 3 errors
            'dependencies': list(self.get_dependencies()),
            'state_hash': self._last_state_hash,
        }
