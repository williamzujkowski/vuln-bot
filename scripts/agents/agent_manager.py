"""Agent Manager - Factory and orchestration for all agents."""

from pathlib import Path
from typing import Dict, List, Optional

import structlog

from scripts.agents.base_agent import BaseAgent
from scripts.agents.ci_agent import CIAgent
from scripts.agents.controller_agent import ControllerAgent
from scripts.agents.cve_fetch_agent import CVEFetchAgent
from scripts.agents.dashboard_agent import DashboardAgent
from scripts.agents.static_page_agent import StaticPageAgent


class AgentManager:
    """Factory and manager for all vulnerability processing agents."""

    def __init__(self, cache_dir: Optional[Path] = None):
        """Initialize agent manager.

        Args:
            cache_dir: Directory for agent cache files
        """
        self.cache_dir = cache_dir or Path(".cache")
        self.logger = structlog.get_logger(self.__class__.__name__)

        # Agent registry
        self.agents: Dict[str, BaseAgent] = {}
        self.controller: Optional[ControllerAgent] = None

        # Initialize agents
        self._initialize_agents()

    def _initialize_agents(self) -> None:
        """Initialize all agents."""
        try:
            # Create individual agents
            self.agents["cve_fetch"] = CVEFetchAgent(self.cache_dir)
            self.agents["static_page"] = StaticPageAgent(self.cache_dir)
            self.agents["dashboard"] = DashboardAgent(self.cache_dir)
            self.agents["ci"] = CIAgent(self.cache_dir)

            # Create controller and register agents
            self.controller = ControllerAgent(self.cache_dir)
            for agent in self.agents.values():
                self.controller.register_agent(agent)

            self.logger.info(
                "Initialized agents",
                agent_count=len(self.agents),
                agents=list(self.agents.keys()),
            )

        except Exception as e:
            self.logger.error("Failed to initialize agents", error=str(e))
            raise

    async def run_pipeline(self, force: bool = False, **kwargs) -> Dict[str, any]:
        """Run the complete vulnerability processing pipeline.

        Args:
            force: Force execution even if no changes detected
            **kwargs: Additional arguments passed to agents

        Returns:
            Pipeline execution results
        """
        if not self.controller:
            raise RuntimeError("Controller not initialized")

        self.logger.info("Starting vulnerability processing pipeline", force=force)

        try:
            results = await self.controller.run(force=force, **kwargs)

            if results["success"]:
                self.logger.info(
                    "Pipeline completed successfully",
                    duration=results.get("metrics", {}).get(
                        "total_duration_seconds", 0
                    ),
                )
            else:
                self.logger.error(
                    "Pipeline completed with errors",
                    error_count=len(results.get("errors", [])),
                )

            return results

        except Exception as e:
            self.logger.error("Pipeline execution failed", error=str(e))
            raise

    async def run_agent(
        self, agent_name: str, force: bool = False, **kwargs
    ) -> Dict[str, any]:
        """Run a specific agent.

        Args:
            agent_name: Name of agent to run
            force: Force execution even if no changes detected
            **kwargs: Additional arguments passed to agent

        Returns:
            Agent execution results
        """
        if agent_name not in self.agents:
            available_agents = list(self.agents.keys())
            raise ValueError(
                f"Agent '{agent_name}' not found. Available agents: {available_agents}"
            )

        agent = self.agents[agent_name]

        self.logger.info("Running agent", agent_name=agent_name, force=force)

        try:
            results = await agent.run(force=force, **kwargs)

            self.logger.info(
                "Agent completed successfully",
                agent_name=agent_name,
                run_count=agent.run_count,
            )

            return results

        except Exception as e:
            self.logger.error(
                "Agent execution failed", agent_name=agent_name, error=str(e)
            )
            raise

    async def get_status(self) -> Dict[str, any]:
        """Get status of all agents and the pipeline.

        Returns:
            Comprehensive status information
        """
        if not self.controller:
            return {"error": "Controller not initialized"}

        return await self.controller.get_pipeline_status()

    async def health_check(self) -> Dict[str, any]:
        """Perform health check on all agents.

        Returns:
            Health check results
        """
        if not self.controller:
            return {"error": "Controller not initialized", "overall_healthy": False}

        return await self.controller.health_check()

    def get_agent(self, agent_name: str) -> Optional[BaseAgent]:
        """Get a specific agent by name.

        Args:
            agent_name: Name of agent to retrieve

        Returns:
            Agent instance or None if not found
        """
        return self.agents.get(agent_name)

    def list_agents(self) -> List[str]:
        """List all available agents.

        Returns:
            List of agent names
        """
        return list(self.agents.keys())

    async def cleanup_cache(self) -> Dict[str, any]:
        """Clean up cache files for all agents.

        Returns:
            Cleanup results
        """
        results = {"agents": {}, "overall_success": True, "errors": []}

        # Clean up CVE fetch agent cache
        cve_agent = self.agents.get("cve_fetch")
        if cve_agent and hasattr(cve_agent, "cleanup_cache"):
            try:
                cleanup_result = await cve_agent.cleanup_cache()
                results["agents"]["cve_fetch"] = cleanup_result
                if not cleanup_result.get("success"):
                    results["overall_success"] = False
            except Exception as e:
                error_msg = f"CVE fetch cache cleanup failed: {str(e)}"
                results["errors"].append(error_msg)
                results["overall_success"] = False

        # Clean up general cache directory
        try:
            import shutil

            cache_dirs = [
                self.cache_dir / "agents",
                Path(".cache/__pycache__"),
                Path("scripts/__pycache__"),
            ]

            cleaned_dirs = 0
            for cache_dir in cache_dirs:
                if cache_dir.exists():
                    shutil.rmtree(cache_dir, ignore_errors=True)
                    cleaned_dirs += 1

            results["cache_directories_cleaned"] = cleaned_dirs

        except Exception as e:
            error_msg = f"General cache cleanup failed: {str(e)}"
            results["errors"].append(error_msg)
            results["overall_success"] = False

        self.logger.info(
            "Cache cleanup completed",
            success=results["overall_success"],
            errors=len(results["errors"]),
        )

        return results

    async def get_metrics(self) -> Dict[str, any]:
        """Get performance metrics for all agents.

        Returns:
            Performance metrics
        """
        metrics = {"agents": {}, "pipeline": {}, "cache": {}}

        # Get agent metrics
        for name, agent in self.agents.items():
            metrics["agents"][name] = {
                "status": agent.get_status(),
                "is_running": agent.is_running,
                "run_count": agent.run_count,
                "error_count": len(agent.errors),
            }

        # Get CVE fetch stats
        cve_agent = self.agents.get("cve_fetch")
        if cve_agent and hasattr(cve_agent, "get_fetch_stats"):
            try:
                fetch_stats = await cve_agent.get_fetch_stats()
                metrics["cache"] = fetch_stats.get("cache_stats", {})
            except Exception as e:
                self.logger.warning("Failed to get CVE fetch stats", error=str(e))

        # Get CI build status
        ci_agent = self.agents.get("ci")
        if ci_agent and hasattr(ci_agent, "get_build_status"):
            try:
                build_status = await ci_agent.get_build_status()
                metrics["pipeline"]["build"] = build_status
            except Exception as e:
                self.logger.warning("Failed to get build status", error=str(e))

        return metrics


# Convenience function for easy access
def create_agent_manager(cache_dir: Optional[Path] = None) -> AgentManager:
    """Create and initialize an agent manager.

    Args:
        cache_dir: Directory for agent cache files

    Returns:
        Initialized AgentManager instance
    """
    return AgentManager(cache_dir)
