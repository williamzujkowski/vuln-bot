"""Controller agent that orchestrates the entire vulnerability processing pipeline."""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Set

from scripts.agents.base_agent import BaseAgent


class ControllerAgent(BaseAgent):
    """Central controller that orchestrates all other agents."""

    def __init__(self, cache_dir: Path = None):
        super().__init__("controller", cache_dir)
        self.agents = {}
        self.pipeline_config = {
            'agents': [
                'cve_fetch',
                'static_page',
                'dashboard',
                'ci'
            ],
            'max_concurrent': 2,
            'retry_attempts': 3,
            'timeout_seconds': 1800  # 30 minutes
        }

    def register_agent(self, agent: BaseAgent) -> None:
        """Register an agent with the controller.

        Args:
            agent: Agent instance to register
        """
        self.agents[agent.name] = agent
        self.logger.info("Registered agent", agent_name=agent.name)

    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute the full vulnerability processing pipeline.

        Returns:
            Pipeline execution results
        """
        force_run = kwargs.get('force', False)
        pipeline_start = datetime.now(timezone.utc)

        results = {
            'pipeline_start': pipeline_start.isoformat(),
            'agents': {},
            'success': True,
            'errors': [],
            'metrics': {}
        }

        try:
            # Execute agents in sequence with dependency management
            for agent_name in self.pipeline_config['agents']:
                if agent_name not in self.agents:
                    error_msg = f"Agent '{agent_name}' not registered"
                    self.logger.error(error_msg)
                    results['errors'].append(error_msg)
                    results['success'] = False
                    continue

                agent = self.agents[agent_name]

                try:
                    self.logger.info("Starting agent", agent_name=agent_name)
                    agent_start = datetime.now(timezone.utc)

                    # Execute agent with timeout
                    agent_result = await asyncio.wait_for(
                        agent.run(force=force_run, **kwargs),
                        timeout=self.pipeline_config['timeout_seconds']
                    )

                    agent_duration = (datetime.now(timezone.utc) - agent_start).total_seconds()

                    results['agents'][agent_name] = {
                        'success': True,
                        'duration_seconds': agent_duration,
                        'result': agent_result,
                        'status': agent.get_status()
                    }

                    self.logger.info(
                        "Agent completed successfully",
                        agent_name=agent_name,
                        duration=f"{agent_duration:.2f}s"
                    )

                except asyncio.TimeoutError:
                    error_msg = f"Agent '{agent_name}' timed out after {self.pipeline_config['timeout_seconds']}s"
                    self.logger.error(error_msg)
                    results['errors'].append(error_msg)
                    results['agents'][agent_name] = {
                        'success': False,
                        'error': 'timeout',
                        'status': agent.get_status()
                    }
                    results['success'] = False

                except Exception as e:
                    error_msg = f"Agent '{agent_name}' failed: {str(e)}"
                    self.logger.error(error_msg, error=str(e))
                    results['errors'].append(error_msg)
                    results['agents'][agent_name] = {
                        'success': False,
                        'error': str(e),
                        'status': agent.get_status()
                    }
                    results['success'] = False

            # Calculate overall metrics
            pipeline_duration = (datetime.now(timezone.utc) - pipeline_start).total_seconds()

            results['metrics'] = {
                'total_duration_seconds': pipeline_duration,
                'agents_executed': len([a for a in results['agents'].values() if 'duration_seconds' in a]),
                'agents_succeeded': len([a for a in results['agents'].values() if a.get('success')]),
                'agents_failed': len([a for a in results['agents'].values() if not a.get('success')]),
            }

            # Log pipeline summary
            if results['success']:
                self.logger.info(
                    "Pipeline completed successfully",
                    duration=f"{pipeline_duration:.2f}s",
                    agents_executed=results['metrics']['agents_executed']
                )
            else:
                self.logger.error(
                    "Pipeline completed with errors",
                    duration=f"{pipeline_duration:.2f}s",
                    error_count=len(results['errors'])
                )

            return results

        except Exception as e:
            results['success'] = False
            results['errors'].append(f"Pipeline execution failed: {str(e)}")
            self.logger.error("Pipeline execution failed", error=str(e))
            return results

    def get_dependencies(self) -> Set[str]:
        """Get dependencies for change detection."""
        # Controller depends on agent configurations and main scripts
        deps = {
            'scripts/agents/',
            'scripts/main.py',
            '.eleventy.js',
            'package.json'
        }

        # Add dependencies from all registered agents
        for agent in self.agents.values():
            deps.update(agent.get_dependencies())

        return deps

    async def get_pipeline_status(self) -> Dict[str, Any]:
        """Get comprehensive pipeline status.

        Returns:
            Status information for the entire pipeline
        """
        status = {
            'controller': self.get_status(),
            'agents': {name: agent.get_status() for name, agent in self.agents.items()},
            'pipeline': {
                'registered_agents': list(self.agents.keys()),
                'configured_agents': self.pipeline_config['agents'],
                'missing_agents': [
                    name for name in self.pipeline_config['agents']
                    if name not in self.agents
                ],
                'config': self.pipeline_config
            },
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        return status

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on all agents.

        Returns:
            Health status for each agent
        """
        health = {
            'overall_healthy': True,
            'agents': {},
            'issues': [],
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        for name, agent in self.agents.items():
            try:
                agent_status = agent.get_status()
                is_healthy = (
                    not agent.is_running or  # Not stuck
                    len(agent.errors) < 5 or  # Not too many errors
                    (agent.last_run and
                     (datetime.now(timezone.utc) - agent.last_run).total_seconds() < 86400)  # Ran recently
                )

                health['agents'][name] = {
                    'healthy': is_healthy,
                    'status': agent_status
                }

                if not is_healthy:
                    health['overall_healthy'] = False
                    health['issues'].append(f"Agent '{name}' appears unhealthy")

            except Exception as e:
                health['agents'][name] = {
                    'healthy': False,
                    'error': str(e)
                }
                health['overall_healthy'] = False
                health['issues'].append(f"Failed to check agent '{name}': {str(e)}")

        return health
