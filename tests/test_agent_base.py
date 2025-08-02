"""Tests for base agent module."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from scripts.agents.base_agent import BaseAgent


class TestAgent(BaseAgent):
    """Test implementation of BaseAgent."""

    async def process(self, data):
        """Test process method."""
        return {"processed": data}


class TestBaseAgent:
    """Test cases for BaseAgent."""

    @pytest.fixture
    def agent(self, tmp_path):
        """Create test agent instance."""
        return TestAgent(name="TestAgent", cache_dir=tmp_path)

    def test_initialization(self, agent, tmp_path):
        """Test agent initialization."""
        assert agent.name == "TestAgent"
        assert agent.cache_dir == tmp_path
        assert agent.logger is not None

    def test_agent_id(self, agent):
        """Test agent ID generation."""
        agent_id = agent.agent_id
        assert agent_id is not None
        assert isinstance(agent_id, str)
        assert len(agent_id) > 0

    def test_status(self, agent):
        """Test agent status."""
        status = agent.status()
        assert status["name"] == "TestAgent"
        assert status["status"] == "idle"
        assert "created_at" in status

    @pytest.mark.asyncio
    async def test_execute(self, agent):
        """Test task execution."""
        result = await agent.execute({"task": "test"})
        assert result["success"] is True
        assert result["result"]["processed"] == {"task": "test"}

    @pytest.mark.asyncio
    async def test_execute_with_error(self, agent):
        """Test task execution with error."""
        # Mock process to raise error
        agent.process = AsyncMock(side_effect=Exception("Test error"))

        result = await agent.execute({"task": "test"})
        assert result["success"] is False
        assert "Test error" in result["error"]

    def test_logging(self, agent):
        """Test agent logging."""
        with patch.object(agent.logger, "info") as mock_log:
            agent.log_info("Test message", extra_data="test")
            mock_log.assert_called_once()

        with patch.object(agent.logger, "error") as mock_log:
            agent.log_error("Test error", error="test")
            mock_log.assert_called_once()

    def test_cache_functionality(self, agent):
        """Test caching functionality."""
        # Test cache set/get
        key = "test_key"
        value = {"data": "test_value"}

        agent._cache_set(key, value)
        cached = agent._cache_get(key)

        assert cached == value

        # Test cache miss
        missing = agent._cache_get("missing_key")
        assert missing is None

    def test_metrics_tracking(self, agent):
        """Test metrics tracking."""
        # Track some metrics
        agent._track_metric("tasks_processed", 5)
        agent._track_metric("errors", 1)

        metrics = agent.get_metrics()
        assert metrics["tasks_processed"] == 5
        assert metrics["errors"] == 1

    @pytest.mark.asyncio
    async def test_concurrent_execution(self, agent):
        """Test concurrent task execution."""
        # Execute multiple tasks concurrently
        tasks = [agent.execute({"task": f"test_{i}"}) for i in range(5)]

        results = await asyncio.gather(*tasks)

        assert len(results) == 5
        assert all(r["success"] for r in results)
        assert all(
            r["result"]["processed"]["task"].startswith("test_") for r in results
        )
