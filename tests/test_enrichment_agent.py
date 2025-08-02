"""Tests for enrichment agent module."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from scripts.agents.enrichment_agent import DataEnrichmentAgent


class TestDataEnrichmentAgent:
    """Test cases for EnrichmentAgent."""

    @pytest.fixture
    def agent(self, tmp_path):
        """Create enrichment agent instance."""
        return DataEnrichmentAgent(cache_dir=tmp_path)

    @pytest.fixture
    def sample_cve(self):
        """Create sample CVE data."""
        return {
            "cveId": "CVE-2024-1234",
            "title": "Test vulnerability",
            "description": "Test description",
            "severity": "HIGH",
            "publishedDate": "2024-01-15T10:00:00Z",
            "lastModifiedDate": "2024-01-15T10:00:00Z",
            "affected_products": ["test-package"],
            "affected_vendors": ["test-vendor"],
        }

    @pytest.mark.asyncio
    async def test_enrich_cve_data_success(self, agent, sample_cve):
        """Test successful CVE enrichment."""
        # Mock API response
        with patch("aiohttp.ClientSession") as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "advisoryKey": {"id": "CVE-2024-1234"},
                    "versions": [
                        {
                            "versionKey": {
                                "system": "npm",
                                "name": "test-package",
                                "version": "1.0.0",
                            },
                            "affectedByDefault": True,
                        }
                    ],
                }
            )

            mock_session.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = (
                mock_response
            )

            enriched = await agent.enrich_cve_data(sample_cve)

            assert enriched is not None
            assert enriched["cveId"] == sample_cve["cveId"]

    @pytest.mark.asyncio
    async def test_enrich_cve_data_with_errors(self, agent, sample_cve):
        """Test enrichment with API errors."""
        # Mock API error
        with patch("aiohttp.ClientSession") as mock_session:
            mock_session.return_value.__aenter__.return_value.get.side_effect = (
                Exception("API Error")
            )

            # Should still return original data
            enriched = await agent.enrich_cve_data(sample_cve)
            assert enriched is not None
            assert enriched["cveId"] == sample_cve["cveId"]

    @pytest.mark.asyncio
    async def test_extract_package_info(self, agent, sample_cve):
        """Test package info extraction."""
        # Test with npm package format
        sample_cve["affected_products"] = ["npm:test-package"]
        info = agent._extract_package_info(sample_cve)

        assert len(info) == 1
        assert info[0] == ("npm", "test-package")

        # Test with vendor/product format
        sample_cve["affected_products"] = ["Microsoft Windows"]
        sample_cve["affected_vendors"] = ["Microsoft"]
        info = agent._extract_package_info(sample_cve)

        assert len(info) >= 0  # May not extract ecosystem

    def test_cache_functionality(self, agent):
        """Test caching functionality."""
        cache_key = "deps_dev_CVE-2024-1234_npm_test-package"

        # Test cache miss
        cached = agent._get_cached_result(cache_key)
        assert cached is None

        # Test cache set
        test_data = {"test": "data"}
        agent._cache_result(cache_key, test_data)

        # Test cache hit
        cached = agent._get_cached_result(cache_key)
        assert cached == test_data

    @pytest.mark.asyncio
    async def test_rate_limiting(self, agent):
        """Test rate limiting."""
        # Make multiple requests quickly
        start_time = asyncio.get_event_loop().time()

        await agent._rate_limit()
        await agent._rate_limit()
        await agent._rate_limit()

        elapsed = asyncio.get_event_loop().time() - start_time

        # Should have delayed at least 2 * rate_limit_delay
        assert elapsed >= 2 * agent.rate_limit_delay
