"""Tests for the DataEnrichmentAgent."""

import asyncio
import json
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch
import aiohttp
import pytest

from scripts.agents.enrichment_agent import DataEnrichmentAgent


@pytest.fixture
def enrichment_agent(tmp_path):
    """Create an enrichment agent instance."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    return DataEnrichmentAgent(cache_dir=cache_dir)


@pytest.fixture
def sample_cve_data():
    """Sample CVE data for testing."""
    return {
        "cve_id": "CVE-2024-1234",
        "title": "Test Vulnerability in Package",
        "description": "A test vulnerability with CWE-79 XSS issue",
        "severity": "HIGH",
        "cvss_score": 8.5,
        "epss_score": 75.0,
        "vendors_list": ["test_vendor"],
        "products_list": ["test_product"],
        "references": [
            "https://github.com/test/repo/commit/abc123",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
        ],
        "tags": ["CWE-79", "XSS"],
        "kev_status": False
    }


@pytest.fixture
def osv_response():
    """Sample OSV API response."""
    return {
        "id": "CVE-2024-1234",
        "aliases": ["GHSA-xxxx-yyyy-zzzz"],
        "summary": "Test vulnerability",
        "severity": [
            {
                "type": "CVSS_V3",
                "score": 8.5
            }
        ],
        "affected": [
            {
                "package": {
                    "ecosystem": "npm",
                    "name": "test-package"
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "1.2.5"}
                        ]
                    }
                ],
                "database_specific": {
                    "source": "osv"
                }
            },
            {
                "package": {
                    "ecosystem": "PyPI",
                    "name": "another-package"
                },
                "versions": ["2.0.0", "2.0.1", "2.0.2"]
            }
        ]
    }


class TestDataEnrichmentAgent:
    """Test cases for DataEnrichmentAgent."""
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, enrichment_agent):
        """Test rate limiting functionality."""
        # Record times
        times = []
        
        async def record_time():
            await enrichment_agent._apply_rate_limit()
            times.append(asyncio.get_event_loop().time())
        
        # Make multiple calls
        await record_time()
        await record_time()
        await record_time()
        
        # Check delays between calls
        if len(times) > 1:
            delays = [times[i] - times[i-1] for i in range(1, len(times))]
            # All delays should be at least the rate limit delay
            assert all(d >= enrichment_agent.rate_limit_delay - 0.01 for d in delays)
    
    @pytest.mark.asyncio
    async def test_make_request_with_retry(self, enrichment_agent):
        """Test HTTP request with retry logic."""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"test": "data"})
        
        with patch('aiohttp.ClientSession.get', return_value=mock_response) as mock_get:
            mock_get.return_value.__aenter__.return_value = mock_response
            
            session = aiohttp.ClientSession()
            result = await enrichment_agent._make_request_with_retry(session, "http://test.url")
            await session.close()
            
            assert result == {"test": "data"}
    
    @pytest.mark.asyncio
    async def test_make_request_with_retry_rate_limit(self, enrichment_agent):
        """Test retry on rate limit (429) response."""
        mock_response = AsyncMock()
        mock_response.status = 429
        mock_response.headers = {"Retry-After": "1"}
        
        with patch('aiohttp.ClientSession.get', return_value=mock_response) as mock_get:
            mock_get.return_value.__aenter__.return_value = mock_response
            
            with patch('asyncio.sleep') as mock_sleep:
                session = aiohttp.ClientSession()
                result = await enrichment_agent._make_request_with_retry(session, "http://test.url")
                await session.close()
                
                # Should have slept for retry-after duration
                mock_sleep.assert_called()
    
    @pytest.mark.asyncio
    async def test_process_osv_response(self, enrichment_agent, osv_response):
        """Test processing of OSV format response."""
        result = enrichment_agent._process_osv_response(osv_response)
        
        assert result["total_affected"] == 2
        assert "npm" in result["ecosystems"]
        assert "pypi" in result["ecosystems"]
        assert len(result["packages"]) == 2
        
        # Check first package
        npm_pkg = next(p for p in result["packages"] if p["ecosystem"] == "npm")
        assert npm_pkg["name"] == "test-package"
        assert npm_pkg["version_range"] == ">= 1.0.0 < 1.2.5"
        assert npm_pkg["patch_available"] is True
        assert "1.2.5" in npm_pkg["fixed_versions"]
        
        # Check second package
        pypi_pkg = next(p for p in result["packages"] if p["ecosystem"] == "pypi")
        assert pypi_pkg["name"] == "another-package"
        assert len(pypi_pkg["affected_versions"]) == 3
    
    def test_map_ecosystem_name(self, enrichment_agent):
        """Test ecosystem name mapping."""
        # Direct mappings
        assert enrichment_agent._map_ecosystem_name("npm") == "npm"
        assert enrichment_agent._map_ecosystem_name("PyPI") == "pypi"
        
        # Variations
        assert enrichment_agent._map_ecosystem_name("python") == "pypi"
        assert enrichment_agent._map_ecosystem_name("node") == "npm"
        assert enrichment_agent._map_ecosystem_name("golang") == "go"
        assert enrichment_agent._map_ecosystem_name("java") == "maven"
        
        # Unknown
        assert enrichment_agent._map_ecosystem_name("unknown") == "unknown"
    
    @pytest.mark.asyncio
    async def test_enrich_cve_data(self, enrichment_agent, sample_cve_data):
        """Test CVE data enrichment."""
        # Mock the fetch_deps_dev_data method
        mock_deps_data = {
            "packages": [
                {
                    "ecosystem": "npm",
                    "name": "test-package",
                    "severity": "HIGH",
                    "version_range": ">= 1.0.0 < 1.2.5",
                    "patch_available": True,
                    "fixed_versions": ["1.2.5"]
                }
            ],
            "total_affected": 1,
            "ecosystems": ["npm"],
            "severity_breakdown": {"HIGH": 1}
        }
        
        with patch.object(enrichment_agent, 'fetch_deps_dev_data', return_value=mock_deps_data):
            result = await enrichment_agent.enrich_cve_data(sample_cve_data)
        
        # Check enrichment structure
        assert "enrichment" in result
        assert "deps.dev" in result["enrichment"]["sources"]
        assert result["has_deps_data"] is True
        assert result["total_affected_packages"] == 1
        assert result["affected_ecosystems"] == ["npm"]
        
        # Check impact summary
        impact = result["enrichment"]["impact_summary"]
        assert impact["total_affected_packages"] == 1
        assert impact["has_impact_data"] is True
        assert impact["patch_availability"]["percentage"] == 100.0
        
        # Check exploitation intelligence
        intel = result["enrichment"]["exploitation_intel"]
        assert intel["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert isinstance(intel["risk_factors"], list)
        assert isinstance(intel["recommendation"], str)
    
    def test_extract_problem_types(self, enrichment_agent, sample_cve_data):
        """Test CWE extraction."""
        result = enrichment_agent._extract_problem_types(sample_cve_data)
        
        assert len(result) == 1
        assert result[0]["type"] == "CWE"
        assert result[0]["id"] == "CWE-79"
        assert "Cross-site Scripting" in result[0]["description"]
    
    def test_categorize_references(self, enrichment_agent):
        """Test reference categorization."""
        references = [
            {"url": "https://github.com/test/commit/123", "tags": ["Patch"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234", "tags": ["CVE Record"]},
            {"url": "https://exploit-db.com/exploits/12345", "tags": ["Exploit"]},
            {"url": "https://blog.example.com/analysis", "tags": ["Third Party Advisory"]}
        ]
        
        result = enrichment_agent._categorize_references(references)
        
        assert "patches" in result
        assert "exploits" in result
        assert len(result["patches"]) == 1
        assert len(result["exploits"]) == 1
    
    def test_analyze_exploitation_risk_high_epss(self, enrichment_agent):
        """Test exploitation risk analysis with high EPSS score."""
        data = {
            "epss_score": 85.0,
            "kev_status": False,
            "total_affected_packages": 5,
            "affected_ecosystems": ["npm"],
            "enrichment": {
                "all_references": [],
                "impact_summary": {
                    "patch_availability": {"percentage": 60}
                }
            }
        }
        
        result = enrichment_agent._analyze_exploitation_risk(data)
        
        assert result["risk_level"] == "HIGH"
        assert any("High EPSS score" in factor for factor in result["risk_factors"])
        assert "HIGH PRIORITY" in result["recommendation"]
    
    def test_analyze_exploitation_risk_kev_listed(self, enrichment_agent):
        """Test exploitation risk analysis for KEV-listed CVE."""
        data = {
            "epss_score": 50.0,
            "kev_status": True,
            "total_affected_packages": 10,
            "affected_ecosystems": ["pypi", "npm"],
            "enrichment": {
                "all_references": [],
                "impact_summary": {
                    "patch_availability": {"percentage": 30}
                }
            }
        }
        
        result = enrichment_agent._analyze_exploitation_risk(data)
        
        assert result["risk_level"] == "CRITICAL"
        assert any("CISA KEV catalog" in factor for factor in result["risk_factors"])
        assert "IMMEDIATE ACTION REQUIRED" in result["recommendation"]
    
    @pytest.mark.asyncio
    async def test_cache_functionality(self, enrichment_agent, sample_cve_data):
        """Test caching of enrichment data."""
        cve_id = sample_cve_data["cve_id"]
        cache_file = enrichment_agent.cache_dir / f"{cve_id}_deps.json"
        
        # Create cached data
        cached_data = {
            "packages": [],
            "total_affected": 0,
            "ecosystems": []
        }
        
        cache_file.write_text(json.dumps(cached_data))
        
        # Test that cached data is used
        result = await enrichment_agent.fetch_deps_dev_data(cve_id)
        
        assert result == cached_data
        
        # Test cache expiry
        # Make file older than TTL
        old_time = datetime.now() - timedelta(hours=25)
        import os
        os.utime(cache_file, (old_time.timestamp(), old_time.timestamp()))
        
        # Mock API call for expired cache
        with patch.object(enrichment_agent, '_make_request_with_retry', return_value=None):
            with patch.object(enrichment_agent, '_fetch_via_osv', return_value=None):
                result = await enrichment_agent.fetch_deps_dev_data(cve_id)
                
                # Should have tried to fetch new data
                assert result is None