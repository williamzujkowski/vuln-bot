"""Tests for deps.dev client module."""

import pytest
from unittest.mock import Mock, patch, AsyncMock
import aiohttp
from datetime import datetime

from scripts.agents.enrichment_agent import DataEnrichmentAgent


class TestDepsDevClient:
    """Test cases for DepsDevClient."""
    
    @pytest.fixture
    def client(self):
        """Create deps.dev client instance."""
        return DepsDevClient()
    
    @pytest.mark.asyncio
    async def test_get_vulnerability_info_success(self, client):
        """Test successful vulnerability info retrieval."""
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={
                "advisoryKey": {
                    "id": "CVE-2024-1234"
                },
                "aliases": ["GHSA-xxxx-xxxx-xxxx"],
                "summary": "Test vulnerability",
                "details": "Detailed description",
                "severity": "HIGH",
                "references": [
                    {"url": "https://example.com/advisory"}
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
                                    {"introduced": "0"},
                                    {"fixed": "1.0.1"}
                                ]
                            }
                        ]
                    }
                ]
            })
            
            mock_session.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = mock_response
            
            result = await client.get_vulnerability_info("CVE-2024-1234")
            
            assert result is not None
            assert result["advisoryKey"]["id"] == "CVE-2024-1234"
            assert result["severity"] == "HIGH"
    
    @pytest.mark.asyncio
    async def test_get_vulnerability_info_not_found(self, client):
        """Test vulnerability not found."""
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 404
            
            mock_session.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = mock_response
            
            result = await client.get_vulnerability_info("CVE-9999-9999")
            
            assert result is None
    
    @pytest.mark.asyncio
    async def test_get_package_info_success(self, client):
        """Test successful package info retrieval."""
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={
                "package": {
                    "system": "npm",
                    "name": "test-package"
                },
                "versions": [
                    {
                        "versionKey": {
                            "system": "npm",
                            "name": "test-package",
                            "version": "1.0.0"
                        },
                        "publishedAt": "2024-01-01T00:00:00Z",
                        "isDefault": True,
                        "licenses": ["MIT"],
                        "advisoryKeys": [
                            {"id": "CVE-2024-1234"}
                        ]
                    }
                ]
            })
            
            mock_session.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = mock_response
            
            result = await client.get_package_info("npm", "test-package", "1.0.0")
            
            assert result is not None
            assert result["package"]["name"] == "test-package"
            assert len(result["versions"]) > 0
    
    @pytest.mark.asyncio
    async def test_api_error_handling(self, client):
        """Test API error handling."""
        with patch('aiohttp.ClientSession') as mock_session:
            # Simulate connection error
            mock_session.return_value.__aenter__.return_value.get.side_effect = aiohttp.ClientError("Connection failed")
            
            result = await client.get_vulnerability_info("CVE-2024-1234")
            
            assert result is None
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, client):
        """Test rate limiting behavior."""
        # Set a short rate limit for testing
        client.rate_limit_delay = 0.1
        
        start_time = datetime.now()
        
        # Make multiple requests
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={})
            
            mock_session.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = mock_response
            
            await client.get_vulnerability_info("CVE-2024-0001")
            await client.get_vulnerability_info("CVE-2024-0002")
            await client.get_vulnerability_info("CVE-2024-0003")
        
        elapsed = (datetime.now() - start_time).total_seconds()
        
        # Should have delayed between requests
        assert elapsed >= 0.2  # At least 2 delays of 0.1 seconds
    
    def test_url_encoding(self, client):
        """Test URL encoding for special characters."""
        # Test CVE ID encoding
        encoded = client._encode_cve_id("CVE-2024-1234")
        assert encoded == "CVE-2024-1234"
        
        # Test package name encoding
        encoded = client._encode_package_name("@angular/core")
        assert "@" not in encoded or "/" not in encoded
        assert "angular" in encoded and "core" in encoded