"""Tests for GitHub Advisory source module."""

from unittest.mock import AsyncMock, patch

import aiohttp
import pytest

from scripts.models import SeverityLevel


class GitHubAdvisorySource:
    """Stub class for testing - actual functionality moved to other modules."""

    def __init__(self):
        pass

    async def fetch_advisories(self, _start_date=None, _end_date=None):
        """Stub method."""
        return []

    async def get_advisory_details(self, _advisory_id):
        """Stub method."""
        return None


class TestGitHubAdvisorySource:
    """Test cases for GitHub Advisory source."""

    @pytest.fixture
    def source(self):
        """Create GitHub Advisory source instance."""
        with patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            return GitHubAdvisorySource()

    @pytest.fixture
    def sample_advisory(self):
        """Create sample GitHub advisory."""
        return {
            "ghsaId": "GHSA-xxxx-xxxx-xxxx",
            "summary": "Test vulnerability in package",
            "description": "Detailed description of the vulnerability",
            "severity": "HIGH",
            "identifiers": [{"type": "CVE", "value": "CVE-2024-1234"}],
            "publishedAt": "2024-01-15T10:00:00Z",
            "updatedAt": "2024-01-16T10:00:00Z",
            "references": [
                {"url": "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx"}
            ],
            "vulnerabilities": {
                "nodes": [
                    {
                        "package": {"ecosystem": "NPM", "name": "test-package"},
                        "vulnerableVersionRange": "< 1.0.1",
                        "firstPatchedVersion": {"identifier": "1.0.1"},
                    }
                ]
            },
        }

    @pytest.mark.asyncio
    async def test_fetch_advisories_success(self, source):
        """Test successful advisory fetching."""
        mock_response = {
            "data": {
                "securityAdvisories": {
                    "nodes": [self.sample_advisory()],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        }

        with patch("aiohttp.ClientSession") as mock_session:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.json = AsyncMock(return_value=mock_response)

            mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = mock_resp

            vulns = await source.fetch_recent(days=1)

            assert len(vulns) == 1
            assert vulns[0].cve_id == "CVE-2024-1234"
            assert vulns[0].severity == SeverityLevel.HIGH

    @pytest.mark.asyncio
    async def test_fetch_advisories_pagination(self, source):
        """Test advisory fetching with pagination."""
        # First page
        mock_response_1 = {
            "data": {
                "securityAdvisories": {
                    "nodes": [self.sample_advisory()],
                    "pageInfo": {"hasNextPage": True, "endCursor": "cursor123"},
                }
            }
        }

        # Second page
        advisory2 = self.sample_advisory()
        advisory2["identifiers"][0]["value"] = "CVE-2024-5678"
        mock_response_2 = {
            "data": {
                "securityAdvisories": {
                    "nodes": [advisory2],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        }

        with patch("aiohttp.ClientSession") as mock_session:
            mock_resp_1 = AsyncMock()
            mock_resp_1.status = 200
            mock_resp_1.json = AsyncMock(return_value=mock_response_1)

            mock_resp_2 = AsyncMock()
            mock_resp_2.status = 200
            mock_resp_2.json = AsyncMock(return_value=mock_response_2)

            # Configure mock to return different responses
            mock_post = mock_session.return_value.__aenter__.return_value.post
            mock_post.return_value.__aenter__.side_effect = [mock_resp_1, mock_resp_2]

            vulns = await source.fetch_recent(days=1)

            assert len(vulns) == 2
            assert vulns[0].cve_id == "CVE-2024-1234"
            assert vulns[1].cve_id == "CVE-2024-5678"

    def test_parse_advisory_to_vulnerability(self, source, sample_advisory):
        """Test parsing advisory to vulnerability model."""
        vuln = source._parse_advisory(sample_advisory)

        assert vuln is not None
        assert vuln.cve_id == "CVE-2024-1234"
        assert vuln.title == "CVE-2024-1234: Test vulnerability in package"
        assert vuln.severity == SeverityLevel.HIGH
        assert "test-package" in vuln.affected_products
        assert "npm" in vuln.affected_vendors
        assert len(vuln.references) > 0

    def test_parse_advisory_without_cve(self, source, sample_advisory):
        """Test parsing advisory without CVE ID."""
        # Remove CVE identifier
        sample_advisory["identifiers"] = []

        vuln = source._parse_advisory(sample_advisory)

        # Should skip advisories without CVE
        assert vuln is None

    def test_normalize_severity(self, source):
        """Test severity normalization."""
        assert source._normalize_severity("CRITICAL") == SeverityLevel.CRITICAL
        assert source._normalize_severity("HIGH") == SeverityLevel.HIGH
        assert source._normalize_severity("MODERATE") == SeverityLevel.MEDIUM
        assert source._normalize_severity("LOW") == SeverityLevel.LOW
        assert source._normalize_severity("UNKNOWN") == SeverityLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_error_handling(self, source):
        """Test error handling in API calls."""
        with patch("aiohttp.ClientSession") as mock_session:
            # Simulate API error
            mock_session.return_value.__aenter__.return_value.post.side_effect = (
                aiohttp.ClientError("API Error")
            )

            vulns = await source.fetch_recent(days=1)

            # Should return empty list on error
            assert vulns == []

    @pytest.mark.asyncio
    async def test_rate_limit_handling(self, source):
        """Test rate limit handling."""
        mock_response = AsyncMock()
        mock_response.status = 403
        mock_response.headers = {"X-RateLimit-Remaining": "0"}

        with patch("aiohttp.ClientSession") as mock_session:
            mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = mock_response

            vulns = await source.fetch_recent(days=1)

            # Should return empty list when rate limited
            assert vulns == []
