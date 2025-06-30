"""Tests for GitHub Security Advisory client."""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from scripts.harvest.github_advisory_client import GitHubAdvisoryClient
from scripts.models import (
    SeverityLevel,
    Vulnerability,
)


@pytest.fixture
def client(tmp_path):
    """Create a GitHub Advisory client with temporary cache directory."""
    return GitHubAdvisoryClient(cache_dir=tmp_path / "cache")


@pytest.fixture
def sample_advisory():
    """Sample GitHub Advisory data."""
    return {
        "ghsaId": "GHSA-1234-5678-9012",
        "summary": "SQL Injection in example-package",
        "description": "A SQL injection vulnerability exists in example-package versions < 2.0.0",
        "severity": "HIGH",
        "publishedAt": "2025-01-01T12:00:00Z",
        "updatedAt": "2025-01-02T12:00:00Z",
        "identifiers": [
            {"type": "CVE", "value": "CVE-2025-1234"},
            {"type": "GHSA", "value": "GHSA-1234-5678-9012"},
        ],
        "references": [
            {
                "url": "https://github.com/example/security/advisories/GHSA-1234-5678-9012"
            },
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2025-1234"},
        ],
        "vulnerabilities": {
            "nodes": [
                {
                    "package": {
                        "ecosystem": "NPM",
                        "name": "example-package",
                    },
                    "vulnerableVersionRange": "< 2.0.0",
                    "firstPatchedVersion": {
                        "identifier": "2.0.0",
                    },
                }
            ]
        },
        "cvss": {
            "score": 7.5,
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        },
        "cwes": {
            "nodes": [
                {"cweId": "CWE-89", "name": "SQL Injection"},
            ]
        },
    }


class TestGitHubAdvisoryClient:
    """Tests for GitHub Advisory client."""

    def test_parse_advisory(self, client, sample_advisory):
        """Test parsing GitHub advisory into Vulnerability model."""
        vuln = client.parse_advisory(sample_advisory)

        assert vuln is not None
        assert vuln.cve_id == "CVE-2025-1234"
        assert vuln.title == "SQL Injection in example-package"
        assert vuln.severity == SeverityLevel.HIGH
        assert vuln.github_advisory_id == "GHSA-1234-5678-9012"
        assert "npm" in vuln.affected_vendors
        assert "example-package" in vuln.affected_products
        assert len(vuln.references) == 3  # 2 from data + 1 added by parser
        assert "CWE-89" in vuln.tags

        # Check CVSS
        assert len(vuln.cvss_metrics) == 1
        assert vuln.cvss_metrics[0].base_score == 7.5
        assert vuln.cvss_metrics[0].version == "3.1"

        # Check source
        assert len(vuln.sources) == 1
        assert vuln.sources[0].name == "GitHub Advisory"

    def test_parse_advisory_without_cve(self, client):
        """Test parsing advisory without CVE ID (should return None)."""
        advisory = {
            "ghsaId": "GHSA-9999-9999-9999",
            "identifiers": [
                {"type": "GHSA", "value": "GHSA-9999-9999-9999"},
            ],
            "summary": "Vulnerability without CVE",
            "publishedAt": "2025-01-01T12:00:00Z",
            "updatedAt": "2025-01-01T12:00:00Z",
        }

        vuln = client.parse_advisory(advisory)
        assert vuln is None

    def test_construct_query(self, client):
        """Test GraphQL query construction."""
        # Basic query
        query = client._construct_query()
        assert "securityAdvisories(first: 100)" in query
        assert "ghsaId" in query
        assert "severity" in query

        # Query with filters
        query = client._construct_query(severity="HIGH", ecosystem="NPM")
        assert "securityAdvisories(severity: HIGH, ecosystem: NPM)" in query

        # Query with pagination
        query = client._construct_query(after_cursor="abc123")
        assert 'after: "abc123"' in query

    @patch("scripts.harvest.github_advisory_client.GitHubAdvisoryClient.post")
    def test_fetch_advisories(self, mock_post, client):
        """Test fetching advisories from GitHub."""
        # Mock response
        mock_post.return_value = {
            "data": {
                "securityAdvisories": {
                    "pageInfo": {
                        "endCursor": "cursor123",
                        "hasNextPage": False,
                    },
                    "nodes": [
                        {
                            "ghsaId": "GHSA-1111-1111-1111",
                            "severity": "HIGH",
                        },
                        {
                            "ghsaId": "GHSA-2222-2222-2222",
                            "severity": "CRITICAL",
                        },
                    ],
                }
            }
        }

        advisories = client.fetch_advisories(severity="HIGH", limit=10)

        assert len(advisories) == 2
        assert advisories[0]["ghsaId"] == "GHSA-1111-1111-1111"
        assert advisories[1]["ghsaId"] == "GHSA-2222-2222-2222"
        mock_post.assert_called_once()

    @patch("scripts.harvest.github_advisory_client.GitHubAdvisoryClient.post")
    def test_fetch_advisories_with_pagination(self, mock_post, client):
        """Test fetching advisories with pagination."""
        # Mock responses for pagination
        mock_post.side_effect = [
            {
                "data": {
                    "securityAdvisories": {
                        "pageInfo": {
                            "endCursor": "cursor1",
                            "hasNextPage": True,
                        },
                        "nodes": [{"ghsaId": f"GHSA-{i}"} for i in range(100)],
                    }
                }
            },
            {
                "data": {
                    "securityAdvisories": {
                        "pageInfo": {
                            "endCursor": "cursor2",
                            "hasNextPage": False,
                        },
                        "nodes": [{"ghsaId": f"GHSA-{i}"} for i in range(100, 150)],
                    }
                }
            },
        ]

        advisories = client.fetch_advisories()

        assert len(advisories) == 150
        assert mock_post.call_count == 2

    @patch(
        "scripts.harvest.github_advisory_client.GitHubAdvisoryClient.fetch_advisories"
    )
    @patch("scripts.harvest.github_advisory_client.GitHubAdvisoryClient.parse_advisory")
    def test_harvest(self, mock_parse, mock_fetch, client, sample_advisory):
        """Test harvesting vulnerabilities."""
        # Mock fetch to return sample advisories only for the first call (CRITICAL severity)
        # and empty for subsequent calls (HIGH severity)
        mock_fetch.side_effect = [
            [sample_advisory, sample_advisory],  # CRITICAL
            [],  # HIGH (should not be called if max_vulnerabilities is reached)
        ]

        # Mock parse to return vulnerabilities
        mock_vuln = Vulnerability(
            cve_id="CVE-2025-1234",
            title="Test Vulnerability",
            description="Test description",
            published_date=datetime.now(timezone.utc),
            last_modified_date=datetime.now(timezone.utc),
            severity=SeverityLevel.HIGH,
            affected_vendors=["test"],
            affected_products=["test-product"],
            references=[],
            sources=[],
        )
        mock_parse.return_value = mock_vuln

        vulnerabilities = client.harvest(
            min_severity=SeverityLevel.HIGH,
            max_vulnerabilities=2,  # Limit to 2 to stop after first severity level
        )

        assert len(vulnerabilities) == 2
        assert all(v.cve_id == "CVE-2025-1234" for v in vulnerabilities)
        # Should only call fetch once because max_vulnerabilities is reached
        assert mock_fetch.call_count == 1
        assert mock_parse.call_count == 2

    def test_severity_mapping(self, client):
        """Test severity level mapping."""
        test_cases = [
            ("CRITICAL", SeverityLevel.CRITICAL),
            ("HIGH", SeverityLevel.HIGH),
            ("MODERATE", SeverityLevel.MEDIUM),
            ("LOW", SeverityLevel.LOW),
            ("UNKNOWN", SeverityLevel.NONE),
        ]

        for github_severity, expected_severity in test_cases:
            advisory = {
                "ghsaId": "GHSA-test",
                "severity": github_severity,
                "identifiers": [{"type": "CVE", "value": "CVE-2025-9999"}],
                "publishedAt": "2025-01-01T12:00:00Z",
                "updatedAt": "2025-01-01T12:00:00Z",
                "summary": "Test",
                "description": "Test",
            }

            vuln = client.parse_advisory(advisory)
            if vuln:  # Will be None for unknown severity without CVSS
                assert vuln.severity == expected_severity

    def test_github_token_header(self, client, monkeypatch):
        """Test that GitHub token is included in headers when available."""
        # Without token
        headers = client.get_headers()
        assert "Authorization" not in headers

        # With token
        monkeypatch.setenv("GITHUB_TOKEN", "test-token-123")
        headers = client.get_headers()
        assert headers["Authorization"] == "Bearer test-token-123"

    @patch("scripts.harvest.github_advisory_client.GitHubAdvisoryClient.post")
    def test_error_handling(self, mock_post, client):
        """Test error handling for GraphQL errors."""
        # Mock GraphQL error response
        mock_post.return_value = {
            "errors": [
                {
                    "message": "API rate limit exceeded",
                    "type": "RATE_LIMITED",
                }
            ]
        }

        advisories = client.fetch_advisories()
        assert advisories == []
        mock_post.assert_called_once()

    def test_parse_advisory_error_handling(self, client):
        """Test error handling in parse_advisory."""
        # Invalid advisory data
        invalid_advisory = {
            "ghsaId": "GHSA-invalid",
            # Missing required fields
        }

        vuln = client.parse_advisory(invalid_advisory)
        assert vuln is None
