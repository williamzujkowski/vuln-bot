"""Tests for CISA KEV Agent."""

import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import pytest
import requests

from scripts.agents.cisa_kev_agent import CISAKEVAgent


class TestCISAKEVAgentInitialization:
    """Test suite for CISA KEV Agent initialization."""

    def test_initialization(self):
        """Test agent initialization."""
        agent = CISAKEVAgent()

        assert agent.name == "CISAKEVAgent"
        assert agent.kev_cache is None
        assert agent.kev_cache_time is None
        assert agent.stats == {
            "kev_enriched": 0,
            "total_processed": 0,
            "kev_catalog_size": 0,
        }

    def test_get_dependencies(self):
        """Test dependencies include CISA KEV URL."""
        agent = CISAKEVAgent()
        deps = agent.get_dependencies()

        assert agent.CISA_KEV_URL in deps
        assert len(deps) == 1


class TestCISAKEVAgentCatalogFetching:
    """Test suite for KEV catalog fetching."""

    def test_fetch_kev_catalog_success(self):
        """Test successful KEV catalog fetch."""
        agent = CISAKEVAgent()

        mock_response = {
            "catalogVersion": "2024.10.23",
            "dateReleased": "2024-10-23",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "vendorProject": "Example Corp",
                    "product": "ExampleDB",
                    "vulnerabilityName": "SQL Injection",
                    "dateAdded": "2024-10-20",
                    "shortDescription": "Critical SQL injection",
                    "requiredAction": "Apply updates immediately",
                    "dueDate": "2024-11-05",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "Active exploitation observed",
                },
                {
                    "cveID": "CVE-2024-0002",
                    "vendorProject": "Another Corp",
                    "product": "AnotherApp",
                    "vulnerabilityName": "RCE",
                    "dateAdded": "2024-10-21",
                    "shortDescription": "Remote code execution",
                    "requiredAction": "Patch immediately",
                    "dueDate": "2024-11-06",
                    "knownRansomwareCampaignUse": "Unknown",
                },
            ],
        }

        with patch("requests.get") as mock_get:
            mock_get.return_value.json.return_value = mock_response
            mock_get.return_value.raise_for_status = Mock()

            catalog = agent.fetch_kev_catalog()

            assert len(catalog) == 2
            assert "CVE-2024-0001" in catalog
            assert "CVE-2024-0002" in catalog
            assert catalog["CVE-2024-0001"]["vendorProject"] == "Example Corp"
            assert catalog["CVE-2024-0001"]["product"] == "ExampleDB"
            assert catalog["CVE-2024-0001"]["knownRansomwareCampaignUse"] == "Known"
            assert catalog["CVE-2024-0002"]["knownRansomwareCampaignUse"] == "Unknown"
            assert agent.kev_cache == catalog
            assert agent.kev_cache_time is not None
            assert agent.stats["kev_catalog_size"] == 2

    def test_fetch_kev_catalog_uses_cache(self):
        """Test that fetch uses cache when valid."""
        agent = CISAKEVAgent()

        # Pre-populate cache
        agent.kev_cache = {"CVE-2024-0001": {"product": "Test"}}
        agent.kev_cache_time = datetime.utcnow()

        with patch("requests.get") as mock_get:
            catalog = agent.fetch_kev_catalog()

            # Should use cache, not make HTTP request
            mock_get.assert_not_called()
            assert catalog == agent.kev_cache

    def test_fetch_kev_catalog_force_refresh(self):
        """Test forcing cache refresh."""
        agent = CISAKEVAgent()

        # Pre-populate cache
        agent.kev_cache = {"CVE-2024-0001": {"product": "Old"}}
        agent.kev_cache_time = datetime.utcnow()

        mock_response = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0002",
                    "product": "New",
                    "vendorProject": "Corp",
                    "vulnerabilityName": "Test",
                    "dateAdded": "2024-10-20",
                    "shortDescription": "Test",
                    "requiredAction": "Test",
                    "dueDate": "2024-11-05",
                }
            ]
        }

        with patch("requests.get") as mock_get:
            mock_get.return_value.json.return_value = mock_response
            mock_get.return_value.raise_for_status = Mock()

            catalog = agent.fetch_kev_catalog(force_refresh=True)

            # Should make HTTP request despite cache
            mock_get.assert_called_once()
            assert "CVE-2024-0002" in catalog
            assert "CVE-2024-0001" not in catalog

    def test_fetch_kev_catalog_expired_cache(self):
        """Test that expired cache triggers re-fetch."""
        agent = CISAKEVAgent()

        # Set cache with expired timestamp (25 hours ago)
        agent.kev_cache = {"CVE-2024-0001": {"product": "Old"}}
        agent.kev_cache_time = datetime.utcnow() - timedelta(hours=25)

        mock_response = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0002",
                    "product": "New",
                    "vendorProject": "Corp",
                    "vulnerabilityName": "Test",
                    "dateAdded": "2024-10-20",
                    "shortDescription": "Test",
                    "requiredAction": "Test",
                    "dueDate": "2024-11-05",
                }
            ]
        }

        with patch("requests.get") as mock_get:
            mock_get.return_value.json.return_value = mock_response
            mock_get.return_value.raise_for_status = Mock()

            catalog = agent.fetch_kev_catalog()

            # Should make HTTP request because cache is expired
            mock_get.assert_called_once()
            assert "CVE-2024-0002" in catalog

    @patch("scripts.agents.cisa_kev_agent.requests.get")
    def test_fetch_kev_catalog_network_error(self, mock_get):
        """Test handling of network errors."""
        agent = CISAKEVAgent()

        mock_get.side_effect = requests.RequestException("Network error")

        catalog = agent.fetch_kev_catalog()

        # Should return empty dict on error
        assert catalog == {}
        assert agent.kev_cache is None

    def test_fetch_kev_catalog_json_decode_error(self):
        """Test handling of JSON decode errors."""
        agent = CISAKEVAgent()

        with patch("requests.get") as mock_get:
            mock_get.return_value.json.side_effect = json.JSONDecodeError(
                "Invalid JSON", "", 0
            )
            mock_get.return_value.raise_for_status = Mock()

            catalog = agent.fetch_kev_catalog()

            # Should return empty dict on JSON error
            assert catalog == {}

    def test_fetch_kev_catalog_missing_cve_id(self):
        """Test handling of entries without CVE IDs."""
        agent = CISAKEVAgent()

        mock_response = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "product": "Valid",
                    "vendorProject": "Corp",
                    "vulnerabilityName": "Test",
                    "dateAdded": "2024-10-20",
                    "shortDescription": "Test",
                    "requiredAction": "Test",
                    "dueDate": "2024-11-05",
                },
                {
                    # Missing cveID
                    "product": "Invalid",
                    "vendorProject": "Corp",
                },
            ]
        }

        with patch("requests.get") as mock_get:
            mock_get.return_value.json.return_value = mock_response
            mock_get.return_value.raise_for_status = Mock()

            catalog = agent.fetch_kev_catalog()

            # Should only include entry with CVE ID
            assert len(catalog) == 1
            assert "CVE-2024-0001" in catalog


class TestCISAKEVAgentEnrichment:
    """Test suite for vulnerability enrichment."""

    def test_enrich_vulnerability_in_kev(self):
        """Test enriching a vulnerability that's in KEV catalog."""
        agent = CISAKEVAgent()

        # Pre-populate cache to avoid network call
        agent.kev_cache = {
            "CVE-2024-0001": {
                "vendorProject": "Example Corp",
                "product": "ExampleDB",
                "vulnerabilityName": "SQL Injection",
                "dateAdded": "2024-10-20",
                "shortDescription": "Critical SQL injection",
                "requiredAction": "Apply updates immediately",
                "dueDate": "2024-11-05",
                "knownRansomwareCampaignUse": "Known",
                "notes": "Active exploitation",
            }
        }
        agent.kev_cache_time = datetime.utcnow()

        vulnerability = {
            "cveId": "CVE-2024-0001",
            "title": "SQL Injection",
            "severity": "CRITICAL",
        }

        enriched = agent.enrich_vulnerability(vulnerability)

        # Check KEV enrichment added
        assert "enrichments" in enriched
        assert "cisa_kev" in enriched["enrichments"]
        assert enriched["enrichments"]["cisa_kev"]["isKnownExploited"] is True
        assert enriched["enrichments"]["cisa_kev"]["dateAdded"] == "2024-10-20"
        assert (
            enriched["enrichments"]["cisa_kev"]["knownRansomwareCampaignUse"] == "Known"
        )

        # Check exploitation status
        assert enriched["exploitationStatus"] == "KNOWN_EXPLOITED"

        # Check KEV reference added
        assert "references" in enriched
        kev_refs = [
            r
            for r in enriched["references"]
            if "cisa.gov/known-exploited-vulnerabilities" in r.get("url", "")
        ]
        assert len(kev_refs) == 1
        assert kev_refs[0]["source"] == "CISA KEV"
        assert "exploit" in kev_refs[0]["tags"]

        # Check tags
        assert "metadata" in enriched
        assert "tags" in enriched["metadata"]
        assert "CISA-KEV" in enriched["metadata"]["tags"]
        assert "RANSOMWARE" in enriched["metadata"]["tags"]

        # Check stats
        assert agent.stats["kev_enriched"] == 1
        assert agent.stats["total_processed"] == 1

    def test_enrich_vulnerability_not_in_kev(self):
        """Test enriching a vulnerability not in KEV catalog."""
        agent = CISAKEVAgent()

        agent.kev_cache = {"CVE-2024-0001": {"product": "Test"}}
        agent.kev_cache_time = datetime.utcnow()

        vulnerability = {
            "cveId": "CVE-2024-9999",  # Not in KEV
            "title": "Test Vulnerability",
        }

        enriched = agent.enrich_vulnerability(vulnerability)

        # Should not add KEV enrichment
        assert enriched.get("enrichments", {}).get("cisa_kev") is None
        assert enriched.get("exploitationStatus") != "KNOWN_EXPLOITED"

        # Stats should still count as processed
        assert agent.stats["kev_enriched"] == 0
        assert agent.stats["total_processed"] == 1

    def test_enrich_vulnerability_no_cve_id(self):
        """Test handling vulnerability without CVE ID."""
        agent = CISAKEVAgent()

        agent.kev_cache = {"CVE-2024-0001": {"product": "Test"}}
        agent.kev_cache_time = datetime.utcnow()

        vulnerability = {"title": "No CVE ID"}

        enriched = agent.enrich_vulnerability(vulnerability)

        # Should return unchanged
        assert enriched == vulnerability
        assert agent.stats["total_processed"] == 0

    def test_enrich_vulnerability_no_ransomware(self):
        """Test enrichment without ransomware tag."""
        agent = CISAKEVAgent()

        agent.kev_cache = {
            "CVE-2024-0001": {
                "vendorProject": "Corp",
                "product": "App",
                "vulnerabilityName": "RCE",
                "dateAdded": "2024-10-20",
                "shortDescription": "RCE",
                "requiredAction": "Patch",
                "dueDate": "2024-11-05",
                "knownRansomwareCampaignUse": "Unknown",  # Not ransomware
            }
        }
        agent.kev_cache_time = datetime.utcnow()

        vulnerability = {"cveId": "CVE-2024-0001"}

        enriched = agent.enrich_vulnerability(vulnerability)

        # Should not add RANSOMWARE tag
        tags = enriched.get("metadata", {}).get("tags", [])
        assert "CISA-KEV" in tags
        assert "RANSOMWARE" not in tags

    def test_enrich_vulnerability_kev_ref_already_exists(self):
        """Test that duplicate KEV references aren't added."""
        agent = CISAKEVAgent()

        agent.kev_cache = {
            "CVE-2024-0001": {
                "vendorProject": "Corp",
                "product": "App",
                "vulnerabilityName": "Test",
                "dateAdded": "2024-10-20",
                "shortDescription": "Test",
                "requiredAction": "Patch",
                "dueDate": "2024-11-05",
                "knownRansomwareCampaignUse": "Unknown",
            }
        }
        agent.kev_cache_time = datetime.utcnow()

        vulnerability = {
            "cveId": "CVE-2024-0001",
            "references": [
                {
                    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "source": "CISA KEV",
                }
            ],
        }

        enriched = agent.enrich_vulnerability(vulnerability)

        # Should not duplicate KEV reference
        kev_refs = [
            r
            for r in enriched["references"]
            if "cisa.gov/known-exploited-vulnerabilities" in r.get("url", "")
        ]
        assert len(kev_refs) == 1


class TestCISAKEVAgentBatchProcessing:
    """Test suite for batch vulnerability enrichment."""

    def test_enrich_batch_success(self):
        """Test successful batch enrichment."""
        agent = CISAKEVAgent()

        agent.kev_cache = {
            "CVE-2024-0001": {
                "vendorProject": "Corp1",
                "product": "App1",
                "vulnerabilityName": "Vuln1",
                "dateAdded": "2024-10-20",
                "shortDescription": "Test1",
                "requiredAction": "Patch1",
                "dueDate": "2024-11-05",
                "knownRansomwareCampaignUse": "Known",
            },
            "CVE-2024-0002": {
                "vendorProject": "Corp2",
                "product": "App2",
                "vulnerabilityName": "Vuln2",
                "dateAdded": "2024-10-21",
                "shortDescription": "Test2",
                "requiredAction": "Patch2",
                "dueDate": "2024-11-06",
                "knownRansomwareCampaignUse": "Unknown",
            },
        }
        agent.kev_cache_time = datetime.utcnow()

        vulnerabilities = [
            {"cveId": "CVE-2024-0001"},
            {"cveId": "CVE-2024-0002"},
            {"cveId": "CVE-2024-9999"},  # Not in KEV
        ]

        enriched = agent.enrich_batch(vulnerabilities)

        assert len(enriched) == 3
        assert agent.stats["total_processed"] == 3
        assert agent.stats["kev_enriched"] == 2

        # First two should be enriched
        assert enriched[0].get("exploitationStatus") == "KNOWN_EXPLOITED"
        assert enriched[1].get("exploitationStatus") == "KNOWN_EXPLOITED"
        # Third should not
        assert enriched[2].get("exploitationStatus") != "KNOWN_EXPLOITED"

    def test_enrich_batch_empty_list(self):
        """Test batch enrichment with empty list."""
        agent = CISAKEVAgent()

        agent.kev_cache = {}
        agent.kev_cache_time = datetime.utcnow()

        enriched = agent.enrich_batch([])

        assert len(enriched) == 0
        assert agent.stats["total_processed"] == 0
        assert agent.stats["kev_enriched"] == 0


class TestCISAKEVAgentStatistics:
    """Test suite for KEV statistics."""

    def test_get_kev_statistics_with_data(self):
        """Test statistics generation with catalog data."""
        agent = CISAKEVAgent()

        agent.kev_cache = {
            "CVE-2024-0001": {
                "dateAdded": "2024-10-20",
                "knownRansomwareCampaignUse": "Known",
            },
            "CVE-2024-0002": {
                "dateAdded": "2024-10-21",
                "knownRansomwareCampaignUse": "Unknown",
            },
            "CVE-2023-0001": {
                "dateAdded": "2023-05-15",
                "knownRansomwareCampaignUse": "Known",
            },
        }
        agent.kev_cache_time = datetime.utcnow()
        agent.stats = {"total_processed": 10, "kev_enriched": 3}

        stats = agent.get_kev_statistics()

        assert stats["catalog_size"] == 3
        assert stats["last_updated"] is not None
        assert stats["enrichment_stats"]["total_processed"] == 10
        assert stats["enrichment_stats"]["kev_enriched"] == 3
        assert stats["enrichment_stats"]["enrichment_rate"] == "30.0%"

        # Check catalog insights
        assert "catalog_insights" in stats
        assert stats["catalog_insights"]["known_ransomware_count"] == 2
        assert "2024" in stats["catalog_insights"]["entries_by_year"]
        assert "2023" in stats["catalog_insights"]["entries_by_year"]

    def test_get_kev_statistics_no_data(self):
        """Test statistics with no catalog data."""
        agent = CISAKEVAgent()

        agent.kev_cache = {}
        agent.kev_cache_time = None
        agent.stats = {"total_processed": 0, "kev_enriched": 0}

        # Mock fetch_kev_catalog to return empty cache
        with patch.object(agent, "fetch_kev_catalog", return_value={}):
            stats = agent.get_kev_statistics()

            assert stats["catalog_size"] == 0
            assert stats["last_updated"] is None
            assert stats["enrichment_stats"]["enrichment_rate"] == "0%"


class TestCISAKEVAgentCacheManagement:
    """Test suite for cache management."""

    def test_is_cache_valid_fresh(self):
        """Test cache validation with fresh cache."""
        agent = CISAKEVAgent()

        agent.kev_cache = {"CVE-2024-0001": {}}
        agent.kev_cache_time = datetime.utcnow()

        assert agent._is_cache_valid() is True

    def test_is_cache_valid_expired(self):
        """Test cache validation with expired cache."""
        agent = CISAKEVAgent()

        agent.kev_cache = {"CVE-2024-0001": {}}
        agent.kev_cache_time = datetime.utcnow() - timedelta(hours=25)

        assert agent._is_cache_valid() is False

    def test_is_cache_valid_no_cache(self):
        """Test cache validation with no cache."""
        agent = CISAKEVAgent()

        assert agent._is_cache_valid() is False

    def test_get_cache_age_hours(self):
        """Test cache age calculation."""
        agent = CISAKEVAgent()

        agent.kev_cache_time = datetime.utcnow() - timedelta(hours=5)

        age = agent._get_cache_age_hours()

        assert 4.9 < age < 5.1  # Allow for small timing variations

    def test_get_cache_age_hours_no_cache(self):
        """Test cache age when no cache exists."""
        agent = CISAKEVAgent()

        age = agent._get_cache_age_hours()

        assert age == float("inf")


class TestCISAKEVAgentAsyncExecution:
    """Test suite for async execution method."""

    @pytest.mark.asyncio
    async def test_execute_async(self):
        """Test async execute method."""
        agent = CISAKEVAgent()

        agent.kev_cache = {
            "CVE-2024-0001": {
                "vendorProject": "Corp",
                "product": "App",
                "vulnerabilityName": "Test",
                "dateAdded": "2024-10-20",
                "shortDescription": "Test",
                "requiredAction": "Patch",
                "dueDate": "2024-11-05",
                "knownRansomwareCampaignUse": "Known",
            }
        }
        agent.kev_cache_time = datetime.utcnow()

        vulnerabilities = [{"cveId": "CVE-2024-0001"}]

        result = await agent.execute(vulnerabilities=vulnerabilities)

        assert "vulnerabilities" in result
        assert "statistics" in result
        assert len(result["vulnerabilities"]) == 1
        assert result["vulnerabilities"][0]["exploitationStatus"] == "KNOWN_EXPLOITED"
