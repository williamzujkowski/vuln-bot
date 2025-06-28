"""Tests for the harvest orchestrator."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from scripts.harvest.orchestrator import HarvestOrchestrator
from scripts.models import (
    EPSSScore,
    SeverityLevel,
    Vulnerability,
    VulnerabilityBatch,
    VulnerabilitySource,
)


@pytest.fixture
def mock_dependencies():
    """Create mock dependencies for orchestrator."""
    with patch("scripts.harvest.orchestrator.CVEListClient") as mock_cvelist, patch(
        "scripts.harvest.orchestrator.EPSSClient"
    ) as mock_epss, patch(
        "scripts.harvest.orchestrator.VulnerabilityNormalizer"
    ) as mock_normalizer, patch(
        "scripts.harvest.orchestrator.RiskScorer"
    ) as mock_scorer, patch("scripts.harvest.orchestrator.CacheManager") as mock_cache:
        # Configure mocks
        mock_cvelist_instance = MagicMock()
        mock_epss_instance = MagicMock()
        mock_normalizer_instance = MagicMock()
        mock_scorer_instance = MagicMock()
        mock_cache_instance = MagicMock()

        mock_cvelist.return_value = mock_cvelist_instance
        mock_epss.return_value = mock_epss_instance
        mock_normalizer.return_value = mock_normalizer_instance
        mock_scorer.return_value = mock_scorer_instance
        mock_cache.return_value = mock_cache_instance

        yield {
            "cvelist": mock_cvelist_instance,
            "epss": mock_epss_instance,
            "normalizer": mock_normalizer_instance,
            "scorer": mock_scorer_instance,
            "cache": mock_cache_instance,
        }


@pytest.fixture
def orchestrator(tmp_path, mock_dependencies):  # noqa: ARG001
    """Create orchestrator with mocked dependencies."""
    return HarvestOrchestrator(cache_dir=tmp_path)


@pytest.fixture
def sample_vulnerabilities():
    """Create sample vulnerabilities for testing."""
    return [
        Vulnerability(
            cve_id="CVE-2025-1001",
            title="Test vulnerability 1",
            description="Test description 1",
            published_date=datetime.now(timezone.utc),
            last_modified_date=datetime.now(timezone.utc),
            severity=SeverityLevel.HIGH,
            cvss_metrics=[],
            affected_vendors=["vendor1"],
            affected_products=["product1"],
            references=[],
            sources=[
                VulnerabilitySource(
                    name="CVEList",
                    url="https://example.com",
                    last_modified=datetime.now(timezone.utc),
                )
            ],
        ),
        Vulnerability(
            cve_id="CVE-2025-1002",
            title="Test vulnerability 2",
            description="Test description 2",
            published_date=datetime.now(timezone.utc),
            last_modified_date=datetime.now(timezone.utc),
            severity=SeverityLevel.CRITICAL,
            cvss_metrics=[],
            affected_vendors=["vendor2"],
            affected_products=["product2"],
            references=[],
            sources=[
                VulnerabilitySource(
                    name="CVEList",
                    url="https://example.com",
                    last_modified=datetime.now(timezone.utc),
                )
            ],
        ),
    ]


class TestHarvestOrchestrator:
    """Tests for HarvestOrchestrator."""

    def test_init(self, tmp_path):
        """Test orchestrator initialization."""
        orchestrator = HarvestOrchestrator(cache_dir=tmp_path)
        assert orchestrator.cache_dir == tmp_path
        assert orchestrator.cvelist_client is not None
        assert orchestrator.epss_client is not None
        assert orchestrator.normalizer is not None
        assert orchestrator.risk_scorer is not None
        assert orchestrator.cache_manager is not None

    def test_harvest_cve_data(
        self, orchestrator, mock_dependencies, sample_vulnerabilities
    ):
        """Test harvesting CVE data."""
        # Configure mock
        mock_dependencies["cvelist"].harvest.return_value = sample_vulnerabilities

        # Test harvest
        result = orchestrator.harvest_cve_data(
            years=[2025], min_severity=SeverityLevel.HIGH
        )

        assert len(result) == 2
        assert all(isinstance(v, Vulnerability) for v in result)
        mock_dependencies["cvelist"].harvest.assert_called_once_with(
            years=[2025], min_severity=SeverityLevel.HIGH
        )

    def test_harvest_cve_data_error(self, orchestrator, mock_dependencies):
        """Test CVE harvest error handling."""
        # Configure mock to raise error
        mock_dependencies["cvelist"].harvest.side_effect = Exception("API error")

        # Test harvest - should return empty list on error
        result = orchestrator.harvest_cve_data(
            years=[2025], min_severity=SeverityLevel.HIGH
        )

        assert result == []

    def test_enrich_with_epss(
        self, orchestrator, mock_dependencies, sample_vulnerabilities
    ):
        """Test EPSS enrichment."""
        # Configure mock
        mock_dependencies["epss"].get_scores_for_cves.return_value = {
            "CVE-2025-1001": EPSSScore(
                cve_id="CVE-2025-1001",
                score=0.75,
                percentile=0.95,
                date=datetime.now(timezone.utc).date(),
            ),
            "CVE-2025-1002": EPSSScore(
                cve_id="CVE-2025-1002",
                score=0.85,
                percentile=0.98,
                date=datetime.now(timezone.utc).date(),
            ),
        }

        # Test enrichment
        orchestrator.enrich_with_epss(sample_vulnerabilities)

        assert sample_vulnerabilities[0].epss_score.score == 0.75
        assert sample_vulnerabilities[1].epss_score.score == 0.85
        mock_dependencies["epss"].get_scores_for_cves.assert_called_once_with(
            ["CVE-2025-1001", "CVE-2025-1002"]
        )

    def test_enrich_with_epss_batch(self, orchestrator, mock_dependencies):
        """Test EPSS enrichment with batching."""
        # Create many vulnerabilities
        vulns = []
        for i in range(150):  # More than batch size of 100
            vulns.append(
                Vulnerability(
                    cve_id=f"CVE-2025-{i:04d}",
                    title=f"Test vulnerability {i}",
                    description="Test",
                    published_date=datetime.now(timezone.utc),
                    last_modified_date=datetime.now(timezone.utc),
                    severity=SeverityLevel.HIGH,
                    cvss_metrics=[],
                    affected_vendors=[],
                    affected_products=[],
                    references=[],
                    sources=[],
                )
            )

        # Configure mock to return empty scores
        mock_dependencies["epss"].get_scores_for_cves.return_value = {}

        # Test enrichment
        orchestrator.enrich_with_epss(vulns)

        # Should be called twice (100 + 50)
        assert mock_dependencies["epss"].get_scores_for_cves.call_count == 2

    def test_harvest_all(self, orchestrator, mock_dependencies, sample_vulnerabilities):
        """Test full harvest pipeline."""
        # Configure mocks
        mock_dependencies["cvelist"].harvest.return_value = sample_vulnerabilities
        mock_dependencies[
            "normalizer"
        ].deduplicate_vulnerabilities.return_value = sample_vulnerabilities
        mock_dependencies["epss"].get_scores_for_cves.return_value = {
            "CVE-2025-1001": EPSSScore(
                cve_id="CVE-2025-1001",
                score=0.75,
                percentile=0.95,
                date=datetime.now(timezone.utc).date(),
            ),
            "CVE-2025-1002": EPSSScore(
                cve_id="CVE-2025-1002",
                score=0.85,
                percentile=0.98,
                date=datetime.now(timezone.utc).date(),
            ),
        }

        # Test harvest
        batch = orchestrator.harvest_all(
            sources=["cvelist"],
            years=[2025],
            min_severity=SeverityLevel.HIGH,
            min_epss_score=0.7,
        )

        assert isinstance(batch, VulnerabilityBatch)
        assert len(batch.vulnerabilities) == 2  # Both pass EPSS threshold
        assert batch.metadata["harvest_id"] is not None
        assert batch.metadata["total_vulnerabilities"] == 2
        assert batch.metadata["unique_vulnerabilities"] == 2

        # Verify methods called
        mock_dependencies["cvelist"].harvest.assert_called_once()
        mock_dependencies["normalizer"].deduplicate_vulnerabilities.assert_called_once()
        mock_dependencies["epss"].get_scores_for_cves.assert_called_once()
        mock_dependencies["scorer"].score_batch.assert_called_once()
        mock_dependencies["cache"].save_batch.assert_called_once()

    def test_harvest_all_with_epss_filter(
        self, orchestrator, mock_dependencies, sample_vulnerabilities
    ):
        """Test harvest with EPSS filtering."""
        # Configure mocks with different EPSS scores
        mock_dependencies["cvelist"].harvest.return_value = sample_vulnerabilities
        mock_dependencies[
            "normalizer"
        ].deduplicate_vulnerabilities.return_value = sample_vulnerabilities
        mock_dependencies["epss"].get_scores_for_cves.return_value = {
            "CVE-2025-1001": EPSSScore(
                cve_id="CVE-2025-1001",
                score=0.3,  # Below threshold
                percentile=0.70,
                date=datetime.now(timezone.utc).date(),
            ),
            "CVE-2025-1002": EPSSScore(
                cve_id="CVE-2025-1002",
                score=0.85,  # Above threshold
                percentile=0.98,
                date=datetime.now(timezone.utc).date(),
            ),
        }

        # Test harvest with EPSS threshold
        batch = orchestrator.harvest_all(
            sources=["cvelist"],
            years=[2025],
            min_severity=SeverityLevel.HIGH,
            min_epss_score=0.6,
        )

        # Only one vulnerability should pass the filter
        assert len(batch.vulnerabilities) == 1
        assert batch.vulnerabilities[0].cve_id == "CVE-2025-1002"

    def test_harvest_all_empty_sources(self, orchestrator, mock_dependencies):
        """Test harvest with no sources specified."""
        # Configure all sources to return empty
        mock_dependencies["cvelist"].harvest.return_value = []

        batch = orchestrator.harvest_all(
            sources=["all"],
            years=[2025],
        )

        assert isinstance(batch, VulnerabilityBatch)
        assert len(batch.vulnerabilities) == 0
        assert batch.metadata["total_vulnerabilities"] == 0

    def test_harvest_all_source_error(self, orchestrator, mock_dependencies):
        """Test harvest with source errors."""
        # Configure mock to raise error
        mock_dependencies["cvelist"].harvest.side_effect = Exception("API down")

        batch = orchestrator.harvest_all(
            sources=["cvelist"],
            years=[2025],
        )

        # Should handle error gracefully
        assert isinstance(batch, VulnerabilityBatch)
        assert len(batch.vulnerabilities) == 0
        assert batch.metadata["sources"][0]["status"] == "failed"
        assert "API down" in batch.metadata["sources"][0]["error"]

    def test_get_recent_vulnerabilities(self, orchestrator, mock_dependencies):
        """Test getting recent vulnerabilities from cache."""
        # Configure mock
        mock_batch = VulnerabilityBatch(
            vulnerabilities=[],
            metadata={"harvest_id": "test"},
            harvest_date=datetime.now(timezone.utc),
        )
        mock_dependencies["cache"].get_recent_batch.return_value = mock_batch

        # Test
        result = orchestrator.get_recent_vulnerabilities(days=7)

        assert result == mock_batch
        mock_dependencies["cache"].get_recent_batch.assert_called_once_with(days=7)

    def test_search_vulnerabilities(
        self, orchestrator, mock_dependencies, sample_vulnerabilities
    ):
        """Test searching vulnerabilities."""
        # Configure mock
        mock_dependencies[
            "cache"
        ].search_vulnerabilities.return_value = sample_vulnerabilities

        # Test
        result = orchestrator.search_vulnerabilities(
            query="test",
            severity=SeverityLevel.HIGH,
            min_score=7.0,
        )

        assert result == sample_vulnerabilities
        mock_dependencies["cache"].search_vulnerabilities.assert_called_once_with(
            query="test",
            severity=SeverityLevel.HIGH,
            min_score=7.0,
        )
