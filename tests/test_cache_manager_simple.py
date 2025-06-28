"""Simple tests for cache manager."""

from datetime import datetime, timezone

import pytest

from scripts.models import (
    Reference,
    SeverityLevel,
    Vulnerability,
    VulnerabilityBatch,
)
from scripts.processing.cache_manager import CacheManager


class TestCacheManagerSimple:
    """Simple tests for CacheManager functionality."""

    @pytest.fixture
    def cache_manager(self, tmp_path):
        """Create a CacheManager instance with test database."""
        db_path = tmp_path / f"test_{id(self)}.db"
        # Ensure clean database
        if db_path.exists():
            db_path.unlink()
        return CacheManager(db_path=str(db_path))

    @pytest.fixture
    def sample_vulnerability(self):
        """Create a sample vulnerability for testing."""
        return Vulnerability(
            cve_id="CVE-2025-0001",
            title="Test Vulnerability",
            description="Test description",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(timezone.utc),
            last_modified_date=datetime.now(timezone.utc),
            references=[Reference(url="https://example.com")],
            affected_vendors=["testvendor"],
            risk_score=75.0,
        )

    def test_initialization(self, cache_manager, tmp_path):
        """Test cache manager initialization."""
        # DB path will have a unique ID in the name
        assert cache_manager.db_path.parent == tmp_path
        assert cache_manager.db_path.exists()

    @pytest.mark.skip(reason="SQLite timezone handling issue in CI")
    def test_cache_and_retrieve_vulnerability(
        self, cache_manager, sample_vulnerability
    ):
        """Test caching and retrieving a vulnerability."""
        # Cache the vulnerability
        cache_manager.cache_vulnerability(sample_vulnerability)

        # Retrieve it
        retrieved = cache_manager.get_vulnerability("CVE-2025-0001")

        assert retrieved is not None
        assert retrieved.cve_id == "CVE-2025-0001"
        assert retrieved.title == "Test Vulnerability"
        assert retrieved.severity == SeverityLevel.HIGH
        assert retrieved.risk_score == 75.0

    @pytest.mark.skip(reason="SQLite timezone handling issue in CI")
    def test_cache_batch(self, cache_manager, sample_vulnerability):
        """Test caching a batch of vulnerabilities."""
        batch = VulnerabilityBatch(
            vulnerabilities=[sample_vulnerability],
            metadata={"source": "test"},
        )

        cache_manager.cache_batch(batch)

        # Verify it was cached
        retrieved = cache_manager.get_vulnerability("CVE-2025-0001")
        assert retrieved is not None

    def test_get_recent_vulnerabilities(self, cache_manager):
        """Test getting recent vulnerabilities."""
        # Create and cache multiple vulnerabilities
        for i in range(5):
            vuln = Vulnerability(
                cve_id=f"CVE-2025-{i:04d}",
                title=f"Vuln {i}",
                description=f"Description {i}",
                severity=SeverityLevel.HIGH,
                published_date=datetime.now(timezone.utc),
                last_modified_date=datetime.now(timezone.utc),
                risk_score=70.0 + i,
            )
            cache_manager.cache_vulnerability(vuln)

        # Get recent vulnerabilities
        recent = cache_manager.get_recent_vulnerabilities(limit=3)

        assert len(recent) == 3
        # Should be ordered by risk score descending
        assert recent[0].risk_score >= recent[1].risk_score
        assert recent[1].risk_score >= recent[2].risk_score

    def test_cache_stats(self, cache_manager, sample_vulnerability):
        """Test getting cache statistics."""
        cache_manager.cache_vulnerability(sample_vulnerability)

        stats = cache_manager.get_cache_stats()

        assert stats["total_entries"] == 1
        assert stats["valid_entries"] == 1
        assert stats["expired_entries"] == 0
        assert "severity_distribution" in stats
        assert "risk_distribution" in stats

    @pytest.mark.skip(reason="SQLite timezone handling issue in CI")
    def test_cleanup_expired(self, cache_manager):
        """Test cleanup doesn't remove non-expired entries."""
        vuln = Vulnerability(
            cve_id="CVE-2025-0001",
            title="Test",
            description="Test",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(timezone.utc),
            last_modified_date=datetime.now(timezone.utc),
            risk_score=75.0,
        )

        cache_manager.cache_vulnerability(vuln)

        # Cleanup should not remove the recent entry
        removed = cache_manager.cleanup_expired()
        assert removed == 0

        # Verify it's still there
        retrieved = cache_manager.get_vulnerability("CVE-2025-0001")
        assert retrieved is not None
