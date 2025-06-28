"""Tests for cache manager."""

import json
from datetime import datetime, timedelta

import pytest
from sqlalchemy.orm import sessionmaker

from scripts.models import (
    CVSSMetric,
    EPSSScore,
    ExploitationStatus,
    SeverityLevel,
    Vulnerability,
    VulnerabilityBatch,
)
from scripts.processing.cache_manager import (
    CacheManager,
    HarvestMetadata,
    VulnerabilityCache,
)


class TestCacheManager:
    """Test CacheManager functionality."""

    @pytest.fixture
    def cache_manager(self, tmp_path):
        """Create a CacheManager instance with test database."""
        db_path = tmp_path / "test.db"
        return CacheManager(db_path=str(db_path))

    @pytest.fixture
    def sample_vulnerability(self):
        """Create a sample vulnerability for testing."""
        return Vulnerability(
            cve_id="CVE-2023-0001",
            title="Test Vulnerability",
            description="Test description",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(datetime.UTC) - timedelta(days=5),
            last_modified_date=datetime.now(datetime.UTC),
            references=["https://example.com"],
            affected_vendors=["testvendor"],
            exploitation_status=ExploitationStatus.POC,
            tags=["test", "sample"],
            risk_score=75.0,
        )

    def test_initialization(self, tmp_path):
        """Test cache manager initialization."""
        db_path = tmp_path / "test.db"
        manager = CacheManager(db_path=str(db_path))

        assert manager.db_path == str(db_path)
        assert db_path.exists()

        # Check tables are created
        with manager.engine.connect() as conn:
            result = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in result]
            assert "cached_vulnerabilities" in tables
            assert "harvest_metadata" in tables

    def test_save_vulnerabilities(self, cache_manager, sample_vulnerability):
        """Test saving vulnerabilities to cache."""
        batch = VulnerabilityBatch(
            vulnerabilities=[sample_vulnerability],
            metadata={"source": "test"},
        )

        cache_manager.save_vulnerabilities(batch)

        # Verify data was saved
        Session = sessionmaker(bind=cache_manager.engine)
        with Session() as session:
            cached = (
                session.query(VulnerabilityCache)
                .filter_by(cve_id="CVE-2023-0001")
                .first()
            )

            assert cached is not None
            assert cached.severity == "HIGH"
            assert cached.risk_score == 75.0
            assert json.loads(cached.affected_vendors) == ["testvendor"]
            assert json.loads(cached.tags) == ["test", "sample"]

    def test_save_vulnerabilities_update_existing(
        self, cache_manager, sample_vulnerability
    ):
        """Test updating existing vulnerabilities."""
        # Save initial version
        batch1 = VulnerabilityBatch(
            vulnerabilities=[sample_vulnerability],
            metadata={"source": "test"},
        )
        cache_manager.save_vulnerabilities(batch1)

        # Update vulnerability
        sample_vulnerability.risk_score = 85.0
        sample_vulnerability.description = "Updated description"
        batch2 = VulnerabilityBatch(
            vulnerabilities=[sample_vulnerability],
            metadata={"source": "test"},
        )
        cache_manager.save_vulnerabilities(batch2)

        # Verify update
        Session = sessionmaker(bind=cache_manager.engine)
        with Session() as session:
            cached = (
                session.query(VulnerabilityCache)
                .filter_by(cve_id="CVE-2023-0001")
                .first()
            )

            assert cached.risk_score == 85.0
            assert cached.description == "Updated description"

    def test_save_vulnerabilities_with_harvest_metadata(
        self, cache_manager, sample_vulnerability
    ):
        """Test saving harvest metadata."""
        batch = VulnerabilityBatch(
            vulnerabilities=[sample_vulnerability],
            metadata={
                "sources": ["NVD", "EPSS"],
                "duration_seconds": 120,
            },
        )

        cache_manager.save_vulnerabilities(batch)

        # Verify harvest metadata
        Session = sessionmaker(bind=cache_manager.engine)
        with Session() as session:
            metadata = session.query(HarvestMetadata).first()

            assert metadata is not None
            assert metadata.vulnerability_count == 1
            assert json.loads(metadata.sources) == ["NVD", "EPSS"]
            extra_meta = json.loads(metadata.extra_metadata)
            assert extra_meta["duration_seconds"] == 120

    def test_get_vulnerabilities_by_date_range(self, cache_manager):
        """Test retrieving vulnerabilities by date range."""
        # Create vulnerabilities with different dates
        vulns = []
        for i in range(5):
            vuln = Vulnerability(
                cve_id=f"CVE-2023-{i:04d}",
                title=f"Vuln {i}",
                description=f"Description {i}",
                severity=SeverityLevel.HIGH,
                published_date=datetime.now(datetime.UTC) - timedelta(days=10 - i),
                last_modified_date=datetime.now(datetime.UTC),
                risk_score=70.0 + i,
            )
            vulns.append(vuln)

        batch = VulnerabilityBatch(vulnerabilities=vulns)
        cache_manager.save_vulnerabilities(batch)

        # Get vulnerabilities from last 7 days
        start_date = datetime.now(datetime.UTC) - timedelta(days=7)
        result = cache_manager.get_vulnerabilities_by_date_range(
            start_date=start_date, end_date=datetime.now(datetime.UTC)
        )

        # Should get 3 vulnerabilities (days 5, 6, 7)
        assert len(result) == 3
        assert all(
            v.cve_id in ["CVE-2023-0002", "CVE-2023-0003", "CVE-2023-0004"]
            for v in result
        )

    def test_get_vulnerabilities_with_limit(self, cache_manager):
        """Test retrieving vulnerabilities with limit."""
        # Create 10 vulnerabilities
        vulns = []
        for i in range(10):
            vuln = Vulnerability(
                cve_id=f"CVE-2023-{i:04d}",
                title=f"Vuln {i}",
                description=f"Description {i}",
                severity=SeverityLevel.HIGH,
                published_date=datetime.now(datetime.UTC) - timedelta(days=1),
                last_modified_date=datetime.now(datetime.UTC),
                risk_score=70.0 + i,
            )
            vulns.append(vuln)

        batch = VulnerabilityBatch(vulnerabilities=vulns)
        cache_manager.save_vulnerabilities(batch)

        # Get only 5 vulnerabilities
        result = cache_manager.get_vulnerabilities_by_date_range(
            start_date=datetime.now(datetime.UTC) - timedelta(days=7),
            end_date=datetime.now(datetime.UTC),
            limit=5,
        )

        assert len(result) == 5
        # Should be ordered by risk score descending
        assert result[0].risk_score == 79.0  # Highest score

    def test_get_recent_vulnerabilities(self, cache_manager):
        """Test getting recent vulnerabilities."""
        # Create vulnerabilities
        vulns = []
        for i in range(3):
            vuln = Vulnerability(
                cve_id=f"CVE-2023-{i:04d}",
                title=f"Vuln {i}",
                description=f"Description {i}",
                severity=SeverityLevel.HIGH,
                published_date=datetime.now(datetime.UTC) - timedelta(days=i),
                last_modified_date=datetime.now(datetime.UTC),
                risk_score=70.0 + i,
            )
            vulns.append(vuln)

        batch = VulnerabilityBatch(vulnerabilities=vulns)
        cache_manager.save_vulnerabilities(batch)

        # Get recent vulnerabilities
        result = cache_manager.get_recent_vulnerabilities(days_back=2)

        # Should get 2 vulnerabilities (0 and 1 days old)
        assert len(result) == 2
        assert all(v.cve_id in ["CVE-2023-0000", "CVE-2023-0001"] for v in result)

    def test_clear_cache(self, cache_manager, sample_vulnerability):
        """Test clearing the cache."""
        # Add data
        batch = VulnerabilityBatch(vulnerabilities=[sample_vulnerability])
        cache_manager.save_vulnerabilities(batch)

        # Verify data exists
        result = cache_manager.get_recent_vulnerabilities(days_back=7)
        assert len(result) == 1

        # Clear cache
        cache_manager.clear_cache()

        # Verify cache is empty
        result = cache_manager.get_recent_vulnerabilities(days_back=7)
        assert len(result) == 0

        # Verify metadata is also cleared
        Session = sessionmaker(bind=cache_manager.engine)
        with Session() as session:
            metadata_count = session.query(HarvestMetadata).count()
            assert metadata_count == 0

    def test_get_harvest_metadata(self, cache_manager, sample_vulnerability):
        """Test retrieving harvest metadata."""
        # Create multiple harvests
        for i in range(3):
            batch = VulnerabilityBatch(
                vulnerabilities=[sample_vulnerability],
                metadata={
                    "sources": [f"Source{i}"],
                    "harvest_number": i,
                },
            )
            cache_manager.save_vulnerabilities(batch)

        # Get metadata
        metadata = cache_manager.get_harvest_metadata(limit=2)

        assert len(metadata) == 2
        # Should be ordered by date descending
        assert metadata[0]["vulnerability_count"] == 1
        assert "harvest_date" in metadata[0]
        assert "sources" in metadata[0]
        assert "metadata" in metadata[0]

    def test_vulnerability_serialization(self, cache_manager):
        """Test vulnerability serialization with complex data."""
        vuln = Vulnerability(
            cve_id="CVE-2023-9999",
            title="Complex Vulnerability",
            description="Test with special chars: 'quotes' and \"double quotes\"",
            severity=SeverityLevel.CRITICAL,
            published_date=datetime.now(datetime.UTC),
            last_modified_date=datetime.now(datetime.UTC),
            references=["https://example.com", "https://test.org"],
            affected_vendors=["vendor1", "vendor2", "vendor3"],
            exploitation_status=ExploitationStatus.ACTIVE,
            tags=["tag1", "tag2", "special-tag"],
            risk_score=95.5,
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    base_score=9.8,
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_severity=SeverityLevel.CRITICAL,
                )
            ],
            epss_score=EPSSScore(
                cve_id="CVE-2023-9999",
                score=0.9543,
                percentile=98.76,
                date=datetime.now(datetime.UTC),
            ),
        )

        batch = VulnerabilityBatch(vulnerabilities=[vuln])
        cache_manager.save_vulnerabilities(batch)

        # Retrieve and verify
        result = cache_manager.get_recent_vulnerabilities(days_back=1)
        assert len(result) == 1

        retrieved = result[0]
        assert retrieved.cve_id == "CVE-2023-9999"
        assert retrieved.affected_vendors == ["vendor1", "vendor2", "vendor3"]
        assert retrieved.tags == ["tag1", "tag2", "special-tag"]
        assert len(retrieved.cvss_metrics) == 1
        assert retrieved.cvss_metrics[0].base_score == 9.8
        assert retrieved.epss_score.score == 0.9543

    def test_database_error_handling(self, tmp_path):
        """Test handling database errors."""
        # Create manager with invalid path
        invalid_path = tmp_path / "nonexistent" / "test.db"

        # Should handle initialization error gracefully
        with pytest.raises(OSError):
            CacheManager(db_path=str(invalid_path))

    def test_concurrent_access(self, cache_manager, sample_vulnerability):
        """Test concurrent database access."""
        # SQLite handles concurrent access with file locking
        # This test verifies no corruption occurs

        batch = VulnerabilityBatch(vulnerabilities=[sample_vulnerability])

        # Multiple saves should work
        for _ in range(5):
            cache_manager.save_vulnerabilities(batch)

        # Should still have only one vulnerability
        result = cache_manager.get_recent_vulnerabilities(days_back=7)
        assert len(result) == 1

        # Verify harvest metadata count
        Session = sessionmaker(bind=cache_manager.engine)
        with Session() as session:
            metadata_count = session.query(HarvestMetadata).count()
            assert metadata_count == 5  # One per save
