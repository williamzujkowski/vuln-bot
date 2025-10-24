"""Comprehensive tests for cache manager SQLite operations."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.models import CVSSMetric, EPSSScore, SeverityLevel, Vulnerability
from scripts.processing.cache_manager import CacheManager

# Test constant for EPSS date
TEST_EPSS_DATE = datetime(2025, 1, 1, tzinfo=timezone.utc)


class TestCacheManagerInitialization:
    """Test suite for cache manager initialization."""

    def test_init_with_cache_dir(self, tmp_path):
        """Test initialization with cache_dir parameter."""
        cache_dir = tmp_path / "cache"
        manager = CacheManager(cache_dir=cache_dir)

        assert manager.cache_dir == cache_dir
        assert manager.db_path == cache_dir / "vulnerability_cache.db"
        assert manager.ttl_days == 10
        assert cache_dir.exists()

    def test_init_with_db_path(self, tmp_path):
        """Test initialization with direct db_path parameter."""
        db_path = tmp_path / "custom_cache.db"
        manager = CacheManager(db_path=str(db_path))

        assert manager.db_path == db_path
        assert manager.cache_dir == db_path.parent

    def test_init_with_custom_ttl(self, tmp_path):
        """Test initialization with custom TTL."""
        manager = CacheManager(cache_dir=tmp_path, ttl_days=5)

        assert manager.ttl_days == 5

    def test_init_without_params_raises_error(self):
        """Test initialization fails without cache_dir or db_path."""
        with pytest.raises(ValueError, match="Either cache_dir or db_path must be provided"):
            CacheManager()


class TestCacheManagerStorageRetrieval:
    """Test suite for cache storage and retrieval operations."""

    def test_store_and_retrieve_vulnerability(self, tmp_path, sample_cve_compliant):
        """Test storing and retrieving a single vulnerability."""
        manager = CacheManager(cache_dir=tmp_path)

        # Create vulnerability from sample
        vuln = Vulnerability(
            cve_id=sample_cve_compliant["cveId"],
            title=sample_cve_compliant["title"],
            description=sample_cve_compliant["description"],
            severity=SeverityLevel.CRITICAL,
            cvss_metrics=[CVSSMetric(
                version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=sample_cve_compliant["cvss"],
                base_severity=SeverityLevel.CRITICAL,
            )],
            published_date=datetime.fromisoformat(sample_cve_compliant["published"].replace("Z", "+00:00")),
            last_modified_date=datetime.fromisoformat(sample_cve_compliant["last_modified"].replace("Z", "+00:00")),
            epss_score=EPSSScore(
                score=sample_cve_compliant["epss_score"],
                percentile=sample_cve_compliant.get("epssPercentile", 0.0),
                date=TEST_EPSS_DATE,
            ),
            references=sample_cve_compliant["references"],
        )

        # Store vulnerability
        vuln.risk_score = 85
        manager.cache_vulnerability(vuln)

        # Retrieve vulnerability
        retrieved = manager.get_vulnerability(vuln.cve_id)

        assert retrieved is not None
        assert retrieved.cve_id == vuln.cve_id
        assert retrieved.title == vuln.title
        assert retrieved.severity == vuln.severity
        assert retrieved.cvss_base_score == sample_cve_compliant["cvss"]

    def test_retrieve_nonexistent_vulnerability(self, tmp_path):
        """Test retrieving a vulnerability that doesn't exist."""
        manager = CacheManager(cache_dir=tmp_path)

        result = manager.get_vulnerability("CVE-9999-0001")

        assert result is None

    def test_update_existing_vulnerability(self, tmp_path, sample_cve_compliant):
        """Test updating an existing vulnerability in cache."""
        manager = CacheManager(cache_dir=tmp_path)

        # Create and store initial vulnerability
        vuln = Vulnerability(
            cve_id=sample_cve_compliant["cveId"],
            title="Original Title",
            description=sample_cve_compliant["description"],
            severity=SeverityLevel.HIGH,
            cvss_metrics=[CVSSMetric(
                version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=7.5,
                base_severity=SeverityLevel.HIGH,
            )],
            published_date=datetime.fromisoformat(sample_cve_compliant["published"].replace("Z", "+00:00")),
            last_modified_date=datetime.fromisoformat(sample_cve_compliant["last_modified"].replace("Z", "+00:00")),
            epss_score=EPSSScore(score=0.75, percentile=80.0, date=TEST_EPSS_DATE),
        )
        vuln.risk_score = 70
        manager.cache_vulnerability(vuln)

        # Update with new data
        updated_vuln = Vulnerability(
            cve_id=sample_cve_compliant["cveId"],
            title="Updated Title",
            description="Updated description",
            severity=SeverityLevel.CRITICAL,
            cvss_metrics=[CVSSMetric(
                version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=9.8,
                base_severity=SeverityLevel.CRITICAL,
            )],
            published_date=datetime.fromisoformat(sample_cve_compliant["published"].replace("Z", "+00:00")),
            last_modified_date=datetime.now(timezone.utc),
            epss_score=EPSSScore(score=0.85, percentile=95.0, date=TEST_EPSS_DATE),
        )
        updated_vuln.risk_score = 95
        manager.cache_vulnerability(updated_vuln)

        # Retrieve and verify update
        retrieved = manager.get_vulnerability(vuln.cve_id)

        assert retrieved.title == "Updated Title"
        assert retrieved.severity == SeverityLevel.CRITICAL
        assert retrieved.cvss_base_score == 9.8


class TestCacheManagerTTLHandling:
    """Test suite for TTL (Time-To-Live) handling."""

    @patch("scripts.processing.cache_manager.get_authoritative_now")
    def test_expired_vulnerability_not_retrieved(self, mock_now, tmp_path, sample_cve_compliant):
        """Test that expired vulnerabilities are not retrieved."""
        manager = CacheManager(cache_dir=tmp_path, ttl_days=10)

        # Set initial time
        initial_time = datetime(2025, 1, 1, tzinfo=timezone.utc)
        mock_now.return_value = initial_time

        # Create and store vulnerability
        vuln = Vulnerability(
            cve_id=sample_cve_compliant["cveId"],
            title=sample_cve_compliant["title"],
            description=sample_cve_compliant["description"],
            severity=SeverityLevel.CRITICAL,
            cvss_metrics=[CVSSMetric(
                version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=9.8,
                base_severity=SeverityLevel.CRITICAL,
            )],
            published_date=datetime.fromisoformat(sample_cve_compliant["published"].replace("Z", "+00:00")),
            last_modified_date=datetime.fromisoformat(sample_cve_compliant["last_modified"].replace("Z", "+00:00")),
            epss_score=EPSSScore(score=0.85, percentile=95.0, date=TEST_EPSS_DATE),
        )
        vuln.risk_score = 95
        manager.cache_vulnerability(vuln)

        # Move time forward past TTL (11 days)
        future_time = initial_time + timedelta(days=11)
        mock_now.return_value = future_time

        # Try to retrieve expired vulnerability
        retrieved = manager.get_vulnerability(vuln.cve_id)

        # Should not retrieve expired data
        assert retrieved is None

    def test_clean_expired_entries(self, tmp_path, sample_cve_list):
        """Test cleaning expired cache entries."""
        manager = CacheManager(cache_dir=tmp_path, ttl_days=10)

        # Store multiple vulnerabilities
        for sample_cve in sample_cve_list[:3]:
            vuln = Vulnerability(
                cve_id=sample_cve["cveId"],
                title=sample_cve["title"],
                description=sample_cve["description"],
                severity=SeverityLevel.CRITICAL,
                cvss_metrics=[CVSSMetric(
                version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=sample_cve.get("cvss", 8.0),
                base_severity=SeverityLevel.CRITICAL if sample_cve.get("cvss", 8.0) >= 9.0 else SeverityLevel.HIGH,
            )],
                published_date=datetime.fromisoformat(sample_cve["published"].replace("Z", "+00:00")),
                last_modified_date=datetime.fromisoformat(sample_cve["last_modified"].replace("Z", "+00:00")),
                epss_score=EPSSScore(
                    score=sample_cve.get("epss_score", 0.6),
                    percentile=sample_cve.get("epssPercentile", 0.0),
                    date=TEST_EPSS_DATE,
                ),
            )
            vuln.risk_score = 85
            manager.cache_vulnerability(vuln)

        # Clean expired entries
        deleted_count = manager.cleanup_expired()

        # Should delete 0 (none expired yet)
        assert deleted_count == 0


class TestCacheManagerFiltering:
    """Test suite for vulnerability filtering and retrieval."""

    def test_get_recent_vulnerabilities_with_limit(self, tmp_path, sample_cve_list):
        """Test retrieving recent vulnerabilities with limit."""
        manager = CacheManager(cache_dir=tmp_path)

        # Store multiple vulnerabilities with different risk scores
        risk_scores = [95, 85, 75, 65]
        for i, sample_cve in enumerate(sample_cve_list[:4]):
            vuln = Vulnerability(
                cve_id=sample_cve["cveId"],
                title=sample_cve["title"],
                description=sample_cve["description"],
                severity=SeverityLevel.CRITICAL if risk_scores[i] > 80 else SeverityLevel.HIGH,
                cvss_metrics=[CVSSMetric(
                version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=sample_cve.get("cvss", 8.0),
                base_severity=SeverityLevel.CRITICAL if sample_cve.get("cvss", 8.0) >= 9.0 else SeverityLevel.HIGH,
            )],
                published_date=datetime.fromisoformat(sample_cve["published"].replace("Z", "+00:00")),
                last_modified_date=datetime.fromisoformat(sample_cve["last_modified"].replace("Z", "+00:00")),
                epss_score=EPSSScore(
                    score=sample_cve.get("epss_score", 0.6),
                    percentile=sample_cve.get("epssPercentile", 0.0),
                    date=TEST_EPSS_DATE,
                ),
            )
            vuln.risk_score = risk_scores[i]
            manager.cache_vulnerability(vuln)

        # Retrieve with limit
        recent = manager.get_recent_vulnerabilities(limit=2)

        assert len(recent) == 2
        # Should be sorted by risk_score descending
        assert recent[0].cve_id == sample_cve_list[0]["cveId"]  # risk_score=95
        assert recent[1].cve_id == sample_cve_list[1]["cveId"]  # risk_score=85

    def test_get_recent_vulnerabilities_with_min_risk_score(self, tmp_path, sample_cve_list):
        """Test filtering vulnerabilities by minimum risk score."""
        manager = CacheManager(cache_dir=tmp_path)

        # Store vulnerabilities with different risk scores
        risk_scores = [95, 85, 75, 65]
        for i, sample_cve in enumerate(sample_cve_list[:4]):
            vuln = Vulnerability(
                cve_id=sample_cve["cveId"],
                title=sample_cve["title"],
                description=sample_cve["description"],
                severity=SeverityLevel.CRITICAL if risk_scores[i] > 80 else SeverityLevel.HIGH,
                cvss_metrics=[CVSSMetric(
                version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=sample_cve.get("cvss", 8.0),
                base_severity=SeverityLevel.CRITICAL if sample_cve.get("cvss", 8.0) >= 9.0 else SeverityLevel.HIGH,
            )],
                published_date=datetime.fromisoformat(sample_cve["published"].replace("Z", "+00:00")),
                last_modified_date=datetime.fromisoformat(sample_cve["last_modified"].replace("Z", "+00:00")),
                epss_score=EPSSScore(
                    score=sample_cve.get("epss_score", 0.6),
                    percentile=sample_cve.get("epssPercentile", 0.0),
                    date=TEST_EPSS_DATE,
                ),
            )
            vuln.risk_score = risk_scores[i]
            manager.cache_vulnerability(vuln)

        # Filter by min_risk_score >= 80
        high_risk = manager.get_recent_vulnerabilities(limit=100, min_risk_score=80)

        assert len(high_risk) == 2  # Only 95 and 85 scores

    def test_get_recent_vulnerabilities_with_min_epss_score(self, tmp_path, sample_cve_list):
        """Test filtering vulnerabilities by minimum EPSS score."""
        manager = CacheManager(cache_dir=tmp_path)

        # Store vulnerabilities with different EPSS scores
        epss_scores = [0.95, 0.75, 0.55, 0.35]
        for i, sample_cve in enumerate(sample_cve_list[:4]):
            vuln = Vulnerability(
                cve_id=sample_cve["cveId"],
                title=sample_cve["title"],
                description=sample_cve["description"],
                severity=SeverityLevel.CRITICAL,
                cvss_metrics=[CVSSMetric(
                version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=9.0,
                base_severity=SeverityLevel.CRITICAL,
            )],
                published_date=datetime.fromisoformat(sample_cve["published"].replace("Z", "+00:00")),
                last_modified_date=datetime.fromisoformat(sample_cve["last_modified"].replace("Z", "+00:00")),
                epss_score=EPSSScore(
                    score=epss_scores[i],
                    percentile=90.0 if epss_scores[i] >= 0.6 else 50.0,
                    date=TEST_EPSS_DATE,
                ),
            )
            vuln.risk_score = 85
            manager.cache_vulnerability(vuln)

        # Filter by min_epss_score >= 60%
        high_epss = manager.get_recent_vulnerabilities(limit=100, min_epss_score=60)

        assert len(high_epss) == 2  # Only 95% and 75% scores
