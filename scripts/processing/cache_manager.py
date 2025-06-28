"""SQLite-based caching manager for vulnerability data."""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

import structlog
from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
    desc,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

from scripts.models import Vulnerability, VulnerabilityBatch

Base = declarative_base()


class VulnerabilityCache(Base):
    """SQLAlchemy model for cached vulnerability data."""

    __tablename__ = "vulnerability_cache"

    id = Column(Integer, primary_key=True)
    cve_id = Column(String(50), unique=True, nullable=False, index=True)
    data = Column(Text, nullable=False)  # JSON serialized vulnerability
    risk_score = Column(Integer, nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    published_date = Column(DateTime, nullable=False, index=True)
    last_modified_date = Column(DateTime, nullable=False)
    cached_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)


class HarvestMetadata(Base):
    """SQLAlchemy model for harvest metadata."""

    __tablename__ = "harvest_metadata"

    id = Column(Integer, primary_key=True)
    harvest_date = Column(DateTime, nullable=False, unique=True, index=True)
    vulnerability_count = Column(Integer, nullable=False)
    sources = Column(Text, nullable=False)  # JSON list of sources
    metadata = Column(Text)  # JSON additional metadata
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class CacheManager:
    """Manage SQLite cache for vulnerability data."""

    def __init__(self, cache_dir: Path, ttl_days: int = 10):
        """Initialize cache manager.

        Args:
            cache_dir: Directory for cache database
            ttl_days: Time-to-live for cached data in days
        """
        self.cache_dir = cache_dir
        self.ttl_days = ttl_days
        self.logger = structlog.get_logger(self.__class__.__name__)

        # Ensure cache directory exists
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Set up database
        self.db_path = self.cache_dir / "vulnerability_cache.db"
        self.engine = create_engine(
            f"sqlite:///{self.db_path}",
            connect_args={"check_same_thread": False},
        )

        # Create tables if they don't exist
        Base.metadata.create_all(self.engine)

        # Create session factory
        self.SessionLocal = sessionmaker(bind=self.engine)

    @contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        """Get database session context manager."""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def cache_vulnerability(self, vulnerability: Vulnerability) -> None:
        """Cache a single vulnerability.

        Args:
            vulnerability: Vulnerability to cache
        """
        with self.get_session() as session:
            # Calculate expiration
            expires_at = datetime.utcnow() + timedelta(days=self.ttl_days)

            # Check if already exists
            existing = (
                session.query(VulnerabilityCache)
                .filter_by(cve_id=vulnerability.cve_id)
                .first()
            )

            # Serialize vulnerability data
            data_json = json.dumps(vulnerability.dict())

            if existing:
                # Update existing record
                existing.data = data_json
                existing.risk_score = vulnerability.risk_score
                existing.severity = vulnerability.severity.value
                existing.published_date = vulnerability.published_date
                existing.last_modified_date = vulnerability.last_modified_date
                existing.cached_at = datetime.utcnow()
                existing.expires_at = expires_at
            else:
                # Create new record
                cache_entry = VulnerabilityCache(
                    cve_id=vulnerability.cve_id,
                    data=data_json,
                    risk_score=vulnerability.risk_score,
                    severity=vulnerability.severity.value,
                    published_date=vulnerability.published_date,
                    last_modified_date=vulnerability.last_modified_date,
                    expires_at=expires_at,
                )
                session.add(cache_entry)

    def cache_batch(self, batch: VulnerabilityBatch) -> None:
        """Cache a batch of vulnerabilities.

        Args:
            batch: Batch of vulnerabilities to cache
        """
        self.logger.info("Caching vulnerability batch", count=batch.count)

        with self.get_session() as session:
            # Record harvest metadata
            harvest_meta = HarvestMetadata(
                harvest_date=batch.generated_at,
                vulnerability_count=batch.count,
                sources=json.dumps(
                    list(
                        {
                            source.name
                            for vuln in batch.vulnerabilities
                            for source in vuln.sources
                        }
                    )
                ),
                metadata=json.dumps(batch.metadata),
            )
            session.add(harvest_meta)

            # Cache individual vulnerabilities
            for vuln in batch.vulnerabilities:
                self.cache_vulnerability(vuln)

        self.logger.info("Cached vulnerability batch", count=batch.count)

    def get_vulnerability(self, cve_id: str) -> Optional[Vulnerability]:
        """Get a cached vulnerability by CVE ID.

        Args:
            cve_id: CVE ID to retrieve

        Returns:
            Vulnerability if found and not expired, None otherwise
        """
        with self.get_session() as session:
            cache_entry = (
                session.query(VulnerabilityCache).filter_by(cve_id=cve_id).first()
            )

            if not cache_entry:
                return None

            # Check if expired
            if cache_entry.expires_at < datetime.utcnow():
                self.logger.debug("Cache entry expired", cve_id=cve_id)
                return None

            # Deserialize vulnerability
            try:
                data = json.loads(cache_entry.data)
                return Vulnerability(**data)
            except Exception as e:
                self.logger.error(
                    "Failed to deserialize cached vulnerability",
                    cve_id=cve_id,
                    error=str(e),
                )
                return None

    def get_recent_vulnerabilities(
        self,
        limit: int = 100,
        min_risk_score: Optional[int] = None,
        severity: Optional[str] = None,
    ) -> List[Vulnerability]:
        """Get recent vulnerabilities from cache.

        Args:
            limit: Maximum number of vulnerabilities to return
            min_risk_score: Minimum risk score filter
            severity: Severity level filter

        Returns:
            List of cached vulnerabilities
        """
        with self.get_session() as session:
            query = session.query(VulnerabilityCache).filter(
                VulnerabilityCache.expires_at > datetime.utcnow()
            )

            if min_risk_score is not None:
                query = query.filter(VulnerabilityCache.risk_score >= min_risk_score)

            if severity:
                query = query.filter(VulnerabilityCache.severity == severity)

            # Order by risk score and published date
            query = query.order_by(
                desc(VulnerabilityCache.risk_score),
                desc(VulnerabilityCache.published_date),
            ).limit(limit)

            vulnerabilities = []
            for cache_entry in query:
                try:
                    data = json.loads(cache_entry.data)
                    vuln = Vulnerability(**data)
                    vulnerabilities.append(vuln)
                except Exception as e:
                    self.logger.error(
                        "Failed to deserialize cached vulnerability",
                        cve_id=cache_entry.cve_id,
                        error=str(e),
                    )

            return vulnerabilities

    def get_harvest_metadata(
        self,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Get recent harvest metadata.

        Args:
            limit: Maximum number of records to return

        Returns:
            List of harvest metadata records
        """
        with self.get_session() as session:
            records = (
                session.query(HarvestMetadata)
                .order_by(desc(HarvestMetadata.harvest_date))
                .limit(limit)
                .all()
            )

            metadata_list = []
            for record in records:
                metadata_list.append(
                    {
                        "harvest_date": record.harvest_date.isoformat(),
                        "vulnerability_count": record.vulnerability_count,
                        "sources": json.loads(record.sources),
                        "metadata": json.loads(record.metadata)
                        if record.metadata
                        else {},
                    }
                )

            return metadata_list

    def cleanup_expired(self) -> int:
        """Remove expired cache entries.

        Returns:
            Number of entries removed
        """
        with self.get_session() as session:
            expired_count = (
                session.query(VulnerabilityCache)
                .filter(VulnerabilityCache.expires_at < datetime.utcnow())
                .count()
            )

            if expired_count > 0:
                session.query(VulnerabilityCache).filter(
                    VulnerabilityCache.expires_at < datetime.utcnow()
                ).delete()

                self.logger.info(
                    "Cleaned up expired cache entries", count=expired_count
                )

            return expired_count

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary of cache statistics
        """
        with self.get_session() as session:
            total_entries = session.query(VulnerabilityCache).count()
            valid_entries = (
                session.query(VulnerabilityCache)
                .filter(VulnerabilityCache.expires_at > datetime.utcnow())
                .count()
            )

            # Get severity distribution
            severity_counts = {}
            for severity, count in (
                session.query(
                    VulnerabilityCache.severity,
                    sqlite3.func.count(VulnerabilityCache.id),
                )
                .filter(VulnerabilityCache.expires_at > datetime.utcnow())
                .group_by(VulnerabilityCache.severity)
                .all()
            ):
                severity_counts[severity] = count

            # Get risk score distribution
            risk_ranges = {
                "critical": session.query(VulnerabilityCache)
                .filter(
                    VulnerabilityCache.expires_at > datetime.utcnow(),
                    VulnerabilityCache.risk_score >= 90,
                )
                .count(),
                "high": session.query(VulnerabilityCache)
                .filter(
                    VulnerabilityCache.expires_at > datetime.utcnow(),
                    VulnerabilityCache.risk_score >= 70,
                    VulnerabilityCache.risk_score < 90,
                )
                .count(),
                "medium": session.query(VulnerabilityCache)
                .filter(
                    VulnerabilityCache.expires_at > datetime.utcnow(),
                    VulnerabilityCache.risk_score >= 40,
                    VulnerabilityCache.risk_score < 70,
                )
                .count(),
                "low": session.query(VulnerabilityCache)
                .filter(
                    VulnerabilityCache.expires_at > datetime.utcnow(),
                    VulnerabilityCache.risk_score < 40,
                )
                .count(),
            }

            return {
                "total_entries": total_entries,
                "valid_entries": valid_entries,
                "expired_entries": total_entries - valid_entries,
                "severity_distribution": severity_counts,
                "risk_distribution": risk_ranges,
                "database_size_mb": round(self.db_path.stat().st_size / 1024 / 1024, 2),
            }
