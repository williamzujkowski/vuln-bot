"""SQLite-based caching manager for vulnerability data."""

import json
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
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
    func,
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
    # Use timezone-naive DateTime for SQLite compatibility
    published_date = Column(DateTime, nullable=False, index=True)
    last_modified_date = Column(DateTime, nullable=False)
    cached_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )
    expires_at = Column(DateTime, nullable=False, index=True)


class HarvestMetadata(Base):
    """SQLAlchemy model for harvest metadata."""

    __tablename__ = "harvest_metadata"

    id = Column(Integer, primary_key=True)
    # Use timezone-naive DateTime for SQLite compatibility
    harvest_date = Column(DateTime, nullable=False, unique=True, index=True)
    vulnerability_count = Column(Integer, nullable=False)
    sources = Column(Text, nullable=False)  # JSON list of sources
    extra_metadata = Column(Text)  # JSON additional metadata
    created_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )


class CacheManager:
    """Manage SQLite cache for vulnerability data."""

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        db_path: Optional[str] = None,
        ttl_days: int = 10,
    ):
        """Initialize cache manager.

        Args:
            cache_dir: Directory for cache database (deprecated, use db_path)
            db_path: Direct path to database file
            ttl_days: Time-to-live for cached data in days
        """
        self.ttl_days = ttl_days
        self.logger = structlog.get_logger(self.__class__.__name__)

        # Handle both cache_dir and db_path for compatibility
        if db_path:
            self.db_path = Path(db_path)
            self.cache_dir = self.db_path.parent
        elif cache_dir:
            self.cache_dir = cache_dir
            self.db_path = self.cache_dir / "vulnerability_cache.db"
        else:
            raise ValueError("Either cache_dir or db_path must be provided")

        # Ensure cache directory exists
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Set up database
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

    def _to_naive_datetime(self, dt: Optional[datetime]) -> Optional[datetime]:
        """Convert timezone-aware datetime to naive UTC datetime for SQLite.

        Args:
            dt: Datetime object (aware or naive)

        Returns:
            Naive datetime in UTC or None
        """
        if dt is None:
            return None
        if dt.tzinfo is not None:
            # Convert to UTC and make naive
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        # Assume naive datetime is already in UTC
        return dt

    def _to_aware_datetime(self, dt: Optional[datetime]) -> Optional[datetime]:
        """Convert naive datetime to timezone-aware UTC datetime.

        Args:
            dt: Naive datetime object

        Returns:
            Timezone-aware datetime in UTC or None
        """
        if dt is None:
            return None
        if dt.tzinfo is None:
            # Assume naive datetime is in UTC
            return dt.replace(tzinfo=timezone.utc)
        return dt

    def cache_vulnerability(self, vulnerability: Vulnerability) -> None:
        """Cache a single vulnerability.

        Args:
            vulnerability: Vulnerability to cache
        """
        with self.get_session() as session:
            # Calculate expiration (use naive datetime for SQLite)
            expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(
                days=self.ttl_days
            )

            # Check if already exists
            existing = (
                session.query(VulnerabilityCache)
                .filter_by(cve_id=vulnerability.cve_id)
                .first()
            )

            # Serialize vulnerability data
            data_json = vulnerability.model_dump_json()

            if existing:
                # Update existing record
                existing.data = data_json
                existing.risk_score = vulnerability.risk_score
                existing.severity = vulnerability.severity.value
                existing.published_date = self._to_naive_datetime(
                    vulnerability.published_date
                )
                existing.last_modified_date = self._to_naive_datetime(
                    vulnerability.last_modified_date
                )
                existing.cached_at = datetime.now(timezone.utc).replace(tzinfo=None)
                existing.expires_at = expires_at
            else:
                # Create new record
                cache_entry = VulnerabilityCache(
                    cve_id=vulnerability.cve_id,
                    data=data_json,
                    risk_score=vulnerability.risk_score,
                    severity=vulnerability.severity.value,
                    published_date=self._to_naive_datetime(
                        vulnerability.published_date
                    ),
                    last_modified_date=self._to_naive_datetime(
                        vulnerability.last_modified_date
                    ),
                    expires_at=expires_at,
                )
                session.add(cache_entry)

            session.commit()

    def cache_batch(self, batch: VulnerabilityBatch) -> None:
        """Cache a batch of vulnerabilities.

        Args:
            batch: Batch of vulnerabilities to cache
        """
        for vuln in batch.vulnerabilities:
            self.cache_vulnerability(vuln)

        # Record harvest metadata
        with self.get_session() as session:
            metadata_entry = HarvestMetadata(
                harvest_date=datetime.now(timezone.utc).replace(tzinfo=None),
                vulnerability_count=batch.count,
                sources=json.dumps(batch.metadata.get("sources", [])),
                extra_metadata=json.dumps(batch.metadata),
            )
            session.add(metadata_entry)
            session.commit()

    def get_vulnerability(self, cve_id: str) -> Optional[Vulnerability]:
        """Get a cached vulnerability by CVE ID.

        Args:
            cve_id: CVE identifier

        Returns:
            Vulnerability if found and not expired, None otherwise
        """
        with self.get_session() as session:
            # Use naive datetime for comparison
            now_naive = datetime.now(timezone.utc).replace(tzinfo=None)

            cache_entry = (
                session.query(VulnerabilityCache)
                .filter_by(cve_id=cve_id)
                .filter(VulnerabilityCache.expires_at > now_naive)
                .first()
            )

            if cache_entry:
                # Deserialize and return
                vuln_dict = json.loads(cache_entry.data)
                # Convert naive datetimes back to aware
                if "published_date" in vuln_dict:
                    vuln_dict["published_date"] = self._to_aware_datetime(
                        datetime.fromisoformat(vuln_dict["published_date"])
                    )
                if "last_modified_date" in vuln_dict:
                    vuln_dict["last_modified_date"] = self._to_aware_datetime(
                        datetime.fromisoformat(vuln_dict["last_modified_date"])
                    )
                return Vulnerability.model_validate(vuln_dict)

            return None

    def get_recent_vulnerabilities(
        self, limit: int = 100, min_risk_score: Optional[int] = None
    ) -> List[Vulnerability]:
        """Get recent vulnerabilities from cache.

        Args:
            limit: Maximum number of vulnerabilities to return
            min_risk_score: Minimum risk score filter

        Returns:
            List of vulnerabilities ordered by risk score descending
        """
        with self.get_session() as session:
            # Use naive datetime for comparison
            now_naive = datetime.now(timezone.utc).replace(tzinfo=None)

            query = session.query(VulnerabilityCache).filter(
                VulnerabilityCache.expires_at > now_naive
            )

            if min_risk_score is not None:
                query = query.filter(VulnerabilityCache.risk_score >= min_risk_score)

            cache_entries = (
                query.order_by(desc(VulnerabilityCache.risk_score)).limit(limit).all()
            )

            vulnerabilities = []
            for entry in cache_entries:
                try:
                    vuln_dict = json.loads(entry.data)
                    # Convert naive datetimes back to aware
                    if "published_date" in vuln_dict:
                        vuln_dict["published_date"] = self._to_aware_datetime(
                            datetime.fromisoformat(vuln_dict["published_date"])
                        )
                    if "last_modified_date" in vuln_dict:
                        vuln_dict["last_modified_date"] = self._to_aware_datetime(
                            datetime.fromisoformat(vuln_dict["last_modified_date"])
                        )
                    vuln = Vulnerability.model_validate(vuln_dict)
                    vulnerabilities.append(vuln)
                except Exception as e:
                    self.logger.warning(
                        "Failed to deserialize vulnerability",
                        cve_id=entry.cve_id,
                        error=str(e),
                    )

            return vulnerabilities

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        with self.get_session() as session:
            # Use naive datetime for comparison
            now_naive = datetime.now(timezone.utc).replace(tzinfo=None)

            total_entries = session.query(func.count(VulnerabilityCache.id)).scalar()
            valid_entries = (
                session.query(func.count(VulnerabilityCache.id))
                .filter(VulnerabilityCache.expires_at > now_naive)
                .scalar()
            )
            expired_entries = total_entries - valid_entries

            # Get severity distribution for valid entries
            severity_dist = (
                session.query(
                    VulnerabilityCache.severity, func.count(VulnerabilityCache.id)
                )
                .filter(VulnerabilityCache.expires_at > now_naive)
                .group_by(VulnerabilityCache.severity)
                .all()
            )

            # Get risk score distribution
            risk_dist = {
                "critical": session.query(func.count(VulnerabilityCache.id))
                .filter(VulnerabilityCache.expires_at > now_naive)
                .filter(VulnerabilityCache.risk_score >= 90)
                .scalar(),
                "high": session.query(func.count(VulnerabilityCache.id))
                .filter(VulnerabilityCache.expires_at > now_naive)
                .filter(VulnerabilityCache.risk_score >= 70)
                .filter(VulnerabilityCache.risk_score < 90)
                .scalar(),
                "medium": session.query(func.count(VulnerabilityCache.id))
                .filter(VulnerabilityCache.expires_at > now_naive)
                .filter(VulnerabilityCache.risk_score >= 50)
                .filter(VulnerabilityCache.risk_score < 70)
                .scalar(),
                "low": session.query(func.count(VulnerabilityCache.id))
                .filter(VulnerabilityCache.expires_at > now_naive)
                .filter(VulnerabilityCache.risk_score < 50)
                .scalar(),
            }

            return {
                "total_entries": total_entries,
                "valid_entries": valid_entries,
                "expired_entries": expired_entries,
                "severity_distribution": dict(severity_dist),
                "risk_distribution": risk_dist,
                "cache_size_mb": self.db_path.stat().st_size / (1024 * 1024),
            }

    def cleanup_expired(self) -> int:
        """Remove expired entries from cache.

        Returns:
            Number of entries removed
        """
        with self.get_session() as session:
            # Use naive datetime for comparison
            now_naive = datetime.now(timezone.utc).replace(tzinfo=None)

            expired_count = (
                session.query(VulnerabilityCache)
                .filter(VulnerabilityCache.expires_at <= now_naive)
                .count()
            )

            if expired_count > 0:
                session.query(VulnerabilityCache).filter(
                    VulnerabilityCache.expires_at <= now_naive
                ).delete()
                session.commit()

                self.logger.info(
                    "Cleaned up expired cache entries", count=expired_count
                )

            return expired_count

    def get_harvest_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent harvest history.

        Args:
            limit: Maximum number of harvest records to return

        Returns:
            List of harvest metadata dictionaries
        """
        with self.get_session() as session:
            harvests = (
                session.query(HarvestMetadata)
                .order_by(desc(HarvestMetadata.harvest_date))
                .limit(limit)
                .all()
            )

            return [
                {
                    "harvest_date": self._to_aware_datetime(h.harvest_date),
                    "vulnerability_count": h.vulnerability_count,
                    "sources": json.loads(h.sources),
                    "metadata": json.loads(h.extra_metadata or "{}"),
                }
                for h in harvests
            ]
