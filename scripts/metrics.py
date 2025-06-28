"""
Metrics collection and monitoring system for vulnerability harvesting.
"""

import json
import sqlite3
import time
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Vulnerability


class MetricsCollector:
    """Collects and stores metrics for vulnerability harvesting operations."""

    def __init__(self, db_path: Optional[Path] = None):
        """Initialize metrics collector.

        Args:
            db_path: Path to SQLite database for metrics storage
        """
        self.db_path = db_path or Path("metrics.db")
        self.current_harvest_id = None
        self.start_time = None
        self.metrics_buffer = defaultdict(list)
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        with self._get_db() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS harvest_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    start_time TIMESTAMP NOT NULL,
                    end_time TIMESTAMP,
                    duration_seconds REAL,
                    total_cves_processed INTEGER DEFAULT 0,
                    new_cves_found INTEGER DEFAULT 0,
                    updated_cves INTEGER DEFAULT 0,
                    errors_count INTEGER DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'running',
                    metadata JSON
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS harvest_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    harvest_id INTEGER NOT NULL,
                    metric_name TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    metadata JSON,
                    FOREIGN KEY (harvest_id) REFERENCES harvest_runs(id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerability_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    harvest_id INTEGER NOT NULL,
                    cve_id TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    cvss_score REAL,
                    epss_score REAL,
                    severity TEXT,
                    has_kev BOOLEAN,
                    has_ssvc BOOLEAN,
                    vendor_count INTEGER,
                    product_count INTEGER,
                    reference_count INTEGER,
                    tag_count INTEGER,
                    FOREIGN KEY (harvest_id) REFERENCES harvest_runs(id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS error_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    harvest_id INTEGER NOT NULL,
                    error_type TEXT NOT NULL,
                    error_message TEXT NOT NULL,
                    error_context JSON,
                    timestamp TIMESTAMP NOT NULL,
                    FOREIGN KEY (harvest_id) REFERENCES harvest_runs(id)
                )
            """)

            # Create indexes for performance
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_harvest_start_time ON harvest_runs(start_time)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_metrics_harvest_id ON harvest_metrics(harvest_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_vuln_metrics_harvest_id ON vulnerability_metrics(harvest_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_vuln_metrics_cve_id ON vulnerability_metrics(cve_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_error_logs_harvest_id ON error_logs(harvest_id)"
            )

    @contextmanager
    def _get_db(self):
        """Get database connection context manager."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def start_harvest(self, metadata: Optional[Dict[str, Any]] = None) -> int:
        """Start a new harvest run.

        Args:
            metadata: Optional metadata about the harvest run

        Returns:
            Harvest run ID
        """
        self.start_time = time.time()

        with self._get_db() as conn:
            cursor = conn.execute(
                """
                INSERT INTO harvest_runs (start_time, metadata)
                VALUES (?, ?)
                """,
                (datetime.now(timezone.utc), json.dumps(metadata or {})),
            )
            self.current_harvest_id = cursor.lastrowid

        return self.current_harvest_id

    def end_harvest(
        self, status: str = "completed", summary: Optional[Dict[str, Any]] = None
    ):
        """End the current harvest run.

        Args:
            status: Final status of the harvest
            summary: Optional summary statistics
        """
        if not self.current_harvest_id:
            return

        end_time = time.time()
        duration = end_time - self.start_time if self.start_time else 0

        # Flush any buffered metrics
        self._flush_metrics()

        with self._get_db() as conn:
            # Get summary statistics
            stats = conn.execute(
                """
                SELECT
                    COUNT(DISTINCT cve_id) as total_cves,
                    AVG(risk_score) as avg_risk_score,
                    AVG(cvss_score) as avg_cvss_score,
                    AVG(epss_score) as avg_epss_score,
                    SUM(has_kev) as kev_count,
                    SUM(has_ssvc) as ssvc_count
                FROM vulnerability_metrics
                WHERE harvest_id = ?
                """,
                (self.current_harvest_id,),
            ).fetchone()

            error_count = conn.execute(
                "SELECT COUNT(*) as count FROM error_logs WHERE harvest_id = ?",
                (self.current_harvest_id,),
            ).fetchone()["count"]

            # Update harvest run
            metadata = {
                "avg_risk_score": stats["avg_risk_score"],
                "avg_cvss_score": stats["avg_cvss_score"],
                "avg_epss_score": stats["avg_epss_score"],
                "kev_count": stats["kev_count"],
                "ssvc_count": stats["ssvc_count"],
                **(summary or {}),
            }

            conn.execute(
                """
                UPDATE harvest_runs
                SET end_time = ?, duration_seconds = ?, status = ?,
                    total_cves_processed = ?, errors_count = ?, metadata = ?
                WHERE id = ?
                """,
                (
                    datetime.now(timezone.utc),
                    duration,
                    status,
                    stats["total_cves"],
                    error_count,
                    json.dumps(metadata),
                    self.current_harvest_id,
                ),
            )

        self.current_harvest_id = None
        self.start_time = None

    def record_vulnerability(self, vuln: Vulnerability):
        """Record metrics for a vulnerability.

        Args:
            vuln: Vulnerability to record metrics for
        """
        if not self.current_harvest_id:
            return

        self.metrics_buffer["vulnerabilities"].append(
            {
                "harvest_id": self.current_harvest_id,
                "cve_id": vuln.cve_id,
                "risk_score": vuln.risk_score,
                "cvss_score": vuln.cvss_score,
                "epss_score": vuln.epss_score,
                "severity": vuln.severity,
                "has_kev": vuln.kev_status is not None,
                "has_ssvc": vuln.ssvc_decision_data is not None,
                "vendor_count": len(vuln.vendors),
                "product_count": len(vuln.products),
                "reference_count": len(vuln.references),
                "tag_count": len(vuln.tags),
            }
        )

        # Flush buffer if it gets too large
        if len(self.metrics_buffer["vulnerabilities"]) >= 100:
            self._flush_metrics()

    def record_metric(
        self, name: str, value: float, metadata: Optional[Dict[str, Any]] = None
    ):
        """Record a general metric.

        Args:
            name: Metric name
            value: Metric value
            metadata: Optional metadata
        """
        if not self.current_harvest_id:
            return

        self.metrics_buffer["metrics"].append(
            {
                "harvest_id": self.current_harvest_id,
                "metric_name": name,
                "metric_value": value,
                "timestamp": datetime.now(timezone.utc),
                "metadata": json.dumps(metadata or {}),
            }
        )

    def record_error(
        self, error_type: str, message: str, context: Optional[Dict[str, Any]] = None
    ):
        """Record an error.

        Args:
            error_type: Type of error
            message: Error message
            context: Optional error context
        """
        if not self.current_harvest_id:
            return

        with self._get_db() as conn:
            conn.execute(
                """
                INSERT INTO error_logs (harvest_id, error_type, error_message, error_context, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    self.current_harvest_id,
                    error_type,
                    message,
                    json.dumps(context or {}),
                    datetime.now(timezone.utc),
                ),
            )

    def _flush_metrics(self):
        """Flush buffered metrics to database."""
        if not self.metrics_buffer:
            return

        with self._get_db() as conn:
            # Insert vulnerability metrics
            if self.metrics_buffer["vulnerabilities"]:
                conn.executemany(
                    """
                    INSERT INTO vulnerability_metrics
                    (harvest_id, cve_id, risk_score, cvss_score, epss_score, severity,
                     has_kev, has_ssvc, vendor_count, product_count, reference_count, tag_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            v["harvest_id"],
                            v["cve_id"],
                            v["risk_score"],
                            v["cvss_score"],
                            v["epss_score"],
                            v["severity"],
                            v["has_kev"],
                            v["has_ssvc"],
                            v["vendor_count"],
                            v["product_count"],
                            v["reference_count"],
                            v["tag_count"],
                        )
                        for v in self.metrics_buffer["vulnerabilities"]
                    ],
                )

            # Insert general metrics
            if self.metrics_buffer["metrics"]:
                conn.executemany(
                    """
                    INSERT INTO harvest_metrics (harvest_id, metric_name, metric_value, timestamp, metadata)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            m["harvest_id"],
                            m["metric_name"],
                            m["metric_value"],
                            m["timestamp"],
                            m["metadata"],
                        )
                        for m in self.metrics_buffer["metrics"]
                    ],
                )

        self.metrics_buffer.clear()

    def get_harvest_summary(self, harvest_id: Optional[int] = None) -> Dict[str, Any]:
        """Get summary statistics for a harvest run.

        Args:
            harvest_id: Harvest ID to get summary for (defaults to current)

        Returns:
            Summary statistics
        """
        harvest_id = harvest_id or self.current_harvest_id
        if not harvest_id:
            return {}

        with self._get_db() as conn:
            # Get harvest run info
            harvest = conn.execute(
                "SELECT * FROM harvest_runs WHERE id = ?", (harvest_id,)
            ).fetchone()

            if not harvest:
                return {}

            # Get vulnerability statistics
            vuln_stats = conn.execute(
                """
                SELECT
                    COUNT(*) as total_vulnerabilities,
                    COUNT(DISTINCT severity) as unique_severities,
                    AVG(risk_score) as avg_risk_score,
                    MIN(risk_score) as min_risk_score,
                    MAX(risk_score) as max_risk_score,
                    AVG(cvss_score) as avg_cvss_score,
                    AVG(epss_score) as avg_epss_score,
                    SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) as critical_risk_count,
                    SUM(CASE WHEN risk_score >= 60 AND risk_score < 80 THEN 1 ELSE 0 END) as high_risk_count,
                    SUM(CASE WHEN risk_score >= 40 AND risk_score < 60 THEN 1 ELSE 0 END) as medium_risk_count,
                    SUM(CASE WHEN risk_score < 40 THEN 1 ELSE 0 END) as low_risk_count,
                    SUM(has_kev) as kev_count,
                    SUM(has_ssvc) as ssvc_count
                FROM vulnerability_metrics
                WHERE harvest_id = ?
                """,
                (harvest_id,),
            ).fetchone()

            # Get error statistics
            error_stats = conn.execute(
                """
                SELECT
                    error_type,
                    COUNT(*) as count
                FROM error_logs
                WHERE harvest_id = ?
                GROUP BY error_type
                """,
                (harvest_id,),
            ).fetchall()

            return {
                "harvest_id": harvest_id,
                "start_time": harvest["start_time"],
                "end_time": harvest["end_time"],
                "duration_seconds": harvest["duration_seconds"],
                "status": harvest["status"],
                "total_vulnerabilities": vuln_stats["total_vulnerabilities"],
                "risk_distribution": {
                    "critical": vuln_stats["critical_risk_count"],
                    "high": vuln_stats["high_risk_count"],
                    "medium": vuln_stats["medium_risk_count"],
                    "low": vuln_stats["low_risk_count"],
                },
                "statistics": {
                    "avg_risk_score": vuln_stats["avg_risk_score"],
                    "min_risk_score": vuln_stats["min_risk_score"],
                    "max_risk_score": vuln_stats["max_risk_score"],
                    "avg_cvss_score": vuln_stats["avg_cvss_score"],
                    "avg_epss_score": vuln_stats["avg_epss_score"],
                    "kev_count": vuln_stats["kev_count"],
                    "ssvc_count": vuln_stats["ssvc_count"],
                },
                "errors": {
                    error["error_type"]: error["count"] for error in error_stats
                },
                "metadata": json.loads(harvest["metadata"] or "{}"),
            }

    def get_recent_harvests(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent harvest runs.

        Args:
            limit: Number of recent harvests to return

        Returns:
            List of harvest summaries
        """
        with self._get_db() as conn:
            harvests = conn.execute(
                """
                SELECT id FROM harvest_runs
                ORDER BY start_time DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [self.get_harvest_summary(h["id"]) for h in harvests]

    def export_metrics(self, output_path: Path, harvest_id: Optional[int] = None):
        """Export metrics to JSON file.

        Args:
            output_path: Path to export metrics to
            harvest_id: Harvest ID to export (defaults to current)
        """
        harvest_id = harvest_id or self.current_harvest_id
        if not harvest_id:
            return

        summary = self.get_harvest_summary(harvest_id)

        with self._get_db() as conn:
            # Get detailed metrics
            metrics = conn.execute(
                """
                SELECT metric_name, metric_value, timestamp, metadata
                FROM harvest_metrics
                WHERE harvest_id = ?
                ORDER BY timestamp
                """,
                (harvest_id,),
            ).fetchall()

            # Get vulnerability details
            vulnerabilities = conn.execute(
                """
                SELECT *
                FROM vulnerability_metrics
                WHERE harvest_id = ?
                ORDER BY risk_score DESC
                """,
                (harvest_id,),
            ).fetchall()

        export_data = {
            "summary": summary,
            "metrics": [
                {
                    "name": m["metric_name"],
                    "value": m["metric_value"],
                    "timestamp": m["timestamp"],
                    "metadata": json.loads(m["metadata"] or "{}"),
                }
                for m in metrics
            ],
            "vulnerabilities": [dict(v) for v in vulnerabilities],
        }

        output_path.write_text(json.dumps(export_data, indent=2, default=str))
