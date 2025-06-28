"""EPSS (Exploit Prediction Scoring System) API client."""

import csv
import gzip
import io
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import requests
import structlog
from dateutil import parser as date_parser

from scripts.harvest.base_client import BaseAPIClient
from scripts.models import EPSSScore


class EPSSClient(BaseAPIClient):
    """Client for FIRST EPSS API."""

    def __init__(self, **kwargs):
        """Initialize EPSS client.

        Args:
            **kwargs: Additional arguments for BaseAPIClient
        """
        super().__init__(
            base_url="https://api.first.org/data/v1",
            rate_limit_calls=100,  # EPSS API is quite generous
            rate_limit_period=60.0,
            **kwargs,
        )
        self.logger = structlog.get_logger(self.__class__.__name__)

    def get_headers(self) -> Dict[str, str]:
        """Get headers for EPSS API requests."""
        headers = super().get_headers()
        headers["Accept"] = "application/json"
        return headers

    def fetch_epss_scores(
        self,
        cve_ids: Optional[List[str]] = None,
        date: Optional[datetime] = None,
    ) -> Dict[str, EPSSScore]:
        """Fetch EPSS scores for CVEs.

        Args:
            cve_ids: List of CVE IDs to fetch scores for (None = all)
            date: Date to fetch scores for (None = latest)

        Returns:
            Dictionary mapping CVE IDs to EPSS scores
        """
        params = {}

        if cve_ids:
            # API supports up to 100 CVEs per request
            params["cve"] = ",".join(cve_ids[:100])

        if date:
            params["date"] = date.strftime("%Y-%m-%d")

        try:
            response = self.get("/epss", params=params)

            scores = {}
            data = response.get("data", [])

            # Get the score date from response
            score_date = date_parser.parse(
                response.get("score_date", datetime.now(timezone.utc).isoformat())
            )

            for item in data:
                cve_id = item.get("cve", "")
                if not cve_id:
                    continue

                try:
                    epss_score = EPSSScore(
                        score=float(item.get("epss", 0.0)),
                        percentile=float(item.get("percentile", 0.0))
                        * 100,  # Convert to percentage
                        date=score_date,
                    )
                    scores[cve_id] = epss_score
                except (ValueError, TypeError) as e:
                    self.logger.warning(
                        "Failed to parse EPSS score",
                        cve_id=cve_id,
                        error=str(e),
                    )

            self.logger.info(
                "Fetched EPSS scores",
                requested=len(cve_ids) if cve_ids else "all",
                received=len(scores),
            )

            return scores

        except Exception as e:
            self.logger.error("Failed to fetch EPSS scores", error=str(e))
            return {}

    def fetch_epss_scores_bulk(
        self,
        cve_ids: List[str],
        batch_size: int = 100,
    ) -> Dict[str, EPSSScore]:
        """Fetch EPSS scores for a large list of CVEs in batches.

        Args:
            cve_ids: List of CVE IDs to fetch scores for
            batch_size: Number of CVEs per API request

        Returns:
            Dictionary mapping CVE IDs to EPSS scores
        """
        all_scores = {}

        # Process in batches
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i : i + batch_size]
            scores = self.fetch_epss_scores(batch)
            all_scores.update(scores)

        return all_scores

    def fetch_daily_epss_file(
        self, date: Optional[datetime] = None
    ) -> Dict[str, EPSSScore]:
        """Fetch and parse the daily EPSS CSV file.

        This is more efficient for getting all EPSS scores at once.

        Args:
            date: Date to fetch file for (None = latest)

        Returns:
            Dictionary mapping CVE IDs to EPSS scores
        """
        # Construct URL for daily file
        if date:
            date_str = date.strftime("%Y-%m-%d")
            url = f"https://epss.cyentia.com/epss_scores-{date_str}.csv.gz"
        else:
            url = "https://epss.cyentia.com/epss_scores-current.csv.gz"

        try:
            self.logger.info("Fetching daily EPSS file", url=url)

            # Download the file
            response = requests.get(url, timeout=60)
            response.raise_for_status()

            # Decompress and parse CSV
            with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as f:
                content = f.read().decode("utf-8")

            reader = csv.DictReader(io.StringIO(content))

            scores = {}
            score_date = datetime.now(timezone.utc)  # Will be updated from file

            for row in reader:
                # First row contains the model version and date
                if "model_version" in row:
                    # Extract date from model version
                    date_parts = row.get("score_date", "").split("-")
                    if len(date_parts) == 3:
                        score_date = datetime(
                            int(date_parts[0]),
                            int(date_parts[1]),
                            int(date_parts[2]),
                        )
                    continue

                cve_id = row.get("cve", "")
                if not cve_id or not cve_id.startswith("CVE-"):
                    continue

                try:
                    epss_score = EPSSScore(
                        score=float(row.get("epss", 0.0)),
                        percentile=float(row.get("percentile", 0.0)) * 100,
                        date=score_date,
                    )
                    scores[cve_id] = epss_score
                except (ValueError, TypeError) as e:
                    self.logger.debug(
                        "Failed to parse EPSS row",
                        cve_id=cve_id,
                        error=str(e),
                    )

            self.logger.info(
                "Parsed EPSS scores from daily file",
                count=len(scores),
                date=score_date.date(),
            )

            return scores

        except Exception as e:
            self.logger.error("Failed to fetch daily EPSS file", error=str(e))
            return {}

    def get_high_risk_cves(
        self,
        min_score: float = 0.5,
        min_percentile: float = 90.0,
    ) -> List[Tuple[str, EPSSScore]]:
        """Get CVEs with high EPSS scores.

        Args:
            min_score: Minimum EPSS score (0-1)
            min_percentile: Minimum percentile (0-100)

        Returns:
            List of tuples (CVE ID, EPSS score) sorted by score
        """
        # Fetch all scores from daily file
        all_scores = self.fetch_daily_epss_file()

        # Filter by criteria
        high_risk = [
            (cve_id, score)
            for cve_id, score in all_scores.items()
            if score.score >= min_score or score.percentile >= min_percentile
        ]

        # Sort by score descending
        high_risk.sort(key=lambda x: x[1].score, reverse=True)

        self.logger.info(
            "Found high-risk CVEs",
            total=len(all_scores),
            high_risk=len(high_risk),
            criteria=f"score>={min_score} or percentile>={min_percentile}",
        )

        return high_risk
