"""Simple tests for EPSS API client."""

import gzip
import io
from unittest.mock import Mock, patch

from scripts.harvest.epss_client import EPSSClient


class TestEPSSClientSimple:
    """Simple tests for EPSSClient functionality."""

    def test_initialization(self, tmp_path):
        """Test client initialization."""
        client = EPSSClient(cache_dir=tmp_path)
        assert client.base_url == "https://api.first.org/data/v1"

    def test_fetch_epss_scores_success(self, tmp_path):
        """Test successful EPSS score fetching."""
        # Mock the API response
        with patch.object(EPSSClient, "get") as mock_get:
            mock_get.return_value = {
                "data": [
                    {
                        "cve": "CVE-2025-0001",
                        "epss": "0.12345",
                        "percentile": "0.95432",
                    },
                    {
                        "cve": "CVE-2025-0002",
                        "epss": "0.00123",
                        "percentile": "0.12345",
                    },
                ],
                "score_date": "2025-01-01T00:00:00Z",
            }

            client = EPSSClient(cache_dir=tmp_path)
            cve_ids = ["CVE-2025-0001", "CVE-2025-0002"]

            scores = client.fetch_epss_scores(cve_ids)

            assert len(scores) == 2
            assert abs(scores["CVE-2025-0001"].score - 0.12345) < 0.0001
            assert abs(scores["CVE-2025-0001"].percentile - 95.432) < 0.001
            assert abs(scores["CVE-2025-0002"].score - 0.00123) < 0.0001
            assert abs(scores["CVE-2025-0002"].percentile - 12.345) < 0.001

    def test_fetch_epss_scores_empty_response(self, tmp_path):
        """Test handling empty EPSS response."""
        with patch.object(EPSSClient, "get") as mock_get:
            mock_get.return_value = {"data": [], "score_date": "2025-01-01T00:00:00Z"}

            client = EPSSClient(cache_dir=tmp_path)
            scores = client.fetch_epss_scores(["CVE-2025-0001"])

            assert len(scores) == 0

    def test_fetch_epss_scores_error_handling(self):
        """Test error handling in EPSS score fetching."""
        # Create client without cache to test error handling
        client = EPSSClient(cache_dir=None)

        with patch.object(EPSSClient, "get") as mock_get:
            mock_get.side_effect = Exception("Network error")
            scores = client.fetch_epss_scores(["CVE-2025-9999"])

            # Should return empty dict on error
            assert scores == {}

    def test_fetch_daily_epss_file(self, tmp_path):
        """Test fetching daily EPSS CSV file."""
        client = EPSSClient(cache_dir=tmp_path)

        # Mock CSV data
        csv_data = b"cve,epss,percentile\nCVE-2025-0001,0.12345,0.95432\nCVE-2025-0002,0.00123,0.12345"
        compressed_data = io.BytesIO()
        with gzip.GzipFile(fileobj=compressed_data, mode="wb") as gz:
            gz.write(csv_data)
        compressed_data.seek(0)

        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.content = compressed_data.read()
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response

            scores = client.fetch_daily_epss_file()

            assert len(scores) == 2
            assert "CVE-2025-0001" in scores
            assert "CVE-2025-0002" in scores
            assert abs(scores["CVE-2025-0001"].score - 0.12345) < 0.0001
            assert abs(scores["CVE-2025-0001"].percentile - 95.432) < 0.001

    def test_fetch_epss_scores_bulk(self, tmp_path):
        """Test bulk fetching of EPSS scores in batches."""
        client = EPSSClient(cache_dir=tmp_path)

        # Create 250 CVE IDs to test batching (batch_size=100)
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(250)]

        # Mock fetch_epss_scores to return different batches
        call_count = 0

        def mock_fetch(ids):
            nonlocal call_count
            call_count += 1
            return {
                cve_id: type(
                    "EPSSScore",
                    (),
                    {
                        "score": 0.75,
                        "percentile": 90.0,
                        "date": None,
                    },
                )()
                for cve_id in ids
            }

        with patch.object(EPSSClient, "fetch_epss_scores", side_effect=mock_fetch):
            scores = client.fetch_epss_scores_bulk(cve_ids, batch_size=100)

            # Should make 3 calls (100, 100, 50)
            assert call_count == 3
            assert len(scores) == 250

    def test_fetch_epss_scores_threshold_filtering(self, tmp_path):
        """Test filtering CVEs by EPSS threshold (≥60%)."""
        with patch.object(EPSSClient, "get") as mock_get:
            mock_get.return_value = {
                "data": [
                    {
                        "cve": "CVE-2024-0001",
                        "epss": "0.85",
                        "percentile": "0.98",
                    },  # 85% - Pass
                    {
                        "cve": "CVE-2024-0002",
                        "epss": "0.45",
                        "percentile": "0.75",
                    },  # 45% - Fail
                    {
                        "cve": "CVE-2024-0003",
                        "epss": "0.60",
                        "percentile": "0.80",
                    },  # 60% - Pass (edge)
                    {
                        "cve": "CVE-2024-0004",
                        "epss": "0.59",
                        "percentile": "0.79",
                    },  # 59% - Fail (edge)
                ],
                "score_date": "2025-01-01T00:00:00Z",
            }

            client = EPSSClient(cache_dir=tmp_path)
            scores = client.fetch_epss_scores()

            # Filter to ≥60% threshold
            high_risk_scores = {
                cve_id: score for cve_id, score in scores.items() if score.score >= 0.6
            }

            assert len(high_risk_scores) == 2
            assert "CVE-2024-0001" in high_risk_scores
            assert "CVE-2024-0003" in high_risk_scores
            assert "CVE-2024-0002" not in high_risk_scores
            assert "CVE-2024-0004" not in high_risk_scores

    def test_get_high_risk_cves(self, tmp_path):
        """Test getting high-risk CVEs with min_score and min_percentile filters."""
        client = EPSSClient(cache_dir=tmp_path)

        # Mock daily file CSV
        csv_data = b"""#model_version:v2025.03.14,score_date:2025-01-01T12:55:00Z
cve,epss,percentile
CVE-2024-0001,0.95,0.99
CVE-2024-0002,0.85,0.95
CVE-2024-0003,0.45,0.75
CVE-2024-0004,0.30,0.60"""

        compressed_data = io.BytesIO()
        with gzip.GzipFile(fileobj=compressed_data, mode="wb") as gz:
            gz.write(csv_data)
        compressed_data.seek(0)

        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.content = compressed_data.read()
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response

            # Get CVEs with score ≥0.6 OR percentile ≥90%
            high_risk = client.get_high_risk_cves(min_score=0.6, min_percentile=90.0)

            assert len(high_risk) == 2  # CVE-0001 (95%), CVE-0002 (85%)
            assert high_risk[0][0] == "CVE-2024-0001"  # Sorted by score desc
            assert high_risk[1][0] == "CVE-2024-0002"

    def test_fetch_epss_scores_invalid_data(self, tmp_path):
        """Test handling of invalid EPSS data (malformed scores)."""
        with patch.object(EPSSClient, "get") as mock_get:
            mock_get.return_value = {
                "data": [
                    {
                        "cve": "CVE-2024-0001",
                        "epss": "invalid",
                        "percentile": "0.95",
                    },  # Invalid
                    {
                        "cve": "CVE-2024-0002",
                        "epss": "0.85",
                        "percentile": "not_a_number",
                    },  # Invalid
                    {"cve": "", "epss": "0.75", "percentile": "0.90"},  # Missing CVE ID
                    {
                        "cve": "CVE-2024-0004",
                        "epss": "0.65",
                        "percentile": "0.85",
                    },  # Valid
                ],
                "score_date": "2025-01-01T00:00:00Z",
            }

            client = EPSSClient(cache_dir=tmp_path)
            scores = client.fetch_epss_scores()

            # Should only have 1 valid score
            assert len(scores) == 1
            assert "CVE-2024-0004" in scores

    def test_fetch_epss_scores_with_date(self, tmp_path):
        """Test fetching EPSS scores for a specific date."""
        from datetime import datetime, timezone

        specific_date = datetime(2024, 12, 15, tzinfo=timezone.utc)

        with patch.object(EPSSClient, "get") as mock_get:
            mock_get.return_value = {
                "data": [
                    {"cve": "CVE-2024-0001", "epss": "0.85", "percentile": "0.95"}
                ],
                "score_date": "2024-12-15T00:00:00Z",
            }

            client = EPSSClient(cache_dir=tmp_path)
            client.fetch_epss_scores(cve_ids=["CVE-2024-0001"], date=specific_date)

            # Verify API was called with correct date parameter
            mock_get.assert_called_once()
            call_args = mock_get.call_args
            assert call_args[1]["params"]["date"] == "2024-12-15"

    def test_fetch_daily_epss_file_with_metadata(self, tmp_path):
        """Test parsing EPSS daily file with metadata line."""
        client = EPSSClient(cache_dir=tmp_path)

        # CSV with metadata line (real format)
        csv_data = b"""#model_version:v2025.03.14,score_date:2025-10-19T12:55:00Z
cve,epss,percentile
CVE-2024-0001,0.85432,0.95321"""

        compressed_data = io.BytesIO()
        with gzip.GzipFile(fileobj=compressed_data, mode="wb") as gz:
            gz.write(csv_data)
        compressed_data.seek(0)

        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.content = compressed_data.read()
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response

            scores = client.fetch_daily_epss_file()

            assert len(scores) == 1
            assert scores["CVE-2024-0001"].date.year == 2025
            assert scores["CVE-2024-0001"].date.month == 10
            assert scores["CVE-2024-0001"].date.day == 19

    def test_fetch_daily_epss_file_network_error(self, tmp_path):
        """Test handling network errors when fetching daily EPSS file."""
        client = EPSSClient(cache_dir=tmp_path)

        with patch("requests.get") as mock_get:
            mock_get.side_effect = Exception("Network timeout")
            scores = client.fetch_daily_epss_file()

            # Should return empty dict on error
            assert scores == {}

    def test_fetch_epss_scores_100_cve_limit(self, tmp_path):
        """Test that API requests are limited to 100 CVEs max."""
        client = EPSSClient(cache_dir=tmp_path)

        # Create 150 CVE IDs
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(150)]

        with patch.object(EPSSClient, "get") as mock_get:
            mock_get.return_value = {"data": [], "score_date": "2025-01-01T00:00:00Z"}

            client.fetch_epss_scores(cve_ids)

            # Should only send first 100 CVEs
            call_args = mock_get.call_args
            cve_param = call_args[1]["params"]["cve"]
            sent_cves = cve_param.split(",")
            assert len(sent_cves) == 100

    def test_get_headers(self, tmp_path):
        """Test that EPSS client sets correct headers."""
        client = EPSSClient(cache_dir=tmp_path)
        headers = client.get_headers()

        assert "Accept" in headers
        assert headers["Accept"] == "application/json"
