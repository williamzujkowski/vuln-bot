"""Tests for EPSS API client."""

import gzip
import io
from datetime import datetime
from unittest.mock import Mock, patch

from scripts.harvest.epss_client import EPSSClient


class TestEPSSClient:
    """Test EPSSClient functionality."""

    def test_initialization(self, tmp_path):
        """Test client initialization."""
        client = EPSSClient(cache_dir=tmp_path)
        assert client.base_url == "https://api.first.org/data/v1"
        assert client._batch_size == 30

    @patch("requests.get")
    def test_fetch_epss_scores_single_batch(self, mock_get, tmp_path):
        """Test fetching EPSS scores for a single batch."""
        # Mock response with gzipped CSV data
        csv_data = b"cve,epss,percentile\nCVE-2023-0001,0.12345,0.95432\nCVE-2023-0002,0.00123,0.12345"
        compressed_data = io.BytesIO()
        with gzip.GzipFile(fileobj=compressed_data, mode="wb") as gz:
            gz.write(csv_data)
        compressed_data.seek(0)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = compressed_data.read()
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        client = EPSSClient(cache_dir=tmp_path)
        cve_ids = ["CVE-2023-0001", "CVE-2023-0002"]

        scores = client.fetch_epss_scores(cve_ids)

        assert len(scores) == 2
        assert scores["CVE-2023-0001"]["epss"] == 0.12345
        assert scores["CVE-2023-0001"]["percentile"] == 0.95432
        assert scores["CVE-2023-0002"]["epss"] == 0.00123
        assert scores["CVE-2023-0002"]["percentile"] == 0.12345

    @patch("requests.get")
    def test_fetch_epss_scores_multiple_batches(self, mock_get, tmp_path):
        """Test fetching EPSS scores with multiple batches."""

        # Create response for each batch
        def create_response(cve_ids):
            csv_lines = ["cve,epss,percentile"]
            for cve_id in cve_ids:
                # Simple formula for test data
                num = int(cve_id.split("-")[-1])
                csv_lines.append(f"{cve_id},{num / 10000:.5f},{num / 100:.5f}")

            csv_data = "\n".join(csv_lines).encode()
            compressed_data = io.BytesIO()
            with gzip.GzipFile(fileobj=compressed_data, mode="wb") as gz:
                gz.write(csv_data)
            compressed_data.seek(0)

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.content = compressed_data.read()
            mock_response.raise_for_status = Mock()
            return mock_response

        # Create 35 CVE IDs (more than one batch)
        cve_ids = [f"CVE-2023-{i:04d}" for i in range(35)]

        # Mock responses for two batches
        mock_get.side_effect = [
            create_response(cve_ids[:30]),
            create_response(cve_ids[30:]),
        ]

        client = EPSSClient(cache_dir=tmp_path)
        scores = client.fetch_epss_scores(cve_ids)

        assert len(scores) == 35
        assert mock_get.call_count == 2
        # Verify some scores
        assert scores["CVE-2023-0001"]["epss"] == 0.00010
        assert scores["CVE-2023-0034"]["epss"] == 0.00340

    @patch("requests.get")
    def test_fetch_epss_scores_empty_list(self, mock_get, tmp_path):
        """Test fetching EPSS scores with empty CVE list."""
        client = EPSSClient(cache_dir=tmp_path)
        scores = client.fetch_epss_scores([])

        assert scores == {}
        mock_get.assert_not_called()

    @patch("requests.get")
    def test_fetch_epss_scores_api_error(self, mock_get, tmp_path):
        """Test handling API errors."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = Exception("API Error")
        mock_get.return_value = mock_response

        client = EPSSClient(cache_dir=tmp_path)
        cve_ids = ["CVE-2023-0001"]

        with patch("scripts.harvest.epss_client.logger") as mock_logger:
            scores = client.fetch_epss_scores(cve_ids)
            assert scores == {}
            mock_logger.error.assert_called()

    @patch("requests.get")
    def test_fetch_epss_scores_invalid_csv(self, mock_get, tmp_path):
        """Test handling invalid CSV data."""
        # Invalid CSV data
        csv_data = b"invalid,csv,data\nno,proper,headers"
        compressed_data = io.BytesIO()
        with gzip.GzipFile(fileobj=compressed_data, mode="wb") as gz:
            gz.write(csv_data)
        compressed_data.seek(0)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = compressed_data.read()
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        client = EPSSClient(cache_dir=tmp_path)
        cve_ids = ["CVE-2023-0001"]

        with patch("scripts.harvest.epss_client.logger") as mock_logger:
            scores = client.fetch_epss_scores(cve_ids)
            assert scores == {}
            mock_logger.error.assert_called()

    @patch("requests.get")
    def test_fetch_epss_scores_missing_values(self, mock_get, tmp_path):
        """Test handling CSV with missing values."""
        # CSV with missing percentile
        csv_data = (
            b"cve,epss,percentile\nCVE-2023-0001,0.12345,\nCVE-2023-0002,,0.12345"
        )
        compressed_data = io.BytesIO()
        with gzip.GzipFile(fileobj=compressed_data, mode="wb") as gz:
            gz.write(csv_data)
        compressed_data.seek(0)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = compressed_data.read()
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        client = EPSSClient(cache_dir=tmp_path)
        cve_ids = ["CVE-2023-0001", "CVE-2023-0002"]

        scores = client.fetch_epss_scores(cve_ids)

        # Should skip entries with missing values
        assert len(scores) == 0

    def test_parse_epss_batch(self, tmp_path):
        """Test parsing EPSS data into EPSSScore objects."""
        client = EPSSClient(cache_dir=tmp_path)

        epss_data = {
            "CVE-2023-0001": {"epss": 0.12345, "percentile": 0.95432},
            "CVE-2023-0002": {"epss": 0.00123, "percentile": 0.12345},
        }

        scores = client.parse_epss_batch(epss_data)

        assert len(scores) == 2

        # Verify first score
        score1 = next(s for s in scores if s.cve_id == "CVE-2023-0001")
        assert score1.score == 0.1235  # Rounded to 4 decimal places
        assert score1.percentile == 0.9543
        assert isinstance(score1.date, datetime)

        # Verify second score
        score2 = next(s for s in scores if s.cve_id == "CVE-2023-0002")
        assert score2.score == 0.0012  # Rounded to 4 decimal places
        assert score2.percentile == 0.1235

    def test_parse_epss_batch_empty(self, tmp_path):
        """Test parsing empty EPSS data."""
        client = EPSSClient(cache_dir=tmp_path)
        scores = client.parse_epss_batch({})
        assert scores == []

    def test_parse_epss_batch_invalid_data(self, tmp_path):
        """Test parsing invalid EPSS data."""
        client = EPSSClient(cache_dir=tmp_path)

        epss_data = {
            "CVE-2023-0001": {"epss": "invalid", "percentile": 0.95432},
            "CVE-2023-0002": {"epss": 0.12345},  # Missing percentile
        }

        with patch("scripts.harvest.epss_client.logger") as mock_logger:
            scores = client.parse_epss_batch(epss_data)
            assert len(scores) == 0
            assert mock_logger.error.call_count == 2

    @patch.object(EPSSClient, "fetch_epss_scores")
    def test_harvest(self, mock_fetch, tmp_path):
        """Test harvest method."""
        mock_fetch.return_value = {
            "CVE-2023-0001": {"epss": 0.12345, "percentile": 0.95432},
        }

        client = EPSSClient(cache_dir=tmp_path)
        cve_ids = ["CVE-2023-0001"]

        scores = client.harvest(cve_ids)

        assert len(scores) == 1
        assert scores[0].cve_id == "CVE-2023-0001"
        mock_fetch.assert_called_once_with(cve_ids)

    def test_harvest_empty_list(self, tmp_path):
        """Test harvest with empty CVE list."""
        client = EPSSClient(cache_dir=tmp_path)
        scores = client.harvest([])
        assert scores == []

    @patch.object(EPSSClient, "fetch_epss_scores")
    def test_harvest_error_handling(self, mock_fetch, tmp_path):
        """Test error handling in harvest method."""
        mock_fetch.side_effect = Exception("API Error")

        client = EPSSClient(cache_dir=tmp_path)
        cve_ids = ["CVE-2023-0001"]

        with patch("scripts.harvest.epss_client.logger") as mock_logger:
            scores = client.harvest(cve_ids)
            assert scores == []
            mock_logger.error.assert_called()

    @patch("requests.get")
    def test_caching_behavior(self, mock_get, tmp_path):
        """Test that caching works properly."""
        # Mock response
        csv_data = b"cve,epss,percentile\nCVE-2023-0001,0.12345,0.95432"
        compressed_data = io.BytesIO()
        with gzip.GzipFile(fileobj=compressed_data, mode="wb") as gz:
            gz.write(csv_data)
        compressed_data.seek(0)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = compressed_data.read()
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        client = EPSSClient(cache_dir=tmp_path)
        cve_ids = ["CVE-2023-0001"]

        # First call should hit the API
        scores1 = client.fetch_epss_scores(cve_ids)
        assert mock_get.call_count == 1

        # Second call should use cache
        scores2 = client.fetch_epss_scores(cve_ids)
        assert mock_get.call_count == 1  # No additional API call

        # Results should be the same
        assert scores1 == scores2
