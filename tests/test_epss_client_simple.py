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
        assert client._batch_size == 30

    @patch("requests.get")
    def test_fetch_epss_scores_success(self, mock_get, tmp_path):
        """Test successful EPSS score fetching."""
        # Mock response with gzipped CSV data
        csv_data = b"cve,epss,percentile\nCVE-2025-0001,0.12345,0.95432\nCVE-2025-0002,0.00123,0.12345"
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
        cve_ids = ["CVE-2025-0001", "CVE-2025-0002"]

        scores = client.fetch_epss_scores(cve_ids)

        assert len(scores) == 2
        assert scores["CVE-2025-0001"]["epss"] == 0.12345
        assert scores["CVE-2025-0001"]["percentile"] == 0.95432
        assert scores["CVE-2025-0002"]["epss"] == 0.00123
        assert scores["CVE-2025-0002"]["percentile"] == 0.12345

    @patch("requests.get")
    def test_fetch_epss_scores_empty_response(self, mock_get, tmp_path):
        """Test handling empty EPSS response."""
        # Mock response with only header
        csv_data = b"cve,epss,percentile\n"
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
        scores = client.fetch_epss_scores(["CVE-2025-0001"])

        assert len(scores) == 0

    @patch("requests.get")
    def test_fetch_epss_scores_error_handling(self):
        """Test error handling in EPSS score fetching."""
        # Create client without cache to test error handling
        client = EPSSClient(cache_dir=None)

        with patch("scripts.harvest.epss_client.EPSSClient.get") as mock_get:
            mock_get.side_effect = Exception("Network error")
            scores = client.fetch_epss_scores(["CVE-2025-9999"])  # Use non-existent CVE

            # Should return empty dict on error
            assert scores == {}

    def test_batch_size_limit(self, tmp_path):
        """Test batch size is respected."""
        client = EPSSClient(cache_dir=tmp_path)

        # Create more CVEs than batch size
        cve_ids = [f"CVE-2025-{i:04d}" for i in range(100)]

        # The client should handle this internally by batching
        # We just verify it doesn't crash
        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.content = gzip.compress(b"cve,epss,percentile\n")
            mock_response.raise_for_status = Mock()
            mock_get.return_value = {"data": []}

            client.fetch_epss_scores(cve_ids)

            # Should have made at least one call
            assert mock_get.call_count >= 1
