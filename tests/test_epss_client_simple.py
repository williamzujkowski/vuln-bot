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
