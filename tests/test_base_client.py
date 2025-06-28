"""Tests for base API client."""

import json
from datetime import datetime
from unittest.mock import Mock, patch

import pytest
import requests

from scripts.harvest.base_client import BaseAPIClient


class ConcreteAPIClient(BaseAPIClient):
    """Concrete implementation for testing."""

    def get_headers(self):
        """Return headers for API requests."""
        return {"User-Agent": "Test Client"}


class TestBaseAPIClient:
    """Test BaseAPIClient functionality."""

    def test_initialization(self, tmp_path):
        """Test client initialization."""
        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=tmp_path,
            cache_ttl=24 * 3600,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        assert client.base_url == "https://api.example.com"
        assert client.cache_dir == tmp_path
        assert client.cache_ttl == 24 * 3600  # 24 hours in seconds
        assert client.rate_limiter.calls == 100
        assert client.rate_limiter.period == 60

    def test_cache_disabled(self):
        """Test client with caching disabled."""
        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=None,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        assert client.cache_dir is None

    @patch("requests.get")
    def test_make_request_success(self, mock_get):
        """Test successful API request."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "test"}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=None,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        result = client._make_request("/test", params={"key": "value"})
        assert result == {"data": "test"}

        mock_get.assert_called_once_with(
            "https://api.example.com/test",
            params={"key": "value"},
            headers=None,
            timeout=30,
        )

    @patch("requests.get")
    def test_make_request_with_headers(self, mock_get):
        """Test API request with custom headers."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "test"}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=None,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        headers = {"Authorization": "Bearer token"}
        result = client._make_request("/test", headers=headers)
        assert result == {"data": "test"}

        mock_get.assert_called_once_with(
            "https://api.example.com/test",
            params=None,
            headers=headers,
            timeout=30,
        )

    @patch("requests.get")
    def test_make_request_retry(self, mock_get):
        """Test API request with retry on failure."""
        # First two calls fail, third succeeds
        mock_response_fail = Mock()
        mock_response_fail.status_code = 500
        mock_response_fail.raise_for_status.side_effect = requests.HTTPError()

        mock_response_success = Mock()
        mock_response_success.status_code = 200
        mock_response_success.json.return_value = {"data": "test"}
        mock_response_success.raise_for_status = Mock()

        mock_get.side_effect = [
            mock_response_fail,
            mock_response_fail,
            mock_response_success,
        ]

        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=None,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        with patch("time.sleep"):  # Mock sleep to speed up test
            result = client._make_request("/test", max_retries=3)
            assert result == {"data": "test"}
            assert mock_get.call_count == 3

    @patch("requests.get")
    def test_make_request_max_retries_exceeded(self, mock_get):
        """Test API request fails after max retries."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = requests.HTTPError()
        mock_get.return_value = mock_response

        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=None,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        with patch("time.sleep"):  # Mock sleep to speed up test
            with pytest.raises(requests.HTTPError):
                client._make_request("/test", max_retries=2)
            assert mock_get.call_count == 2

    def test_get_cache_path(self, tmp_path):
        """Test cache path generation."""
        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=tmp_path,
            cache_ttl=24 * 3600,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        cache_path = client._get_cache_path("/test", {"key": "value"})
        assert cache_path.parent == tmp_path
        assert cache_path.suffix == ".json"
        # Should include URL and params in filename
        assert "test" in cache_path.name
        assert "key" in cache_path.name

    def test_is_cache_valid_not_exists(self, tmp_path):
        """Test cache validity when file doesn't exist."""
        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=tmp_path,
            cache_ttl=24 * 3600,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        cache_path = tmp_path / "nonexistent.json"
        assert not client._is_cache_valid(cache_path)

    def test_is_cache_valid_expired(self, tmp_path):
        """Test cache validity when file is expired."""
        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=tmp_path,
            cache_ttl=24 * 3600,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        cache_path = tmp_path / "expired.json"
        cache_path.write_text("{}")
        # Set modification time to 25 hours ago
        old_time = datetime.now().timestamp() - (25 * 3600)
        cache_path.touch()
        cache_path.chmod(0o666)

        # Mock os.path.getmtime to return old timestamp
        with patch("os.path.getmtime", return_value=old_time):
            assert not client._is_cache_valid(cache_path)

    def test_is_cache_valid_fresh(self, tmp_path):
        """Test cache validity when file is fresh."""
        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=tmp_path,
            cache_ttl=24 * 3600,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        cache_path = tmp_path / "fresh.json"
        cache_path.write_text("{}")
        assert client._is_cache_valid(cache_path)

    def test_read_cache(self, tmp_path):
        """Test reading from cache."""
        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=tmp_path,
            cache_ttl=24 * 3600,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        cache_path = tmp_path / "data.json"
        test_data = {"key": "value", "number": 42}
        cache_path.write_text(json.dumps(test_data))

        result = client._read_cache(cache_path)
        assert result == test_data

    def test_write_cache(self, tmp_path):
        """Test writing to cache."""
        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=tmp_path,
            cache_ttl=24 * 3600,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        cache_path = tmp_path / "output.json"
        test_data = {"key": "value", "number": 42}

        client._write_cache(cache_path, test_data)
        assert cache_path.exists()

        with open(cache_path) as f:
            saved_data = json.load(f)
        assert saved_data == test_data

    def test_write_cache_creates_directory(self, tmp_path):
        """Test cache write creates directory if needed."""
        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=tmp_path / "subdir",
            cache_ttl=24 * 3600,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        cache_path = client.cache_dir / "data.json"
        test_data = {"key": "value"}

        client._write_cache(cache_path, test_data)
        assert cache_path.exists()
        assert client.cache_dir.exists()

    @patch("requests.get")
    def test_get_with_cache_hit(self, mock_get, tmp_path):
        """Test GET request with cache hit."""
        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=tmp_path,
            cache_ttl=24 * 3600,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        # Pre-populate cache
        cache_path = client._get_cache_path("/test", {"key": "value"})
        cache_data = {"cached": True, "data": "test"}
        client._write_cache(cache_path, cache_data)

        result = client.get("/test", params={"key": "value"})
        assert result == cache_data
        # Should not make API call
        mock_get.assert_not_called()

    @patch("requests.get")
    def test_get_with_cache_miss(self, mock_get, tmp_path):
        """Test GET request with cache miss."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"fresh": True, "data": "test"}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=tmp_path,
            cache_ttl=24 * 3600,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        result = client.get("/test", params={"key": "value"})
        assert result == {"fresh": True, "data": "test"}
        mock_get.assert_called_once()

        # Verify cache was written
        cache_path = client._get_cache_path("/test", {"key": "value"})
        assert cache_path.exists()

    @patch("requests.get")
    def test_get_bypass_cache(self, mock_get, tmp_path):
        """Test GET request bypassing cache."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"fresh": True}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=tmp_path,
            cache_ttl=24 * 3600,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        # Pre-populate cache
        cache_path = client._get_cache_path("/test", {})
        client._write_cache(cache_path, {"cached": True})

        result = client.get("/test", use_cache=False)
        assert result == {"fresh": True}
        mock_get.assert_called_once()

    def test_clear_expired_cache(self, tmp_path):
        """Test clearing expired cache entries."""
        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=tmp_path,
            cache_ttl=24 * 3600,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        # Create mix of fresh and expired cache files
        fresh_file = tmp_path / "fresh.json"
        expired_file = tmp_path / "expired.json"

        fresh_file.write_text("{}")
        expired_file.write_text("{}")

        # Set expired file's modification time to 25 hours ago
        old_time = datetime.now().timestamp() - (25 * 3600)

        with patch("os.path.getmtime") as mock_getmtime:
            # Return old time for expired file, current time for fresh file
            def getmtime_side_effect(path):
                if "expired" in str(path):
                    return old_time
                return datetime.now().timestamp()

            mock_getmtime.side_effect = getmtime_side_effect

            client.clear_expired_cache()

            # Fresh file should still exist
            assert fresh_file.exists()
            # Expired file should be removed
            assert not expired_file.exists()

    def test_clear_expired_cache_no_cache_dir(self):
        """Test clearing cache when cache is disabled."""
        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=None,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        # Should not raise error
        client.clear_expired_cache()

    def test_rate_limiter_wait(self):
        """Test rate limiter enforces wait time."""
        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=None,
            rate_limit_calls=2,
            rate_limit_period=1,  # 1 second window
        )

        with patch("time.time") as mock_time, patch("time.sleep") as mock_sleep:
            # Set up time sequence
            mock_time.side_effect = [0, 0, 0.5, 0.5, 0.6]

            # First two calls should succeed without waiting
            client.rate_limiter.wait_if_needed()
            client.rate_limiter.call_times.append(0)  # Record the call
            client.rate_limiter.wait_if_needed()
            client.rate_limiter.call_times.append(0)  # Record the call

            # Third call should wait
            client.rate_limiter.wait_if_needed()

            # Verify sleep was called to wait for rate limit window
            mock_sleep.assert_called()
