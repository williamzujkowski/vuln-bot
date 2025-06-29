"""Extended tests for base client to improve coverage."""

import json
import time
from unittest.mock import Mock, patch

import pytest
import requests

from scripts.harvest.base_client import BaseAPIClient, RateLimiter


class TestBaseAPIClientExtended:
    """Extended test cases for BaseAPIClient."""

    @pytest.fixture
    def temp_cache_dir(self, tmp_path):
        """Create temporary cache directory."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        return cache_dir

    @pytest.fixture
    def client_with_cache(self, temp_cache_dir):
        """Create client with caching enabled."""
        return BaseAPIClient(
            base_url="https://api.example.com", cache_dir=temp_cache_dir, cache_ttl=3600
        )

    def test_cache_operations(self, client_with_cache):
        """Test cache read/write operations."""
        test_data = {"key": "value", "number": 42}
        cache_key = "test_key"

        # Write to cache
        cache_path = client_with_cache._get_cache_path(cache_key)
        client_with_cache._write_cache(cache_path, test_data)

        # Verify file exists
        assert cache_path.exists()

        # Read from cache
        cached_data = client_with_cache._read_cache(cache_path)
        assert cached_data == test_data

    def test_cache_expiration(self, client_with_cache):
        """Test cache TTL expiration."""
        cache_key = "expired_key"
        cache_path = client_with_cache._get_cache_path(cache_key)

        # Write expired cache
        old_time = time.time() - 7200  # 2 hours ago
        client_with_cache._write_cache(cache_path, {"data": "old"})

        # Manually set old modification time
        import os

        os.utime(cache_path, (old_time, old_time))

        # Check if cache is valid
        assert not client_with_cache._is_cache_valid(cache_path)

    def test_make_request_with_retries(self, client_with_cache):
        """Test request retry logic."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "success"}

        with patch("requests.Session.request") as mock_request:
            # First two attempts fail, third succeeds
            mock_request.side_effect = [
                requests.exceptions.ConnectionError("Network error"),
                requests.exceptions.Timeout("Timeout"),
                mock_response,
            ]

            result = client_with_cache._make_request("GET", "/test")
            assert result == {"result": "success"}
            assert mock_request.call_count == 3

    def test_make_request_all_retries_fail(self, client_with_cache):
        """Test when all retries fail."""
        with patch("requests.Session.request") as mock_request:
            mock_request.side_effect = requests.exceptions.ConnectionError(
                "Network error"
            )

            with pytest.raises(requests.exceptions.ConnectionError):
                client_with_cache._make_request("GET", "/test")

            # Should attempt max_retries times
            assert mock_request.call_count == client_with_cache.max_retries

    def test_get_with_cache_hit(self, client_with_cache):
        """Test GET request with cache hit."""
        endpoint = "/test"
        cached_data = {"cached": True, "data": "test"}

        # Pre-populate cache
        cache_path = client_with_cache._get_cache_path(endpoint)
        client_with_cache._write_cache(cache_path, cached_data)

        # Should return cached data without making request
        with patch.object(client_with_cache, "_make_request") as mock_request:
            result = client_with_cache.get(endpoint)
            assert result == cached_data
            mock_request.assert_not_called()

    def test_get_with_cache_miss(self, client_with_cache):
        """Test GET request with cache miss."""
        endpoint = "/test"
        response_data = {"fresh": True, "data": "new"}

        with patch.object(
            client_with_cache, "_make_request", return_value=response_data
        ):
            result = client_with_cache.get(endpoint)
            assert result == response_data

            # Verify data was cached
            cache_path = client_with_cache._get_cache_path(endpoint)
            assert cache_path.exists()

    def test_post_request(self, client_with_cache):
        """Test POST request (should not use cache)."""
        endpoint = "/create"
        post_data = {"name": "test"}
        response_data = {"id": 123, "created": True}

        with patch.object(
            client_with_cache, "_make_request", return_value=response_data
        ) as mock_request:
            result = client_with_cache.post(endpoint, data=post_data)
            assert result == response_data
            mock_request.assert_called_once_with("POST", endpoint, json=post_data)

    def test_request_with_params(self, client_with_cache):
        """Test request with query parameters."""
        endpoint = "/search"
        params = {"q": "test", "limit": 10}

        with patch.object(client_with_cache, "_make_request") as mock_request:
            client_with_cache.get(endpoint, params=params)
            mock_request.assert_called_with("GET", endpoint, params=params)

    def test_request_with_headers(self, client_with_cache):
        """Test request with custom headers."""
        client_with_cache.headers = {"Authorization": "Bearer token"}

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "test"}

        with patch(
            "requests.Session.request", return_value=mock_response
        ) as mock_request:
            client_with_cache._make_request("GET", "/test")

            # Verify headers were included
            call_kwargs = mock_request.call_args[1]
            assert "headers" in call_kwargs
            assert call_kwargs["headers"]["Authorization"] == "Bearer token"

    def test_handle_response_errors(self, client_with_cache):
        """Test response error handling."""
        # Test 404 error
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = requests.HTTPError("Not found")

        with patch(
            "requests.Session.request", return_value=mock_response
        ), pytest.raises(requests.HTTPError):
            client_with_cache._make_request("GET", "/notfound")

    def test_json_decode_error(self, client_with_cache):
        """Test handling of invalid JSON responses."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("Invalid", "", 0)
        mock_response.text = "Invalid JSON"

        with patch(
            "requests.Session.request", return_value=mock_response
        ), pytest.raises(json.JSONDecodeError):
            client_with_cache._make_request("GET", "/badjson")

    def test_rate_limiter_wait(self):
        """Test rate limiter waiting behavior."""
        # Create rate limiter with 2 requests per second
        limiter = RateLimiter(requests_per_second=2)

        start_time = time.time()

        # Make 3 requests rapidly
        for _ in range(3):
            limiter.wait_if_needed()

        elapsed = time.time() - start_time

        # Third request should have waited ~0.5 seconds
        assert elapsed >= 0.4  # Allow some tolerance

    def test_session_persistence(self):
        """Test that session is reused across requests."""
        client = BaseAPIClient(base_url="https://api.example.com")

        # Access session twice
        session1 = client.session
        session2 = client.session

        # Should be the same session object
        assert session1 is session2

    def test_cache_key_sanitization(self, client_with_cache):
        """Test cache key sanitization for filesystem safety."""
        # Test with special characters
        endpoint = "/test?param=value&special=chars/\\<>:|*"
        cache_path = client_with_cache._get_cache_path(endpoint)

        # Path should be valid and not contain illegal characters
        assert cache_path.parent.exists()
        assert "*" not in str(cache_path)
        assert "/" not in cache_path.name
        assert "\\" not in cache_path.name
