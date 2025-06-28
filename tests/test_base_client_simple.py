"""Simple tests for base API client."""

from scripts.harvest.base_client import BaseAPIClient, RateLimiter


class ConcreteAPIClient(BaseAPIClient):
    """Concrete implementation for testing."""

    def get_headers(self):
        """Return headers for API requests."""
        return {"User-Agent": "Test Client"}


class TestRateLimiter:
    """Test RateLimiter functionality."""

    def test_rate_limiter_initialization(self):
        """Test rate limiter initialization."""
        limiter = RateLimiter(calls=10, period=60)
        assert limiter.calls == 10
        assert limiter.period == 60
        assert len(limiter.call_times) == 0


class TestBaseAPIClientSimple:
    """Simple tests for BaseAPIClient functionality."""

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
        assert client.cache_ttl == 24 * 3600
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

    def test_get_cache_path(self, tmp_path):
        """Test cache path generation."""
        client = ConcreteAPIClient(
            base_url="https://api.example.com",
            cache_dir=tmp_path,
            cache_ttl=24 * 3600,
            rate_limit_calls=100,
            rate_limit_period=60,
        )

        cache_path = client._get_cache_path("test-key")
        assert cache_path is not None
        assert cache_path.parent == tmp_path
        assert cache_path.suffix == ".json"
        assert "test-key" in cache_path.name

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
