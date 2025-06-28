"""Base API client with rate limiting, caching, and retry logic."""

import hashlib
import json
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional, Union

import requests
import structlog
from requests.adapters import HTTPAdapter
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)
from urllib3.util.retry import Retry


class RateLimiter:
    """Simple rate limiter implementation."""

    def __init__(self, calls: int, period: float):
        """Initialize rate limiter.
        
        Args:
            calls: Number of calls allowed in the period
            period: Time period in seconds
        """
        self.calls = calls
        self.period = period
        self.call_times: list[float] = []

    def wait_if_needed(self) -> None:
        """Wait if rate limit would be exceeded."""
        now = time.time()
        # Remove old calls outside the period
        self.call_times = [t for t in self.call_times if now - t < self.period]
        
        if len(self.call_times) >= self.calls:
            # Calculate wait time
            wait_time = self.period - (now - self.call_times[0]) + 0.1
            if wait_time > 0:
                time.sleep(wait_time)
        
        self.call_times.append(now)


class BaseAPIClient(ABC):
    """Abstract base class for API clients with common functionality."""

    def __init__(
        self,
        base_url: str,
        cache_dir: Optional[Path] = None,
        cache_ttl: int = 86400 * 10,  # 10 days default
        rate_limit_calls: int = 10,
        rate_limit_period: float = 60.0,
        timeout: int = 30,
    ):
        """Initialize base API client.
        
        Args:
            base_url: Base URL for the API
            cache_dir: Directory for caching responses
            cache_ttl: Cache time-to-live in seconds
            rate_limit_calls: Number of calls allowed per period
            rate_limit_period: Rate limit period in seconds
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.cache_dir = cache_dir
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self.logger = structlog.get_logger(self.__class__.__name__)
        
        # Set up rate limiting
        self.rate_limiter = RateLimiter(rate_limit_calls, rate_limit_period)
        
        # Set up session with retry logic
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set up headers
        self.session.headers.update(self.get_headers())

    @abstractmethod
    def get_headers(self) -> Dict[str, str]:
        """Get headers for API requests."""
        return {
            "User-Agent": "Morning-Vuln-Briefing/1.0",
            "Accept": "application/json",
        }

    def _get_cache_path(self, cache_key: str) -> Optional[Path]:
        """Get cache file path for a given key."""
        if not self.cache_dir:
            return None
        
        # Create cache directory if it doesn't exist
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Use SHA256 to avoid filesystem issues with special characters
        safe_key = hashlib.sha256(cache_key.encode()).hexdigest()
        return self.cache_dir / f"{safe_key}.json"

    def _is_cache_valid(self, cache_path: Path) -> bool:
        """Check if cache file is still valid."""
        if not cache_path.exists():
            return False
        
        # Check age
        cache_age = time.time() - cache_path.stat().st_mtime
        return cache_age < self.cache_ttl

    def _read_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Read data from cache if available and valid."""
        cache_path = self._get_cache_path(cache_key)
        if not cache_path:
            return None
        
        if self._is_cache_valid(cache_path):
            try:
                with open(cache_path, "r") as f:
                    data = json.load(f)
                self.logger.debug("Cache hit", cache_key=cache_key)
                return data
            except Exception as e:
                self.logger.warning("Failed to read cache", error=str(e))
        
        return None

    def _write_cache(self, cache_key: str, data: Dict[str, Any]) -> None:
        """Write data to cache."""
        cache_path = self._get_cache_path(cache_key)
        if not cache_path:
            return
        
        try:
            with open(cache_path, "w") as f:
                json.dump(data, f, indent=2)
            self.logger.debug("Cache written", cache_key=cache_key)
        except Exception as e:
            self.logger.warning("Failed to write cache", error=str(e))

    @retry(
        retry=retry_if_exception_type(requests.exceptions.RequestException),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
    )
    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        """Make HTTP request with retry logic."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        # Apply rate limiting
        self.rate_limiter.wait_if_needed()
        
        self.logger.debug(
            "Making request",
            method=method,
            url=url,
            params=params,
        )
        
        response = self.session.request(
            method=method,
            url=url,
            params=params,
            json=json_data,
            timeout=self.timeout,
        )
        
        response.raise_for_status()
        return response

    def get(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        use_cache: bool = True,
    ) -> Dict[str, Any]:
        """Make GET request with caching support."""
        # Generate cache key
        cache_key = f"GET:{endpoint}:{json.dumps(params, sort_keys=True)}"
        
        # Check cache first
        if use_cache:
            cached_data = self._read_cache(cache_key)
            if cached_data is not None:
                return cached_data
        
        # Make request
        response = self._make_request("GET", endpoint, params=params)
        data = response.json()
        
        # Cache the response
        if use_cache:
            self._write_cache(cache_key, data)
        
        return data

    def post(
        self,
        endpoint: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Make POST request."""
        response = self._make_request(
            "POST", endpoint, params=params, json_data=json_data
        )
        return response.json()