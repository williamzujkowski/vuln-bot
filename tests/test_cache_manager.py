"""Tests for cache manager module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone, timedelta
import json
import sqlite3
import time

from scripts.processing.cache_manager import CacheManager


class TestCacheManager:
    """Test cases for CacheManager."""
    
    @pytest.fixture
    def cache_dir(self, tmp_path):
        """Create temporary cache directory."""
        cache_path = tmp_path / "test_cache"
        cache_path.mkdir()
        return cache_path
    
    @pytest.fixture
    def cache_manager(self, cache_dir):
        """Create cache manager instance."""
        return CacheManager(cache_dir=str(cache_dir))
    
    def test_initialization(self, cache_manager, cache_dir):
        """Test cache manager initialization."""
        assert cache_manager.cache_dir == cache_dir
        assert cache_manager.db_path == cache_dir / "cache.db"
        assert cache_manager.db_path.exists()
    
    def test_set_and_get(self, cache_manager):
        """Test basic cache operations."""
        # Set cache entry
        cache_manager.set("test_key", {"data": "test_value"}, ttl=3600)
        
        # Get cache entry
        result = cache_manager.get("test_key")
        assert result is not None
        assert result["data"] == "test_value"
    
    def test_cache_expiration(self, cache_manager):
        """Test cache TTL expiration."""
        # Set with 1 second TTL
        cache_manager.set("expire_key", {"data": "test"}, ttl=1)
        
        # Should exist immediately
        assert cache_manager.get("expire_key") is not None
        
        # Mock time to simulate expiration
        with patch("time.time", return_value=time.time() + 2):
            assert cache_manager.get("expire_key") is None
    
    def test_delete(self, cache_manager):
        """Test cache deletion."""
        cache_manager.set("delete_key", {"data": "test"})
        assert cache_manager.get("delete_key") is not None
        
        cache_manager.delete("delete_key")
        assert cache_manager.get("delete_key") is None
    
    def test_clear(self, cache_manager):
        """Test clearing all cache."""
        # Set multiple entries
        cache_manager.set("key1", {"data": 1})
        cache_manager.set("key2", {"data": 2})
        cache_manager.set("key3", {"data": 3})
        
        # Clear all
        cache_manager.clear()
        
        # All should be gone
        assert cache_manager.get("key1") is None
        assert cache_manager.get("key2") is None
        assert cache_manager.get("key3") is None
    
    def test_cleanup_expired(self, cache_manager):
        """Test cleanup of expired entries."""
        # Set entries with different TTLs
        cache_manager.set("keep", {"data": "keep"}, ttl=3600)
        cache_manager.set("expire", {"data": "expire"}, ttl=1)
        
        # Mock time and cleanup
        with patch("time.time", return_value=time.time() + 2):
            cache_manager.cleanup_expired()
        
        assert cache_manager.get("keep") is not None
        assert cache_manager.get("expire") is None
    
    def test_large_data(self, cache_manager):
        """Test caching large data."""
        large_data = {"items": [{"id": i, "data": f"item_{i}" * 100} for i in range(1000)]}
        
        cache_manager.set("large_key", large_data)
        result = cache_manager.get("large_key")
        
        assert result is not None
        assert len(result["items"]) == 1000
    
    def test_concurrent_access(self, cache_manager):
        """Test concurrent cache access."""
        import threading
        
        def write_cache(i):
            cache_manager.set(f"concurrent_{i}", {"thread": i})
        
        def read_cache(i):
            return cache_manager.get(f"concurrent_{i}")
        
        # Create multiple threads
        threads = []
        for i in range(10):
            t1 = threading.Thread(target=write_cache, args=(i,))
            t2 = threading.Thread(target=read_cache, args=(i,))
            threads.extend([t1, t2])
        
        # Start all threads
        for t in threads:
            t.start()
        
        # Wait for completion
        for t in threads:
            t.join()
        
        # Verify all writes succeeded
        for i in range(10):
            result = cache_manager.get(f"concurrent_{i}")
            assert result is not None
    
    def test_error_handling(self, cache_manager):
        """Test error handling."""
        # Invalid JSON serialization
        with patch("json.dumps", side_effect=TypeError("Not serializable")):
            # Should not raise, but return False
            result = cache_manager.set("error_key", {"data": object()})
            assert result is False
        
        # Database errors
        with patch.object(cache_manager, "_get_connection", side_effect=sqlite3.Error("DB Error")):
            assert cache_manager.get("any_key") is None
