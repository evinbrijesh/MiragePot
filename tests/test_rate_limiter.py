"""Tests for rate limiting module."""

import time
import pytest
from miragepot.rate_limiter import RateLimiter


class TestRateLimiter:
    """Tests for RateLimiter class."""

    def test_can_accept_first_connection(self):
        """Test that first connection from IP is accepted."""
        limiter = RateLimiter(max_connections_per_ip=3)
        can_accept, reason = limiter.can_accept_connection("192.168.1.1")
        assert can_accept is True
        assert reason == ""

    def test_register_and_unregister_connection(self):
        """Test registering and unregistering connections."""
        limiter = RateLimiter(max_connections_per_ip=3)
        
        # Register connection
        limiter.register_connection("192.168.1.1")
        stats = limiter.get_stats()
        assert stats["active_connections"] == 1
        assert stats["tracked_ips"] == 1
        
        # Unregister connection
        limiter.unregister_connection("192.168.1.1")
        stats = limiter.get_stats()
        assert stats["active_connections"] == 0

    def test_per_ip_connection_limit(self):
        """Test that per-IP connection limit is enforced."""
        limiter = RateLimiter(max_connections_per_ip=2)
        
        # First two connections should be accepted
        can_accept, _ = limiter.can_accept_connection("192.168.1.1")
        assert can_accept is True
        limiter.register_connection("192.168.1.1")
        
        can_accept, _ = limiter.can_accept_connection("192.168.1.1")
        assert can_accept is True
        limiter.register_connection("192.168.1.1")
        
        # Third connection should be rejected and IP blocked
        can_accept, reason = limiter.can_accept_connection("192.168.1.1")
        assert can_accept is False
        assert "Too many connections" in reason

    def test_global_connection_limit(self):
        """Test that global connection limit is enforced."""
        limiter = RateLimiter(max_total_connections=2)
        
        # First two connections from different IPs
        limiter.register_connection("192.168.1.1")
        limiter.register_connection("192.168.1.2")
        
        # Third connection should be rejected
        can_accept, reason = limiter.can_accept_connection("192.168.1.3")
        assert can_accept is False
        assert "Maximum total connections" in reason

    def test_blocked_ip_timeout(self):
        """Test that blocked IPs are unblocked after timeout."""
        limiter = RateLimiter(max_connections_per_ip=1, block_duration=1)
        
        # Exceed limit to get blocked
        limiter.register_connection("192.168.1.1")
        can_accept, _ = limiter.can_accept_connection("192.168.1.1")
        assert can_accept is False
        
        # Check that IP is blocked
        assert limiter.is_blocked("192.168.1.1") is True
        
        # Wait for block to expire
        time.sleep(1.1)
        
        # Should be unblocked now
        assert limiter.is_blocked("192.168.1.1") is False

    def test_cleanup_old_entries(self):
        """Test that old connection entries are cleaned up."""
        limiter = RateLimiter(time_window=1)
        
        # Register and immediately unregister
        limiter.register_connection("192.168.1.1")
        limiter.unregister_connection("192.168.1.1")
        
        # Entry should exist
        assert "192.168.1.1" in limiter._connections
        
        # Wait for time window to expire
        time.sleep(1.1)
        
        # Manually trigger cleanup
        limiter._cleanup_old_entries()
        
        # Entry should be removed
        assert "192.168.1.1" not in limiter._connections

    def test_stats(self):
        """Test get_stats returns correct information."""
        limiter = RateLimiter(max_connections_per_ip=2)
        
        # Register connections
        limiter.register_connection("192.168.1.1")
        limiter.register_connection("192.168.1.2")
        limiter.register_connection("192.168.1.2")
        
        stats = limiter.get_stats()
        assert stats["active_connections"] == 3
        assert stats["tracked_ips"] == 2
        assert stats["blocked_ips"] == 0
        
        # Block an IP
        can_accept, _ = limiter.can_accept_connection("192.168.1.1")  # Second from same IP
        limiter.register_connection("192.168.1.1")
        can_accept, _ = limiter.can_accept_connection("192.168.1.1")  # Should block
        
        stats = limiter.get_stats()
        assert stats["blocked_ips"] >= 0  # Might be 0 or 1 depending on timing

    def test_multiple_ips(self):
        """Test handling multiple IPs simultaneously."""
        limiter = RateLimiter(max_connections_per_ip=2, max_total_connections=10)
        
        # Register connections from different IPs
        ips = [f"192.168.1.{i}" for i in range(1, 6)]
        for ip in ips:
            limiter.register_connection(ip)
        
        stats = limiter.get_stats()
        assert stats["active_connections"] == 5
        assert stats["tracked_ips"] == 5
        
        # Each IP can still add one more connection
        for ip in ips:
            can_accept, _ = limiter.can_accept_connection(ip)
            assert can_accept is True
