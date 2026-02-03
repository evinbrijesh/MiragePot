"""Rate limiting module for MiragePot.

Prevents resource exhaustion DoS attacks by tracking and limiting:
- Connections per IP address
- Total concurrent connections
- Session duration limits
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .config import SecurityConfig

LOGGER = logging.getLogger(__name__)


@dataclass
class ConnectionInfo:
    """Tracks information about a connection from an IP."""

    ip: str
    count: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    blocked_until: Optional[float] = None


class RateLimiter:
    """Rate limiter to prevent resource exhaustion attacks.

    Features:
    - Per-IP connection limits
    - Global concurrent connection limits
    - Temporary blocking of abusive IPs
    - Automatic cleanup of old tracking data
    """

    def __init__(
        self,
        max_connections_per_ip: int = 3,
        max_total_connections: int = 50,
        time_window: int = 60,
        block_duration: int = 300,
    ):
        """Initialize the rate limiter.

        Args:
            max_connections_per_ip: Maximum concurrent connections from one IP
            max_total_connections: Maximum total concurrent connections
            time_window: Time window in seconds for connection tracking
            block_duration: How long to block an IP in seconds (default: 5 minutes)
        """
        self.max_connections_per_ip = max_connections_per_ip
        self.max_total_connections = max_total_connections
        self.time_window = time_window
        self.block_duration = block_duration

        self._connections: Dict[str, ConnectionInfo] = {}
        self._active_count = 0
        self._lock = threading.Lock()
        self._cleanup_thread: Optional[threading.Thread] = None
        self._running = False

    def start_cleanup_thread(self) -> None:
        """Start the background cleanup thread."""
        if self._cleanup_thread is None or not self._cleanup_thread.is_alive():
            self._running = True
            self._cleanup_thread = threading.Thread(
                target=self._cleanup_loop, daemon=True
            )
            self._cleanup_thread.start()
            LOGGER.info("Rate limiter cleanup thread started")

    def stop_cleanup_thread(self) -> None:
        """Stop the background cleanup thread."""
        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)

    def _cleanup_loop(self) -> None:
        """Background thread to clean up old connection tracking data."""
        while self._running:
            try:
                time.sleep(60)  # Clean up every minute
                self._cleanup_old_entries()
            except Exception as exc:
                LOGGER.error("Error in cleanup thread: %s", exc)

    def _cleanup_old_entries(self) -> None:
        """Remove old connection tracking entries."""
        with self._lock:
            now = time.time()
            cutoff = now - self.time_window

            # Remove old entries
            to_remove = [
                ip
                for ip, info in self._connections.items()
                if info.count == 0
                and info.last_seen < cutoff
                and (info.blocked_until is None or info.blocked_until < now)
            ]

            for ip in to_remove:
                del self._connections[ip]

            if to_remove:
                LOGGER.debug("Cleaned up %d old connection entries", len(to_remove))

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked.

        Args:
            ip: IP address to check

        Returns:
            True if the IP is blocked, False otherwise
        """
        with self._lock:
            if ip not in self._connections:
                return False

            info = self._connections[ip]
            if info.blocked_until is None:
                return False

            # Check if block has expired
            if time.time() >= info.blocked_until:
                info.blocked_until = None
                return False

            return True

    def can_accept_connection(self, ip: str) -> tuple[bool, str]:
        """Check if a new connection from this IP should be accepted.

        Args:
            ip: IP address attempting to connect

        Returns:
            Tuple of (can_accept, reason)
            - can_accept: True if connection should be accepted
            - reason: Human-readable reason if rejected
        """
        with self._lock:
            LOGGER.debug(
                "Rate limiter checking IP: %s (current active: %d/%d total)",
                ip,
                self._active_count,
                self.max_total_connections,
            )

            # Check if IP is blocked
            if ip in self._connections:
                info = self._connections[ip]
                LOGGER.debug(
                    "IP %s - existing connections: %d/%d, blocked_until: %s",
                    ip,
                    info.count,
                    self.max_connections_per_ip,
                    info.blocked_until,
                )
                if info.blocked_until and time.time() < info.blocked_until:
                    remaining = int(info.blocked_until - time.time())
                    LOGGER.warning(
                        "IP %s is BLOCKED for %d more seconds", ip, remaining
                    )
                    return (
                        False,
                        f"IP {ip} is blocked for {remaining} more seconds",
                    )

            # Check global connection limit
            if self._active_count >= self.max_total_connections:
                LOGGER.warning(
                    "Global connection limit reached: %d/%d",
                    self._active_count,
                    self.max_total_connections,
                )
                return (
                    False,
                    f"Maximum total connections ({self.max_total_connections}) reached",
                )

            # Check per-IP limit
            if ip in self._connections:
                info = self._connections[ip]
                if info.count >= self.max_connections_per_ip:
                    # Block this IP
                    info.blocked_until = time.time() + self.block_duration
                    LOGGER.warning(
                        "IP %s exceeded connection limit (%d), blocking for %d seconds",
                        ip,
                        self.max_connections_per_ip,
                        self.block_duration,
                    )
                    return (
                        False,
                        f"Too many connections from {ip}. Blocked for {self.block_duration} seconds.",
                    )

            LOGGER.debug("Rate limiter: ALLOWING connection from %s", ip)
            return (True, "")

    def register_connection(self, ip: str) -> None:
        """Register a new connection from an IP.

        Args:
            ip: IP address of the connection
        """
        with self._lock:
            if ip not in self._connections:
                self._connections[ip] = ConnectionInfo(ip=ip)

            info = self._connections[ip]
            info.count += 1
            info.last_seen = time.time()
            self._active_count += 1

            LOGGER.info(
                "Connection from %s registered (active: %d from this IP, %d total)",
                ip,
                info.count,
                self._active_count,
            )

    def unregister_connection(self, ip: str) -> None:
        """Unregister a connection when it closes.

        Args:
            ip: IP address of the connection
        """
        with self._lock:
            if ip not in self._connections:
                LOGGER.warning("Attempted to unregister unknown IP: %s", ip)
                return

            info = self._connections[ip]
            info.count = max(0, info.count - 1)
            info.last_seen = time.time()
            self._active_count = max(0, self._active_count - 1)

            LOGGER.info(
                "Connection from %s closed (remaining: %d from this IP, %d total)",
                ip,
                info.count,
                self._active_count,
            )

    def get_stats(self) -> Dict[str, int]:
        """Get current rate limiter statistics.

        Returns:
            Dictionary with statistics
        """
        with self._lock:
            blocked_count = sum(
                1
                for info in self._connections.values()
                if info.blocked_until and time.time() < info.blocked_until
            )

            return {
                "active_connections": self._active_count,
                "tracked_ips": len(self._connections),
                "blocked_ips": blocked_count,
            }


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None
_rate_limiter_lock = threading.Lock()


def get_rate_limiter() -> RateLimiter:
    """Get or create the global rate limiter instance.

    Returns:
        Global RateLimiter instance
    """
    global _rate_limiter
    with _rate_limiter_lock:
        if _rate_limiter is None:
            # Import config here to avoid circular dependency
            from .config import get_security_config

            security_config = get_security_config()
            _rate_limiter = RateLimiter(
                max_connections_per_ip=security_config.max_connections_per_ip,
                max_total_connections=security_config.max_total_connections,
                time_window=security_config.connection_time_window,
                block_duration=security_config.block_duration,
            )
            _rate_limiter.start_cleanup_thread()
        return _rate_limiter
