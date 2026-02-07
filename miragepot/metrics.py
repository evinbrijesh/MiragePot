"""Prometheus metrics exporter for MiragePot.

This module provides Prometheus-compatible metrics endpoints for monitoring
honeypot activity, threat detection, and system health.

Metrics exposed:
- Connection attempts (total, successful, failed)
- Active sessions
- Commands executed (by threat level)
- Threat score distribution
- LLM response latency
- Unique attacker IPs
- Attack patterns and TTPs
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
    REGISTRY,
    CONTENT_TYPE_LATEST,
)

logger = logging.getLogger(__name__)

# =============================================================================
# Metric Definitions
# =============================================================================

# Connection metrics
connections_total = Counter(
    "miragepot_connections_total",
    "Total number of connection attempts",
    ["result"],  # success, rejected_ratelimit, failed
)

connections_active = Gauge(
    "miragepot_connections_active",
    "Currently active connections",
)

# Session metrics
sessions_total = Counter(
    "miragepot_sessions_total",
    "Total number of SSH sessions established",
)

sessions_active = Gauge(
    "miragepot_sessions_active",
    "Currently active SSH sessions",
)

session_duration = Histogram(
    "miragepot_session_duration_seconds",
    "SSH session duration in seconds",
    buckets=[10, 30, 60, 300, 600, 1800, 3600, 7200],
)

# Command execution metrics
commands_total = Counter(
    "miragepot_commands_total",
    "Total number of commands executed",
    ["threat_level"],  # low, medium, high
)

commands_by_type = Counter(
    "miragepot_commands_by_type_total",
    "Commands grouped by type",
    ["command_type"],  # reconnaissance, credential_access, etc.
)

# Threat metrics
threat_score_histogram = Histogram(
    "miragepot_threat_score",
    "Distribution of command threat scores",
    buckets=[0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
)

high_threat_commands = Counter(
    "miragepot_high_threat_commands_total",
    "Commands with threat score >= 80",
    ["command_pattern"],
)

# Attacker metrics
unique_ips_24h = Gauge(
    "miragepot_unique_attacker_ips",
    "Number of unique attacker IPs in last 24 hours",
)

attacker_countries = Gauge(
    "miragepot_attacker_countries",
    "Number of unique countries attackers originate from",
    ["country_code"],
)

# Authentication metrics
auth_attempts = Counter(
    "miragepot_auth_attempts_total",
    "Total authentication attempts",
    ["username"],
)

unique_credentials = Gauge(
    "miragepot_unique_credentials_tried",
    "Number of unique username/password combinations tried",
)

# LLM metrics
llm_requests_total = Counter(
    "miragepot_llm_requests_total",
    "Total LLM API requests",
    ["model", "result"],  # result: success, timeout, error
)

llm_latency = Histogram(
    "miragepot_llm_latency_seconds",
    "LLM response time in seconds",
    buckets=[0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0],
)

llm_cache_hits = Counter(
    "miragepot_llm_cache_hits_total",
    "Number of cache hits (avoided LLM calls)",
)

llm_cache_misses = Counter(
    "miragepot_llm_cache_misses_total",
    "Number of cache misses (required LLM calls)",
)

# TTP/MITRE ATT&CK metrics
ttp_detections = Counter(
    "miragepot_ttp_detections_total",
    "Detected TTPs/techniques",
    ["attack_stage", "technique"],
)

# System health metrics
system_info = Info(
    "miragepot_system",
    "MiragePot system information",
)

uptime_seconds = Gauge(
    "miragepot_uptime_seconds",
    "Honeypot uptime in seconds",
)

# Honeytoken metrics
honeytokens_triggered = Counter(
    "miragepot_honeytokens_triggered_total",
    "Number of honeytokens accessed",
    ["token_type"],
)


# =============================================================================
# Metrics Collector Class
# =============================================================================


class MetricsCollector:
    """Centralized metrics collection and management."""

    def __init__(self):
        self._lock = Lock()
        self._start_time = time.time()
        self._unique_ips: Dict[str, datetime] = {}  # ip -> last_seen
        self._unique_creds: set = set()
        self._country_codes: Dict[str, int] = defaultdict(int)

        # Initialize system info
        system_info.info(
            {
                "version": "1.0.0",
                "python_version": "3.11",
                "mode": "production",
            }
        )

        logger.info("Prometheus metrics collector initialized")

    # -------------------------------------------------------------------------
    # Connection Metrics
    # -------------------------------------------------------------------------

    def record_connection_attempt(self, result: str):
        """Record a connection attempt.

        Args:
            result: 'success', 'rejected_ratelimit', or 'failed'
        """
        connections_total.labels(result=result).inc()
        logger.debug(f"Connection attempt recorded: {result}")

    def increment_active_connections(self):
        """Increment active connections counter."""
        connections_active.inc()

    def decrement_active_connections(self):
        """Decrement active connections counter."""
        connections_active.dec()

    # -------------------------------------------------------------------------
    # Session Metrics
    # -------------------------------------------------------------------------

    def record_session_start(self):
        """Record the start of a new SSH session."""
        sessions_total.inc()
        sessions_active.inc()
        logger.debug("New session started")

    def record_session_end(self, duration_seconds: float):
        """Record the end of an SSH session.

        Args:
            duration_seconds: Session duration in seconds
        """
        sessions_active.dec()
        session_duration.observe(duration_seconds)
        logger.debug(f"Session ended: duration={duration_seconds:.1f}s")

    # -------------------------------------------------------------------------
    # Command Metrics
    # -------------------------------------------------------------------------

    def record_command(
        self, command: str, score: int, command_type: Optional[str] = None
    ):
        """Record a command execution.

        Args:
            command: The command executed
            score: Threat score (0-100)
            command_type: Command category (optional)
        """
        # Categorize threat level
        if score >= 80:
            threat_level = "high"
            # Extract command pattern for high-threat tracking
            pattern = command.split()[0] if command else "unknown"
            high_threat_commands.labels(command_pattern=pattern).inc()
        elif score >= 30:
            threat_level = "medium"
        else:
            threat_level = "low"

        commands_total.labels(threat_level=threat_level).inc()
        threat_score_histogram.observe(score)

        if command_type:
            commands_by_type.labels(command_type=command_type).inc()

        logger.debug(f"Command recorded: threat_level={threat_level}, score={score}")

    # -------------------------------------------------------------------------
    # Attacker Metrics
    # -------------------------------------------------------------------------

    def record_attacker_ip(self, ip: str, country_code: Optional[str] = None):
        """Record an attacker IP address.

        Args:
            ip: Attacker IP address
            country_code: Two-letter country code (optional)
        """
        with self._lock:
            self._unique_ips[ip] = datetime.now()

            # Update country counter if provided
            if country_code:
                self._country_codes[country_code] += 1
                attacker_countries.labels(country_code=country_code).set(
                    self._country_codes[country_code]
                )

            # Clean up old IPs (older than 24 hours)
            cutoff = datetime.now() - timedelta(days=1)
            self._unique_ips = {k: v for k, v in self._unique_ips.items() if v > cutoff}

            unique_ips_24h.set(len(self._unique_ips))

        logger.debug(f"Attacker IP recorded: {ip} ({country_code})")

    # -------------------------------------------------------------------------
    # Authentication Metrics
    # -------------------------------------------------------------------------

    def record_auth_attempt(self, username: str, password: str):
        """Record an authentication attempt.

        Args:
            username: Username tried
            password: Password tried
        """
        auth_attempts.labels(username=username).inc()

        with self._lock:
            cred_pair = f"{username}:{password}"
            self._unique_creds.add(cred_pair)
            unique_credentials.set(len(self._unique_creds))

        logger.debug(f"Auth attempt recorded: username={username}")

    # -------------------------------------------------------------------------
    # LLM Metrics
    # -------------------------------------------------------------------------

    def record_llm_request(
        self, model: str, result: str, latency: Optional[float] = None
    ):
        """Record an LLM API request.

        Args:
            model: LLM model used
            result: 'success', 'timeout', or 'error'
            latency: Request latency in seconds (optional)
        """
        llm_requests_total.labels(model=model, result=result).inc()

        if latency is not None:
            llm_latency.observe(latency)

        logger.debug(
            f"LLM request recorded: model={model}, result={result}, latency={latency}"
        )

    def record_cache_hit(self):
        """Record a command cache hit."""
        llm_cache_hits.inc()

    def record_cache_miss(self):
        """Record a command cache miss."""
        llm_cache_misses.inc()

    # -------------------------------------------------------------------------
    # TTP Metrics
    # -------------------------------------------------------------------------

    def record_ttp_detection(self, attack_stage: str, technique: str):
        """Record a TTP/MITRE ATT&CK technique detection.

        Args:
            attack_stage: MITRE ATT&CK tactic (e.g., 'reconnaissance')
            technique: Specific technique detected
        """
        ttp_detections.labels(attack_stage=attack_stage, technique=technique).inc()
        logger.debug(f"TTP detected: {attack_stage} - {technique}")

    # -------------------------------------------------------------------------
    # Honeytoken Metrics
    # -------------------------------------------------------------------------

    def record_honeytoken_triggered(self, token_type: str):
        """Record a honeytoken being accessed.

        Args:
            token_type: Type of honeytoken (e.g., 'file', 'credential')
        """
        honeytokens_triggered.labels(token_type=token_type).inc()
        logger.info(f"🍯 Honeytoken triggered: {token_type}")

    # -------------------------------------------------------------------------
    # System Metrics
    # -------------------------------------------------------------------------

    def update_uptime(self):
        """Update the uptime metric."""
        uptime = time.time() - self._start_time
        uptime_seconds.set(uptime)

    def get_metrics(self) -> bytes:
        """Generate Prometheus metrics in text format.

        Returns:
            Metrics in Prometheus exposition format
        """
        self.update_uptime()
        return generate_latest(REGISTRY)

    def get_content_type(self) -> str:
        """Get the content type for metrics response.

        Returns:
            MIME type for Prometheus metrics
        """
        return CONTENT_TYPE_LATEST


# =============================================================================
# Global Metrics Instance
# =============================================================================

# Global singleton instance
_metrics_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get the global metrics collector instance.

    Returns:
        Global MetricsCollector instance
    """
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector


def reset_metrics_collector():
    """Reset the global metrics collector (for testing)."""
    global _metrics_collector
    _metrics_collector = None


# =============================================================================
# HTTP Server for Metrics Endpoint
# =============================================================================


def start_metrics_server(port: int = 9090, host: str = "0.0.0.0"):
    """Start HTTP server for Prometheus metrics endpoint.

    Args:
        port: Port to listen on
        host: Host address to bind to
    """
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from threading import Thread

    collector = get_metrics_collector()

    class MetricsHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/metrics":
                self.send_response(200)
                self.send_header("Content-Type", collector.get_content_type())
                self.end_headers()
                self.wfile.write(collector.get_metrics())
            elif self.path == "/health":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK\n")
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not Found\n")

        def log_message(self, format, *args):
            # Suppress default logging
            pass

    server = HTTPServer((host, port), MetricsHandler)

    def serve():
        logger.info(f"Metrics server started on http://{host}:{port}/metrics")
        server.serve_forever()

    thread = Thread(target=serve, daemon=True, name="MetricsServer")
    thread.start()

    return server
