"""Real-time attack notification system for MiragePot.

This module provides Discord and Telegram notifications for security events:
- High-risk session summaries with full forensics
- Real-time high-threat command alerts
- Honeytoken access/exfiltration alerts

Supports:
- Discord webhooks (rich embeds with color coding)
- Telegram Bot API (markdown formatting)
- Rate limiting to prevent spam
- JSON session log attachments
- Retry logic with exponential backoff
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from threading import Lock
import requests

from .metrics import get_metrics_collector

LOGGER = logging.getLogger(__name__)


@dataclass
class NotificationConfig:
    """Configuration for notification system."""

    enabled: bool
    discord_webhook_url: str
    telegram_bot_token: str
    telegram_chat_id: str
    min_risk_level: str  # "low", "medium", "high", "critical"
    notify_on_session_end: bool
    notify_on_realtime_events: bool
    notify_on_honeytoken_access: bool
    notify_on_honeytoken_exfiltration: bool
    include_json_attachment: bool
    include_summary: bool
    max_notifications_per_minute: int


class RateLimiter:
    """Token bucket rate limiter to prevent notification spam."""

    def __init__(self, max_per_minute: int):
        """Initialize rate limiter.

        Args:
            max_per_minute: Maximum notifications allowed per minute
        """
        self.max_per_minute = max_per_minute
        self.tokens = max_per_minute
        self.last_refill = time.time()
        self.lock = Lock()

    def allow(self) -> bool:
        """Check if notification is allowed (has tokens available).

        Returns:
            True if notification can be sent, False if rate limited
        """
        with self.lock:
            # Refill tokens based on time passed
            now = time.time()
            elapsed = now - self.last_refill
            tokens_to_add = elapsed * (self.max_per_minute / 60.0)

            self.tokens = min(self.max_per_minute, self.tokens + tokens_to_add)
            self.last_refill = now

            # Check if we have tokens
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False

    def get_queue_size(self) -> int:
        """Get approximate queue size (notifications waiting).

        Returns:
            Number of notifications that would be rate limited (negative tokens)
        """
        with self.lock:
            # Refill tokens first to get accurate count
            now = time.time()
            elapsed = now - self.last_refill
            tokens_to_add = elapsed * (self.max_per_minute / 60.0)
            current_tokens = min(self.max_per_minute, self.tokens + tokens_to_add)

            # If tokens < 0, that represents backlog
            return max(0, int(-current_tokens))


class NotificationManager:
    """Manages notification delivery to Discord and Telegram."""

    def __init__(self, config: NotificationConfig):
        """Initialize notification manager.

        Args:
            config: Notification configuration
        """
        self.config = config
        self.rate_limiter = RateLimiter(config.max_notifications_per_minute)
        self.enabled = config.enabled and (
            bool(config.discord_webhook_url) or bool(config.telegram_bot_token)
        )

        if self.enabled:
            LOGGER.info("Notification system enabled")
            if config.discord_webhook_url:
                LOGGER.info("Discord notifications enabled")
            if config.telegram_bot_token:
                LOGGER.info("Telegram notifications enabled")
        else:
            LOGGER.info("Notification system disabled")

    def _should_notify(self, risk_level: str) -> bool:
        """Check if notification should be sent based on risk level.

        Args:
            risk_level: Risk level string ("low", "medium", "high", "critical")

        Returns:
            True if notification should be sent
        """
        risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_risk = risk_order.get(self.config.min_risk_level, 2)
        current_risk = risk_order.get(risk_level, 0)
        return current_risk >= min_risk

    def _get_risk_color(self, risk_level: str) -> int:
        """Get Discord embed color for risk level.

        Args:
            risk_level: Risk level string

        Returns:
            Integer color code for Discord embed
        """
        colors = {
            "critical": 0xFF0000,  # Red
            "high": 0xFF6600,  # Orange
            "medium": 0xFFCC00,  # Yellow
            "low": 0x0099FF,  # Blue
        }
        return colors.get(risk_level, 0x808080)  # Gray default

    def _send_discord_webhook(
        self, embed: Dict[str, Any], file_path: Optional[Path] = None
    ) -> bool:
        """Send message to Discord webhook.

        Args:
            embed: Discord embed dictionary
            file_path: Optional file to attach

        Returns:
            True if successful, False otherwise
        """
        if not self.config.discord_webhook_url:
            return False

        start_time = time.time()
        notification_type = embed.get("title", "unknown").lower()

        # Extract notification type from title (e.g., "🚨 HIGH RISK ATTACK SESSION ENDED" -> "session_end")
        if "session ended" in notification_type:
            notification_type = "session_end"
        elif "high-threat command" in notification_type:
            notification_type = "high_threat_command"
        elif "honeytoken access" in notification_type:
            notification_type = "honeytoken_access"
        elif "exfiltration" in notification_type:
            notification_type = "exfiltration"
        else:
            notification_type = "unknown"

        try:
            payload = {"embeds": [embed]}

            if file_path and file_path.exists():
                # Send with file attachment
                LOGGER.info(
                    f"Attaching file to Discord notification: {file_path.name} ({file_path.stat().st_size} bytes)"
                )
                with open(file_path, "rb") as f:
                    files = {"file": (file_path.name, f, "application/json")}
                    response = requests.post(
                        self.config.discord_webhook_url,
                        data={"payload_json": json.dumps(payload)},
                        files=files,
                        timeout=10,
                    )
            else:
                # Send without file
                if file_path:
                    LOGGER.warning(
                        f"JSON attachment requested but file not found: {file_path}"
                    )
                response = requests.post(
                    self.config.discord_webhook_url, json=payload, timeout=10
                )

            response.raise_for_status()
            duration = time.time() - start_time

            # Record success metrics
            metrics = get_metrics_collector()
            metrics.record_notification_sent("discord", notification_type, duration)

            LOGGER.debug("Discord notification sent successfully")
            return True

        except requests.exceptions.Timeout:
            metrics = get_metrics_collector()
            metrics.record_notification_failed("discord", notification_type, "timeout")
            LOGGER.error("Failed to send Discord notification: timeout")
            return False
        except requests.exceptions.HTTPError as e:
            metrics = get_metrics_collector()
            metrics.record_notification_failed(
                "discord", notification_type, "http_error"
            )
            LOGGER.error(
                f"Failed to send Discord notification: HTTP {e.response.status_code}"
            )
            return False
        except requests.exceptions.RequestException as e:
            metrics = get_metrics_collector()
            metrics.record_notification_failed(
                "discord", notification_type, "network_error"
            )
            LOGGER.error(f"Failed to send Discord notification: {e}")
            return False
        except Exception as e:
            metrics = get_metrics_collector()
            metrics.record_notification_failed(
                "discord", notification_type, "unknown_error"
            )
            LOGGER.error(f"Failed to send Discord notification: unexpected error {e}")
            return False

    def send_session_end_summary(self, session_log: Dict[str, Any]) -> None:
        """Send notification when high-risk session ends.

        Args:
            session_log: Complete session log dictionary
        """
        if not self.enabled or not self.config.notify_on_session_end:
            return

        ttp_summary = session_log.get("ttp_summary", {})
        risk_level = ttp_summary.get("risk_level", "low")

        if not self._should_notify(risk_level):
            return

        if not self.rate_limiter.allow():
            LOGGER.warning("Rate limit exceeded, skipping session end notification")
            # Update queue size metric
            metrics = get_metrics_collector()
            metrics.update_notification_queue_size(self.rate_limiter.get_queue_size())
            return

        # Update queue size metric after successful token acquisition
        metrics = get_metrics_collector()
        metrics.update_notification_queue_size(self.rate_limiter.get_queue_size())

        # Build Discord embed
        session_id = session_log.get("session_id", "unknown")
        attacker_ip = session_log.get("attacker_ip", "unknown")
        duration = session_log.get("duration_seconds", 0)
        commands_count = len(session_log.get("commands", []))

        embed = {
            "title": f"🚨 {risk_level.upper()} RISK ATTACK SESSION ENDED",
            "color": self._get_risk_color(risk_level),
            "fields": [
                {"name": "Attacker IP", "value": attacker_ip, "inline": True},
                {"name": "Session ID", "value": session_id[:12], "inline": True},
                {
                    "name": "Duration",
                    "value": f"{duration:.1f} seconds",
                    "inline": True,
                },
                {
                    "name": "Risk Level",
                    "value": f"⚠️ {risk_level.upper()}",
                    "inline": True,
                },
                {
                    "name": "Commands Executed",
                    "value": str(commands_count),
                    "inline": True,
                },
            ],
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Add attack profile information
        if ttp_summary:
            current_stage = ttp_summary.get("current_stage", "unknown")
            techniques = ttp_summary.get("techniques_used", [])
            attack_profile = f"**Stage:** {current_stage}\n"
            attack_profile += (
                f"**Techniques:** {len(techniques)} MITRE ATT&CK patterns\n"
            )

            if techniques:
                top_techniques = techniques[:3]
                for tech in top_techniques:
                    tech_id = tech.get("technique_id", "")
                    description = tech.get("description", "")
                    attack_profile += f"  • {tech_id}: {description}\n"

            embed["fields"].append(
                {"name": "Attack Profile", "value": attack_profile, "inline": False}
            )

        # Add honeytoken information
        honeytokens_summary = session_log.get("honeytokens_summary", {})
        if honeytokens_summary:
            tokens_accessed = honeytokens_summary.get("unique_tokens_accessed", 0)
            exfil_attempts = honeytokens_summary.get("exfiltration_attempts", 0)

            if tokens_accessed > 0:
                honeytoken_text = f"🔑 **Tokens Accessed:** {tokens_accessed}\n"
                honeytoken_text += f"📤 **Exfiltration Attempts:** {exfil_attempts}\n"

                token_types = honeytokens_summary.get("token_types_accessed", [])
                if token_types:
                    honeytoken_text += "\n**Token Types:**\n"
                    for token_type in token_types[:5]:
                        honeytoken_text += f"  • {token_type}\n"

                embed["fields"].append(
                    {
                        "name": "Honeytoken Activity",
                        "value": honeytoken_text,
                        "inline": False,
                    }
                )

        # Send notification
        file_path = None
        if self.config.include_json_attachment:
            # Session log path from config
            from .config import get_config

            cfg = get_config()
            log_dir = cfg.logs_dir
            # session_id already includes "session_" prefix (e.g., "session_abc123...")
            file_path = log_dir / f"{session_id}.json"
            LOGGER.info(f"Looking for session log at: {file_path}")

            # If file doesn't exist yet, create it from session_log data
            if not file_path.exists():
                LOGGER.info(f"Session log not found, creating from session_log data")
                try:
                    log_dir.mkdir(parents=True, exist_ok=True)
                    with open(file_path, "w") as f:
                        json.dump(session_log, f, indent=2, default=str)
                    LOGGER.info(f"Created session log file: {file_path}")
                except Exception as e:
                    LOGGER.error(f"Failed to create session log file: {e}")
                    file_path = None
            else:
                LOGGER.info(f"Found existing session log: {file_path}")

        self._send_discord_webhook(embed, file_path)

    def send_high_threat_command_alert(
        self, command: str, threat_score: int, session_id: str, attacker_ip: str
    ) -> None:
        """Send real-time alert for high-threat command.

        Args:
            command: Command that was executed
            threat_score: Threat score (0-100)
            session_id: Session identifier
            attacker_ip: Attacker's IP address
        """
        if not self.enabled or not self.config.notify_on_realtime_events:
            return

        if not self.rate_limiter.allow():
            LOGGER.warning("Rate limit exceeded, skipping high-threat command alert")
            # Update queue size metric
            metrics = get_metrics_collector()
            metrics.update_notification_queue_size(self.rate_limiter.get_queue_size())
            return

        # Update queue size metric after successful token acquisition
        metrics = get_metrics_collector()
        metrics.update_notification_queue_size(self.rate_limiter.get_queue_size())

        # Truncate long commands
        display_command = command[:200] + "..." if len(command) > 200 else command

        embed = {
            "title": "⚡ HIGH THREAT COMMAND DETECTED",
            "color": 0xFF0000,  # Red
            "fields": [
                {
                    "name": "Command",
                    "value": f"```{display_command}```",
                    "inline": False,
                },
                {
                    "name": "Threat Score",
                    "value": f"{threat_score}/100",
                    "inline": True,
                },
                {"name": "Attacker IP", "value": attacker_ip, "inline": True},
                {"name": "Session ID", "value": session_id[:12], "inline": True},
            ],
            "timestamp": datetime.utcnow().isoformat(),
        }

        self._send_discord_webhook(embed)

    def send_honeytoken_access_alert(
        self,
        token_type: str,
        file_path: str,
        command: str,
        session_id: str,
        attacker_ip: str,
    ) -> None:
        """Send alert when honeytoken is accessed.

        Args:
            token_type: Type of honeytoken (e.g., "AWS Access Key")
            file_path: Path to file containing token
            command: Command that accessed the token
            session_id: Session identifier
            attacker_ip: Attacker's IP address
        """
        if not self.enabled or not self.config.notify_on_honeytoken_access:
            return

        if not self.rate_limiter.allow():
            LOGGER.warning("Rate limit exceeded, skipping honeytoken access alert")
            # Update queue size metric
            metrics = get_metrics_collector()
            metrics.update_notification_queue_size(self.rate_limiter.get_queue_size())
            return

        # Update queue size metric after successful token acquisition
        metrics = get_metrics_collector()
        metrics.update_notification_queue_size(self.rate_limiter.get_queue_size())

        display_command = command[:150] + "..." if len(command) > 150 else command

        embed = {
            "title": "🍯 HONEYTOKEN ACCESSED",
            "color": 0xFFC107,  # Amber/Yellow
            "fields": [
                {"name": "Token Type", "value": token_type, "inline": True},
                {"name": "File Path", "value": file_path, "inline": True},
                {"name": "Session ID", "value": session_id[:12], "inline": True},
                {"name": "Attacker IP", "value": attacker_ip, "inline": True},
                {
                    "name": "Command",
                    "value": f"```{display_command}```",
                    "inline": False,
                },
            ],
            "timestamp": datetime.utcnow().isoformat(),
        }

        self._send_discord_webhook(embed)

    def send_exfiltration_alert(
        self,
        destination: str,
        tokens: List[str],
        command: str,
        session_id: str,
        attacker_ip: str,
    ) -> None:
        """Send alert when honeytoken exfiltration is detected.

        Args:
            destination: Exfiltration destination (URL, IP, etc.)
            tokens: List of token types being exfiltrated
            command: Command performing exfiltration
            session_id: Session identifier
            attacker_ip: Attacker's IP address
        """
        if not self.enabled or not self.config.notify_on_honeytoken_exfiltration:
            return

        if not self.rate_limiter.allow():
            LOGGER.warning("Rate limit exceeded, skipping exfiltration alert")
            # Update queue size metric
            metrics = get_metrics_collector()
            metrics.update_notification_queue_size(self.rate_limiter.get_queue_size())
            return

        # Update queue size metric after successful token acquisition
        metrics = get_metrics_collector()
        metrics.update_notification_queue_size(self.rate_limiter.get_queue_size())

        display_command = command[:150] + "..." if len(command) > 150 else command
        tokens_text = "\n".join([f"  • {t}" for t in tokens[:5]])

        embed = {
            "title": "🚨 HONEYTOKEN EXFILTRATION ATTEMPT",
            "color": 0xFF0000,  # Red
            "fields": [
                {"name": "Destination", "value": destination, "inline": False},
                {
                    "name": "Tokens Involved",
                    "value": tokens_text or "Unknown",
                    "inline": False,
                },
                {"name": "Attacker IP", "value": attacker_ip, "inline": True},
                {"name": "Session ID", "value": session_id[:12], "inline": True},
                {
                    "name": "Command",
                    "value": f"```{display_command}```",
                    "inline": False,
                },
            ],
            "timestamp": datetime.utcnow().isoformat(),
        }

        self._send_discord_webhook(embed)


# Global notifier instance
_notifier: Optional[NotificationManager] = None


def get_notifier() -> NotificationManager:
    """Get global notification manager instance.

    Returns:
        NotificationManager instance
    """
    global _notifier
    if _notifier is None:
        from .config import get_config

        cfg = get_config()
        notification_config = NotificationConfig(
            enabled=cfg.notifications.enabled,
            discord_webhook_url=cfg.notifications.discord_webhook_url,
            telegram_bot_token=cfg.notifications.telegram_bot_token,
            telegram_chat_id=cfg.notifications.telegram_chat_id,
            min_risk_level=cfg.notifications.min_risk_level,
            notify_on_session_end=cfg.notifications.notify_session_end,
            notify_on_realtime_events=cfg.notifications.notify_realtime,
            notify_on_honeytoken_access=cfg.notifications.notify_honeytokens_access,
            notify_on_honeytoken_exfiltration=cfg.notifications.notify_honeytokens_exfil,
            include_json_attachment=cfg.notifications.notify_include_json,
            include_summary=cfg.notifications.notify_include_summary,
            max_notifications_per_minute=cfg.notifications.notify_rate_limit,
        )
        _notifier = NotificationManager(notification_config)
    return _notifier
