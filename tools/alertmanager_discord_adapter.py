#!/usr/bin/env python3
"""
AlertManager to Discord Webhook Adapter

This service receives AlertManager webhook payloads and forwards them
to Discord with proper embed formatting.

Run with: python alertmanager_discord_adapter.py
Listens on: http://localhost:9094/webhook
"""

import json
import logging
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests

# Configuration
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1488225718415523980/5_bMAuhhM7kaBYDb1-NIsbAd8eh_3hv2JXnGQRtH27FL-d5PQorvW8GptjP44mQzNOrx"
LISTEN_PORT = 9094

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def severity_to_color(severity: str) -> int:
    """Map AlertManager severity to Discord embed color."""
    colors = {
        "critical": 0xFF0000,  # Red
        "high": 0xFF6600,  # Orange
        "warning": 0xFFCC00,  # Yellow
        "info": 0x0099FF,  # Blue
    }
    return colors.get(severity.lower(), 0x808080)  # Gray default


def severity_to_emoji(severity: str) -> str:
    """Map severity to emoji."""
    emojis = {
        "critical": "🚨",
        "high": "⚠️",
        "warning": "⚡",
        "info": "ℹ️",
    }
    return emojis.get(severity.lower(), "📢")


def format_alert_to_embed(alert: dict, status: str) -> dict:
    """Convert AlertManager alert to Discord embed format."""
    labels = alert.get("labels", {})
    annotations = alert.get("annotations", {})

    alertname = labels.get("alertname", "Unknown Alert")
    severity = labels.get("severity", "info")
    category = labels.get("category", "general")

    summary = annotations.get("summary", "No summary provided")
    description = annotations.get("description", "")

    # Determine if firing or resolved
    if status == "resolved":
        title = f"✅ RESOLVED: {alertname}"
        color = 0x00FF00  # Green
    else:
        emoji = severity_to_emoji(severity)
        title = f"{emoji} {severity.upper()}: {alertname}"
        color = severity_to_color(severity)

    embed = {
        "title": title,
        "color": color,
        "description": summary,
        "fields": [],
        "timestamp": datetime.utcnow().isoformat(),
        "footer": {"text": f"MiragePot AlertManager | Category: {category}"},
    }

    # Add description if different from summary
    if description and description != summary:
        embed["fields"].append(
            {
                "name": "Details",
                "value": description[:1024],  # Discord limit
                "inline": False,
            }
        )

    # Add severity field
    embed["fields"].append(
        {"name": "Severity", "value": severity.upper(), "inline": True}
    )

    # Add category field
    embed["fields"].append({"name": "Category", "value": category, "inline": True})

    # Add MITRE tactic if present
    mitre_tactic = labels.get("mitre_tactic")
    if mitre_tactic:
        embed["fields"].append(
            {"name": "MITRE ATT&CK", "value": mitre_tactic, "inline": True}
        )

    # Add generator URL if present
    generator_url = alert.get("generatorURL")
    if generator_url:
        embed["fields"].append(
            {
                "name": "View in Prometheus",
                "value": f"[Open Query]({generator_url})",
                "inline": True,
            }
        )

    return embed


def send_to_discord(embeds: list) -> bool:
    """Send embeds to Discord webhook."""
    try:
        # Discord allows max 10 embeds per message
        for i in range(0, len(embeds), 10):
            batch = embeds[i : i + 10]
            payload = {"embeds": batch}

            response = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10)
            response.raise_for_status()
            logger.info(f"Sent {len(batch)} alerts to Discord")

        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send to Discord: {e}")
        return False


class WebhookHandler(BaseHTTPRequestHandler):
    """Handle incoming AlertManager webhooks."""

    def do_POST(self):
        """Process AlertManager webhook payload."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            payload = json.loads(body.decode("utf-8"))

            logger.info(
                f"Received webhook: status={payload.get('status')}, alerts={len(payload.get('alerts', []))}"
            )

            status = payload.get("status", "firing")
            alerts = payload.get("alerts", [])

            if not alerts:
                self.send_response(200)
                self.end_headers()
                return

            # Convert alerts to Discord embeds
            embeds = []
            for alert in alerts:
                alert_status = alert.get("status", status)
                embed = format_alert_to_embed(alert, alert_status)
                embeds.append(embed)

            # Send to Discord
            success = send_to_discord(embeds)

            if success:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "ok"}')
            else:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    b'{"status": "error", "message": "Failed to send to Discord"}'
                )

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON: {e}")
            self.send_response(400)
            self.end_headers()
        except Exception as e:
            logger.error(f"Error processing webhook: {e}")
            self.send_response(500)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress default HTTP logging."""
        pass


def main():
    """Start the webhook adapter server."""
    server = HTTPServer(("0.0.0.0", LISTEN_PORT), WebhookHandler)
    logger.info(f"AlertManager Discord Adapter listening on port {LISTEN_PORT}")
    logger.info(
        f"Configure AlertManager to send webhooks to: http://localhost:{LISTEN_PORT}/webhook"
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
