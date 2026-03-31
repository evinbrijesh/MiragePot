#!/usr/bin/env python3
"""Test script to verify notification metrics are properly recorded."""

import sys
import os

# Add parent directory to path to import miragepot
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from miragepot.metrics import get_metrics_collector


def test_notification_metrics():
    """Test that notification metrics can be recorded."""
    metrics = get_metrics_collector()

    print("Testing notification metrics...")

    # Test successful notification
    print("\n1. Recording successful Discord notification...")
    metrics.record_notification_sent("discord", "session_end", 0.234)
    print("   ✓ Success metric recorded")

    # Test failed notification
    print("\n2. Recording failed Discord notification...")
    metrics.record_notification_failed("discord", "high_threat_command", "timeout")
    print("   ✓ Failure metric recorded")

    # Test queue size update
    print("\n3. Updating notification queue size...")
    metrics.update_notification_queue_size(5)
    print("   ✓ Queue size metric updated")

    # Get metrics output
    print("\n4. Fetching Prometheus metrics...")
    metrics_output = metrics.get_metrics().decode("utf-8")

    # Check for our new metrics
    expected_metrics = [
        "miragepot_notifications_sent_total",
        "miragepot_notifications_failed_total",
        "miragepot_notification_delivery_duration_seconds",
        "miragepot_notification_queue_size",
    ]

    print("\n5. Verifying metrics are present in output...")
    for metric_name in expected_metrics:
        if metric_name in metrics_output:
            print(f"   ✓ Found {metric_name}")
        else:
            print(f"   ✗ Missing {metric_name}")
            return False

    # Show sample of metrics output
    print("\n6. Sample metrics output:")
    print("-" * 80)
    for line in metrics_output.split("\n"):
        if "notification" in line.lower() and not line.startswith("#"):
            print(f"   {line}")
    print("-" * 80)

    print("\n✅ All notification metrics tests passed!")
    return True


if __name__ == "__main__":
    try:
        success = test_notification_metrics()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
