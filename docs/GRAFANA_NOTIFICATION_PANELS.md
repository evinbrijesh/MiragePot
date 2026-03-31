# Grafana Dashboard Update for Notification Metrics

## Overview
This document describes the new notification metrics panels that should be added to the MiragePot Grafana dashboards.

## New Metrics Available

The following Prometheus metrics have been added to track notification system performance:

1. **miragepot_notifications_sent_total** (Counter)
   - Labels: `platform` (discord/telegram), `notification_type` (session_end/high_threat_command/honeytoken_access/exfiltration)
   - Total count of successfully sent notifications

2. **miragepot_notifications_failed_total** (Counter)
   - Labels: `platform`, `notification_type`, `reason` (timeout/http_error/network_error/unknown_error)
   - Total count of failed notification attempts

3. **miragepot_notification_delivery_duration_seconds** (Histogram)
   - Labels: `platform`, `notification_type`
   - Time taken to deliver notifications (buckets: 0.05s to 10s)

4. **miragepot_notification_queue_size** (Gauge)
   - Current number of notifications waiting in rate limiter queue

## Recommended Panel Configurations

### Panel 1: Notification Success Rate
**Type:** Time Series Graph
**Query:**
```promql
# Success rate percentage
100 * (
  rate(miragepot_notifications_sent_total[5m])
  / 
  (rate(miragepot_notifications_sent_total[5m]) + rate(miragepot_notifications_failed_total[5m]))
)
```
**Legend:** `{{platform}} - {{notification_type}}`
**Y-Axis:** Percent (0-100)
**Thresholds:** 
- Green: >95%
- Yellow: 80-95%
- Red: <80%

### Panel 2: Notifications Sent (by Type)
**Type:** Stat Panel or Time Series
**Query:**
```promql
sum(rate(miragepot_notifications_sent_total[5m])) by (notification_type)
```
**Legend:** `{{notification_type}}`
**Unit:** ops/sec

### Panel 3: Notification Failures (by Reason)
**Type:** Time Series or Bar Chart
**Query:**
```promql
sum(rate(miragepot_notifications_failed_total[5m])) by (reason)
```
**Legend:** `{{reason}}`
**Unit:** failures/sec
**Thresholds:** Alert if >0.1 failures/sec

### Panel 4: Notification Delivery Latency (p95)
**Type:** Time Series Graph
**Query:**
```promql
histogram_quantile(0.95, 
  sum(rate(miragepot_notification_delivery_duration_seconds_bucket[5m])) by (le, platform)
)
```
**Legend:** `{{platform}} (p95)`
**Y-Axis:** Seconds
**Thresholds:**
- Green: <1s
- Yellow: 1-3s
- Red: >3s

### Panel 5: Average Delivery Time
**Type:** Gauge or Stat
**Query:**
```promql
rate(miragepot_notification_delivery_duration_seconds_sum[5m])
/
rate(miragepot_notification_delivery_duration_seconds_count[5m])
```
**Unit:** seconds (s)
**Decimals:** 3

### Panel 6: Notification Queue Size
**Type:** Gauge or Time Series
**Query:**
```promql
miragepot_notification_queue_size
```
**Unit:** short (count)
**Thresholds:**
- Green: 0
- Yellow: 1-5
- Red: >5

### Panel 7: Notification Volume by Platform
**Type:** Pie Chart or Stat
**Query:**
```promql
sum(rate(miragepot_notifications_sent_total[1h])) by (platform)
```
**Legend:** `{{platform}}`
**Time Range:** Last 1 hour

## Suggested Dashboard Layout

Add a new row to `miragepot-overview.json` titled "**Notification System**" with the following layout:

```
Row: Notification System (collapsed by default)
+------------------+------------------+------------------+
| Success Rate     | Queue Size       | Avg Latency      |
| (Time Series)    | (Gauge)          | (Stat)           |
| 8 wide           | 4 wide           | 4 wide           |
+------------------+------------------+------------------+
| Notifications Sent by Type          | Failures by      |
| (Time Series)                       | Reason           |
| 12 wide                             | (Bar Chart)      |
|                                     | 4 wide           |
+-------------------------------------+------------------+
| Delivery Latency p95                                   |
| (Time Series with multiple quantiles)                  |
| 16 wide                                                |
+--------------------------------------------------------+
```

## Manual Dashboard Import Steps

1. Open Grafana at `http://localhost:3000`
2. Navigate to **Dashboards** → **MiragePot Overview**
3. Click **Dashboard settings** (gear icon) → **JSON Model**
4. Add the panels from the JSON snippet below
5. Save the dashboard

## Automated Panel Creation

Alternatively, use the Grafana API to add panels programmatically:

```bash
# Export current dashboard
curl -u admin:admin http://localhost:3000/api/dashboards/uid/miragepot-overview > dashboard.json

# Edit dashboard.json to add notification panels
# (Use the panel definitions above)

# Import updated dashboard
curl -X POST -H "Content-Type: application/json" \
  -u admin:admin \
  -d @dashboard.json \
  http://localhost:3000/api/dashboards/db
```

## Testing the Panels

After adding the panels:

1. Run the notification test script:
   ```bash
   python test_notifications.py
   ```

2. Check the metrics endpoint:
   ```bash
   curl http://localhost:9090/metrics | grep notification
   ```

3. View panels in Grafana and verify data is displayed

## Alert Rules (Optional)

Consider adding Prometheus alert rules for notification failures:

```yaml
# In docker/prometheus/alerts.yml
groups:
  - name: notifications
    rules:
      - alert: HighNotificationFailureRate
        expr: |
          (
            rate(miragepot_notifications_failed_total[5m])
            /
            (rate(miragepot_notifications_sent_total[5m]) + rate(miragepot_notifications_failed_total[5m]))
          ) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High notification failure rate"
          description: "{{ $value | humanizePercentage }} of notifications are failing"
      
      - alert: NotificationQueueBacklog
        expr: miragepot_notification_queue_size > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Notification queue has backlog"
          description: "{{ $value }} notifications waiting in queue"
```

## Verification Checklist

- [ ] All 4 new metrics appear in Prometheus `/metrics` endpoint
- [ ] Grafana can query the new metrics
- [ ] Panels display data when notifications are sent
- [ ] Success rate panel shows 100% when all notifications succeed
- [ ] Failure panel shows errors when notifications fail
- [ ] Latency panel shows realistic delivery times (0.1-2s for Discord)
- [ ] Queue size updates correctly when rate limited

---

**Note:** The actual Grafana dashboard JSON is complex. These panel definitions are provided as PromQL queries that can be manually added through the Grafana UI or programmatically via the Grafana API.
