# MiragePot Monitoring Guide

Complete guide to monitoring your MiragePot honeypot using Prometheus, Grafana, and the built-in Streamlit dashboard.

## Table of Contents

- [Monitoring Overview](#monitoring-overview)
- [Streamlit Dashboard](#streamlit-dashboard)
- [Grafana Dashboards](#grafana-dashboards)
- [Prometheus Metrics](#prometheus-metrics)
- [Setting Up Alerts](#setting-up-alerts)
- [Custom Dashboards](#custom-dashboards)
- [Metric Reference](#metric-reference)

---

## Monitoring Overview

MiragePot provides three levels of monitoring:

| Tool | Purpose | Deployment | URL |
|------|---------|------------|-----|
| **Streamlit** | Real-time session viewer | Both | http://localhost:8501 |
| **Prometheus** | Metrics collection & storage | Full stack | http://localhost:9091 |
| **Grafana** | Dashboards & visualization | Full stack | http://localhost:3000 |

### Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   MiragePot     │────▶│   Prometheus    │────▶│    Grafana      │
│                 │     │                 │     │                 │
│ • SSH Honeypot  │     │ • Scrapes /9090 │     │ • Dashboards    │
│ • Metrics :9090 │     │ • Stores data   │     │ • Alerts        │
│ • Streamlit     │     │ • 30 day retain │     │ • Visualizations│
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

---

## Streamlit Dashboard

The built-in Streamlit dashboard provides real-time session monitoring without additional setup.

### Access

```
http://localhost:8501
```

### Features

- **Live Sessions**: Watch attackers interact in real-time
- **Command History**: See all commands executed with threat scores
- **Session Timeline**: Visual timeline of session activity
- **Threat Analysis**: Automatic threat categorization
- **IP Statistics**: Track unique attackers and their behavior
- **MITRE ATT&CK Mapping**: See detected TTPs

### Using the Dashboard

1. Open http://localhost:8501 in your browser
2. Sessions appear automatically as attackers connect
3. Click on a session to see detailed command history
4. Use filters to find specific activity

---

## Grafana Dashboards

The full stack deployment includes three pre-built Grafana dashboards.

### Setup

1. Deploy the full stack:
   ```bash
   ./scripts/deploy.sh --full
   ```

2. Import dashboards:
   ```bash
   ./scripts/setup-grafana-dashboards.sh
   ```

3. Access Grafana:
   - URL: http://localhost:3000
   - Username: `admin`
   - Password: `admin` (change immediately!)

### Available Dashboards

#### 1. MiragePot - Overview

**Purpose**: High-level operational monitoring

**Panels**:
- Total connections (stat)
- Active sessions (stat)
- Unique IPs in 24h (stat)
- Uptime (stat)
- High threat commands/min (stat)
- Connection attempts over time (line graph)
- Commands by threat level (pie chart)
- Command rate by threat level (stacked area)
- Top 10 usernames tried (table)
- Threat score distribution (bar chart)
- Session duration percentiles (line graph)

#### 2. MiragePot - TTP Analysis

**Purpose**: MITRE ATT&CK and threat intelligence

**Panels**:
- Total TTP detections (stat)
- Unique techniques detected (stat)
- Honeytokens triggered (stat)
- TTP detections/min (stat)
- TTPs by attack stage (stacked bars)
- Top attack stages distribution (pie chart)
- Top 20 detected techniques (table)
- TTP detection rate over time (line graph)
- Honeytokens triggered by type (table)
- Honeytoken triggers over time (line graph)
- High threat command patterns (table)

#### 3. MiragePot - Performance

**Purpose**: System and AI performance monitoring

**Panels**:
- LLM latency median (stat)
- Cache hit ratio (gauge)
- Total LLM requests (stat)
- LLM success rate (gauge)
- LLM latency percentiles (line graph)
- LLM request rate by result (stacked area)
- Cache hit/miss rate (line graph)
- Requests by LLM model (pie chart)
- LLM request distribution (bar chart)
- LLM requests by model and result (table)
- Total cache hits/misses (stats)

### Navigation

1. Click the dashboard icon (four squares) in the left sidebar
2. Select "Browse" to see all dashboards
3. Dashboards are tagged with "miragepot" for easy filtering

---

## Prometheus Metrics

### Accessing Prometheus

```
http://localhost:9091
```

### Useful Queries

**Connection rate over time:**
```promql
rate(miragepot_connections_total[5m]) * 60
```

**Average threat score:**
```promql
histogram_quantile(0.5, rate(miragepot_threat_score_bucket[5m]))
```

**Commands by threat level:**
```promql
sum by (threat_level) (miragepot_commands_total)
```

**LLM success rate:**
```promql
100 * rate(miragepot_llm_requests_total{result="success"}[5m]) / rate(miragepot_llm_requests_total[5m])
```

**Cache efficiency:**
```promql
100 * rate(miragepot_llm_cache_hits_total[5m]) / (rate(miragepot_llm_cache_hits_total[5m]) + rate(miragepot_llm_cache_misses_total[5m]))
```

**Top TTPs detected:**
```promql
topk(10, sum by (technique) (miragepot_ttp_detections_total))
```

---

## Setting Up Alerts

### Email Alerts

1. Edit `.env.docker`:
   ```bash
   ALERT_EMAIL_ENABLED=true
   ALERT_EMAIL_TO=security@yourcompany.com
   ALERT_EMAIL_FROM=miragepot@yourcompany.com
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=your-email@gmail.com
   SMTP_PASSWORD=your-app-password
   ```

2. Restart the deployment:
   ```bash
   ./scripts/deploy.sh --restart
   ```

### Slack Alerts

1. Create a Slack webhook:
   - Go to https://api.slack.com/messaging/webhooks
   - Create a new app and enable webhooks
   - Copy the webhook URL

2. Edit `.env.docker`:
   ```bash
   ALERT_SLACK_ENABLED=true
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/HERE
   SLACK_CHANNEL=#security-alerts
   ```

### Discord Alerts

1. Create a Discord webhook:
   - Server Settings → Integrations → Webhooks
   - Create new webhook and copy URL

2. Edit `.env.docker`:
   ```bash
   ALERT_DISCORD_ENABLED=true
   DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR/WEBHOOK/HERE
   ```

### Grafana Alerts

For more advanced alerting, configure Grafana alerts:

1. Go to Alerting → Alert rules
2. Click "New alert rule"
3. Configure the query and conditions
4. Set up notification channels

**Example: High Threat Alert**
```yaml
Name: High Threat Activity
Condition: rate(miragepot_commands_total{threat_level="high"}[5m]) > 0.5
For: 5 minutes
Notification: Send to #security-alerts
```

---

## Custom Dashboards

### Creating a New Dashboard

1. In Grafana, click "+" → "Dashboard"
2. Click "Add visualization"
3. Select Prometheus as the data source
4. Write your query
5. Customize the visualization
6. Save the dashboard

### Example: Attacker Activity Heatmap

1. Create new panel
2. Choose "Heatmap" visualization
3. Query:
   ```promql
   sum by (le) (rate(miragepot_session_duration_seconds_bucket[1h]))
   ```
4. Configure colors and axes

### Sharing Dashboards

Export dashboard JSON:
1. Dashboard settings (gear icon)
2. JSON Model
3. Copy and save to `grafana/dashboards/`

---

## Metric Reference

### Connection Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `miragepot_connections_total` | Counter | result | Total connection attempts |
| `miragepot_connections_active` | Gauge | - | Currently active connections |

**Labels for `result`**: `success`, `rejected_ratelimit`, `failed`

### Session Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `miragepot_sessions_total` | Counter | - | Total SSH sessions |
| `miragepot_sessions_active` | Gauge | - | Currently active sessions |
| `miragepot_session_duration_seconds` | Histogram | - | Session duration distribution |

### Command Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `miragepot_commands_total` | Counter | threat_level | Commands by threat level |
| `miragepot_commands_by_type_total` | Counter | command_type | Commands by category |
| `miragepot_threat_score` | Histogram | - | Threat score distribution |
| `miragepot_high_threat_commands_total` | Counter | command_pattern | High threat patterns |

**Labels for `threat_level`**: `low`, `medium`, `high`

### Attacker Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `miragepot_unique_attacker_ips` | Gauge | - | Unique IPs (24h) |
| `miragepot_auth_attempts_total` | Counter | username | Auth attempts by username |
| `miragepot_unique_credentials_tried` | Gauge | - | Unique credential combinations |

### LLM Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `miragepot_llm_requests_total` | Counter | model, result | LLM API requests |
| `miragepot_llm_latency_seconds` | Histogram | - | LLM response time |
| `miragepot_llm_cache_hits_total` | Counter | - | Cache hits |
| `miragepot_llm_cache_misses_total` | Counter | - | Cache misses |

**Labels for `result`**: `success`, `timeout`, `error`

### TTP Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `miragepot_ttp_detections_total` | Counter | attack_stage, technique | TTP detections |
| `miragepot_honeytokens_triggered_total` | Counter | token_type | Honeytoken access |

### System Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `miragepot_uptime_seconds` | Gauge | - | Honeypot uptime |
| `miragepot_system_info` | Info | version, python_version, mode | System info |

---

## Troubleshooting

### Metrics Not Appearing

1. Check if metrics endpoint is accessible:
   ```bash
   curl http://localhost:9090/metrics
   ```

2. Check Prometheus targets:
   ```
   http://localhost:9091/targets
   ```

3. Verify Prometheus is scraping:
   ```bash
   docker logs miragepot-prometheus
   ```

### Grafana Can't Connect to Prometheus

1. Check datasource configuration:
   - URL should be `http://prometheus:9091` (Docker internal)
   
2. Test connection:
   - Data Sources → Prometheus → Test

### Dashboards Not Loading

1. Re-import dashboards:
   ```bash
   ./scripts/setup-grafana-dashboards.sh
   ```

2. Check for datasource UID mismatch:
   - Edit dashboard JSON
   - Update `"uid": "prometheus"` in datasource references

---

## Best Practices

1. **Set up alerts early** - Don't wait for an incident
2. **Review dashboards daily** - Look for patterns and anomalies
3. **Tune alert thresholds** - Reduce false positives
4. **Backup Grafana dashboards** - Export JSON regularly
5. **Monitor the monitors** - Ensure Prometheus is healthy
6. **Document custom queries** - Help future analysis

---

## Next Steps

- [Configure Alerts](CONFIGURATION.md#alerting)
- [Analyze Session Data](USAGE.md)
- [Understand TTP Detection](architecture.md#ttp-detection)
