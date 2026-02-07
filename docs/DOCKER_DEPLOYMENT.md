# MiragePot Docker Deployment Guide

Complete guide for deploying MiragePot using Docker, including configuration, security hardening, and production considerations.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Deployment Options](#deployment-options)
- [Pre-Deployment Setup](#pre-deployment-setup)
- [Simple Stack Deployment](#simple-stack-deployment)
- [Full Stack Deployment](#full-stack-deployment)
- [Configuration Reference](#configuration-reference)
- [Port Mappings](#port-mappings)
- [Volume Management](#volume-management)
- [Security Hardening](#security-hardening)
- [Remote Access](#remote-access)
- [Maintenance](#maintenance)
- [Troubleshooting](#troubleshooting)

---

## Architecture Overview

### Simple Stack (2 Containers)

```
┌─────────────────────────────────────────────────────────┐
│                    Docker Network                        │
│  ┌─────────────────────┐    ┌─────────────────────┐    │
│  │   MiragePot         │    │   Ollama            │    │
│  │   ─────────────     │    │   ──────            │    │
│  │   • SSH Server      │───▶│   • phi3 model      │    │
│  │   • Command Handler │    │   • LLM API         │    │
│  │   • Streamlit UI    │    │                     │    │
│  │   • Metrics         │    │                     │    │
│  └─────────────────────┘    └─────────────────────┘    │
│          │                                              │
│          ▼                                              │
│    Ports: 2222, 8501, 9090                             │
└─────────────────────────────────────────────────────────┘
```

### Full Stack (5 Containers)

```
┌──────────────────────────────────────────────────────────────────────┐
│                           Docker Network                              │
│                                                                       │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐             │
│  │  MiragePot   │   │   Ollama     │   │  Prometheus  │             │
│  │  ──────────  │──▶│   ──────     │   │  ──────────  │             │
│  │  SSH + UI    │   │   LLM API    │   │  Metrics DB  │◀────┐       │
│  └──────────────┘   └──────────────┘   └──────────────┘     │       │
│         │                                     │              │       │
│         │                                     ▼              │       │
│         │                            ┌──────────────┐       │       │
│         │                            │   Grafana    │       │       │
│         │                            │   ───────    │       │       │
│         │                            │  Dashboards  │       │       │
│         │                            └──────────────┘       │       │
│         │                                                   │       │
│         │                            ┌──────────────┐       │       │
│         └───────────────────────────▶│ Alertmanager │───────┘       │
│                                      │ ────────────  │              │
│                                      │    Alerts     │              │
│                                      └──────────────┘              │
│                                                                      │
│  Ports: 2222, 8501, 9090, 9091, 9093, 3000                         │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Deployment Options

| Feature | Simple Stack | Full Stack |
|---------|--------------|------------|
| **File** | `docker-compose-simple.yml` | `docker/docker-compose.yml` |
| **Containers** | 2 | 5 |
| **SSH Honeypot** | ✅ | ✅ |
| **AI Responses** | ✅ (Ollama + phi3) | ✅ (Ollama + phi3) |
| **Streamlit Dashboard** | ✅ | ✅ |
| **JSON Session Logs** | ✅ | ✅ |
| **Prometheus Metrics** | ✅ (endpoint only) | ✅ (full stack) |
| **Grafana Dashboards** | ❌ | ✅ |
| **Alertmanager** | ❌ | ✅ |
| **RAM Usage** | ~2-3GB | ~4-5GB |
| **Disk Usage** | ~3GB | ~5GB |

---

## Pre-Deployment Setup

### 1. System Requirements

- **CPU**: 2+ cores recommended
- **RAM**: 4GB minimum (8GB recommended for full stack)
- **Disk**: 10GB free space
- **OS**: Linux, macOS, or Windows with WSL2

### 2. Install Docker

**Linux (Ubuntu/Debian):**
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Log out and back in
```

**macOS:**
Download and install [Docker Desktop](https://www.docker.com/products/docker-desktop/)

**Windows:**
Install [Docker Desktop with WSL2](https://docs.docker.com/desktop/install/windows-install/)

### 3. Clone Repository

```bash
git clone https://github.com/yourusername/MiragePot.git
cd MiragePot
```

### 4. Configure Environment

```bash
# Copy the example configuration
cp .env.docker.example .env.docker

# Edit configuration (optional)
nano .env.docker
```

Key settings to review:

```bash
# Honeypot identity (what attackers see)
MIRAGEPOT_HOSTNAME=webserver-prod-01
MIRAGEPOT_OS_NAME=Ubuntu
MIRAGEPOT_OS_VERSION=20.04.6 LTS

# LLM Model (phi3 is recommended)
MIRAGEPOT_LLM_MODEL=phi3

# Security settings
MIRAGEPOT_MAX_CONNECTIONS_PER_IP=3
MIRAGEPOT_MAX_SESSION_DURATION=3600

# Grafana password (CHANGE THIS!)
GRAFANA_ADMIN_PASSWORD=admin
```

---

## Simple Stack Deployment

Best for: Quick testing, demos, learning, resource-constrained environments.

### Deploy

```bash
# Using the deploy script (recommended)
./scripts/deploy.sh --simple

# Or manually
docker compose -f docker-compose-simple.yml up -d
docker exec miragepot-ollama-simple ollama pull phi3
```

### Verify

```bash
# Check container status
docker compose -f docker-compose-simple.yml ps

# Expected output:
# NAME                        STATUS
# miragepot-honeypot-simple   Up (healthy)
# miragepot-ollama-simple     Up (healthy)
```

### Access

| Service | URL/Command |
|---------|-------------|
| SSH Honeypot | `ssh root@localhost -p 2222` |
| Dashboard | http://localhost:8501 |
| Metrics | http://localhost:9090/metrics |

### Stop

```bash
docker compose -f docker-compose-simple.yml down
```

---

## Full Stack Deployment

Best for: Production use, full monitoring, threat analysis, alerting.

### Deploy

```bash
# Using the deploy script (recommended)
./scripts/deploy.sh --full

# Or manually
cd docker/
docker compose up -d
docker exec miragepot-ollama ollama pull phi3
```

### Verify

```bash
cd docker/
docker compose ps

# Expected output:
# NAME                    STATUS
# miragepot-honeypot      Up (healthy)
# miragepot-ollama        Up (healthy)
# miragepot-prometheus    Up (healthy)
# miragepot-grafana       Up
# miragepot-alertmanager  Up
```

### Access

| Service | URL/Command | Default Credentials |
|---------|-------------|---------------------|
| SSH Honeypot | `ssh root@localhost -p 2222` | Any password |
| Dashboard | http://localhost:8501 | None |
| Grafana | http://localhost:3000 | admin / admin |
| Prometheus | http://localhost:9091 | None |
| Alertmanager | http://localhost:9093 | None |

### Import Grafana Dashboards

```bash
# Automatic import
./scripts/setup-grafana-dashboards.sh

# Or manual import:
# 1. Open Grafana at http://localhost:3000
# 2. Go to Dashboards → Import
# 3. Upload JSON files from grafana/dashboards/
```

### Stop

```bash
cd docker/
docker compose down
```

---

## Configuration Reference

### Environment Variables

All configuration is done via `.env.docker`. Key sections:

#### SSH Honeypot Settings

```bash
MIRAGEPOT_SSH_HOST=0.0.0.0        # Bind address
MIRAGEPOT_SSH_PORT=2222           # Internal port
MIRAGEPOT_SSH_BANNER=SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
```

#### LLM/AI Settings

```bash
OLLAMA_HOST=http://ollama:11434   # Ollama container address
MIRAGEPOT_LLM_MODEL=phi3          # Model to use
MIRAGEPOT_LLM_TIMEOUT=30.0        # Request timeout
MIRAGEPOT_LLM_TEMPERATURE=0.7     # Response creativity
```

#### Honeypot Identity

```bash
MIRAGEPOT_HOSTNAME=webserver-prod-01
MIRAGEPOT_OS_NAME=Ubuntu
MIRAGEPOT_OS_VERSION=20.04.6 LTS
MIRAGEPOT_KERNEL_VERSION=5.15.0-86-generic
```

#### Security & Rate Limiting

```bash
MIRAGEPOT_MAX_CONNECTIONS_PER_IP=3
MIRAGEPOT_MAX_TOTAL_CONNECTIONS=50
MIRAGEPOT_BLOCK_DURATION=300       # 5 minutes
MIRAGEPOT_MAX_SESSION_DURATION=3600  # 1 hour
```

#### Alerting (Full Stack)

```bash
# Email alerts
ALERT_EMAIL_ENABLED=true
ALERT_EMAIL_TO=security@yourcompany.com
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# Slack alerts
ALERT_SLACK_ENABLED=false
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

# Discord alerts
ALERT_DISCORD_ENABLED=false
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

---

## Port Mappings

### Default Ports

| Port | Service | Description | Public? |
|------|---------|-------------|---------|
| 2222 | SSH Honeypot | Main honeypot port | ✅ Yes |
| 8501 | Streamlit | Web dashboard | ⚠️ Localhost only |
| 9090 | Metrics | Prometheus metrics endpoint | ⚠️ Internal |
| 9091 | Prometheus | Prometheus UI (full stack) | ⚠️ Localhost only |
| 9093 | Alertmanager | Alert management (full stack) | ⚠️ Localhost only |
| 3000 | Grafana | Monitoring dashboards | ⚠️ Localhost only |
| 11434 | Ollama | LLM API | ❌ Internal only |

### Changing Ports

Edit the docker-compose file to change port mappings:

```yaml
ports:
  - "22:2222"      # Map honeypot to standard SSH port
  - "127.0.0.1:8501:8501"  # Bind dashboard to localhost only
```

### Using Standard SSH Port (22)

To run the honeypot on port 22:

1. Stop any existing SSH server: `sudo systemctl stop sshd`
2. Update docker-compose:
   ```yaml
   ports:
     - "22:2222"
   ```
3. Run with elevated privileges or use port forwarding

---

## Volume Management

### Data Volumes

| Volume | Container Path | Purpose |
|--------|---------------|---------|
| `./data/logs` | `/app/data/logs` | Session JSON logs |
| `./data/cache.json` | `/app/data/cache.json` | LLM response cache |
| `./data/host.key` | `/app/data/host.key` | SSH host key |
| `ollama-data` | `/root/.ollama` | Ollama models |
| `prometheus-data` | `/prometheus` | Metrics data |
| `grafana-data` | `/var/lib/grafana` | Dashboards, settings |

### Backup Volumes

```bash
# Backup session logs
tar -czvf backup-logs-$(date +%Y%m%d).tar.gz data/logs/

# Backup all data
tar -czvf backup-full-$(date +%Y%m%d).tar.gz data/ grafana/ prometheus/
```

### Clean Up Volumes

```bash
# Remove containers and volumes (DESTRUCTIVE)
docker compose down -v

# Remove only unused volumes
docker volume prune
```

---

## Security Hardening

### 1. Bind Dashboard Ports to Localhost

Edit docker-compose to restrict dashboard access:

```yaml
services:
  miragepot:
    ports:
      - "2222:2222"                    # Public: honeypot
      - "127.0.0.1:8501:8501"         # Localhost only: dashboard
      - "127.0.0.1:9090:9090"         # Localhost only: metrics
```

### 2. Change Default Passwords

```bash
# Grafana (edit .env.docker)
GRAFANA_ADMIN_PASSWORD=your-secure-password-here
```

### 3. Firewall Configuration

**UFW (Ubuntu):**
```bash
# Allow honeypot port
sudo ufw allow 2222/tcp

# Block direct access to dashboards (use SSH tunnel)
sudo ufw deny 8501/tcp
sudo ufw deny 3000/tcp
sudo ufw deny 9091/tcp
```

**iptables:**
```bash
# Allow honeypot
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT

# Restrict dashboard to localhost
iptables -A INPUT -p tcp --dport 8501 ! -s 127.0.0.1 -j DROP
iptables -A INPUT -p tcp --dport 3000 ! -s 127.0.0.1 -j DROP
```

### 4. Network Isolation

Create an isolated network for the honeypot:

```yaml
networks:
  miragepot-net:
    driver: bridge
    internal: false  # Set to true to fully isolate
    ipam:
      config:
        - subnet: 172.28.0.0/16
```

### 5. Resource Limits

Add resource constraints to prevent DoS:

```yaml
services:
  miragepot:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
```

---

## Remote Access

### SSH Tunneling (Recommended)

Access dashboards securely via SSH tunnel:

```bash
# Single tunnel for Grafana
ssh -L 3000:localhost:3000 user@your-server

# Multiple tunnels
ssh -L 3000:localhost:3000 \
    -L 8501:localhost:8501 \
    -L 9091:localhost:9091 \
    user@your-server
```

Then access locally:
- Grafana: http://localhost:3000
- Dashboard: http://localhost:8501

### Reverse Proxy (Advanced)

For production, use nginx with SSL:

```nginx
server {
    listen 443 ssl;
    server_name grafana.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Maintenance

### View Logs

```bash
# All containers
docker compose logs -f

# Specific container
docker logs -f miragepot-honeypot-simple

# Last 100 lines
docker logs --tail 100 miragepot-honeypot-simple
```

### Update Containers

```bash
# Pull latest images
docker compose pull

# Rebuild and restart
docker compose up -d --build
```

### Update Ollama Model

```bash
# Update phi3 model
docker exec miragepot-ollama ollama pull phi3

# Switch to different model
# Edit .env.docker: MIRAGEPOT_LLM_MODEL=llama2
docker compose restart miragepot
```

### Health Checks

```bash
# Check container health
docker compose ps

# Test SSH honeypot
nc -zv localhost 2222

# Test metrics endpoint
curl http://localhost:9090/metrics | head

# Test Ollama
curl http://localhost:11434/api/tags
```

---

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker compose logs miragepot

# Common issues:
# - Port already in use
# - Missing .env.docker file
# - Insufficient permissions
```

### Ollama Model Not Loading

```bash
# Check Ollama status
docker exec miragepot-ollama ollama list

# Re-pull model
docker exec miragepot-ollama ollama pull phi3

# Check Ollama logs
docker logs miragepot-ollama
```

### High Memory Usage

```bash
# Check container stats
docker stats

# Reduce memory:
# 1. Use smaller model (phi3:mini)
# 2. Add memory limits to docker-compose
# 3. Reduce max connections
```

### Metrics Not Appearing in Grafana

```bash
# Check Prometheus targets
curl http://localhost:9091/api/v1/targets

# Verify metrics endpoint
curl http://localhost:9090/metrics

# Check Prometheus logs
docker logs miragepot-prometheus
```

### Session Logs Not Saving

```bash
# Check volume mount
docker exec miragepot-honeypot ls -la /app/data/logs/

# Check permissions
ls -la data/logs/

# Fix permissions
chmod 755 data/logs/
```

---

## Next Steps

- [Configure Monitoring & Alerts](MONITORING.md)
- [Understand the Architecture](architecture.md)
- [Customize Configuration](CONFIGURATION.md)
- [Analyze Session Data](USAGE.md)
