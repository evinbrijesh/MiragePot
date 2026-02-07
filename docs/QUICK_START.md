# MiragePot Quick Start Guide

Get MiragePot running in under 5 minutes with Docker.

## Prerequisites

- **Docker** 20.10+ ([Install Docker](https://docs.docker.com/get-docker/))
- **Docker Compose** v2.0+ (included with Docker Desktop)
- **5GB free disk space** (for Ollama models)
- **4GB RAM minimum** (8GB recommended)

Verify installation:
```bash
docker --version
docker compose version
```

## Quick Deploy

### Option 1: One-Command Deploy (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/MiragePot.git
cd MiragePot

# Run the deployment script
./scripts/deploy.sh
```

The script will:
1. Check prerequisites
2. Set up configuration
3. Pull/build Docker images
4. Start all services
5. Download the AI model (~2GB)
6. Display access URLs

### Option 2: Manual Docker Compose

**Simple Stack** (Honeypot + AI only):
```bash
# Copy environment file
cp .env.docker.example .env.docker

# Start services
docker compose -f docker-compose-simple.yml up -d

# Pull the AI model (wait ~2-3 minutes)
docker exec miragepot-ollama-simple ollama pull phi3
```

**Full Stack** (+ Prometheus, Grafana, Alertmanager):
```bash
# Copy environment file
cp .env.docker.example .env.docker

# Start services
cd docker/
docker compose up -d

# Pull the AI model
docker exec miragepot-ollama ollama pull phi3
```

## Access Your Honeypot

Once deployed, access these services:

| Service | URL | Credentials |
|---------|-----|-------------|
| **SSH Honeypot** | `ssh root@localhost -p 2222` | Any password works |
| **Streamlit Dashboard** | http://localhost:8501 | None |
| **Grafana** (full stack) | http://localhost:3000 | admin / admin |
| **Prometheus** (full stack) | http://localhost:9091 | None |

## Test the Honeypot

Open a terminal and connect to the honeypot:

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
```

The AI will generate realistic responses. Watch the Streamlit dashboard to see your session being logged in real-time.

## View Your Data

### Streamlit Dashboard
Open http://localhost:8501 to see:
- Live session activity
- Command history
- Threat analysis
- Attacker statistics

### Grafana Dashboards (Full Stack)
Open http://localhost:3000 and import dashboards from `grafana/dashboards/`:
- **MiragePot Overview** - Connections, commands, threats
- **TTP Analysis** - MITRE ATT&CK detections
- **Performance** - LLM latency, cache efficiency

### Session Logs
JSON logs are saved to `data/logs/`:
```bash
ls -la data/logs/
cat data/logs/session_*.json | jq .
```

## Common Commands

```bash
# View container status
./scripts/deploy.sh --status

# View logs
./scripts/deploy.sh --logs

# Stop everything
./scripts/deploy.sh --stop

# Restart services
./scripts/deploy.sh --restart
```

## Deployment Options Comparison

| Feature | Simple Stack | Full Stack |
|---------|--------------|------------|
| SSH Honeypot | ✅ | ✅ |
| AI Responses (Ollama) | ✅ | ✅ |
| Streamlit Dashboard | ✅ | ✅ |
| Session Logging | ✅ | ✅ |
| Prometheus Metrics | ✅ (endpoint only) | ✅ (full UI) |
| Grafana Dashboards | ❌ | ✅ |
| Alertmanager | ❌ | ✅ |
| Containers | 2 | 5 |
| RAM Usage | ~2GB | ~4GB |

**Choose Simple Stack if:** You want quick testing or demos.

**Choose Full Stack if:** You want full monitoring, alerting, and analysis capabilities.

## Troubleshooting

### "Cannot connect to Docker daemon"
```bash
# Start Docker service
sudo systemctl start docker

# Or on macOS, start Docker Desktop
```

### "Port 2222 already in use"
```bash
# Find what's using the port
sudo lsof -i :2222

# Change port in docker-compose file or kill the process
```

### "Ollama model not responding"
```bash
# Check if model is downloaded
docker exec miragepot-ollama-simple ollama list

# Re-pull the model
docker exec miragepot-ollama-simple ollama pull phi3
```

### "Services not starting"
```bash
# Check container logs
docker compose -f docker-compose-simple.yml logs

# Check specific container
docker logs miragepot-honeypot-simple
```

### Low disk space warning
The phi3 model requires ~2GB. Free up space or use a smaller model:
```bash
# Edit .env.docker and change:
MIRAGEPOT_LLM_MODEL=phi3:mini  # Smaller variant
```

## Next Steps

- Read the full [Docker Deployment Guide](DOCKER_DEPLOYMENT.md)
- Learn about [Monitoring & Dashboards](MONITORING.md)
- Understand the [Architecture](architecture.md)
- Configure [Alerts & Notifications](CONFIGURATION.md)

## Getting Help

- Check existing [documentation](.)
- Open an issue on GitHub
- Review logs: `./scripts/deploy.sh --logs`

---

**Congratulations!** You now have an AI-powered SSH honeypot running. Watch attackers interact with your fake server while the AI generates convincing responses!
