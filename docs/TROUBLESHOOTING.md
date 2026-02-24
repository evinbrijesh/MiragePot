# MiragePot Troubleshooting Guide

Common issues and solutions for MiragePot deployment and operation.

## Table of Contents

- [Docker Issues](#docker-issues)
- [Installation Issues](#installation-issues)
- [Runtime Issues](#runtime-issues)
- [Monitoring Issues](#monitoring-issues)
- [Offline Deployment Issues](#offline-deployment-issues)

---

## Docker Issues

### "Cannot connect to Docker daemon"

**Problem:** Docker service is not running.

**Solution:**
```bash
# On Linux
sudo systemctl start docker

# Or on macOS/Windows, start Docker Desktop from Applications
```

---

### "Port 2222 already in use"

**Problem:** Another process is using the SSH honeypot port.

**Solution:**
```bash
# Find what's using the port
sudo lsof -i :2222

# Option 1: Kill the process (replace PID)
kill <PID>

# Option 2: Change port in docker-compose.yml
# Edit ports: "2223:2222" instead of "2222:2222"
```

---

### Container Won't Start

**Problem:** Container exits immediately or fails to start.

**Solution:**
```bash
# Check container logs
docker compose logs miragepot

# Common causes:
# 1. Missing .env.docker file
cp .env.docker.example .env.docker

# 2. Port conflicts (see above)

# 3. Insufficient permissions
chmod 755 data/logs/

# Restart after fixing
docker compose down
docker compose up -d
```

---

### "Containers not starting"

**Problem:** Multiple containers failing to start.

**Solution:**
```bash
# Check all container logs
docker compose logs

# Check specific container
docker logs miragepot-honeypot
docker logs miragepot-ollama

# Check container status
docker compose ps

# Force rebuild if needed
docker compose down
docker compose build --no-cache
docker compose up -d
```

---

### "Ollama model not responding" / "Ollama Model Not Loading"

**Problem:** AI responses are failing or timing out.

**Solution:**
```bash
# Check if model is downloaded
docker exec miragepot-ollama ollama list

# If model not found, wait for automatic download (first run)
# Monitor progress:
docker logs -f miragepot-ollama

# Or manually re-pull the model
docker exec miragepot-ollama ollama pull phi3

# Check Ollama logs for errors
docker logs miragepot-ollama
```

**Note:** First model download takes 2-5 minutes (~2GB). Subsequent starts are instant.

---

### "Waiting for model download"

**Problem:** First-time setup is slow.

**Solution:** This is normal! The phi3 model (~2GB) downloads automatically on first run.

```bash
# Monitor progress
docker logs -f miragepot-ollama

# If download seems stuck:
# 1. Check internet connection
# 2. Restart Ollama container
docker compose restart ollama
```

---

### "Connection refused to Ollama"

**Problem:** Honeypot can't reach Ollama service.

**Solution:**
```bash
# Wait for model download to complete (first run)
docker logs miragepot-ollama

# Check if Ollama container is running
docker compose ps ollama

# Test Ollama directly
docker exec miragepot-ollama ollama run phi3 "test"

# Check network connectivity
docker compose exec miragepot curl http://ollama:11434
```

---

### "AI responses are slow"

**Problem:** Long delays between commands and responses.

**Solution:**
```bash
# Check if model is loaded in memory
docker exec miragepot-ollama ollama list

# Restart Ollama to reload model
docker restart miragepot-ollama

# Use a smaller model (edit .env.docker)
OLLAMA_MODEL=phi3:mini

# Check system resources
docker stats
```

**Note:** First query is always slowest (model loading). Subsequent queries are faster.

---

### High Memory Usage

**Problem:** Containers using too much RAM.

**Solution:**
```bash
# Check container memory usage
docker stats

# Solutions:
# 1. Use smaller model (phi3:mini ~1GB instead of ~2GB)
OLLAMA_MODEL=phi3:mini

# 2. Add memory limits to docker-compose.yml
services:
  ollama:
    mem_limit: 3g

# 3. Reduce max connections (edit .env.docker)
MIRAGEPOT_MAX_TOTAL_CONNECTIONS=25
```

---

### Session Logs Not Saving

**Problem:** No logs appearing in `data/logs/`.

**Solution:**
```bash
# Check volume mount inside container
docker exec miragepot-honeypot ls -la /app/data/logs/

# Check permissions on host
ls -la data/logs/

# Fix permissions
chmod 755 data/logs/

# Create directory if missing
mkdir -p data/logs/

# Restart container
docker restart miragepot-honeypot
```

---

### "SSH connection refused"

**Problem:** Can't connect to honeypot via SSH.

**Solution:**
```bash
# Check if port is bound
docker compose ps
lsof -i :2222

# Check honeypot logs
docker logs miragepot-honeypot

# Restart honeypot container
docker restart miragepot-honeypot

# Test from inside Docker network
docker compose exec miragepot nc -zv localhost 2222
```

---

### "Browser tabs won't load" (Streamlit/Grafana)

**Problem:** Web interfaces not accessible.

**Solution:**
```bash
# Check if containers are healthy
docker compose ps

# Test each service
curl http://localhost:8501                  # Streamlit
curl http://localhost:3000/api/health       # Grafana
curl http://localhost:9091/api/v1/targets   # Prometheus

# Check logs
docker logs miragepot-honeypot  # Streamlit embedded
docker logs miragepot-grafana
docker logs miragepot-prometheus

# Restart specific service
docker restart miragepot-grafana
```

---

## Installation Issues

### "Address already in use" Error

**Problem:** Port 2222 is already occupied.

**Solution:**
```bash
# Find the process using the port
lsof -i :2222

# Kill it
kill <PID>

# Or use a different port
miragepot --port 2223
```

---

### "ollama: command not found"

**Problem:** Ollama is not installed or not in PATH.

**Solution:**
```bash
# Check if Ollama is installed
which ollama

# If not found, install it:
# Linux:
curl -fsSL https://ollama.ai/install.sh | sh

# macOS:
brew install ollama

# Verify installation
ollama --version
```

---

### "Model not found" Warning

**Problem:** LLM model hasn't been downloaded.

**Solution:**
```bash
# Start Ollama service
ollama serve &

# Download the model
ollama pull phi3

# Verify model exists
ollama list
```

---

### Connection Refused to Ollama

**Problem:** Ollama server isn't running (local installation).

**Solution:**
```bash
# Start Ollama in background
ollama serve &

# Or use systemd (Linux)
sudo systemctl start ollama

# Verify it's running
curl http://localhost:11434/api/tags
```

---

### Permission Denied on Port 22

**Problem:** Standard SSH port requires root privileges.

**Solution:**
```bash
# Option 1: Use a high port (recommended)
miragepot --port 2222

# Option 2: Run as root (not recommended for security)
sudo miragepot --port 22

# Option 3: Grant capability to Python (Linux only)
sudo setcap 'cap_net_bind_service=+ep' $(which python3)
miragepot --port 22
```

---

## Runtime Issues

### Honeypot Not Responding

**Problem:** SSH connections hang or don't get responses.

**Solution:**

1. **Check if Ollama is running:**
   ```bash
   # Docker deployment
   docker logs miragepot-ollama
   
   # Local deployment
   ollama list
   ```

2. **Check port availability:**
   ```bash
   lsof -i :2222
   ```

3. **Check logs for errors:**
   ```bash
   # Docker
   docker logs miragepot-honeypot
   
   # Local
   miragepot --log-level DEBUG
   ```

---

### Slow Responses

**Problem:** Long delays between commands and AI responses.

**Solution:**

1. **First query is always slowest** (Ollama loads model into memory)
   
2. **Try a smaller model:**
   ```bash
   # Edit .env or .env.docker
   MIRAGEPOT_LLM_MODEL=phi3:mini
   ```

3. **Reduce timeout:**
   ```bash
   MIRAGEPOT_LLM_TIMEOUT=15
   ```

4. **Check system resources:**
   ```bash
   # CPU/RAM usage
   top
   # or
   docker stats
   ```

---

### Dashboard Not Loading

**Problem:** Streamlit dashboard not accessible.

**Solution:**

1. **Check if Streamlit is installed:**
   ```bash
   pip install streamlit
   ```

2. **Check if port 8501 is available:**
   ```bash
   lsof -i :8501
   ```

3. **Check logs:**
   ```bash
   # Docker
   docker logs miragepot-honeypot | grep streamlit
   
   # Local
   # Dashboard runs embedded in honeypot
   ```

---

### No Session Logs

**Problem:** No files appearing in `data/logs/`.

**Solution:**

1. **Check directory exists:**
   ```bash
   ls -la data/logs/
   mkdir -p data/logs/  # Create if missing
   ```

2. **Verify write permissions:**
   ```bash
   chmod 755 data/logs/
   ```

3. **Ensure attacker ran commands:**
   - Just connecting doesn't create a log
   - Commands must be entered for logging

4. **Check honeypot logs for errors:**
   ```bash
   docker logs miragepot-honeypot | grep -i log
   ```

---

## Monitoring Issues

### Metrics Not Appearing / "Grafana shows no data"

**Problem:** Grafana dashboards are empty or Prometheus not collecting metrics.

**Solution:**

1. **Check metrics endpoint:**
   ```bash
   curl http://localhost:9090/metrics
   ```

2. **Check Prometheus targets:**
   ```
   # Open in browser
   http://localhost:9091/targets
   
   # Or via CLI
   curl http://localhost:9091/api/v1/targets
   ```

3. **Wait for first scrape:**
   ```bash
   # Prometheus scrapes every 15 seconds
   # Wait 30 seconds after starting, then refresh Grafana
   ```

4. **Check Prometheus logs:**
   ```bash
   docker logs miragepot-prometheus
   ```

5. **Restart Prometheus:**
   ```bash
   docker restart miragepot-prometheus
   ```

---

### Grafana Can't Connect to Prometheus

**Problem:** Grafana datasource shows "Connection refused" or "Bad Gateway".

**Solution:**

1. **Check datasource configuration:**
   - In Grafana: Configuration → Data Sources → Prometheus
   - URL should be `http://prometheus:9090` (Docker internal network)
   - NOT `http://localhost:9091` (that's for host access)

2. **Test connection:**
   - Click "Save & Test" in datasource settings
   - Should show green "Data source is working"

3. **Verify Prometheus is running:**
   ```bash
   docker compose ps prometheus
   ```

---

### Dashboards Not Loading

**Problem:** Grafana dashboards show errors or are missing.

**Solution:**

1. **Re-import dashboards:**
   ```bash
   ./scripts/setup-grafana-dashboards.sh
   ```

2. **Check for datasource UID mismatch:**
   - Edit dashboard JSON
   - Find: `"datasource": {"uid": "..."}`
   - Should match Prometheus datasource UID
   - Update to `"uid": "prometheus"` if different

3. **Check Grafana logs:**
   ```bash
   docker logs miragepot-grafana
   ```

4. **Manually import:**
   - Grafana UI → Dashboards → Import
   - Upload JSON from `grafana/dashboards/`

---

## Offline Deployment Issues

### "Image not found" after docker load

**Problem:** Docker can't find images after loading from tar file.

**Solution:**
```bash
# Verify image file exists and isn't corrupted
ls -lh miragepot-images.tar

# Try loading with verbose output
docker load -i miragepot-images.tar

# Verify images are loaded
docker images | grep miragepot

# If missing, re-export from source machine
./scripts/export-offline.sh
```

---

### "Ollama model not found" (Offline)

**Problem:** Model not available after restoring from offline bundle.

**Solution:**
```bash
# Check if volume was restored
docker volume inspect ollama

# Check model inside container
docker exec miragepot-ollama ls -la /root/.ollama/models/

# If missing, restore model volume:
docker run --rm \
  -v ollama:/ollama \
  -v $(pwd):/backup \
  alpine tar xzf /backup/ollama-models.tar.gz -C /ollama

# Verify model
docker exec miragepot-ollama ollama list
```

---

### "Container keeps restarting" (Offline)

**Problem:** Container enters restart loop.

**Solution:**
```bash
# Check logs for specific error
docker logs miragepot-honeypot

# Common issues:

# 1. Missing .env.docker file
cp .env.docker.example .env.docker

# 2. Volume permission issues
chmod 755 data/logs/
chmod 644 data/cache.json data/system_prompt.txt

# 3. Corrupted image - re-export and reload
# On source machine:
./scripts/export-offline.sh

# 4. Check dependencies
docker compose config  # Validates compose file
```

---

## General Tips

### Enable Debug Logging

**Docker:**
```bash
# Edit .env.docker
MIRAGEPOT_LOG_LEVEL=DEBUG

# Restart
docker compose restart miragepot
```

**Local:**
```bash
miragepot --log-level DEBUG
```

---

### Clean Start (Reset Everything)

**Docker:**
```bash
# Stop and remove everything (including volumes)
docker compose down -v

# Remove images (optional)
docker rmi miragepot-honeypot ollama/ollama prom/prometheus grafana/grafana prom/alertmanager

# Start fresh
cd docker/
docker compose up -d
```

**Local:**
```bash
# Clear logs
rm -rf data/logs/*.json

# Reset cache
rm data/cache.json

# Reinstall
pip uninstall miragepot
pip install -e .
```

---

### Check All Services Health

```bash
# Docker deployment
docker compose ps
docker compose logs --tail=50

# Test each service
curl http://localhost:2222        # Should refuse (not HTTP)
curl http://localhost:8501        # Streamlit
curl http://localhost:9090/metrics # Honeypot metrics
curl http://localhost:9091        # Prometheus
curl http://localhost:3000        # Grafana

# SSH test
ssh root@localhost -p 2222
```

---

## Still Having Issues?

If none of these solutions work:

1. **Check the logs carefully:**
   ```bash
   docker compose logs > full-logs.txt
   ```

2. **Verify system requirements:**
   - Docker 20.10+
   - Docker Compose v2+
   - 4GB RAM minimum
   - 5GB disk space

3. **Try simple stack first:**
   ```bash
   docker compose -f docker-compose-simple.yml up -d
   ```

4. **Report the issue:**
   - GitHub: https://github.com/evinbrijesh/MiragePot/issues
   - Include: logs, docker-compose.yml, OS version
