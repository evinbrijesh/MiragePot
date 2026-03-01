#!/usr/bin/env bash
# MiragePot — Start the full Docker stack
set -euo pipefail

# ── Ensure we're in the project root ────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -f "docker/docker-compose.yml" ]]; then
    echo "ERROR: docker/docker-compose.yml not found."
    echo "       Run this script from the MiragePot project root."
    exit 1
fi

# ── Ensure .env.docker exists ───────────────────────────────────────
if [[ ! -f ".env.docker" ]]; then
    if [[ -f ".env.docker.example" ]]; then
        cp .env.docker.example .env.docker
        echo "Created .env.docker from .env.docker.example"
        echo ""
        echo "  >>> IMPORTANT: Open .env.docker and set GRAFANA_ADMIN_PASSWORD <<<"
        echo "      (it is currently set to a placeholder value)"
        echo ""
        echo "Then re-run this script."
        exit 1
    else
        echo "ERROR: .env.docker.example not found. Cannot create .env.docker."
        exit 1
    fi
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " MiragePot — Starting Docker Stack"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Build and start containers ──────────────────────────────────────
echo "[1/4] Building and starting containers..."
docker compose -f docker/docker-compose.yml --env-file .env.docker up -d --build

# ── Show live model download progress (first run only) ──────────────
echo ""
echo "[2/4] Checking AI model status..."
# Follow ollama logs until the model is ready or the pull finishes.
# Stream output live so the user sees download progress bars.
# Timeout after 10 minutes (model pull can take a while on slow connections).
(
    timeout 600 docker logs -f miragepot-ollama 2>&1 &
    LOG_PID=$!
    # Wait until the container is healthy or the pull completes
    while true; do
        STATUS=$(docker inspect --format='{{.State.Health.Status}}' miragepot-ollama 2>/dev/null || echo "starting")
        if [[ "$STATUS" == "healthy" ]]; then
            kill $LOG_PID 2>/dev/null || true
            break
        fi
        sleep 5
    done
) 2>/dev/null || true
echo ""
echo "   AI model ready."

# ── Wait for all containers to be healthy ───────────────────────────
echo ""
echo "[3/4] Waiting for all services to become healthy..."
CONTAINERS=("miragepot-ollama" "miragepot-honeypot" "miragepot-prometheus" "miragepot-alertmanager" "miragepot-grafana")
MAX_WAIT=300
ELAPSED=0

all_healthy() {
    for c in "${CONTAINERS[@]}"; do
        STATUS=$(docker inspect --format='{{.State.Health.Status}}' "$c" 2>/dev/null || echo "missing")
        if [[ "$STATUS" != "healthy" ]]; then
            return 1
        fi
    done
    return 0
}

while ! all_healthy; do
    if (( ELAPSED >= MAX_WAIT )); then
        echo ""
        echo "WARNING: Timed out waiting for all containers to become healthy."
        echo "         Run 'docker ps' to check status."
        break
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
    # Print a dot every 5 seconds to show progress
    printf "."
done
echo ""
echo "   All services healthy."

# ── Clear stale SSH host key ────────────────────────────────────────
echo ""
echo "[4/4] Clearing stale SSH host keys for localhost:2222..."
ssh-keygen -R "[localhost]:2222" 2>/dev/null || true

# ── Open browser tabs ──────────────────────────────────────────────
open_url() {
    local url="$1"
    if command -v xdg-open &>/dev/null; then
        xdg-open "$url" 2>/dev/null &
    elif command -v open &>/dev/null; then
        open "$url" &
    elif command -v wslview &>/dev/null; then
        wslview "$url" &
    fi
}

echo ""
echo "Opening dashboards in your browser..."
sleep 1
open_url "http://localhost:8501"
open_url "http://localhost:3000"
open_url "http://localhost:9091"
open_url "http://localhost:9093"

# ── Summary ─────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " MiragePot is running!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Streamlit Dashboard : http://localhost:8501"
echo "  Grafana Dashboards  : http://localhost:3000  (admin / <your password>)"
echo "  Prometheus UI       : http://localhost:9091"
echo "  Alertmanager UI     : http://localhost:9093"
echo ""
echo "  SSH into honeypot   : ssh root@localhost -p 2222"
echo ""
echo "  Stop the stack      : ./stop.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
