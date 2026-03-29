#!/usr/bin/env bash
# MiragePot — Start the full Docker stack
set -euo pipefail

# ── Parse arguments ─────────────────────────────────────────────────
SKIP_BUILD=false
QUICK_START=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --no-build|-n)
            SKIP_BUILD=true
            shift
            ;;
        --quick|-q)
            QUICK_START=true
            SKIP_BUILD=true
            shift
            ;;
        --help|-h)
            echo "Usage: ./start.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-build, -n    Skip Docker image rebuild (faster restart)"
            echo "  --quick, -q       Quick start: skip build + minimal health wait"
            echo "  --help, -h        Show this help message"
            echo ""
            echo "Examples:"
            echo "  ./start.sh           # Full build and start (first time)"
            echo "  ./start.sh -n        # Restart without rebuilding"
            echo "  ./start.sh -q        # Quick restart (fastest)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# ── Ensure we're in the project root ────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -f "docker/docker-compose.yml" ]]; then
    echo "ERROR: docker/docker-compose.yml not found."
    echo "       Run this script from the MiragePot project root."
    exit 1
fi

# ── Check for Docker ────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo ""
    echo "ERROR: Docker is not installed."
    echo ""
    OS="$(uname -s)"
    if [[ "$OS" == "Linux" ]]; then
        echo "  Docker can be installed automatically using the official install script."
        echo "  Source: https://get.docker.com"
        echo ""
        read -r -p "  Install Docker now? [y/N] " REPLY
        echo ""
        if [[ "$REPLY" =~ ^[Yy]$ ]]; then
            echo "  Downloading and running Docker install script..."
            if curl -fsSL https://get.docker.com -o /tmp/get-docker.sh; then
                sh /tmp/get-docker.sh
                rm -f /tmp/get-docker.sh
                # Add current user to docker group so they don't need sudo
                if ! id -nG "$USER" | grep -qw docker; then
                    echo ""
                    echo "  Adding $USER to the 'docker' group..."
                    usermod -aG docker "$USER" 2>/dev/null || true
                fi
                echo ""
                echo "  Docker installed successfully."
                echo ""
                # newgrp would drop us back to a subshell; instruct user to re-login instead
                echo "  NOTE: You may need to log out and back in (or run 'newgrp docker')"
                echo "        before running Docker as a non-root user."
                echo "        Then re-run: ./start.sh"
                echo ""
            else
                echo "  ERROR: Failed to download the Docker install script."
                echo "         Check your internet connection or install Docker manually:"
                echo "         https://docs.docker.com/engine/install/"
            fi
            exit 1
        else
            echo "  Install Docker manually and re-run this script:"
            echo "  https://docs.docker.com/engine/install/"
            exit 1
        fi
    elif [[ "$OS" == "Darwin" ]]; then
        echo "  Install Docker Desktop for Mac and re-run this script:"
        echo "  https://docs.docker.com/desktop/install/mac-install/"
        exit 1
    else
        echo "  Install Docker for your platform and re-run this script:"
        echo "  https://docs.docker.com/engine/install/"
        exit 1
    fi
fi

# ── Check for Docker Compose ────────────────────────────────────────
if ! docker compose version &>/dev/null 2>&1; then
    echo ""
    echo "ERROR: Docker Compose plugin is not available."
    echo "       It is bundled with Docker Desktop and Docker Engine >= 20.10."
    echo "       Install or update Docker: https://docs.docker.com/engine/install/"
    echo ""
    exit 1
fi

# ── Ensure .env.docker exists ───────────────────────────────────────
if [[ ! -f ".env.docker" ]]; then
    if [[ -f ".env.docker.example" ]]; then
        cp .env.docker.example .env.docker
        echo "Created .env.docker from .env.docker.example"
        echo ""
        # Check if passwords are still set to placeholder values
        if grep -q "changeme_set_a_strong_password_here" .env.docker; then
            echo "  >>> IMPORTANT: Open .env.docker and set GRAFANA_ADMIN_PASSWORD <<<"
            echo "      (it is currently set to a placeholder value)"
            echo ""
            echo "Then re-run this script."
            exit 1
        else
            echo "  ✓ Using demo credentials (admin/admin)"
            echo "  ⚠️  WARNING: Change these for production use!"
            echo ""
        fi
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
# Use DOCKER_BUILDKIT for faster builds with better caching
if [[ "$SKIP_BUILD" == "true" ]]; then
    echo "   (Skipping rebuild - using cached image)"
    docker compose -f docker/docker-compose.yml --env-file .env.docker up -d
else
    DOCKER_BUILDKIT=1 docker compose -f docker/docker-compose.yml --env-file .env.docker up -d --build
fi

# ── Show live model download progress (first run only) ──────────────
echo ""
echo "[2/4] Checking AI model status..."

if [[ "$QUICK_START" == "true" ]]; then
    echo "   (Quick start mode - minimal health wait)"
    sleep 2
    echo "   ✅ Skipped detailed health check"
else
    # Wait for ollama server to respond (not full model load)
    MAX_WAIT=30
    ELAPSED=0
    while true; do
        # Check if Ollama is responding (server started)
        if docker exec miragepot-ollama curl -sf http://localhost:11434/ >/dev/null 2>&1; then
            echo "   ✅ Ollama server responding"
            break
        fi
        if (( ELAPSED >= MAX_WAIT )); then
            echo "   ⚠️  Ollama still starting (honeypot will retry)"
            break
        fi
        sleep 2
        ELAPSED=$((ELAPSED + 2))
        printf "."
    done
fi
echo ""
echo "   AI model loading in background..."

# ── Wait for all containers to be healthy ───────────────────────────
echo ""
echo "[3/4] Waiting for all services to become healthy..."

if [[ "$QUICK_START" == "true" ]]; then
    echo "   (Quick start mode - skipping full health check)"
    sleep 2
    echo "   ✅ Services starting..."
else
    # Don't wait for Ollama to be fully healthy - just check honeypot and monitoring
    CONTAINERS=("miragepot-honeypot" "miragepot-prometheus" "miragepot-alertmanager" "miragepot-grafana")
    MAX_WAIT=60
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
        sleep 2
        ELAPSED=$((ELAPSED + 2))
        # Print a dot every 2 seconds to show progress
        printf "."
    done
    echo ""
    echo "   All services healthy."
fi

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
echo "Opening MiragePot dashboard in your browser..."
sleep 1
open_url "http://localhost:8501"

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
