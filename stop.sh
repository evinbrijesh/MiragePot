#!/usr/bin/env bash
# MiragePot — Stop the Docker stack (preserves volumes/data)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -f "docker/docker-compose.yml" ]]; then
    echo "ERROR: docker/docker-compose.yml not found."
    echo "       Run this script from the MiragePot project root."
    exit 1
fi

echo "Stopping MiragePot..."
docker compose -f docker/docker-compose.yml --env-file .env.docker down
echo "Done. All containers stopped. Data volumes preserved."
echo ""
echo "To restart: ./start.sh"
