#!/bin/bash
# Wait for all Docker Compose services to become healthy
# Used by 'make demo' to ensure cold start is complete

set -e

COMPOSE_FILE="${COMPOSE_FILE:-docker/docker-compose.yml}"
MAX_WAIT_SECONDS=300  # 5 minutes timeout
CHECK_INTERVAL=3      # Check every 3 seconds

echo "⏳ Waiting for all services to become healthy..."
echo "   (timeout: ${MAX_WAIT_SECONDS}s)"

start_time=$(date +%s)
all_healthy=false

while true; do
    current_time=$(date +%s)
    elapsed=$((current_time - start_time))
    
    if [ $elapsed -ge $MAX_WAIT_SECONDS ]; then
        echo ""
        echo "❌ Timeout: Services did not become healthy within ${MAX_WAIT_SECONDS}s"
        echo ""
        echo "Service status:"
        docker compose -f "$COMPOSE_FILE" ps
        exit 1
    fi
    
    # Get service health status
    # Format: service_name|health_status
    services_status=$(docker compose -f "$COMPOSE_FILE" ps --format json 2>/dev/null | \
        jq -r 'select(.Health != "") | "\(.Service)|\(.Health)"' 2>/dev/null || echo "")
    
    if [ -z "$services_status" ]; then
        # No health info yet, services still starting
        printf "."
        sleep $CHECK_INTERVAL
        continue
    fi
    
    # Check if all services are healthy
    unhealthy_count=0
    unhealthy_services=""
    
    while IFS='|' read -r service health; do
        if [ "$health" != "healthy" ]; then
            unhealthy_count=$((unhealthy_count + 1))
            unhealthy_services="$unhealthy_services $service($health)"
        fi
    done <<< "$services_status"
    
    if [ $unhealthy_count -eq 0 ]; then
        all_healthy=true
        break
    fi
    
    # Print progress
    printf "."
    sleep $CHECK_INTERVAL
done

if [ "$all_healthy" = true ]; then
    echo ""
    echo "✅ All services are healthy! (took ${elapsed}s)"
    echo ""
    docker compose -f "$COMPOSE_FILE" ps
    exit 0
fi
