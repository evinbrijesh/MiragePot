#!/bin/bash
# =============================================================================
# MiragePot Docker Logs Viewer
# =============================================================================
# Quick access to container logs with filtering options
#
# Usage:
#   ./scripts/logs.sh                     # Interactive menu
#   ./scripts/logs.sh miragepot           # Show honeypot logs
#   ./scripts/logs.sh ollama              # Show Ollama logs
#   ./scripts/logs.sh prometheus          # Show Prometheus logs
#   ./scripts/logs.sh alertmanager        # Show Alertmanager logs
#   ./scripts/logs.sh grafana             # Show Grafana logs
#   ./scripts/logs.sh all                 # All logs interleaved
#   ./scripts/logs.sh miragepot --follow  # Tail logs (Ctrl+C to exit)
#   ./scripts/logs.sh all --errors        # Only ERROR/CRITICAL lines
#
# Author: MiragePot Team
# =============================================================================

set -e

# =============================================================================
# Color Codes
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# =============================================================================
# Container Name Mapping
# =============================================================================
declare -A CONTAINER_NAMES=(
    ["miragepot"]="miragepot-honeypot"
    ["ollama"]="miragepot-ollama"
    ["prometheus"]="miragepot-prometheus"
    ["alertmanager"]="miragepot-alertmanager"
    ["grafana"]="miragepot-grafana"
)

# =============================================================================
# Helper Functions
# =============================================================================

print_header() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

check_container_exists() {
    local container=$1
    
    if ! docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
        print_error "Container '$container' not found"
        echo ""
        echo "Available containers:"
        docker ps -a --format '  - {{.Names}}' | grep miragepot
        echo ""
        echo "Start services with: ./scripts/test-docker.sh"
        exit 1
    fi
}

# =============================================================================
# Log Display Functions
# =============================================================================

show_logs() {
    local service=$1
    local follow=${2:-false}
    local errors_only=${3:-false}
    
    # Get full container name
    local container="${CONTAINER_NAMES[$service]}"
    
    if [[ -z "$container" ]]; then
        print_error "Unknown service: $service"
        exit 1
    fi
    
    # Check if container exists
    check_container_exists "$container"
    
    # Build docker logs command
    local cmd="docker logs"
    
    if [[ "$follow" == "true" ]]; then
        cmd="$cmd --follow"
    else
        cmd="$cmd --tail 100"
    fi
    
    cmd="$cmd $container"
    
    # Add timestamp
    cmd="$cmd --timestamps"
    
    print_header "Logs: $service ($container)"
    
    if [[ "$follow" == "true" ]]; then
        print_info "Following logs (press Ctrl+C to exit)..."
        echo ""
    fi
    
    # Execute command
    if [[ "$errors_only" == "true" ]]; then
        $cmd 2>&1 | grep -i -E "error|critical|fatal|exception" || echo "(no errors found)"
    else
        $cmd 2>&1
    fi
}

show_all_logs() {
    local follow=${1:-false}
    local errors_only=${2:-false}
    
    print_header "All Container Logs"
    
    # Find all running miragepot containers
    local containers=$(docker ps --filter "name=miragepot-" --format "{{.Names}}" | tr '\n' ' ')
    
    if [[ -z "$containers" ]]; then
        print_error "No MiragePot containers are running"
        echo ""
        echo "Start services with: ./scripts/test-docker.sh"
        exit 1
    fi
    
    print_info "Showing logs from: $containers"
    
    if [[ "$follow" == "true" ]]; then
        print_info "Following logs (press Ctrl+C to exit)..."
    fi
    
    echo ""
    
    # Build command
    local cmd="docker logs"
    
    if [[ "$follow" == "true" ]]; then
        # For follow mode, we need to run separate commands
        for container in $containers; do
            docker logs --follow --timestamps $container 2>&1 &
        done
        wait
    else
        # For static logs, show last 50 lines from each
        for container in $containers; do
            echo ""
            echo -e "${CYAN}=== $container ===${NC}"
            echo ""
            
            if [[ "$errors_only" == "true" ]]; then
                docker logs --tail 50 --timestamps $container 2>&1 | grep -i -E "error|critical|fatal|exception" || echo "(no errors)"
            else
                docker logs --tail 50 --timestamps $container 2>&1
            fi
        done
    fi
}

# =============================================================================
# Interactive Menu
# =============================================================================

show_menu() {
    print_header "MiragePot Logs Viewer"
    
    # Check which containers are running
    local running_containers=$(docker ps --filter "name=miragepot-" --format "{{.Names}}")
    
    if [[ -z "$running_containers" ]]; then
        print_error "No MiragePot containers are running"
        echo ""
        echo "Start services with: ./scripts/test-docker.sh"
        exit 1
    fi
    
    echo "Running containers:"
    echo "$running_containers" | sed 's/^/  ✓ /'
    echo ""
    
    echo "Select container to view logs:"
    echo ""
    echo "  1) miragepot     - SSH honeypot"
    echo "  2) ollama        - AI model server"
    echo "  3) prometheus    - Metrics collection"
    echo "  4) alertmanager  - Alert routing"
    echo "  5) grafana       - Dashboards"
    echo "  6) all           - All containers"
    echo ""
    echo "  0) Exit"
    echo ""
    
    read -p "Enter choice [0-6]: " choice
    
    case $choice in
        1) service="miragepot" ;;
        2) service="ollama" ;;
        3) service="prometheus" ;;
        4) service="alertmanager" ;;
        5) service="grafana" ;;
        6) service="all" ;;
        0) exit 0 ;;
        *)
            print_error "Invalid choice"
            exit 1
            ;;
    esac
    
    echo ""
    echo "Options:"
    echo "  1) Show last 100 lines"
    echo "  2) Follow logs (tail -f)"
    echo "  3) Show only errors"
    echo ""
    
    read -p "Enter option [1-3]: " opt_choice
    
    follow=false
    errors_only=false
    
    case $opt_choice in
        1) ;;
        2) follow=true ;;
        3) errors_only=true ;;
        *)
            print_error "Invalid option"
            exit 1
            ;;
    esac
    
    echo ""
    
    if [[ "$service" == "all" ]]; then
        show_all_logs "$follow" "$errors_only"
    else
        show_logs "$service" "$follow" "$errors_only"
    fi
}

# =============================================================================
# Main
# =============================================================================

main() {
    # Change to project root if running from scripts/ directory
    if [[ $(basename "$PWD") == "scripts" ]]; then
        cd ..
    fi
    
    # Parse arguments
    if [[ $# -eq 0 ]]; then
        # No arguments, show menu
        show_menu
    else
        service=$1
        follow=false
        errors_only=false
        
        # Check for flags
        for arg in "${@:2}"; do
            case $arg in
                --follow|-f)
                    follow=true
                    ;;
                --errors|-e)
                    errors_only=true
                    ;;
                *)
                    echo "Unknown flag: $arg"
                    echo ""
                    echo "Available flags:"
                    echo "  --follow, -f    Follow logs (tail -f)"
                    echo "  --errors, -e    Show only errors"
                    exit 1
                    ;;
            esac
        done
        
        # Show logs
        if [[ "$service" == "all" ]]; then
            show_all_logs "$follow" "$errors_only"
        else
            show_logs "$service" "$follow" "$errors_only"
        fi
    fi
}

# Run main function
main "$@"
