#!/usr/bin/env bash
# =============================================================================
# MiragePot Deployment Script
# =============================================================================
# Automated deployment script for MiragePot SSH Honeypot
# Supports both simple (2-container) and full (5-container) deployments
#
# Usage:
#   ./scripts/deploy.sh               # Interactive mode
#   ./scripts/deploy.sh --simple      # Simple deployment (no monitoring)
#   ./scripts/deploy.sh --full        # Full deployment (with Prometheus/Grafana)
#   ./scripts/deploy.sh --help        # Show help
#
# Requirements:
#   - Docker 20.10+
#   - Docker Compose v2.0+ (or docker-compose 1.29+)
#
# Author: MiragePot Team
# License: MIT
# =============================================================================

set -e  # Exit on error
set -u  # Exit on undefined variable

# -----------------------------------------------------------------------------
# Color Codes & Formatting
# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

# Print colored messages
print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_info() { echo -e "${BLUE}ℹ${NC} $1"; }
print_header() { echo -e "\n${BOLD}${CYAN}$1${NC}\n"; }

# Error handler
error_exit() {
    print_error "$1"
    exit 1
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Wait for service to be healthy
wait_for_service() {
    local service="$1"
    local max_attempts="${2:-30}"
    local attempt=1
    
    echo -n "Waiting for $service to be ready"
    while [ $attempt -le $max_attempts ]; do
        if docker compose $COMPOSE_FILE_FLAG ps "$service" 2>/dev/null | grep -q "healthy\|running"; then
            echo ""
            print_success "$service is ready"
            return 0
        fi
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    echo ""
    print_error "$service failed to become ready after $((max_attempts * 2)) seconds"
    return 1
}

# Display help message
show_help() {
    cat << EOF
${BOLD}MiragePot Deployment Script${NC}

${BOLD}USAGE:${NC}
    $0 [OPTIONS]

${BOLD}OPTIONS:${NC}
    --simple        Deploy simple stack (Honeypot + Ollama only)
    --full          Deploy full stack (+ Prometheus + Grafana + Alertmanager)
    --stop          Stop all containers
    --restart       Restart all containers
    --logs          Show container logs
    --status        Show deployment status
    --help          Show this help message

${BOLD}EXAMPLES:${NC}
    $0                    # Interactive mode (choose deployment type)
    $0 --simple           # Quick deployment for testing
    $0 --full             # Full deployment with monitoring
    $0 --status           # Check current deployment status
    $0 --logs             # View container logs

${BOLD}DEPLOYMENT TYPES:${NC}
    ${BOLD}Simple (2 containers):${NC}
        - MiragePot SSH Honeypot
        - Ollama LLM Service
        
    ${BOLD}Full (5 containers):${NC}
        - MiragePot SSH Honeypot
        - Ollama LLM Service
        - Prometheus (Metrics)
        - Grafana (Dashboards)
        - Alertmanager (Alerts)

${BOLD}AFTER DEPLOYMENT:${NC}
    - Test SSH: ssh root@localhost -p 2222 (any password works)
    - Dashboard: http://localhost:8501
    - Grafana: http://localhost:3000 (full deployment only)
    - Prometheus: http://localhost:9091 (full deployment only)

${BOLD}SECURITY NOTES:${NC}
    - Dashboard ports bind to localhost by default
    - Use SSH tunneling for remote access
    - Change default Grafana password immediately

EOF
    exit 0
}

# -----------------------------------------------------------------------------
# Pre-flight Checks
# -----------------------------------------------------------------------------

check_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Check Docker
    if ! command_exists docker; then
        error_exit "Docker is not installed. Install from https://docs.docker.com/get-docker/"
    fi
    print_success "Docker is installed: $(docker --version | head -n1)"
    
    # Check if Docker daemon is running
    if ! docker info >/dev/null 2>&1; then
        error_exit "Docker daemon is not running. Start Docker and try again."
    fi
    print_success "Docker daemon is running"
    
    # Check Docker Compose (v2 or v1)
    if docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
        print_success "Docker Compose is installed: $(docker compose version | head -n1)"
    elif command_exists docker-compose; then
        COMPOSE_CMD="docker-compose"
        print_success "Docker Compose is installed: $(docker-compose --version)"
    else
        error_exit "Docker Compose is not installed. Install from https://docs.docker.com/compose/install/"
    fi
    
    # Check disk space (need at least 5GB for Ollama models)
    available_space=$(df -BG . | tail -1 | awk '{print $4}' | sed 's/G//')
    if [ "$available_space" -lt 5 ]; then
        print_warning "Low disk space: ${available_space}GB available. Ollama models require ~4GB."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        print_success "Sufficient disk space: ${available_space}GB available"
    fi
}

# -----------------------------------------------------------------------------
# Environment Setup
# -----------------------------------------------------------------------------

setup_environment() {
    print_header "Setting Up Environment"
    
    # Check if .env.docker exists
    if [ ! -f .env.docker ]; then
        print_warning ".env.docker not found. Creating from template..."
        if [ -f .env.docker.example ]; then
            cp .env.docker.example .env.docker
            print_success "Created .env.docker from .env.docker.example"
            print_info "Review and customize .env.docker if needed"
        else
            error_exit ".env.docker.example not found. Cannot create .env.docker"
        fi
    else
        print_success ".env.docker already exists"
    fi
    
    # Create data directories
    mkdir -p data/logs backups
    print_success "Created data directories"
    
    # Generate SSH host key if needed
    if [ ! -f data/host.key ]; then
        print_info "SSH host key will be generated on first run"
    else
        print_success "SSH host key exists"
    fi
}

# -----------------------------------------------------------------------------
# Deployment Functions
# -----------------------------------------------------------------------------

deploy_simple() {
    print_header "Deploying Simple Stack (2 containers)"
    
    COMPOSE_FILE="docker-compose-simple.yml"
    COMPOSE_FILE_FLAG="-f $COMPOSE_FILE"
    
    print_info "Stack: Honeypot + Ollama"
    print_info "Compose file: $COMPOSE_FILE"
    echo ""
    
    # Pull images
    print_info "Pulling Docker images..."
    $COMPOSE_CMD $COMPOSE_FILE_FLAG pull
    print_success "Images pulled successfully"
    
    # Build honeypot image
    print_info "Building MiragePot image..."
    $COMPOSE_CMD $COMPOSE_FILE_FLAG build
    print_success "Build completed"
    
    # Start services
    print_info "Starting services..."
    $COMPOSE_CMD $COMPOSE_FILE_FLAG up -d
    print_success "Services started"
    
    # Wait for services to be ready
    print_info "Waiting for services to initialize..."
    wait_for_service "ollama" 30
    wait_for_service "miragepot" 20
    
    # Pull phi3 model into Ollama
    print_info "Pulling phi3 model into Ollama (this may take a few minutes)..."
    if docker exec miragepot-ollama-simple ollama pull phi3 >/dev/null 2>&1; then
        print_success "Phi3 model downloaded successfully"
    else
        print_warning "Failed to pull phi3 model. Run manually: docker exec miragepot-ollama-simple ollama pull phi3"
    fi
    
    # Display success message
    print_header "Deployment Complete!"
    cat << EOF
${GREEN}${BOLD}Simple stack is now running!${NC}

${BOLD}Access Points:${NC}
  ${CYAN}SSH Honeypot:${NC}        ssh root@localhost -p 2222 (any password)
  ${CYAN}Streamlit Dashboard:${NC}  http://localhost:8501
  ${CYAN}Metrics Endpoint:${NC}     http://localhost:9090/metrics

${BOLD}Quick Commands:${NC}
  View logs:          $COMPOSE_CMD $COMPOSE_FILE_FLAG logs -f
  Stop services:      $COMPOSE_CMD $COMPOSE_FILE_FLAG down
  Restart services:   $COMPOSE_CMD $COMPOSE_FILE_FLAG restart
  Service status:     $COMPOSE_CMD $COMPOSE_FILE_FLAG ps

${BOLD}Session Logs:${NC}
  Location: $(pwd)/data/logs/
  Format: JSON (one file per session)

${YELLOW}Note: This is the simple stack without monitoring.${NC}
${YELLOW}For full monitoring (Prometheus/Grafana), run: $0 --full${NC}

EOF
}

deploy_full() {
    print_header "Deploying Full Stack (5 containers)"
    
    COMPOSE_FILE="docker/docker-compose.yml"
    COMPOSE_FILE_FLAG="-f $COMPOSE_FILE"
    
    print_info "Stack: Honeypot + Ollama + Prometheus + Grafana + Alertmanager"
    print_info "Compose file: $COMPOSE_FILE"
    echo ""
    
    # Check if docker directory exists
    if [ ! -f "$COMPOSE_FILE" ]; then
        error_exit "Full stack compose file not found: $COMPOSE_FILE"
    fi
    
    # Pull images
    print_info "Pulling Docker images..."
    $COMPOSE_CMD $COMPOSE_FILE_FLAG pull
    print_success "Images pulled successfully"
    
    # Build honeypot image
    print_info "Building MiragePot image..."
    $COMPOSE_CMD $COMPOSE_FILE_FLAG build
    print_success "Build completed"
    
    # Start services
    print_info "Starting services..."
    $COMPOSE_CMD $COMPOSE_FILE_FLAG up -d
    print_success "Services started"
    
    # Wait for services to be ready
    print_info "Waiting for services to initialize..."
    wait_for_service "ollama" 30
    wait_for_service "prometheus" 20
    wait_for_service "grafana" 20
    wait_for_service "miragepot" 20
    
    # Pull phi3 model into Ollama
    print_info "Pulling phi3 model into Ollama (this may take a few minutes)..."
    if docker exec miragepot-ollama ollama pull phi3 >/dev/null 2>&1; then
        print_success "Phi3 model downloaded successfully"
    else
        print_warning "Failed to pull phi3 model. Run manually: docker exec miragepot-ollama ollama pull phi3"
    fi
    
    # Display success message
    print_header "Deployment Complete!"
    cat << EOF
${GREEN}${BOLD}Full stack is now running!${NC}

${BOLD}Access Points:${NC}
  ${CYAN}SSH Honeypot:${NC}        ssh root@localhost -p 2222 (any password)
  ${CYAN}Streamlit Dashboard:${NC}  http://localhost:8501
  ${CYAN}Grafana:${NC}              http://localhost:3000 (admin/admin)
  ${CYAN}Prometheus:${NC}           http://localhost:9091
  ${CYAN}Alertmanager:${NC}         http://localhost:9093

${BOLD}Quick Commands:${NC}
  View logs:          $COMPOSE_CMD $COMPOSE_FILE_FLAG logs -f
  Stop services:      $COMPOSE_CMD $COMPOSE_FILE_FLAG down
  Restart services:   $COMPOSE_CMD $COMPOSE_FILE_FLAG restart
  Service status:     $COMPOSE_CMD $COMPOSE_FILE_FLAG ps

${BOLD}Session Logs:${NC}
  Location: $(pwd)/data/logs/
  Format: JSON (one file per session)

${BOLD}Next Steps:${NC}
  1. ${YELLOW}Change Grafana password:${NC} http://localhost:3000 (admin/admin)
  2. ${YELLOW}Import dashboards:${NC} Run ./scripts/setup-grafana-dashboards.sh
  3. ${YELLOW}Configure alerts:${NC} Edit .env.docker for email/Slack/Discord

${YELLOW}Security Note:${NC} Dashboard ports are bound to localhost.
${YELLOW}For remote access, use SSH tunneling:${NC}
  ssh -L 3000:localhost:3000 -L 8501:localhost:8501 user@your-server

EOF
}

# -----------------------------------------------------------------------------
# Management Functions
# -----------------------------------------------------------------------------

stop_deployment() {
    print_header "Stopping Deployment"
    
    # Detect which deployment is running
    if docker ps --format '{{.Names}}' | grep -q "miragepot-ollama-simple"; then
        COMPOSE_FILE_FLAG="-f docker-compose-simple.yml"
        print_info "Detected simple stack"
    elif docker ps --format '{{.Names}}' | grep -q "miragepot-ollama"; then
        COMPOSE_FILE_FLAG="-f docker/docker-compose.yml"
        print_info "Detected full stack"
    else
        print_warning "No MiragePot deployment detected"
        exit 0
    fi
    
    $COMPOSE_CMD $COMPOSE_FILE_FLAG down
    print_success "All services stopped"
}

restart_deployment() {
    print_header "Restarting Deployment"
    
    # Detect which deployment is running
    if docker ps --format '{{.Names}}' | grep -q "miragepot-ollama-simple"; then
        COMPOSE_FILE_FLAG="-f docker-compose-simple.yml"
        print_info "Detected simple stack"
    elif docker ps --format '{{.Names}}' | grep -q "miragepot-ollama"; then
        COMPOSE_FILE_FLAG="-f docker/docker-compose.yml"
        print_info "Detected full stack"
    else
        error_exit "No MiragePot deployment detected"
    fi
    
    $COMPOSE_CMD $COMPOSE_FILE_FLAG restart
    print_success "All services restarted"
}

show_logs() {
    # Detect which deployment is running
    if docker ps --format '{{.Names}}' | grep -q "miragepot-ollama-simple"; then
        COMPOSE_FILE_FLAG="-f docker-compose-simple.yml"
    elif docker ps --format '{{.Names}}' | grep -q "miragepot-ollama"; then
        COMPOSE_FILE_FLAG="-f docker/docker-compose.yml"
    else
        error_exit "No MiragePot deployment detected"
    fi
    
    $COMPOSE_CMD $COMPOSE_FILE_FLAG logs -f
}

show_status() {
    print_header "Deployment Status"
    
    # Check if any MiragePot containers are running
    if ! docker ps --format '{{.Names}}' | grep -q "miragepot"; then
        print_warning "No MiragePot deployment detected"
        exit 0
    fi
    
    # Detect which deployment is running
    if docker ps --format '{{.Names}}' | grep -q "miragepot-ollama-simple"; then
        COMPOSE_FILE_FLAG="-f docker-compose-simple.yml"
        print_info "Deployment type: Simple Stack"
        echo ""
        $COMPOSE_CMD $COMPOSE_FILE_FLAG ps
    elif docker ps --format '{{.Names}}' | grep -q "miragepot-ollama"; then
        COMPOSE_FILE_FLAG="-f docker/docker-compose.yml"
        print_info "Deployment type: Full Stack"
        echo ""
        $COMPOSE_CMD $COMPOSE_FILE_FLAG ps
    fi
}

# -----------------------------------------------------------------------------
# Interactive Mode
# -----------------------------------------------------------------------------

interactive_mode() {
    print_header "MiragePot Deployment - Interactive Mode"
    
    echo "Select deployment type:"
    echo ""
    echo "  ${BOLD}1)${NC} Simple Stack (2 containers)"
    echo "     - MiragePot SSH Honeypot"
    echo "     - Ollama LLM Service"
    echo "     ${CYAN}Best for: Testing, demos, learning${NC}"
    echo ""
    echo "  ${BOLD}2)${NC} Full Stack (5 containers)"
    echo "     - MiragePot SSH Honeypot"
    echo "     - Ollama LLM Service"
    echo "     - Prometheus (Metrics)"
    echo "     - Grafana (Dashboards)"
    echo "     - Alertmanager (Alerts)"
    echo "     ${CYAN}Best for: Production, monitoring, analysis${NC}"
    echo ""
    read -p "Enter choice (1 or 2): " choice
    
    case $choice in
        1)
            deploy_simple
            ;;
        2)
            deploy_full
            ;;
        *)
            error_exit "Invalid choice. Please run again and select 1 or 2."
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Main Script Logic
# -----------------------------------------------------------------------------

main() {
    # Change to project root directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
    cd "$PROJECT_ROOT"
    
    # Parse command line arguments
    case "${1:-}" in
        --help|-h)
            show_help
            ;;
        --simple)
            check_prerequisites
            setup_environment
            deploy_simple
            ;;
        --full)
            check_prerequisites
            setup_environment
            deploy_full
            ;;
        --stop)
            stop_deployment
            ;;
        --restart)
            restart_deployment
            ;;
        --logs)
            show_logs
            ;;
        --status)
            show_status
            ;;
        "")
            check_prerequisites
            setup_environment
            interactive_mode
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Run '$0 --help' for usage information"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
