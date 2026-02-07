#!/bin/bash
# =============================================================================
# MiragePot Docker Test Suite
# =============================================================================
# Interactive testing script for MiragePot Docker deployment
#
# Usage:
#   ./scripts/test-docker.sh              # Interactive menu
#   ./scripts/test-docker.sh smoke        # Test honeypot + ollama
#   ./scripts/test-docker.sh metrics      # Test + prometheus
#   ./scripts/test-docker.sh full         # Test all services
#   ./scripts/test-docker.sh down         # Stop all containers
#   ./scripts/test-docker.sh clean        # Stop + remove volumes
#
# Author: MiragePot Team
# =============================================================================

set -e  # Exit on error

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
# Helper Functions
# =============================================================================

print_header() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_waiting() {
    echo -e "${YELLOW}⏳${NC} $1"
}

# =============================================================================
# Pre-flight Checks
# =============================================================================

check_docker() {
    print_header "Pre-flight Checks"
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        echo ""
        echo "Install Docker:"
        echo "  Ubuntu/Debian: sudo apt-get install docker.io"
        echo "  macOS:         brew install docker"
        echo "  Windows:       https://docs.docker.com/desktop/windows/install/"
        exit 1
    fi
    print_success "Docker installed"
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running"
        echo ""
        echo "Start Docker:"
        echo "  Linux:   sudo systemctl start docker"
        echo "  macOS:   Open Docker Desktop"
        echo "  Windows: Start Docker Desktop"
        exit 1
    fi
    print_success "Docker daemon running"
    
    # Check if docker-compose is available
    if ! docker compose version &> /dev/null && ! command -v docker-compose &> /dev/null; then
        print_error "docker-compose is not available"
        echo ""
        echo "Docker Compose comes with Docker Desktop on macOS/Windows"
        echo "On Linux, install: sudo apt-get install docker-compose-plugin"
        exit 1
    fi
    print_success "docker-compose available"
}

check_files() {
    local missing_files=0
    
    # Check required files
    if [[ ! -f "docker/Dockerfile" ]]; then
        print_error "docker/Dockerfile not found"
        missing_files=1
    else
        print_success "docker/Dockerfile exists"
    fi
    
    if [[ ! -f "docker/docker-compose.yml" ]]; then
        print_error "docker/docker-compose.yml not found"
        missing_files=1
    else
        print_success "docker/docker-compose.yml exists"
    fi
    
    if [[ ! -f "docker/prometheus/prometheus.yml" ]]; then
        print_error "docker/prometheus/prometheus.yml not found"
        missing_files=1
    else
        print_success "docker/prometheus/prometheus.yml exists"
    fi
    
    # Check if .env.docker exists, if not offer to create from example
    if [[ ! -f ".env.docker" ]]; then
        print_warning ".env.docker not found"
        
        if [[ -f ".env.docker.example" ]]; then
            echo ""
            read -p "Create .env.docker from .env.docker.example? [Y/n] " -n 1 -r
            echo ""
            if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
                cp .env.docker.example .env.docker
                print_success "Created .env.docker from example"
                print_warning "Note: Alerts not configured. Edit .env.docker to add email/Slack/Discord"
            else
                print_error ".env.docker is required"
                exit 1
            fi
        else
            print_error ".env.docker.example not found"
            missing_files=1
        fi
    else
        print_success ".env.docker exists"
        
        # Check if alerts are configured (optional)
        if grep -q "SMTP_PASSWORD=your-app-password-here" .env.docker 2>/dev/null; then
            print_warning "Email alerts not configured (optional)"
        fi
    fi
    
    if [[ $missing_files -eq 1 ]]; then
        print_error "Missing required files. Are you in the MiragePot directory?"
        exit 1
    fi
}

# =============================================================================
# Service Management
# =============================================================================

get_compose_cmd() {
    # Try docker compose (new) first, fall back to docker-compose (old)
    if docker compose version &> /dev/null; then
        echo "docker compose -f docker/docker-compose.yml"
    else
        echo "docker-compose -f docker/docker-compose.yml"
    fi
}

start_service() {
    local service=$1
    local compose_cmd=$(get_compose_cmd)
    
    print_waiting "Starting $service..."
    
    if $compose_cmd up -d $service 2>&1 | grep -q "error\|Error"; then
        print_error "Failed to start $service"
        echo ""
        echo "View logs with: docker logs miragepot-$service"
        return 1
    fi
    
    print_success "$service started"
    return 0
}

check_container_health() {
    local container=$1
    local max_wait=${2:-30}
    local elapsed=0
    
    print_waiting "Checking $container health..."
    
    while [[ $elapsed -lt $max_wait ]]; do
        if docker ps --filter "name=$container" --filter "status=running" | grep -q "$container"; then
            # Container is running, check health if health check is defined
            local health=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' $container 2>/dev/null || echo "unknown")
            
            if [[ "$health" == "healthy" ]] || [[ "$health" == "no-healthcheck" ]]; then
                print_success "$container is healthy"
                return 0
            elif [[ "$health" == "starting" ]]; then
                sleep 2
                elapsed=$((elapsed + 2))
                continue
            elif [[ "$health" == "unhealthy" ]]; then
                print_error "$container is unhealthy"
                return 1
            fi
        else
            # Container not running
            if [[ $elapsed -eq 0 ]]; then
                # First check, give it a moment
                sleep 2
                elapsed=$((elapsed + 2))
                continue
            else
                print_error "$container is not running"
                return 1
            fi
        fi
        
        sleep 2
        elapsed=$((elapsed + 2))
    done
    
    print_warning "$container health check timed out (container may still be starting)"
    return 0  # Don't fail, just warn
}

wait_for_ollama_model() {
    print_waiting "Waiting for Ollama to download phi3 model (this may take 2-3 minutes)..."
    
    local max_wait=300  # 5 minutes max
    local elapsed=0
    local spinner=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local spin_idx=0
    
    while [[ $elapsed -lt $max_wait ]]; do
        # Check if model is available
        if docker exec miragepot-ollama ollama list 2>/dev/null | grep -q "phi3"; then
            echo ""  # New line after spinner
            print_success "Phi3 model ready"
            return 0
        fi
        
        # Show spinner
        printf "\r${YELLOW}⏳${NC} Downloading phi3... ${spinner[$spin_idx]} ($elapsed seconds)"
        spin_idx=$(( (spin_idx + 1) % 10 ))
        
        sleep 1
        elapsed=$((elapsed + 1))
    done
    
    echo ""  # New line after spinner
    print_error "Ollama model download timed out"
    print_info "Check logs: docker logs miragepot-ollama"
    return 1
}

test_http_endpoint() {
    local url=$1
    local name=$2
    
    if curl -sf "$url" > /dev/null 2>&1; then
        print_success "$name endpoint responding"
        return 0
    else
        print_error "$name endpoint not responding"
        return 1
    fi
}

# =============================================================================
# Test Phases
# =============================================================================

test_smoke() {
    print_header "Smoke Test (Ollama + Honeypot)"
    
    # Start Ollama
    start_service "ollama" || exit 1
    check_container_health "miragepot-ollama" 60 || {
        echo ""
        print_error "Ollama failed health check"
        print_info "View logs: docker logs miragepot-ollama"
        exit 1
    }
    
    # Wait for model download
    wait_for_ollama_model || exit 1
    
    # Start MiragePot
    start_service "miragepot" || exit 1
    check_container_health "miragepot-honeypot" 30 || {
        echo ""
        print_error "MiragePot failed health check"
        print_info "View logs: docker logs miragepot-honeypot"
        print_info "Common issue: ModuleNotFoundError - rebuild with: docker compose -f docker/docker-compose.yml build --no-cache"
        exit 1
    }
    
    # Test endpoints
    echo ""
    print_header "Testing Endpoints"
    
    sleep 3  # Give services a moment to fully start
    
    test_http_endpoint "http://localhost:11434/api/tags" "Ollama API"
    test_http_endpoint "http://localhost:9090/metrics" "Metrics"
    
    # Test SSH port
    if timeout 2 bash -c "</dev/tcp/localhost/2222" 2>/dev/null; then
        print_success "SSH honeypot port (2222) is open"
    else
        print_warning "SSH honeypot port (2222) not responding (may need more time)"
    fi
    
    print_results_smoke
}

test_metrics() {
    print_header "Metrics Test (+ Prometheus)"
    
    # First ensure smoke test services are running
    if ! docker ps | grep -q "miragepot-honeypot"; then
        print_info "Starting smoke test services first..."
        test_smoke
    fi
    
    # Start Prometheus
    start_service "prometheus" || exit 1
    check_container_health "miragepot-prometheus" 30 || exit 1
    
    # Wait a moment for Prometheus to scrape
    sleep 5
    
    # Test endpoints
    echo ""
    print_header "Testing Metrics Collection"
    
    test_http_endpoint "http://localhost:9091" "Prometheus UI"
    
    # Check if Prometheus is scraping MiragePot
    if curl -s "http://localhost:9091/api/v1/targets" | grep -q "miragepot"; then
        print_success "Prometheus is scraping MiragePot metrics"
    else
        print_warning "Prometheus target may not be configured correctly"
    fi
    
    # Show sample metrics
    echo ""
    print_info "Sample metrics from http://localhost:9090/metrics:"
    echo ""
    curl -s http://localhost:9090/metrics | grep "^miragepot_" | head -5 | sed 's/^/  /'
    
    print_results_metrics
}

test_full() {
    print_header "Full Stack Test (All Services)"
    
    # First ensure metrics test services are running
    if ! docker ps | grep -q "miragepot-prometheus"; then
        print_info "Starting metrics test services first..."
        test_metrics
    fi
    
    # Start Alertmanager
    start_service "alertmanager" || exit 1
    check_container_health "miragepot-alertmanager" 30 || exit 1
    
    # Start Grafana
    start_service "grafana" || exit 1
    check_container_health "miragepot-grafana" 60 || exit 1
    
    # Wait for Grafana plugins to install
    print_waiting "Waiting for Grafana to initialize..."
    sleep 10
    
    # Test endpoints
    echo ""
    print_header "Testing All Services"
    
    test_http_endpoint "http://localhost:9093" "Alertmanager UI"
    test_http_endpoint "http://localhost:3000" "Grafana UI"
    
    print_results_full
}

# =============================================================================
# Results Display
# =============================================================================

print_results_smoke() {
    echo ""
    print_header "Smoke Test Results"
    
    echo -e "${GREEN}✓ Ollama:${NC}      http://localhost:11434"
    echo -e "${GREEN}✓ Honeypot:${NC}    ssh root@localhost -p 2222"
    echo -e "${GREEN}✓ Metrics:${NC}     http://localhost:9090/metrics"
    
    echo ""
    print_info "Try connecting: ${CYAN}ssh root@localhost -p 2222${NC}"
    print_info "Use any password, the honeypot accepts everything!"
    echo ""
    print_info "View logs: ${CYAN}./scripts/logs.sh miragepot${NC}"
}

print_results_metrics() {
    echo ""
    print_header "Metrics Test Results"
    
    echo -e "${GREEN}✓ Prometheus:${NC}  http://localhost:9091"
    echo -e "  Targets:     http://localhost:9091/targets"
    echo -e "  Graph:       http://localhost:9091/graph"
    
    echo ""
    print_info "Try this query in Prometheus:"
    echo -e "  ${CYAN}miragepot_connections_total${NC}"
    echo ""
    print_info "Generate metrics by SSHing to honeypot:"
    echo -e "  ${CYAN}ssh root@localhost -p 2222${NC}"
}

print_results_full() {
    echo ""
    print_header "Full Stack Test Results"
    
    echo -e "${GREEN}All 5 services are running!${NC}"
    echo ""
    echo "Access URLs:"
    echo -e "  ${CYAN}SSH Honeypot:${NC}   ssh root@localhost -p 2222"
    echo -e "  ${CYAN}Metrics:${NC}        http://localhost:9090/metrics"
    echo -e "  ${CYAN}Prometheus:${NC}     http://localhost:9091"
    echo -e "  ${CYAN}Alertmanager:${NC}   http://localhost:9093"
    echo -e "  ${CYAN}Grafana:${NC}        http://localhost:3000"
    echo ""
    echo "Grafana login: ${YELLOW}admin${NC} / ${YELLOW}admin${NC}"
    echo ""
    print_info "Add datasource in Grafana:"
    echo "  Already configured! Go to Connections > Data Sources"
    echo ""
    print_info "Test alerts:"
    echo -e "  ${CYAN}./scripts/test-alerts.sh${NC}"
}

# =============================================================================
# Stop/Clean Functions
# =============================================================================

stop_services() {
    print_header "Stopping Services"
    
    local compose_cmd=$(get_compose_cmd)
    $compose_cmd down
    
    print_success "All services stopped"
}

clean_all() {
    print_header "Cleaning All Data"
    
    echo ""
    print_warning "This will remove all containers, volumes, and data!"
    read -p "Are you sure? [y/N] " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Cancelled"
        exit 0
    fi
    
    local compose_cmd=$(get_compose_cmd)
    $compose_cmd down -v
    
    print_success "All containers and volumes removed"
}

# =============================================================================
# Interactive Menu
# =============================================================================

show_menu() {
    print_header "MiragePot Docker Test Suite"
    
    echo "Choose test level:"
    echo ""
    echo "  1) Smoke test     - Honeypot + Ollama (fastest, ~3 min)"
    echo "  2) Metrics test   - + Prometheus monitoring"
    echo "  3) Full stack     - All 5 services + Grafana"
    echo ""
    echo "  4) Stop services  - docker compose down"
    echo "  5) Clean all      - Remove containers + volumes"
    echo ""
    echo "  6) Exit"
    echo ""
    
    read -p "Enter choice [1-6]: " choice
    
    case $choice in
        1)
            test_smoke
            ;;
        2)
            test_metrics
            ;;
        3)
            test_full
            ;;
        4)
            stop_services
            ;;
        5)
            clean_all
            ;;
        6)
            print_info "Goodbye!"
            exit 0
            ;;
        *)
            print_error "Invalid choice"
            exit 1
            ;;
    esac
}

# =============================================================================
# Main
# =============================================================================

main() {
    # Change to project root if running from scripts/ directory
    if [[ $(basename "$PWD") == "scripts" ]]; then
        cd ..
    fi
    
    # Run pre-flight checks
    check_docker
    check_files
    
    # Parse command line argument
    if [[ $# -eq 0 ]]; then
        # No arguments, show menu
        show_menu
    else
        case $1 in
            smoke)
                test_smoke
                ;;
            metrics)
                test_metrics
                ;;
            full)
                test_full
                ;;
            down)
                stop_services
                ;;
            clean)
                clean_all
                ;;
            *)
                echo "Usage: $0 [smoke|metrics|full|down|clean]"
                echo ""
                echo "  smoke    - Test Honeypot + Ollama"
                echo "  metrics  - Test + Prometheus"
                echo "  full     - Test all 5 services"
                echo "  down     - Stop all services"
                echo "  clean    - Remove containers + volumes"
                echo ""
                echo "Run without arguments for interactive menu"
                exit 1
                ;;
        esac
    fi
}

# Run main function
main "$@"
