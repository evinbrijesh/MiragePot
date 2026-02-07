#!/usr/bin/env bash
# =============================================================================
# MiragePot Grafana Dashboard Setup Script
# =============================================================================
# Automatically imports pre-built dashboards into Grafana
# and configures the Prometheus datasource.
#
# Usage:
#   ./scripts/setup-grafana-dashboards.sh
#   ./scripts/setup-grafana-dashboards.sh --grafana-url http://localhost:3000
#
# Requirements:
#   - Grafana running (full stack deployment)
#   - curl installed
#
# Author: MiragePot Team
# License: MIT
# =============================================================================

set -e

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
GRAFANA_USER="${GRAFANA_USER:-admin}"
GRAFANA_PASSWORD="${GRAFANA_PASSWORD:-admin}"
PROMETHEUS_URL="${PROMETHEUS_URL:-http://prometheus:9091}"

# Dashboard directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DASHBOARD_DIR="$PROJECT_ROOT/grafana/dashboards"

# -----------------------------------------------------------------------------
# Color Codes
# -----------------------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_info() { echo -e "${BLUE}ℹ${NC} $1"; }
print_header() { echo -e "\n${BOLD}${CYAN}$1${NC}\n"; }

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --grafana-url)
            GRAFANA_URL="$2"
            shift 2
            ;;
        --grafana-user)
            GRAFANA_USER="$2"
            shift 2
            ;;
        --grafana-password)
            GRAFANA_PASSWORD="$2"
            shift 2
            ;;
        --prometheus-url)
            PROMETHEUS_URL="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --grafana-url URL       Grafana URL (default: http://localhost:3000)"
            echo "  --grafana-user USER     Grafana admin user (default: admin)"
            echo "  --grafana-password PWD  Grafana admin password (default: admin)"
            echo "  --prometheus-url URL    Prometheus URL for datasource (default: http://prometheus:9091)"
            echo "  --help                  Show this help"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# -----------------------------------------------------------------------------
# Pre-flight Checks
# -----------------------------------------------------------------------------

print_header "MiragePot Grafana Dashboard Setup"

# Check if curl is installed
if ! command -v curl &> /dev/null; then
    print_error "curl is required but not installed"
    exit 1
fi

# Check if dashboard directory exists
if [ ! -d "$DASHBOARD_DIR" ]; then
    print_error "Dashboard directory not found: $DASHBOARD_DIR"
    exit 1
fi

# Check if Grafana is reachable
print_info "Checking Grafana connection..."
if ! curl -s --max-time 5 "$GRAFANA_URL/api/health" > /dev/null; then
    print_error "Cannot connect to Grafana at $GRAFANA_URL"
    print_info "Make sure the full stack is running: ./scripts/deploy.sh --full"
    exit 1
fi
print_success "Grafana is reachable at $GRAFANA_URL"

# -----------------------------------------------------------------------------
# Setup Prometheus Datasource
# -----------------------------------------------------------------------------

print_header "Setting up Prometheus Datasource"

# Check if datasource already exists
DATASOURCE_EXISTS=$(curl -s -u "$GRAFANA_USER:$GRAFANA_PASSWORD" \
    "$GRAFANA_URL/api/datasources/name/Prometheus" \
    -w "%{http_code}" -o /dev/null)

if [ "$DATASOURCE_EXISTS" == "200" ]; then
    print_info "Prometheus datasource already exists"
else
    print_info "Creating Prometheus datasource..."
    
    RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -u "$GRAFANA_USER:$GRAFANA_PASSWORD" \
        "$GRAFANA_URL/api/datasources" \
        -d '{
            "name": "Prometheus",
            "type": "prometheus",
            "url": "'"$PROMETHEUS_URL"'",
            "access": "proxy",
            "isDefault": true,
            "jsonData": {
                "httpMethod": "POST",
                "timeInterval": "15s"
            }
        }')
    
    if echo "$RESPONSE" | grep -q '"id"'; then
        print_success "Prometheus datasource created"
    else
        print_warning "Could not create datasource: $RESPONSE"
    fi
fi

# -----------------------------------------------------------------------------
# Import Dashboards
# -----------------------------------------------------------------------------

print_header "Importing Dashboards"

# Count dashboards
DASHBOARD_COUNT=$(find "$DASHBOARD_DIR" -name "*.json" -type f | wc -l)
if [ "$DASHBOARD_COUNT" -eq 0 ]; then
    print_warning "No dashboard JSON files found in $DASHBOARD_DIR"
    exit 0
fi

print_info "Found $DASHBOARD_COUNT dashboard(s) to import"

# Import each dashboard
IMPORTED=0
FAILED=0

for DASHBOARD_FILE in "$DASHBOARD_DIR"/*.json; do
    [ -f "$DASHBOARD_FILE" ] || continue
    
    FILENAME=$(basename "$DASHBOARD_FILE")
    DASHBOARD_NAME=$(jq -r '.title // "Unknown"' "$DASHBOARD_FILE" 2>/dev/null || echo "Unknown")
    
    print_info "Importing: $DASHBOARD_NAME ($FILENAME)"
    
    # Prepare dashboard payload
    # Grafana import API expects dashboard wrapped in a specific structure
    PAYLOAD=$(jq '{
        "dashboard": .,
        "overwrite": true,
        "inputs": [
            {
                "name": "DS_PROMETHEUS",
                "type": "datasource",
                "pluginId": "prometheus",
                "value": "Prometheus"
            }
        ],
        "folderId": 0
    }' "$DASHBOARD_FILE")
    
    # Import dashboard
    RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -u "$GRAFANA_USER:$GRAFANA_PASSWORD" \
        "$GRAFANA_URL/api/dashboards/import" \
        -d "$PAYLOAD")
    
    if echo "$RESPONSE" | grep -q '"imported":\s*true\|"status":\s*"success"\|"uid"'; then
        print_success "  Imported: $DASHBOARD_NAME"
        IMPORTED=$((IMPORTED + 1))
    else
        print_error "  Failed to import: $DASHBOARD_NAME"
        print_info "  Response: $RESPONSE"
        FAILED=$((FAILED + 1))
    fi
done

# -----------------------------------------------------------------------------
# Set Default Dashboard (Optional)
# -----------------------------------------------------------------------------

print_header "Finalizing Setup"

# Try to set MiragePot Overview as the home dashboard
OVERVIEW_UID="miragepot-overview"
if [ $IMPORTED -gt 0 ]; then
    print_info "Setting MiragePot Overview as home dashboard..."
    
    # Update organization preferences
    curl -s -X PUT \
        -H "Content-Type: application/json" \
        -u "$GRAFANA_USER:$GRAFANA_PASSWORD" \
        "$GRAFANA_URL/api/org/preferences" \
        -d "{\"homeDashboardUID\": \"$OVERVIEW_UID\"}" > /dev/null 2>&1
    
    print_success "Home dashboard configured"
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------

print_header "Setup Complete"

echo -e "${BOLD}Summary:${NC}"
echo -e "  Dashboards imported: ${GREEN}$IMPORTED${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "  Failed imports: ${RED}$FAILED${NC}"
fi
echo ""
echo -e "${BOLD}Access Grafana:${NC}"
echo -e "  URL: ${CYAN}$GRAFANA_URL${NC}"
echo -e "  User: ${CYAN}$GRAFANA_USER${NC}"
echo ""
echo -e "${BOLD}Available Dashboards:${NC}"
echo -e "  • MiragePot - Overview (connections, commands, threats)"
echo -e "  • MiragePot - TTP Analysis (MITRE ATT&CK detections)"
echo -e "  • MiragePot - Performance (LLM latency, cache efficiency)"
echo ""

if [ "$GRAFANA_PASSWORD" == "admin" ]; then
    print_warning "You're using the default Grafana password!"
    print_info "Change it at: $GRAFANA_URL/profile/password"
fi
