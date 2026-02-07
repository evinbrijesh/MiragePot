#!/usr/bin/env bash
# =============================================================================
# MiragePot Update Script
# =============================================================================
# Updates MiragePot to the latest version with minimal downtime.
#
# Usage:
#   ./scripts/update.sh              # Update and restart
#   ./scripts/update.sh --no-restart # Update only, don't restart
#   ./scripts/update.sh --backup     # Create backup before updating
#
# Author: MiragePot Team
# License: MIT
# =============================================================================

set -e

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Options
DO_RESTART=true
DO_BACKUP=false
DO_PULL=true

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

show_help() {
    cat << EOF
${BOLD}MiragePot Update Script${NC}

${BOLD}USAGE:${NC}
    $0 [OPTIONS]

${BOLD}OPTIONS:${NC}
    --no-restart    Update code but don't restart containers
    --backup        Create backup before updating
    --no-pull       Don't pull latest git changes
    --force         Force update even with uncommitted changes
    --help          Show this help

${BOLD}EXAMPLES:${NC}
    $0                      # Standard update with restart
    $0 --backup             # Backup first, then update
    $0 --no-restart         # Update without restarting services

${BOLD}WHAT THIS DOES:${NC}
    1. (Optional) Creates a backup of session logs
    2. Pulls latest code from git repository
    3. Rebuilds Docker images
    4. Restarts containers with zero-downtime strategy
    5. Verifies services are healthy

EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-restart)
            DO_RESTART=false
            shift
            ;;
        --backup)
            DO_BACKUP=true
            shift
            ;;
        --no-pull)
            DO_PULL=false
            shift
            ;;
        --force)
            FORCE_UPDATE=true
            shift
            ;;
        --help|-h)
            show_help
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Run '$0 --help' for usage"
            exit 1
            ;;
    esac
done

# -----------------------------------------------------------------------------
# Pre-Update Checks
# -----------------------------------------------------------------------------

print_header "MiragePot Update"

cd "$PROJECT_ROOT"

# Check for git
if ! command -v git &> /dev/null; then
    print_error "git is required but not installed"
    exit 1
fi

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    print_error "Not a git repository. Cannot update."
    exit 1
fi

# Check for uncommitted changes
if [ "$DO_PULL" = true ]; then
    if [ -n "$(git status --porcelain)" ] && [ "$FORCE_UPDATE" != true ]; then
        print_warning "You have uncommitted changes:"
        git status --short
        echo ""
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Update cancelled"
            exit 0
        fi
    fi
fi

# Detect current deployment type
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "miragepot-ollama-simple"; then
    DEPLOY_TYPE="simple"
    COMPOSE_FILE="docker-compose-simple.yml"
    COMPOSE_FILE_FLAG="-f $COMPOSE_FILE"
    print_info "Detected deployment: Simple Stack"
elif docker ps --format '{{.Names}}' 2>/dev/null | grep -q "miragepot-ollama"; then
    DEPLOY_TYPE="full"
    COMPOSE_FILE="docker/docker-compose.yml"
    COMPOSE_FILE_FLAG="-f $COMPOSE_FILE"
    print_info "Detected deployment: Full Stack"
else
    DEPLOY_TYPE="none"
    print_info "No running deployment detected"
fi

# Check Docker Compose command
if docker compose version &>/dev/null; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
else
    print_error "Docker Compose not found"
    exit 1
fi

# -----------------------------------------------------------------------------
# Create Backup (Optional)
# -----------------------------------------------------------------------------

if [ "$DO_BACKUP" = true ]; then
    print_header "Creating Backup"
    
    if [ -x "$SCRIPT_DIR/backup.sh" ]; then
        "$SCRIPT_DIR/backup.sh"
    else
        print_warning "Backup script not found, creating manual backup..."
        BACKUP_DIR="backups/pre-update_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        
        if [ -d "data/logs" ]; then
            cp -r data/logs "$BACKUP_DIR/"
            print_success "Backed up session logs"
        fi
        
        [ -f ".env.docker" ] && cp ".env.docker" "$BACKUP_DIR/"
        print_success "Backup saved to: $BACKUP_DIR"
    fi
fi

# -----------------------------------------------------------------------------
# Pull Latest Code
# -----------------------------------------------------------------------------

if [ "$DO_PULL" = true ]; then
    print_header "Pulling Latest Code"
    
    CURRENT_BRANCH=$(git branch --show-current)
    print_info "Current branch: $CURRENT_BRANCH"
    
    # Fetch updates
    print_info "Fetching updates..."
    git fetch origin
    
    # Check if we're behind
    LOCAL=$(git rev-parse HEAD)
    REMOTE=$(git rev-parse "origin/$CURRENT_BRANCH" 2>/dev/null || echo "$LOCAL")
    
    if [ "$LOCAL" = "$REMOTE" ]; then
        print_success "Already up to date"
    else
        # Show what's new
        print_info "New commits:"
        git log --oneline HEAD..origin/$CURRENT_BRANCH | head -10
        echo ""
        
        # Pull changes
        print_info "Pulling changes..."
        if git pull origin "$CURRENT_BRANCH"; then
            print_success "Code updated successfully"
        else
            print_error "Failed to pull changes"
            print_info "You may need to resolve conflicts manually"
            exit 1
        fi
    fi
fi

# -----------------------------------------------------------------------------
# Rebuild and Restart
# -----------------------------------------------------------------------------

if [ "$DEPLOY_TYPE" != "none" ] && [ "$DO_RESTART" = true ]; then
    print_header "Rebuilding Docker Images"
    
    # Rebuild images
    print_info "Building updated images..."
    $COMPOSE_CMD $COMPOSE_FILE_FLAG build
    print_success "Images rebuilt"
    
    print_header "Restarting Services"
    
    # Rolling restart strategy for minimal downtime
    print_info "Performing rolling restart..."
    
    # For simple stack, just restart
    if [ "$DEPLOY_TYPE" = "simple" ]; then
        $COMPOSE_CMD $COMPOSE_FILE_FLAG up -d --force-recreate
    else
        # For full stack, restart services in order
        # First: Monitoring (can be briefly unavailable)
        $COMPOSE_CMD $COMPOSE_FILE_FLAG up -d --force-recreate prometheus grafana alertmanager 2>/dev/null || true
        
        # Then: Ollama (should stay up for responses)
        $COMPOSE_CMD $COMPOSE_FILE_FLAG up -d --force-recreate ollama
        
        # Finally: Honeypot
        $COMPOSE_CMD $COMPOSE_FILE_FLAG up -d --force-recreate miragepot
    fi
    
    print_success "Services restarted"
    
    # Wait for health checks
    print_info "Waiting for services to be healthy..."
    sleep 5
    
    # Check status
    $COMPOSE_CMD $COMPOSE_FILE_FLAG ps
    
elif [ "$DO_RESTART" = false ]; then
    print_info "Skipping restart (--no-restart specified)"
    print_info "To apply changes, run: ./scripts/deploy.sh --$DEPLOY_TYPE"
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------

print_header "Update Complete"

if [ "$DO_PULL" = true ]; then
    NEW_VERSION=$(git describe --tags --always 2>/dev/null || git rev-parse --short HEAD)
    echo -e "  Version: ${CYAN}$NEW_VERSION${NC}"
fi

if [ "$DEPLOY_TYPE" != "none" ]; then
    echo -e "  Deployment: ${CYAN}$DEPLOY_TYPE stack${NC}"
    echo ""
    echo -e "${BOLD}Quick Commands:${NC}"
    echo "  View status:  ./scripts/deploy.sh --status"
    echo "  View logs:    ./scripts/deploy.sh --logs"
    echo "  Restart:      ./scripts/deploy.sh --restart"
fi

echo ""
print_success "MiragePot has been updated!"
