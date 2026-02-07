#!/usr/bin/env bash
# =============================================================================
# MiragePot Backup Script
# =============================================================================
# Creates timestamped backups of session logs, configuration, and optionally
# Prometheus/Grafana data.
#
# Usage:
#   ./scripts/backup.sh                    # Backup logs only (default)
#   ./scripts/backup.sh --full             # Backup everything including metrics
#   ./scripts/backup.sh --output /path     # Custom backup location
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

# Default backup directory
BACKUP_DIR="${BACKUP_DIR:-$PROJECT_ROOT/backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="miragepot_backup_$TIMESTAMP"

# What to backup
BACKUP_LOGS=true
BACKUP_CONFIG=true
BACKUP_FULL=false

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
${BOLD}MiragePot Backup Script${NC}

${BOLD}USAGE:${NC}
    $0 [OPTIONS]

${BOLD}OPTIONS:${NC}
    --full              Backup everything (logs, config, Docker volumes)
    --logs-only         Backup only session logs (default)
    --output DIR        Custom backup directory (default: ./backups)
    --keep N            Keep only last N backups (default: keep all)
    --help              Show this help

${BOLD}EXAMPLES:${NC}
    $0                          # Quick backup of logs
    $0 --full                   # Full backup including metrics
    $0 --output /mnt/backup     # Backup to external drive
    $0 --keep 7                 # Keep only last 7 backups

${BOLD}BACKUP CONTENTS:${NC}
    Default backup includes:
      • data/logs/*.json      Session logs
      • data/cache.json       LLM response cache
      • .env.docker           Configuration

    Full backup also includes:
      • Docker volume exports (Prometheus, Grafana data)
      • grafana/dashboards/   Dashboard definitions

EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --full)
            BACKUP_FULL=true
            shift
            ;;
        --logs-only)
            BACKUP_CONFIG=false
            shift
            ;;
        --output)
            BACKUP_DIR="$2"
            shift 2
            ;;
        --keep)
            KEEP_COUNT="$2"
            shift 2
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
# Main Backup Logic
# -----------------------------------------------------------------------------

print_header "MiragePot Backup"

cd "$PROJECT_ROOT"

# Create backup directory
mkdir -p "$BACKUP_DIR"
BACKUP_PATH="$BACKUP_DIR/$BACKUP_NAME"
mkdir -p "$BACKUP_PATH"

print_info "Backup location: $BACKUP_PATH"
echo ""

# Track backup size
TOTAL_SIZE=0

# -----------------------------------------------------------------------------
# Backup Session Logs
# -----------------------------------------------------------------------------

if [ "$BACKUP_LOGS" = true ]; then
    print_info "Backing up session logs..."
    
    if [ -d "data/logs" ] && [ "$(ls -A data/logs 2>/dev/null)" ]; then
        mkdir -p "$BACKUP_PATH/data/logs"
        cp -r data/logs/* "$BACKUP_PATH/data/logs/" 2>/dev/null || true
        
        LOG_COUNT=$(find "$BACKUP_PATH/data/logs" -name "*.json" -type f 2>/dev/null | wc -l)
        LOG_SIZE=$(du -sh "$BACKUP_PATH/data/logs" 2>/dev/null | cut -f1)
        
        print_success "  Backed up $LOG_COUNT session log(s) ($LOG_SIZE)"
    else
        print_warning "  No session logs found"
    fi
fi

# -----------------------------------------------------------------------------
# Backup Configuration
# -----------------------------------------------------------------------------

if [ "$BACKUP_CONFIG" = true ]; then
    print_info "Backing up configuration..."
    
    mkdir -p "$BACKUP_PATH/config"
    
    # Copy configuration files
    [ -f ".env.docker" ] && cp ".env.docker" "$BACKUP_PATH/config/"
    [ -f "data/cache.json" ] && cp "data/cache.json" "$BACKUP_PATH/config/"
    [ -f "data/system_prompt.txt" ] && cp "data/system_prompt.txt" "$BACKUP_PATH/config/"
    [ -f "data/host.key" ] && cp "data/host.key" "$BACKUP_PATH/config/"
    
    print_success "  Configuration files backed up"
fi

# -----------------------------------------------------------------------------
# Backup Grafana Dashboards
# -----------------------------------------------------------------------------

if [ "$BACKUP_FULL" = true ]; then
    print_info "Backing up Grafana dashboards..."
    
    if [ -d "grafana/dashboards" ] && [ "$(ls -A grafana/dashboards/*.json 2>/dev/null)" ]; then
        mkdir -p "$BACKUP_PATH/grafana/dashboards"
        cp grafana/dashboards/*.json "$BACKUP_PATH/grafana/dashboards/" 2>/dev/null || true
        
        DASH_COUNT=$(find "$BACKUP_PATH/grafana/dashboards" -name "*.json" -type f 2>/dev/null | wc -l)
        print_success "  Backed up $DASH_COUNT dashboard(s)"
    else
        print_warning "  No custom dashboards found"
    fi
fi

# -----------------------------------------------------------------------------
# Backup Docker Volumes (Full backup only)
# -----------------------------------------------------------------------------

if [ "$BACKUP_FULL" = true ]; then
    print_info "Backing up Docker volumes (this may take a while)..."
    
    # Check if Docker is available
    if command -v docker &> /dev/null; then
        mkdir -p "$BACKUP_PATH/volumes"
        
        # Backup Prometheus data
        if docker volume ls -q | grep -q "prometheus"; then
            print_info "  Exporting Prometheus data..."
            docker run --rm \
                -v miragepot_prometheus-data:/data \
                -v "$BACKUP_PATH/volumes:/backup" \
                alpine tar -czf /backup/prometheus-data.tar.gz -C /data . 2>/dev/null || \
                print_warning "  Could not backup Prometheus volume"
        fi
        
        # Backup Grafana data
        if docker volume ls -q | grep -q "grafana"; then
            print_info "  Exporting Grafana data..."
            docker run --rm \
                -v miragepot_grafana-data:/data \
                -v "$BACKUP_PATH/volumes:/backup" \
                alpine tar -czf /backup/grafana-data.tar.gz -C /data . 2>/dev/null || \
                print_warning "  Could not backup Grafana volume"
        fi
        
        if [ "$(ls -A "$BACKUP_PATH/volumes" 2>/dev/null)" ]; then
            VOLUME_SIZE=$(du -sh "$BACKUP_PATH/volumes" 2>/dev/null | cut -f1)
            print_success "  Docker volumes backed up ($VOLUME_SIZE)"
        fi
    else
        print_warning "  Docker not available, skipping volume backup"
    fi
fi

# -----------------------------------------------------------------------------
# Create Archive
# -----------------------------------------------------------------------------

print_info "Creating compressed archive..."

cd "$BACKUP_DIR"
tar -czf "${BACKUP_NAME}.tar.gz" "$BACKUP_NAME"
rm -rf "$BACKUP_NAME"

ARCHIVE_SIZE=$(du -sh "${BACKUP_NAME}.tar.gz" | cut -f1)
print_success "Archive created: ${BACKUP_NAME}.tar.gz ($ARCHIVE_SIZE)"

# -----------------------------------------------------------------------------
# Cleanup Old Backups
# -----------------------------------------------------------------------------

if [ -n "$KEEP_COUNT" ]; then
    print_info "Cleaning up old backups (keeping last $KEEP_COUNT)..."
    
    # List backups sorted by date, skip the newest $KEEP_COUNT
    OLD_BACKUPS=$(ls -t "$BACKUP_DIR"/miragepot_backup_*.tar.gz 2>/dev/null | tail -n +$((KEEP_COUNT + 1)))
    
    if [ -n "$OLD_BACKUPS" ]; then
        echo "$OLD_BACKUPS" | while read -r old_backup; do
            rm -f "$old_backup"
            print_info "  Removed: $(basename "$old_backup")"
        done
    else
        print_info "  No old backups to remove"
    fi
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------

print_header "Backup Complete"

echo -e "${BOLD}Backup Details:${NC}"
echo -e "  Location: ${CYAN}$BACKUP_DIR/${BACKUP_NAME}.tar.gz${NC}"
echo -e "  Size: ${CYAN}$ARCHIVE_SIZE${NC}"
echo ""

echo -e "${BOLD}Contents:${NC}"
echo "  • Session logs"
[ "$BACKUP_CONFIG" = true ] && echo "  • Configuration files"
[ "$BACKUP_FULL" = true ] && echo "  • Grafana dashboards"
[ "$BACKUP_FULL" = true ] && echo "  • Docker volume exports"
echo ""

echo -e "${BOLD}To restore:${NC}"
echo "  tar -xzf ${BACKUP_NAME}.tar.gz"
echo "  cp -r ${BACKUP_NAME}/data/logs/* data/logs/"
[ "$BACKUP_CONFIG" = true ] && echo "  cp ${BACKUP_NAME}/config/.env.docker ."
echo ""
