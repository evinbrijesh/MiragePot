#!/bin/bash
# =============================================================================
# MiragePot Alert Testing Script
# =============================================================================
# Test alert notifications through Alertmanager
#
# Usage:
#   ./scripts/test-alerts.sh              # Interactive menu
#   ./scripts/test-alerts.sh email        # Test email alert
#   ./scripts/test-alerts.sh slack        # Test Slack alert
#   ./scripts/test-alerts.sh discord      # Test Discord alert
#   ./scripts/test-alerts.sh all          # Test all configured channels
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
# Configuration
# =============================================================================
ALERTMANAGER_URL="http://localhost:9093"
ENV_FILE=".env.docker"

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

# =============================================================================
# Configuration Check
# =============================================================================

check_alertmanager() {
    if ! curl -sf "$ALERTMANAGER_URL" > /dev/null 2>&1; then
        print_error "Alertmanager is not running at $ALERTMANAGER_URL"
        echo ""
        echo "Start services with: ./scripts/test-docker.sh full"
        exit 1
    fi
    print_success "Alertmanager is running"
}

check_env_file() {
    if [[ ! -f "$ENV_FILE" ]]; then
        print_error "$ENV_FILE not found"
        echo ""
        echo "Create it from: cp .env.docker.example .env.docker"
        exit 1
    fi
}

get_env_value() {
    local key=$1
    local default=$2
    
    if [[ -f "$ENV_FILE" ]]; then
        # Read value from .env file, handle comments and whitespace
        local value=$(grep "^${key}=" "$ENV_FILE" | cut -d'=' -f2- | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/#.*//')
        echo "${value:-$default}"
    else
        echo "$default"
    fi
}

check_email_config() {
    local smtp_user=$(get_env_value "SMTP_USER")
    local smtp_pass=$(get_env_value "SMTP_PASSWORD")
    
    if [[ -z "$smtp_user" ]] || [[ "$smtp_user" == "your-email@gmail.com" ]]; then
        return 1
    fi
    
    if [[ -z "$smtp_pass" ]] || [[ "$smtp_pass" == "your-app-password-here" ]]; then
        return 1
    fi
    
    return 0
}

check_slack_config() {
    local webhook=$(get_env_value "SLACK_WEBHOOK_URL")
    
    if [[ -z "$webhook" ]] || [[ "$webhook" == "https://hooks.slack.com/services/YOUR/WEBHOOK/HERE" ]]; then
        return 1
    fi
    
    return 0
}

check_discord_config() {
    local webhook=$(get_env_value "DISCORD_WEBHOOK_URL")
    
    if [[ -z "$webhook" ]] || [[ "$webhook" == "https://discord.com/api/webhooks/YOUR/WEBHOOK/HERE" ]]; then
        return 1
    fi
    
    return 0
}

show_config_status() {
    print_header "Alert Configuration Status"
    
    # Email
    if check_email_config; then
        local email_to=$(get_env_value "ALERT_EMAIL_TO")
        print_success "Email configured: $email_to"
    else
        print_warning "Email not configured"
    fi
    
    # Slack
    if check_slack_config; then
        local channel=$(get_env_value "SLACK_CHANNEL" "#security-alerts")
        print_success "Slack configured: $channel"
    else
        print_warning "Slack not configured"
    fi
    
    # Discord
    if check_discord_config; then
        print_success "Discord configured"
    else
        print_warning "Discord not configured"
    fi
    
    echo ""
}

# =============================================================================
# Alert Sending Functions
# =============================================================================

send_test_alert() {
    local severity=$1
    local title=$2
    local description=$3
    
    print_info "Sending test alert to Alertmanager..."
    
    # Create alert payload
    local payload=$(cat <<EOF
[{
    "labels": {
        "alertname": "MiragePotTestAlert",
        "severity": "$severity",
        "service": "miragepot-honeypot",
        "instance": "test"
    },
    "annotations": {
        "summary": "$title",
        "description": "$description"
    },
    "startsAt": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
}]
EOF
)
    
    # Send to Alertmanager
    local response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "$ALERTMANAGER_URL/api/v1/alerts")
    
    local http_code=$(echo "$response" | tail -n1)
    
    if [[ "$http_code" == "200" ]]; then
        print_success "Alert sent successfully"
        return 0
    else
        print_error "Failed to send alert (HTTP $http_code)"
        return 1
    fi
}

test_email_alert() {
    print_header "Testing Email Alert"
    
    if ! check_email_config; then
        print_error "Email is not configured"
        echo ""
        echo "Configure in $ENV_FILE:"
        echo "  SMTP_USER=your-email@gmail.com"
        echo "  SMTP_PASSWORD=your-app-password"
        echo "  ALERT_EMAIL_TO=recipient@example.com"
        echo ""
        echo "For Gmail, create app password at:"
        echo "  https://myaccount.google.com/apppasswords"
        return 1
    fi
    
    local email_to=$(get_env_value "ALERT_EMAIL_TO")
    print_info "Sending to: $email_to"
    
    send_test_alert "info" \
        "MiragePot Email Test" \
        "This is a test email alert from MiragePot. If you receive this, email alerts are working correctly!"
    
    if [[ $? -eq 0 ]]; then
        echo ""
        print_success "Email alert queued!"
        print_info "Check your inbox at: $email_to"
        print_warning "Note: Email delivery may take 1-2 minutes"
    fi
}

test_slack_alert() {
    print_header "Testing Slack Alert"
    
    if ! check_slack_config; then
        print_error "Slack is not configured"
        echo ""
        echo "Configure in $ENV_FILE:"
        echo "  ALERT_SLACK_ENABLED=true"
        echo "  SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/HERE"
        echo ""
        echo "Create webhook at:"
        echo "  https://api.slack.com/messaging/webhooks"
        return 1
    fi
    
    local channel=$(get_env_value "SLACK_CHANNEL" "#security-alerts")
    print_info "Sending to: $channel"
    
    send_test_alert "warning" \
        "MiragePot Slack Test" \
        "This is a test Slack alert from MiragePot. If you see this, Slack alerts are working!"
    
    if [[ $? -eq 0 ]]; then
        echo ""
        print_success "Slack alert queued!"
        print_info "Check your Slack channel: $channel"
        print_warning "Note: Delivery may take 5-10 seconds"
    fi
}

test_discord_alert() {
    print_header "Testing Discord Alert"
    
    if ! check_discord_config; then
        print_error "Discord is not configured"
        echo ""
        echo "Configure in $ENV_FILE:"
        echo "  ALERT_DISCORD_ENABLED=true"
        echo "  DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR/WEBHOOK/HERE"
        echo ""
        echo "Create webhook in Discord:"
        echo "  Server Settings > Integrations > Webhooks > New Webhook"
        return 1
    fi
    
    print_info "Sending to Discord webhook"
    
    send_test_alert "info" \
        "MiragePot Discord Test" \
        "This is a test Discord alert from MiragePot. If you see this, Discord alerts are working!"
    
    if [[ $? -eq 0 ]]; then
        echo ""
        print_success "Discord alert queued!"
        print_info "Check your Discord server"
        print_warning "Note: Delivery may take 5-10 seconds"
    fi
}

test_all_alerts() {
    print_header "Testing All Alert Channels"
    
    local tested=0
    local failed=0
    
    # Test email
    if check_email_config; then
        test_email_alert
        if [[ $? -ne 0 ]]; then
            failed=$((failed + 1))
        fi
        tested=$((tested + 1))
        echo ""
    fi
    
    # Test Slack
    if check_slack_config; then
        test_slack_alert
        if [[ $? -ne 0 ]]; then
            failed=$((failed + 1))
        fi
        tested=$((tested + 1))
        echo ""
    fi
    
    # Test Discord
    if check_discord_config; then
        test_discord_alert
        if [[ $? -ne 0 ]]; then
            failed=$((failed + 1))
        fi
        tested=$((tested + 1))
        echo ""
    fi
    
    if [[ $tested -eq 0 ]]; then
        print_error "No alert channels are configured"
        echo ""
        echo "Configure alerts in $ENV_FILE"
        return 1
    fi
    
    print_header "Test Summary"
    echo "Tested: $tested channel(s)"
    if [[ $failed -eq 0 ]]; then
        print_success "All tests passed!"
    else
        print_warning "$failed test(s) failed"
    fi
}

# =============================================================================
# Interactive Menu
# =============================================================================

show_menu() {
    print_header "MiragePot Alert Test Utility"
    
    show_config_status
    
    echo "Choose test:"
    echo ""
    
    # Build menu dynamically based on config
    local menu_num=1
    local -a menu_options
    
    if check_email_config; then
        echo "  $menu_num) Test email alert"
        menu_options[$menu_num]="email"
        menu_num=$((menu_num + 1))
    else
        echo "  -) Test email alert ${YELLOW}(not configured)${NC}"
    fi
    
    if check_slack_config; then
        echo "  $menu_num) Test Slack alert"
        menu_options[$menu_num]="slack"
        menu_num=$((menu_num + 1))
    else
        echo "  -) Test Slack alert ${YELLOW}(not configured)${NC}"
    fi
    
    if check_discord_config; then
        echo "  $menu_num) Test Discord alert"
        menu_options[$menu_num]="discord"
        menu_num=$((menu_num + 1))
    else
        echo "  -) Test Discord alert ${YELLOW}(not configured)${NC}"
    fi
    
    # Check if any alerts are configured
    if [[ ${#menu_options[@]} -gt 0 ]]; then
        echo ""
        echo "  $menu_num) Test all configured channels"
        menu_options[$menu_num]="all"
        menu_num=$((menu_num + 1))
    fi
    
    echo ""
    echo "  0) Exit"
    echo ""
    
    if [[ ${#menu_options[@]} -eq 0 ]]; then
        print_error "No alert channels configured!"
        echo ""
        echo "Edit $ENV_FILE to configure alerts"
        exit 1
    fi
    
    read -p "Enter choice: " choice
    
    if [[ "$choice" == "0" ]]; then
        print_info "Goodbye!"
        exit 0
    fi
    
    local selected="${menu_options[$choice]}"
    
    if [[ -z "$selected" ]]; then
        print_error "Invalid choice"
        exit 1
    fi
    
    echo ""
    
    case $selected in
        email)
            test_email_alert
            ;;
        slack)
            test_slack_alert
            ;;
        discord)
            test_discord_alert
            ;;
        all)
            test_all_alerts
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
    
    # Check prerequisites
    check_env_file
    check_alertmanager
    
    # Parse arguments
    if [[ $# -eq 0 ]]; then
        # No arguments, show menu
        show_menu
    else
        case $1 in
            email)
                show_config_status
                test_email_alert
                ;;
            slack)
                show_config_status
                test_slack_alert
                ;;
            discord)
                show_config_status
                test_discord_alert
                ;;
            all)
                test_all_alerts
                ;;
            *)
                echo "Usage: $0 [email|slack|discord|all]"
                echo ""
                echo "  email    - Test email alert"
                echo "  slack    - Test Slack alert"
                echo "  discord  - Test Discord alert"
                echo "  all      - Test all configured channels"
                echo ""
                echo "Run without arguments for interactive menu"
                exit 1
                ;;
        esac
    fi
}

# Run main function
main "$@"
