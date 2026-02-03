#!/bin/bash
# Test SSH connection to MiragePot honeypot with verbose output
# This script helps diagnose SSH connection issues

echo "================================"
echo "MiragePot Connection Test Script"
echo "================================"
echo ""

# Get local IP
LOCAL_IP=$(ip addr show wlan0 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1)
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP=$(ip addr show eth0 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1)
fi

if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP="10.211.40.20"
fi

echo "Local IP detected: $LOCAL_IP"
echo "Testing port: 2222"
echo ""

# Test 1: Check if port is listening
echo "Test 1: Checking if port 2222 is listening..."
if command -v netstat &> /dev/null; then
    netstat -tuln | grep 2222
elif command -v ss &> /dev/null; then
    ss -tuln | grep 2222
fi
echo ""

# Test 2: TCP connectivity test
echo "Test 2: Testing TCP connectivity with telnet..."
timeout 3 bash -c "echo test | telnet $LOCAL_IP 2222 2>&1" | head -5
echo ""

# Test 3: SSH connection test from localhost
echo "Test 3: Testing SSH connection from localhost (127.0.0.1)..."
echo "Running: ssh -vvv -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1 -p 2222"
echo "Password: test123"
echo "---"
timeout 10 ssh -vvv -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1 -p 2222 <<EOF 2>&1 | head -50
test123
exit
EOF
echo ""

# Test 4: SSH connection test from local network IP
echo "Test 4: Testing SSH connection from local network IP ($LOCAL_IP)..."
echo "Running: ssh -vvv -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@$LOCAL_IP -p 2222"
echo "Password: test123"
echo "---"
timeout 10 ssh -vvv -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@$LOCAL_IP -p 2222 <<EOF 2>&1 | head -50
test123
exit
EOF
echo ""

echo "================================"
echo "Test Complete"
echo "================================"
echo ""
echo "Check the MiragePot terminal output for detailed server-side logs"
echo "Look for messages starting with:"
echo "  - === SOCKET ACCEPT ==="
echo "  - === _handle_client() ENTRY ==="
echo "  - Rate limiter:"
echo "  - Starting SSH server negotiation"
echo "  - SSH negotiation FAILED (if any errors)"
