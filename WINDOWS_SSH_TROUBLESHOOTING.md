# Windows SSH Connection Troubleshooting Guide

## Current Status

### What Works ✓
- TCP connectivity from both localhost and network IP (10.211.40.20)
- SSH handshake completes successfully from Linux client
- Full SSH authentication and command execution from Linux

### What Fails ✗
- Windows PowerShell SSH client gets "Connection timed out"

## Root Cause Analysis

Based on your screenshots and test results, the issue is **NOT** with the SSH protocol or Paramiko configuration. The issue is most likely:

### Most Likely Cause: Network/Firewall Issue

**Evidence:**
1. Linux SSH client works perfectly → SSH server is functioning correctly
2. Telnet succeeds → TCP port is reachable
3. Works on same network AND different networks with same result → Not a routing issue
4. PowerShell shows "Connection timed out" not "Connection refused" → Connection attempt is being blocked somewhere

**Possible causes:**
1. **Windows Firewall on the honeypot machine** blocking incoming connections from external IPs
2. **Router/NAT firewall** blocking the connection
3. **Windows SSH client timeout** is too short (unlikely since it works on same network for Linux)
4. **Network interface binding issue** (though we bind to 0.0.0.0 correctly)

## Recent Improvements Made

I've added several enhancements to improve Windows compatibility:

### 1. Socket-Level Improvements
- Enabled TCP keepalive on both server and client sockets
- Disabled Nagle's algorithm (TCP_NODELAY) for lower latency
- Added 60-second timeout for SSH handshake operations

### 2. Paramiko Transport Configuration  
- Added keepalive to Paramiko transport
- Added debug logging for negotiated algorithms
- Better timeout handling

### 3. Enhanced Logging
- Shows every stage of connection handling
- Logs socket configuration
- Paramiko debug output for SSH protocol details

## Testing Steps

### Step 1: Check Windows Firewall on Honeypot Machine

```bash
# On the honeypot machine (Linux), check if firewall is blocking:
sudo iptables -L -n -v | grep 2222

# If you see any DROP or REJECT rules for port 2222, that's the problem

# To allow all traffic to port 2222 (for testing):
sudo iptables -I INPUT -p tcp --dport 2222 -j ACCEPT

# Or if using ufw:
sudo ufw allow 2222/tcp
sudo ufw reload
```

### Step 2: Test from Windows with Verbose Output

On your Windows machine, run PowerShell as Administrator:

```powershell
# Test 1: Check TCP connectivity with Test-NetConnection
Test-NetConnection -ComputerName 10.211.40.20 -Port 2222

# You should see: TcpTestSucceeded : True

# Test 2: Try SSH with maximum verbosity
ssh -vvv root@10.211.40.20 -p 2222

# Watch for where it fails:
# - "Connecting to..." → TCP connection attempt
# - "Connection established" → TCP works
# - "Local version string" → SSH handshake starting
# - "Remote protocol version" → Server responded
# - TIMEOUT here → SSH handshake problem
# - "Connection timed out" immediately → Firewall blocking
```

### Step 3: Test with Telnet from Windows

```powershell
# Install telnet client if not available:
dism /online /Enable-Feature /FeatureName:TelnetClient

# Test connection:
telnet 10.211.40.20 2222

# If you see "SSH-2.0-paramiko_4.0.0", the connection works
# If it times out, it's a firewall/network issue
```

### Step 4: Check Network Path

From Windows:

```powershell
# Trace route to honeypot
tracert 10.211.40.20

# Check if there's packet loss
ping -n 10 10.211.40.20

# Check if any routers/firewalls between
```

### Step 5: Restart MiragePot with New Changes

```bash
# Stop current instance (Ctrl+C in the MiragePot terminal)

# Start with enhanced logging:
cd /home/evin/Documents/04_projects/MiragePot
python run.py
```

Then try connecting from Windows again and watch the detailed logs.

## Expected Behavior After Fixes

After restarting MiragePot with the new socket configurations, you should see:

```
[DEBUG] === SOCKET ACCEPT === New TCP connection from <Windows-IP>:<port>
[DEBUG] === _handle_client() ENTRY === Connection from <Windows-IP>:<port>
[DEBUG] Configured client socket with keepalive and 60s timeout
[DEBUG] Rate limiter: ALLOWING connection from <Windows-IP>
[DEBUG] Creating Paramiko transport for <Windows-IP>:<port>
[DEBUG] Default key exchange algorithms: [...]
[DEBUG] Starting SSH server negotiation with <Windows-IP>:<port>
[DEBUG] paramiko.transport - Remote version: SSH-2.0-OpenSSH_for_Windows_8.1
...
[DEBUG] SSH server negotiation SUCCESSFUL
```

If you DON'T see "=== SOCKET ACCEPT ===" when connecting from Windows, the connection isn't reaching the Python server at all → firewall issue.

## Quick Fix Commands

### Option 1: Temporarily Disable Firewall (for testing only)

```bash
# On honeypot machine:
sudo ufw disable  # If using ufw
# OR
sudo systemctl stop firewalld  # If using firewalld
# OR
sudo iptables -F  # Flush all iptables rules (CAUTION: removes all rules)
```

Then test from Windows again.

### Option 2: Add Specific Firewall Rule

```bash
# Allow port 2222 from specific Windows IP:
sudo iptables -I INPUT -p tcp -s <YOUR_WINDOWS_IP> --dport 2222 -j ACCEPT

# Or allow from anywhere (honeypot use case):
sudo iptables -I INPUT -p tcp --dport 2222 -j ACCEPT

# Make persistent:
sudo netfilter-persistent save  # On Debian/Ubuntu
# OR
sudo iptables-save > /etc/iptables/rules.v4  # Manual save
```

## What to Share for Further Diagnosis

If the issue persists after trying these steps, please provide:

1. **Windows SSH verbose output:**
   ```powershell
   ssh -vvv root@10.211.40.20 -p 2222 2>&1 | Out-File ssh-debug.txt
   ```

2. **Windows network test:**
   ```powershell
   Test-NetConnection -ComputerName 10.211.40.20 -Port 2222
   ```

3. **MiragePot server logs** from the moment you try to connect from Windows

4. **Firewall rules:**
   ```bash
   sudo iptables -L -n -v
   # OR
   sudo ufw status verbose
   ```

5. **Network interfaces:**
   ```bash
   ip addr show
   ip route show
   ```

This will help pinpoint exactly where the connection is being blocked.

## Summary

The SSH server is working correctly (proven by Linux client success). The Windows timeout issue is almost certainly a firewall or network configuration problem, NOT a code issue. The enhancements I've made will improve logging and compatibility, but the core issue needs network-level troubleshooting.
