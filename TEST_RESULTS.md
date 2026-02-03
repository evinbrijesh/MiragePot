# Test Results Summary

## Date: February 3, 2026

## Tests Performed

### 1. Python Connection Test ✓
**Result:** PASS

```
- TCP connection to 127.0.0.1:2222: SUCCESS
- SSH handshake with 127.0.0.1:2222: SUCCESS (received 920 bytes)
- TCP connection to 10.211.40.20:2222: SUCCESS
- SSH handshake with 10.211.40.20:2222: SUCCESS (received 920 bytes)
```

### 2. Linux SSH Client Test ✓
**Result:** PASS

```
- Connection established successfully
- Key exchange completed
- Authentication succeeded
- Commands executed successfully
- SSH protocol: paramiko_4.0.0
- Algorithms negotiated: curve25519-sha256, rsa-sha2-512, aes128-gcm
```

### 3. Windows PowerShell SSH Test ✗
**Result:** FAIL (Connection timed out)

From your screenshots:
```
PS C:\Users\fayol> ssh root@10.211.40.20 -p 2222
ssh: connect to host 10.211.40.20 port 2222: Connection timed out
```

## Diagnosis

### What This Tells Us:

1. **SSH Server is Working Correctly** ✓
   - Linux clients can connect and authenticate
   - SSH handshake completes successfully
   - All SSH protocol negotiation works

2. **TCP Connectivity is Working** ✓
   - Telnet test succeeded
   - Python socket test succeeded
   - Port 2222 is listening on 0.0.0.0

3. **Windows SSH Client Cannot Connect** ✗
   - Gets "Connection timed out" error
   - Same behavior on different networks
   - Same behavior on same network

### Root Cause Analysis:

The issue is **NOT** with the SSH protocol or MiragePot code. Based on the evidence:

**Primary Suspects (in order of likelihood):**

1. **Network Firewall Between Windows and Linux**
   - Most likely: Router/gateway firewall blocking SSH from Windows → Linux
   - Windows packets are being dropped before reaching the honeypot
   - Explains why Linux client works (same machine) but Windows doesn't

2. **Windows Firewall on Windows Machine**
   - Windows firewall blocking outbound SSH connections
   - Less likely since timeout suggests connection attempt is made

3. **Asymmetric Routing or NAT Issues**
   - Connection packets reach honeypot but replies don't reach Windows
   - Would explain why we see no logs on honeypot side when Windows connects

4. **Different Network Interface Behavior**
   - Possible issue with how wlan0 interface handles external connections
   - Though binding to 0.0.0.0 should handle this

## Improvements Made

### 1. Enhanced Diagnostic Logging
- Added DEBUG level logging throughout connection handling
- Enabled Paramiko SSH protocol debug logs
- Added logging at every connection stage:
  - Socket accept
  - Client handler entry
  - Rate limiter decisions
  - Transport creation
  - SSH negotiation stages
  - Full exception tracebacks

### 2. Socket Configuration Improvements (server.py)
- Added TCP keepalive on client sockets
- Disabled Nagle's algorithm (TCP_NODELAY) for lower latency
- Set 60-second timeout for SSH handshake
- Better error handling

### 3. Listening Socket Improvements (ssh_interface.py)
- Enabled TCP keepalive on server socket
- Added TCP_NODELAY for interactive sessions
- Improved compatibility with various clients

### 4. Paramiko Transport Configuration
- Added keepalive to transport (30 seconds)
- Added debug logging for negotiated algorithms
- Better visibility into what the server supports

## Files Modified

1. `/home/evin/Documents/04_projects/MiragePot/miragepot/server.py`
   - Enhanced logging throughout `_handle_client()`
   - Added socket configuration for client connections
   - Added Paramiko transport keepalive
   - Better exception handling

2. `/home/evin/Documents/04_projects/MiragePot/miragepot/rate_limiter.py`
   - Added debug logging for connection checks
   - Shows connection counts and limits
   - Logs acceptance decisions

3. `/home/evin/Documents/04_projects/MiragePot/miragepot/ssh_interface.py`
   - Enhanced listening socket with keepalive
   - Added TCP_NODELAY for lower latency
   - Better socket options for compatibility

## Files Created

1. `test_connection.py` - Python-based connection tester
2. `test_connection.sh` - Bash-based test suite
3. `DIAGNOSTIC_GUIDE.md` - Complete testing guide
4. `WINDOWS_SSH_TROUBLESHOOTING.md` - Windows-specific troubleshooting
5. `TEST_RESULTS.md` - This file

## Next Steps

### Immediate Actions Required:

1. **Restart MiragePot** with the new enhanced logging:
   ```bash
   # Stop current instance (Ctrl+C)
   cd /home/evin/Documents/04_projects/MiragePot
   python run.py
   ```

2. **Test from Windows with Verbose Output:**
   ```powershell
   ssh -vvv root@10.211.40.20 -p 2222
   ```
   
   Save the full output and check:
   - Does it say "Connecting to..."?
   - Does it say "Connection established"?
   - Where exactly does it timeout?

3. **Test TCP Connectivity from Windows:**
   ```powershell
   Test-NetConnection -ComputerName 10.211.40.20 -Port 2222
   ```
   
   This will show if TCP can reach the server at all.

4. **Check MiragePot Logs:**
   - When you try connecting from Windows, watch the honeypot terminal
   - Look for: `=== SOCKET ACCEPT ===`
   - If you see this, connection is reaching the server
   - If you DON'T see this, connection is being blocked before it reaches Python

5. **Check Firewall Rules (requires sudo):**
   ```bash
   sudo iptables -L -n -v | grep 2222
   ```
   
   If there are any DROP or REJECT rules, that's the problem.

### Diagnostic Questions:

1. **When connecting from Windows, do you see ANY logs in MiragePot terminal?**
   - If YES: Connection is reaching the server, it's an SSH protocol issue
   - If NO: Connection is being blocked by firewall/network

2. **Can Windows ping the Linux machine?**
   ```powershell
   ping 10.211.40.20
   ```

3. **Can Windows telnet to port 2222?**
   ```powershell
   telnet 10.211.40.20 2222
   ```
   (Install telnet: `dism /online /Enable-Feature /FeatureName:TelnetClient`)

4. **Is there a router/firewall between Windows and Linux machines?**
   - Check router admin panel for firewall rules
   - Check for any SSH blocking rules
   - Check for port forwarding needs

5. **Are both machines on the same subnet?**
   - Linux: 10.211.40.20/24
   - Windows: 10.211.40.? (check with `ipconfig`)

## Temporary Workaround for Testing

If this is just for testing/development, you can temporarily:

1. **Test from a Linux VM on the Windows machine** (if available)
2. **Test from Windows WSL** (Windows Subsystem for Linux)
3. **Use a VPN to connect both machines** to the same network
4. **Disable firewalls temporarily** (not recommended for production)

## Conclusion

**The MiragePot SSH honeypot is working correctly.** The issue is with network connectivity between your Windows client and the Linux honeypot server. This is evidenced by:

- ✓ Successful connections from Linux SSH client
- ✓ Successful TCP connectivity tests
- ✓ Proper SSH protocol negotiation
- ✗ Windows timeout suggests network/firewall blocking

The enhancements I've made will improve logging, compatibility, and debuggability, but the root issue requires network-level troubleshooting on the Windows side or network infrastructure between the two machines.

## Support

If you need further assistance, please provide:
1. Full verbose SSH output from Windows (`ssh -vvv ...`)
2. MiragePot terminal logs when attempting Windows connection
3. Result of `Test-NetConnection` from Windows
4. Network topology (same network? different networks? router in between?)
