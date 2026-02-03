# MiragePot Enhanced Diagnostic Logging - Testing Guide

## Summary of Changes

### 1. Enhanced Server Logging (miragepot/server.py)
- Changed logging level from INFO to DEBUG
- Enabled Paramiko debug logging to see SSH protocol details
- Added detailed logging at every stage of connection handling:
  - Socket accept (TCP connection established)
  - Handler function entry
  - Rate limiter decision
  - Paramiko transport creation
  - SSH negotiation start/success/failure
  - Channel accept/reject
  - Full exception tracebacks for SSH failures

### 2. Enhanced Rate Limiter Logging (miragepot/rate_limiter.py)
- Added debug logging for connection checks
- Shows current connection counts
- Logs acceptance decisions (not just rejections)
- Shows per-IP connection tracking

### 3. Test Scripts Created
- `test_connection.py` - Python-based connection tester
- `test_connection.sh` - Bash-based comprehensive test suite

## What the Logs Will Show

With these changes, you'll see detailed logs like:

```
[DEBUG] === SOCKET ACCEPT === New TCP connection from 10.211.40.20:51234
[DEBUG] === _handle_client() ENTRY === Connection from 10.211.40.20:51234
[DEBUG] Rate limiter checking IP: 10.211.40.20 (current active: 1/50 total)
[DEBUG] Rate limiter: ALLOWING connection from 10.211.40.20
[DEBUG] Rate limiter: ACCEPTED connection from 10.211.40.20:51234
[INFO] New connection from 10.211.40.20:51234
[DEBUG] Creating Paramiko transport for 10.211.40.20:51234
[DEBUG] Added host key to transport for 10.211.40.20:51234
[DEBUG] Starting SSH server negotiation with 10.211.40.20:51234
[DEBUG] paramiko.transport - starting thread (client mode): 0x...
[DEBUG] paramiko.transport - Local version/idstring: SSH-2.0-paramiko_3.x.x
[DEBUG] paramiko.transport - Remote version/idstring: SSH-2.0-OpenSSH_for_Windows_8.1
... [Paramiko detailed handshake logs] ...
[DEBUG] SSH server negotiation SUCCESSFUL with 10.211.40.20:51234
[DEBUG] Waiting for channel from 10.211.40.20:51234 (20 second timeout)
[DEBUG] Channel accepted from 10.211.40.20:51234
```

If there's a failure, you'll see exactly where and why:
```
[ERROR] SSH negotiation FAILED with 10.211.40.20:51234 - Exception: <error details>
[ERROR] SSH negotiation FAILED - Exception type: SSHException
[ERROR] SSH negotiation FAILED - Full traceback:
<full stack trace>
```

## Testing Instructions

### Step 1: Stop Current MiragePot
If MiragePot is running, stop it with Ctrl+C

### Step 2: Start MiragePot with Enhanced Logging
```bash
cd /home/evin/Documents/04_projects/MiragePot
python run.py
```

You should immediately see more detailed startup logs.

### Step 3: Run Local Connection Tests

#### Option A: Python Test (Recommended)
```bash
# In a new terminal
cd /home/evin/Documents/04_projects/MiragePot
python test_connection.py
```

This will:
- Test TCP connectivity to 127.0.0.1:2222
- Test SSH handshake from localhost
- Test from local network IP
- Show exactly where the connection fails

#### Option B: Bash Test (More comprehensive)
```bash
# In a new terminal
cd /home/evin/Documents/04_projects/MiragePot
./test_connection.sh
```

This will run 4 tests:
1. Check if port is listening
2. TCP connectivity with telnet
3. SSH from localhost (127.0.0.1)
4. SSH from local network IP

### Step 4: Analyze MiragePot Server Logs

Watch the MiragePot terminal for diagnostic output. Look for:

1. **TCP Connection**: `=== SOCKET ACCEPT ===`
   - If you don't see this, the TCP connection isn't reaching the server

2. **Handler Called**: `=== _handle_client() ENTRY ===`
   - If you see SOCKET ACCEPT but not this, threading issue

3. **Rate Limiter**: `Rate limiter: ALLOWING`
   - If rejected, shows the reason (blocked IP, too many connections)

4. **SSH Negotiation**: `Starting SSH server negotiation`
   - If you see this but then FAILED, it's an SSH protocol issue

5. **Paramiko Details**: Look for `paramiko.transport` logs
   - Shows SSH version exchange
   - Shows key exchange algorithms
   - Shows cipher negotiation
   - Will pinpoint exact failure in SSH handshake

### Step 5: Test from Windows PowerShell

After confirming local tests work, try from your Windows machine:
```powershell
ssh -vvv root@10.211.40.20 -p 2222
```

Compare the Windows SSH client output with the MiragePot server logs.

## Common Issues and What to Look For

### Issue 1: Connection Timeout - TCP Level
**Logs show**: Nothing (no SOCKET ACCEPT)
**Cause**: Firewall or network routing issue
**Solution**: Check firewall rules, network connectivity

### Issue 2: Connection Timeout - After TCP
**Logs show**: SOCKET ACCEPT but no _handle_client
**Cause**: Threading issue or Python crash
**Solution**: Check for exceptions in server startup

### Issue 3: Connection Timeout - During Rate Limiting
**Logs show**: _handle_client but rejected by rate limiter
**Cause**: IP blocked or connection limit reached
**Solution**: Wait for block to expire or adjust limits in config

### Issue 4: Connection Timeout - During SSH Handshake
**Logs show**: SSH negotiation started but FAILED
**Cause**: SSH protocol incompatibility (most likely for your issue)
**Solution**: Look at Paramiko logs to see which algorithm/cipher failed

### Issue 5: Client-Specific Issues
**Logs show**: Works from Linux SSH but not from Windows
**Cause**: Windows SSH client uses different ciphers/algorithms
**Solution**: Configure Paramiko to accept Windows-compatible algorithms

## Next Steps After Diagnosis

Once you run the tests and analyze the logs, we'll know:
1. Exactly where the connection is failing
2. What error Paramiko is throwing
3. What SSH protocol negotiation is failing
4. Whether it's a client compatibility issue

Then we can implement a targeted fix based on the actual root cause.

## Files Modified
- `/home/evin/Documents/04_projects/MiragePot/miragepot/server.py`
- `/home/evin/Documents/04_projects/MiragePot/miragepot/rate_limiter.py`

## Files Created
- `/home/evin/Documents/04_projects/MiragePot/test_connection.py`
- `/home/evin/Documents/04_projects/MiragePot/test_connection.sh`
- `/home/evin/Documents/04_projects/MiragePot/DIAGNOSTIC_GUIDE.md` (this file)
