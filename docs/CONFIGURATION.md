# Configuration Reference

MiragePot can be configured through environment variables or a `.env` file. This document describes all available configuration options.

## Configuration Methods

### 1. Environment Variables

Set variables directly in your shell:

```bash
export MIRAGEPOT_SSH_PORT=2222
export MIRAGEPOT_LLM_MODEL=phi3
miragepot
```

### 2. Environment File (.env)

Create a `.env` file in the project root:

```bash
cp .env.example .env
# Edit .env with your settings
```

### 3. Command Line Arguments

Some settings can be overridden via CLI:

```bash
miragepot --port 2222 --host 0.0.0.0 --log-level DEBUG
```

**Priority**: CLI > Environment Variables > Defaults

## Configuration Options

### SSH Server

| Variable | Default | Description |
|----------|---------|-------------|
| `MIRAGEPOT_SSH_HOST` | `0.0.0.0` | Address to bind the SSH server |
| `MIRAGEPOT_SSH_PORT` | `2222` | Port for SSH connections |
| `MIRAGEPOT_HOST_KEY` | `./data/host.key` | Path to SSH host key file |
| `MIRAGEPOT_SSH_BANNER` | `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5` | SSH version banner |

**Examples:**

```bash
# Listen on all interfaces, port 2222
MIRAGEPOT_SSH_HOST=0.0.0.0
MIRAGEPOT_SSH_PORT=2222

# Listen only on localhost for testing
MIRAGEPOT_SSH_HOST=127.0.0.1
MIRAGEPOT_SSH_PORT=2222

# Production on standard port (requires root)
MIRAGEPOT_SSH_PORT=22
```

### LLM/Ollama

| Variable | Default | Description |
|----------|---------|-------------|
| `MIRAGEPOT_LLM_MODEL` | `phi3` | Ollama model to use |
| `MIRAGEPOT_LLM_TIMEOUT` | `30.0` | Request timeout (seconds) |
| `MIRAGEPOT_LLM_TEMPERATURE` | `0.7` | Response randomness (0.0-1.0) |
| `MIRAGEPOT_LLM_MAX_TOKENS` | `512` | Maximum response length |
| `MIRAGEPOT_LLM_CHECK_INTERVAL` | `30.0` | Connection check interval (seconds) |

**Model Recommendations:**

| Model | Size | Speed | Quality | Best For |
|-------|------|-------|---------|----------|
| `phi3` | ~2GB | Fast | Good | Default, balanced |
| `llama2` | ~4GB | Medium | Better | Higher quality responses |
| `mistral` | ~4GB | Medium | Good | Alternative to llama2 |
| `codellama` | ~4GB | Medium | Good | Code/technical commands |

**Examples:**

```bash
# Use Phi-3 (default, recommended)
MIRAGEPOT_LLM_MODEL=phi3

# Use Llama 2 for better quality
MIRAGEPOT_LLM_MODEL=llama2

# Lower temperature for more consistent responses
MIRAGEPOT_LLM_TEMPERATURE=0.3

# Higher temperature for more varied responses
MIRAGEPOT_LLM_TEMPERATURE=0.9
```

### Dashboard

| Variable | Default | Description |
|----------|---------|-------------|
| `MIRAGEPOT_DASHBOARD_HOST` | `localhost` | Dashboard bind address |
| `MIRAGEPOT_DASHBOARD_PORT` | `8501` | Dashboard port |
| `MIRAGEPOT_DASHBOARD_REFRESH` | `5` | Auto-refresh interval (seconds) |

**Examples:**

```bash
# Default (local only)
MIRAGEPOT_DASHBOARD_HOST=localhost
MIRAGEPOT_DASHBOARD_PORT=8501

# Accessible from network
MIRAGEPOT_DASHBOARD_HOST=0.0.0.0
MIRAGEPOT_DASHBOARD_PORT=8080
```

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `MIRAGEPOT_LOG_LEVEL` | `INFO` | Log verbosity level |
| `MIRAGEPOT_LOG_FORMAT` | See below | Python logging format |
| `MIRAGEPOT_LOG_FILE` | (none) | Optional log file path |

**Log Levels:**
- `DEBUG` - Detailed debugging information
- `INFO` - General operational messages
- `WARNING` - Warning messages
- `ERROR` - Error messages only
- `CRITICAL` - Critical errors only

**Default Format:**
```
%(asctime)s - %(name)s - %(levelname)s - %(message)s
```

**Examples:**

```bash
# Debug mode for troubleshooting
MIRAGEPOT_LOG_LEVEL=DEBUG

# Log to file
MIRAGEPOT_LOG_FILE=./data/logs/miragepot.log

# Custom format
MIRAGEPOT_LOG_FORMAT="[%(levelname)s] %(message)s"
```

### Honeypot Identity

| Variable | Default | Description |
|----------|---------|-------------|
| `MIRAGEPOT_HOSTNAME` | `miragepot` | Fake hostname |
| `MIRAGEPOT_OS_NAME` | `Ubuntu` | Fake OS name |
| `MIRAGEPOT_OS_VERSION` | `20.04.6 LTS` | Fake OS version |
| `MIRAGEPOT_KERNEL_VERSION` | `5.15.0-86-generic` | Fake kernel version |

**Examples:**

```bash
# Appear as a web server
MIRAGEPOT_HOSTNAME=webserver01

# Appear as CentOS
MIRAGEPOT_OS_NAME=CentOS
MIRAGEPOT_OS_VERSION=7.9.2009
MIRAGEPOT_KERNEL_VERSION=3.10.0-1160.el7.x86_64
```

### Security & Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `MIRAGEPOT_MAX_CONNECTIONS_PER_IP` | `3` | Maximum concurrent connections per IP |
| `MIRAGEPOT_MAX_TOTAL_CONNECTIONS` | `50` | Maximum total concurrent connections |
| `MIRAGEPOT_CONNECTION_TIME_WINDOW` | `60` | Time window for connection tracking (seconds) |
| `MIRAGEPOT_BLOCK_DURATION` | `300` | Block duration for abusive IPs (seconds) |
| `MIRAGEPOT_MAX_SESSION_DURATION` | `3600` | Maximum session duration (seconds, 0=unlimited) |
| `MIRAGEPOT_LOG_PASSWORDS` | `false` | Log passwords to console (true/false) |

**Examples:**

```bash
# Stricter rate limiting
MIRAGEPOT_MAX_CONNECTIONS_PER_IP=1
MIRAGEPOT_MAX_TOTAL_CONNECTIONS=20
MIRAGEPOT_BLOCK_DURATION=600

# Relaxed settings for testing
MIRAGEPOT_MAX_CONNECTIONS_PER_IP=10
MIRAGEPOT_MAX_SESSION_DURATION=7200

# Enable password logging (use with caution)
MIRAGEPOT_LOG_PASSWORDS=true
```

## Sample Configurations

### Development Setup

```bash
# .env for development
MIRAGEPOT_SSH_HOST=127.0.0.1
MIRAGEPOT_SSH_PORT=2222
MIRAGEPOT_LOG_LEVEL=DEBUG
MIRAGEPOT_LLM_MODEL=phi3
```

### Production Setup

```bash
# .env for production
MIRAGEPOT_SSH_HOST=0.0.0.0
MIRAGEPOT_SSH_PORT=22
MIRAGEPOT_LOG_LEVEL=INFO
MIRAGEPOT_LOG_FILE=/var/log/miragepot/honeypot.log
MIRAGEPOT_LLM_MODEL=phi3
MIRAGEPOT_LLM_TEMPERATURE=0.5
```

### High-Interaction Setup

```bash
# .env for detailed logging and slower responses
MIRAGEPOT_SSH_HOST=0.0.0.0
MIRAGEPOT_SSH_PORT=2222
MIRAGEPOT_LOG_LEVEL=DEBUG
MIRAGEPOT_LLM_MODEL=llama2
MIRAGEPOT_LLM_TEMPERATURE=0.8
MIRAGEPOT_LLM_TIMEOUT=60.0
```

## Programmatic Access

You can also access configuration in Python:

```python
from miragepot.config import get_config

config = get_config()

# Access settings
print(config.ssh.port)        # 2222
print(config.llm.model)       # "phi3"
print(config.logging.level)   # "INFO"

# Reload configuration
from miragepot.config import reload_config
config = reload_config()
```

## See Also

- [INSTALL.md](INSTALL.md) - Installation guide
- [USAGE.md](USAGE.md) - Usage guide
- [.env.example](../.env.example) - Example configuration file
