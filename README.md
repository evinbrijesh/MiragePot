# MiragePot

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)

**AI-Driven Adaptive SSH Honeypot**

MiragePot is an intelligent SSH honeypot that simulates a realistic Linux terminal using a local LLM (Phi-3 via Ollama). Instead of executing real commands, it generates believable responses to keep attackers engaged while logging their activities for analysis.

## Features

- **Realistic SSH Server** - Paramiko-based SSH server accepting any credentials
- **AI-Powered Responses** - Uses local LLM (Ollama) for dynamic command output
- **Hybrid Engine** - Fast cached responses + AI fallback for unknown commands
- **Fake Filesystem** - In-memory filesystem with realistic files and structure
- **Enhanced Security** - Rate limiting, Unicode normalization, 4096-bit RSA keys
- **Prompt Injection Protection** - Advanced detection with normalization to prevent bypasses
- **Active Defense** - Threat scoring with configurable tarpit delays
- **Session Logging** - Detailed JSON logs of all attacker activity
- **Web Dashboard** - Real-time Streamlit dashboard for monitoring

## Quick Start

### Prerequisites

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| **Docker** | 20.10+ | [Install Docker](https://docs.docker.com/get-docker/) |
| **Docker Compose** | v2.0+ | Included with Docker Desktop |
| **Disk Space** | 5GB free | For images + AI model |
| **RAM** | 4GB minimum | 8GB recommended for full stack |

Verify installation:
```bash
docker --version
docker compose version
```

### Docker Deployment (Recommended for Demos)

Deploy the complete monitoring stack in one command:

```bash
# Clone the repository
git clone https://github.com/evinbrijesh/MiragePot.git
cd MiragePot

# Deploy full stack - AI model downloads automatically on first run
cp .env.docker.example .env.docker
cd docker/
docker compose up -d

# First-time setup takes 2-5 minutes while AI model downloads
# Watch the progress:
docker compose logs -f miragepot-ollama

# Once you see "✅ AI Engine Ready", you're good to go!
```

**Access your honeypot:**
```bash
ssh root@localhost -p 2222  # Use ANY password
```

**View dashboards:**
- **Streamlit**: http://localhost:8501 (session logs, real-time activity)
- **Grafana**: http://localhost:3000 (metrics, TTPs, performance) - login: admin/admin
- **Prometheus**: http://localhost:9091 (raw metrics)

### First-Time Setup Notes

**⏱️ First Run (2-5 minutes):**
The first time you start MiragePot, the AI model (~2GB) downloads automatically.
Watch the progress with `docker compose logs -f miragepot-ollama`.
Subsequent starts are instant (model is cached).

**✅ Quick Health Check:**
```bash
# Check if everything is running
docker compose ps

# All services should show "healthy" status within 2-5 minutes
```

**🔧 Common Issues:**

For detailed troubleshooting, see [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

Quick fixes:
- **"Waiting for model download"** → Normal on first run, be patient (2-5 min)
- **"Connection refused to Ollama"** → Model still downloading, check `docker logs miragepot-ollama`
- **Download seems stuck** → Check internet connection, try `docker compose restart ollama`

**Offline deployment** (for demos without internet):
See [Offline Deployment Guide](docs/OFFLINE_DEPLOYMENT.md) - includes script to create a portable bundle.

**Demo presentation:**
See [Demo Walkthrough](docs/DEMO_WALKTHROUGH.md) - complete script for technical presentations.

### Local Installation (For Development)

For development setup without Docker, see the [Installation Guide](docs/INSTALL.md).

Quick summary:
```bash
# Clone and install
git clone https://github.com/evinbrijesh/MiragePot.git
cd MiragePot
python -m venv venv
source venv/bin/activate
pip install -e .

# Setup Ollama
ollama serve &
ollama pull phi3

# Start honeypot
python run.py
```

Test: `ssh root@127.0.0.1 -p 2222` (any password works)  
Dashboard: http://localhost:8501

See [INSTALL.md](docs/INSTALL.md) for detailed OS-specific instructions.

## Deployment Options

**Recommended for Demos/Production**: Use **Full Stack** deployment to showcase complete capabilities.

| Feature | Full Stack (Recommended) | Simple Stack | Local Dev |
|---------|--------------------------|--------------|-----------|
| **SSH Honeypot** | ✅ Docker | ✅ Docker | Python |
| **AI Responses** | ✅ Ollama+phi3 | ✅ Ollama+phi3 | Ollama (manual) |
| **Streamlit Dashboard** | ✅ Real-time | ✅ Real-time | Manual start |
| **Prometheus Metrics** | ✅ Full UI + Storage | Endpoint only | Endpoint only |
| **Grafana Dashboards** | ✅ 3 pre-built | ❌ | ❌ |
| **Alertmanager** | ✅ Alert system | ❌ | ❌ |
| **MITRE ATT&CK Mapping** | ✅ Visualized | ✅ Logged | ✅ Logged |
| **Setup Time** | ~5 min | ~3 min | ~10 min |
| **RAM Required** | ~5GB | ~3GB | ~4GB |
| **Best For** | **Demos, Production** | Quick testing | Development |

### Why Full Stack?

For CS demos and production use, the Full Stack deployment provides:
- **Complete visibility** - Grafana dashboards for visual presentations
- **Professional appearance** - Shows production-ready architecture
- **Threat analysis** - Real-time MITRE ATT&CK technique visualization
- **Scalability demonstration** - Shows how to monitor at scale
- **One command deployment** - Just as easy as simple stack

### Simple Stack Use Case

Use simple stack only for:
- Quick local testing
- Resource-constrained environments
- Learning the basics before full deployment

## Architecture

```
MiragePot/
├── miragepot/              # Core honeypot package
│   ├── server.py           # SSH server implementation
│   ├── command_handler.py  # Command processing engine
│   ├── ai_interface.py     # Ollama/LLM integration
│   ├── defense_module.py   # Threat scoring & tarpit
│   └── config.py           # Configuration management
├── dashboard/              # Streamlit web dashboard
├── data/
│   ├── cache.json          # Cached command responses
│   ├── system_prompt.txt   # LLM system prompt
│   └── logs/               # Session logs (JSON)
└── tests/                  # Test suite
```

## Configuration

Copy `.env.example` to `.env` and customize:

```bash
# SSH Settings
MIRAGEPOT_SSH_PORT=2222
MIRAGEPOT_SSH_HOST=0.0.0.0

# LLM Settings
MIRAGEPOT_LLM_MODEL=phi3
MIRAGEPOT_LLM_TEMPERATURE=0.7

# Logging
MIRAGEPOT_LOG_LEVEL=INFO
```

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for all options.

## CLI Usage

```bash
# Basic usage
miragepot

# Custom port
miragepot --port 2222

# With dashboard
miragepot --dashboard

# Debug mode
miragepot --log-level DEBUG

# Show help
miragepot --help
```

## Documentation

### Getting Started
- [Installation Guide](docs/INSTALL.md) - Local development setup
- [Docker Deployment](docs/DOCKER_DEPLOYMENT.md) - Production deployment guide
- [Configuration Reference](docs/CONFIGURATION.md) - All settings explained

### Operations
- [Usage Guide](docs/USAGE.md) - Running and testing MiragePot
- [Monitoring Guide](docs/MONITORING.md) - Grafana dashboards and metrics
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues and solutions

### Specialized Deployments
- [Offline Deployment](docs/OFFLINE_DEPLOYMENT.md) - Deploy without internet (for demos)
- [Demo Walkthrough](docs/DEMO_WALKTHROUGH.md) - Present to technical audiences

### Development
- [Architecture](docs/architecture.md) - System design and components
- [Contributing](CONTRIBUTING.md) - How to contribute

## How It Works

1. **SSH Connection**: Attacker connects to the honeypot via SSH
2. **Authentication**: Any username/password is accepted
3. **Command Processing**:
   - Check cache for known commands (fast path)
   - Fall back to LLM for unknown commands
   - Apply prompt injection protection
4. **Response Generation**: Return realistic terminal output
5. **Threat Scoring**: Analyze command for malicious patterns
6. **Tarpit Delay**: Slow down high-threat commands
7. **Logging**: Record everything for analysis

## Example Session

```
$ ssh root@127.0.0.1 -p 2222
root@127.0.0.1's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-86-generic x86_64)
Last login: just now from unknown

root@miragepot:~# whoami
root

root@miragepot:~# cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...

root@miragepot:~# ls -la
drwxr-xr-x 2 root root 4096 Jan 20 12:00 .
drwxr-xr-x 2 root root 4096 Jan 20 12:00 ..
-rw-r--r-- 1 root root  156 Jan 20 12:00 notes.txt
-rw-r--r-- 1 root root  123 Jan 20 12:00 passwords.txt
```

## Security Considerations

- **Isolation**: Run in a VM or isolated network segment
- **Not for Production**: This is a research/education tool
- **No Real Execution**: Commands are simulated, not executed
- **Monitor Resources**: LLM queries can be CPU-intensive

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Format code
make format

# Run linters
make lint
```

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas we'd love help with:
- Expanding cached command responses
- Improving LLM prompts
- Adding threat detection patterns
- Dashboard visualizations
- Documentation improvements

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**Evin Brijesh** - [GitHub](https://github.com/evinbrijesh)

## Acknowledgments

- [Paramiko](https://www.paramiko.org/) - SSH library for Python
- [Ollama](https://ollama.ai/) - Local LLM server
- [Streamlit](https://streamlit.io/) - Dashboard framework
- [Phi-3](https://huggingface.co/microsoft/Phi-3-mini-4k-instruct) - Microsoft's efficient LLM
