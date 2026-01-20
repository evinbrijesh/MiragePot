# MiragePot

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**AI-Driven Adaptive SSH Honeypot**

MiragePot is an intelligent SSH honeypot that simulates a realistic Linux terminal using a local LLM (Phi-3 via Ollama). Instead of executing real commands, it generates believable responses to keep attackers engaged while logging their activities for analysis.

## Features

- **Realistic SSH Server** - Paramiko-based SSH server accepting any credentials
- **AI-Powered Responses** - Uses local LLM (Ollama) for dynamic command output
- **Hybrid Engine** - Fast cached responses + AI fallback for unknown commands
- **Fake Filesystem** - In-memory filesystem with realistic files and structure
- **Prompt Injection Protection** - Detects and blocks LLM manipulation attempts
- **Active Defense** - Threat scoring with configurable tarpit delays
- **Session Logging** - Detailed JSON logs of all attacker activity
- **Web Dashboard** - Real-time Streamlit dashboard for monitoring

## Quick Start

### Prerequisites

- Python 3.10+
- [Ollama](https://ollama.ai) with phi3 model

### Installation

```bash
# Clone the repository
git clone https://github.com/evinbrijesh/MiragePot.git
cd MiragePot

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install MiragePot
pip install -e .

# Setup Ollama
ollama pull phi3
ollama serve  # Keep running in background
```

### Running

```bash
# Start honeypot and dashboard
python run.py

# Or use the CLI
miragepot --dashboard
```

### Testing

Connect via SSH (any password works):

```bash
ssh root@127.0.0.1 -p 2222
```

Open the dashboard at http://localhost:8501

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

- [Installation Guide](docs/INSTALL.md)
- [Configuration Reference](docs/CONFIGURATION.md)
- [Usage Guide](docs/USAGE.md)
- [Architecture](docs/architecture.md)
- [Contributing](CONTRIBUTING.md)

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
