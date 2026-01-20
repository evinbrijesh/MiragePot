# Installation Guide

This guide covers installing MiragePot on Linux and macOS systems.

## Prerequisites

### Required

- **Python 3.10+** - MiragePot requires Python 3.10 or later
- **Ollama** - Local LLM server for generating responses
- **pip** - Python package manager

### Optional

- **Make** - For using the Makefile commands
- **Git** - For cloning the repository

## Quick Install

```bash
# Clone the repository
git clone https://github.com/evinbrijesh/MiragePot.git
cd MiragePot

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install MiragePot
pip install -e .
```

## Detailed Installation

### 1. Install Python

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3.10 python3.10-venv python3-pip
```

**Fedora:**
```bash
sudo dnf install python3.10 python3-pip
```

**macOS (Homebrew):**
```bash
brew install python@3.10
```

### 2. Install Ollama

Ollama is required for the AI-driven responses. Install it from [ollama.ai](https://ollama.ai):

**Linux:**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

**macOS:**
```bash
brew install ollama
```

### 3. Download the LLM Model

Start Ollama and pull the Phi-3 model:

```bash
# Start Ollama server (runs in background)
ollama serve &

# Pull the Phi-3 model (about 2GB download)
ollama pull phi3
```

Alternative models (modify MIRAGEPOT_LLM_MODEL):
- `llama2` - Larger, more capable
- `mistral` - Good balance of speed/quality
- `codellama` - Better for code-related queries

### 4. Clone and Install MiragePot

```bash
# Clone repository
git clone https://github.com/evinbrijesh/MiragePot.git
cd MiragePot

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install MiragePot
pip install -e .

# Verify installation
miragepot --version
```

### 5. Configuration (Optional)

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` to customize settings. See [CONFIGURATION.md](CONFIGURATION.md) for details.

## Installation Methods

### Method 1: Editable Install (Recommended for Development)

```bash
pip install -e .
```

This installs MiragePot in "editable" mode - changes to source code take effect immediately.

### Method 2: Regular Install

```bash
pip install .
```

### Method 3: With Development Dependencies

```bash
pip install -e ".[dev]"
```

This includes testing, linting, and formatting tools.

## Verifying Installation

1. **Check MiragePot CLI:**
   ```bash
   miragepot --help
   ```

2. **Check Ollama connection:**
   ```bash
   ollama list
   ```
   You should see `phi3` (or your chosen model) listed.

3. **Test the honeypot:**
   ```bash
   # Start the honeypot
   miragepot --port 2222

   # In another terminal, try connecting
   ssh root@127.0.0.1 -p 2222
   # (any password works)
   ```

## Troubleshooting

### "Address already in use" Error

Another process is using port 2222:

```bash
# Find the process
lsof -i :2222

# Kill it or use a different port
miragepot --port 2223
```

### "ollama: command not found"

Ollama is not installed or not in PATH:

```bash
# Check if Ollama is installed
which ollama

# If not found, reinstall
curl -fsSL https://ollama.ai/install.sh | sh
```

### "Model not found" Warning

The LLM model hasn't been downloaded:

```bash
ollama pull phi3
```

### Connection Refused to Ollama

Ollama server isn't running:

```bash
# Start Ollama
ollama serve
```

### Permission Denied on Port 22

Standard SSH port requires root privileges:

```bash
# Option 1: Use a high port (recommended)
miragepot --port 2222

# Option 2: Run as root (not recommended)
sudo miragepot --port 22

# Option 3: Use capabilities
sudo setcap 'cap_net_bind_service=+ep' $(which python3)
```

## Uninstalling

```bash
# Deactivate virtual environment
deactivate

# Remove the directory
cd ..
rm -rf MiragePot
```

## Next Steps

- Read [USAGE.md](USAGE.md) for running the honeypot
- Review [CONFIGURATION.md](CONFIGURATION.md) for customization options
- Check the main [README](../README.md) for quick start guide
