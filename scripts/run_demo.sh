#!/bin/bash
# Wrapper script to run demo_session.py using the project's virtual environment

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_PYTHON="$PROJECT_ROOT/venv/bin/python"

# Check if venv exists
if [ ! -f "$VENV_PYTHON" ]; then
    echo "Error: Virtual environment not found at $PROJECT_ROOT/venv"
    echo "Please run 'python -m venv venv && source venv/bin/activate && pip install -e .' first"
    exit 1
fi

# Check if paramiko is installed in venv
if ! "$VENV_PYTHON" -c "import paramiko" 2>/dev/null; then
    echo "Installing paramiko in virtual environment..."
    "$VENV_PYTHON" -m pip install paramiko
fi

# Run the demo script with all passed arguments
exec "$VENV_PYTHON" "$SCRIPT_DIR/demo_session.py" "$@"
