#!/usr/bin/env python
"""MiragePot CLI entry point.

Run the honeypot with: python -m miragepot
Or after installation: miragepot

Usage:
    miragepot [OPTIONS]

Options:
    --host HOST         SSH bind address (default: 0.0.0.0)
    --port PORT         SSH port (default: 2222)
    --dashboard         Also start the Streamlit dashboard
    --dashboard-port    Dashboard port (default: 8501)
    --log-level LEVEL   Logging level (default: INFO)
    --version           Show version and exit
    --help              Show this message and exit
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import subprocess
import sys
import time
from typing import Optional

from .config import get_config

__version__ = "0.1.0"


def setup_logging(level: str) -> None:
    """Configure logging for the application."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def print_banner() -> None:
    """Print the MiragePot startup banner."""
    banner = r"""
    __  __ _                       ____        _   
   |  \/  (_)_ __ __ _  __ _  ___ |  _ \ ___ | |_ 
   | |\/| | | '__/ _` |/ _` |/ _ \| |_) / _ \| __|
   | |  | | | | | (_| | (_| |  __/|  __/ (_) | |_ 
   |_|  |_|_|_|  \__,_|\__, |\___||_|   \___/ \__|
                       |___/                      
    AI-Driven Adaptive SSH Honeypot v{}
    """.format(__version__)
    print(banner)


def start_dashboard(port: int) -> Optional[subprocess.Popen]:
    """Start the Streamlit dashboard in a subprocess."""
    config = get_config()
    dashboard_path = config.project_root / "dashboard" / "app.py"

    if not dashboard_path.exists():
        logging.warning("Dashboard not found at %s", dashboard_path)
        return None

    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(dashboard_path),
        "--server.port",
        str(port),
        "--server.headless",
        "true",
    ]

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        logging.info("Dashboard started on http://localhost:%d", port)
        return proc
    except FileNotFoundError:
        logging.warning("Streamlit not installed, dashboard will not be available")
        return None
    except Exception as e:
        logging.error("Failed to start dashboard: %s", e)
        return None


def run_server(host: str, port: int) -> None:
    """Run the SSH honeypot server."""
    # Import here to avoid circular imports
    from .server import HoneypotServer
    from .ai_interface import verify_ollama_setup

    # Check Ollama status
    ollama_ok, ollama_msg = verify_ollama_setup()
    if ollama_ok:
        logging.info("LLM: %s", ollama_msg)
    else:
        logging.warning("LLM: %s (honeypot will use fallback responses)", ollama_msg)

    # Create and start server
    server = HoneypotServer(host=host, port=port)

    print(f"\nSSH Honeypot listening on {host}:{port}")
    print(
        f"Connect with: ssh root@{host if host != '0.0.0.0' else '127.0.0.1'} -p {port}"
    )
    print("Press Ctrl+C to stop\n")

    try:
        server.run()
    except KeyboardInterrupt:
        logging.info("Received interrupt signal, shutting down...")
        server.shutdown()


def main() -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="miragepot",
        description="MiragePot - AI-Driven Adaptive SSH Honeypot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    miragepot                          Start honeypot on default port 2222
    miragepot --port 22                Start on standard SSH port (requires root)
    miragepot --dashboard              Start with web dashboard
    miragepot --log-level DEBUG        Enable debug logging

Environment variables:
    MIRAGEPOT_SSH_HOST       SSH bind address
    MIRAGEPOT_SSH_PORT       SSH port
    MIRAGEPOT_LLM_MODEL      Ollama model name (default: phi3)
    MIRAGEPOT_LOG_LEVEL      Logging level

For more information, visit: https://github.com/evinbrijesh/MiragePot
        """,
    )

    parser.add_argument(
        "--host",
        default=None,
        help="SSH bind address (default: 0.0.0.0, or MIRAGEPOT_SSH_HOST)",
    )
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=None,
        help="SSH port (default: 2222, or MIRAGEPOT_SSH_PORT)",
    )
    parser.add_argument(
        "--dashboard",
        "-d",
        action="store_true",
        help="Also start the Streamlit dashboard",
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=None,
        help="Dashboard port (default: 8501, or MIRAGEPOT_DASHBOARD_PORT)",
    )
    parser.add_argument(
        "--log-level",
        "-l",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level (default: INFO, or MIRAGEPOT_LOG_LEVEL)",
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"MiragePot {__version__}",
    )

    args = parser.parse_args()

    # Load config (picks up environment variables)
    config = get_config()

    # CLI args override environment/config
    host = args.host or config.ssh.host
    port = args.port or config.ssh.port
    dashboard_port = args.dashboard_port or config.dashboard.port
    log_level = args.log_level or config.logging.level

    # Setup logging
    setup_logging(log_level)

    # Print banner
    print_banner()

    # Start dashboard if requested
    dashboard_proc = None
    if args.dashboard:
        dashboard_proc = start_dashboard(dashboard_port)

    # Setup signal handlers
    def signal_handler(sig, frame):
        print("\n")
        logging.info("Shutting down MiragePot...")
        if dashboard_proc and dashboard_proc.poll() is None:
            dashboard_proc.terminate()
            try:
                dashboard_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                dashboard_proc.kill()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Run the server (blocks until interrupted)
        run_server(host, port)
    finally:
        # Cleanup dashboard if running
        if dashboard_proc and dashboard_proc.poll() is None:
            dashboard_proc.terminate()
            try:
                dashboard_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                dashboard_proc.kill()

    return 0


if __name__ == "__main__":
    sys.exit(main())
