#!/usr/bin/env python
"""MiragePot CLI entry point.

Run the honeypot with: python -m miragepot
Or after installation: miragepot

Usage:
    miragepot [OPTIONS]                    Start the honeypot server
    miragepot sessions list                List all captured sessions
    miragepot sessions show <id>           Show session details
    miragepot sessions export <id>         Export session to file
    miragepot sessions replay <id>         Replay session in terminal

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
from pathlib import Path
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


# =============================================================================
# Sessions CLI Commands
# =============================================================================


def cmd_sessions_list(args: argparse.Namespace) -> int:
    """List all captured sessions."""
    from .session_export import list_sessions

    config = get_config()
    logs_dir = config.logs_dir

    if not logs_dir.exists():
        print(f"No logs directory found at: {logs_dir}")
        return 1

    sessions = list_sessions(logs_dir)

    if not sessions:
        print("No sessions found.")
        return 0

    # Print header
    print()
    print(
        f"{'SESSION ID':<45} {'IP ADDRESS':<18} {'COMMANDS':<10} {'DURATION':<12} {'RISK':<10}"
    )
    print("-" * 95)

    for s in sessions:
        session_id = s.get("session_id", "unknown")[:44]
        ip = s.get("attacker_ip", "unknown")
        cmd_count = s.get("command_count", 0)
        duration = s.get("duration_seconds", 0) or 0
        risk = s.get("risk_level", "unknown")

        # Color code risk level
        risk_display = risk.upper()

        print(
            f"{session_id:<45} {ip:<18} {cmd_count:<10} {duration:<12.1f} {risk_display:<10}"
        )

    print()
    print(f"Total: {len(sessions)} session(s)")
    print()
    return 0


def cmd_sessions_show(args: argparse.Namespace) -> int:
    """Show details of a specific session."""
    from .session_export import load_session, export_as_text

    config = get_config()
    logs_dir = config.logs_dir

    session_id = args.session_id

    # Find the session file
    session_path = _find_session_file(logs_dir, session_id)

    if session_path is None:
        print(f"Session not found: {session_id}")
        print(f"Use 'miragepot sessions list' to see available sessions.")
        return 1

    try:
        session = load_session(session_path)
        print(export_as_text(session, include_metadata=True))
        return 0
    except Exception as e:
        print(f"Error loading session: {e}")
        return 1


def cmd_sessions_export(args: argparse.Namespace) -> int:
    """Export a session to a file."""
    from .session_export import export_session

    config = get_config()
    logs_dir = config.logs_dir

    session_id = args.session_id
    format_type = args.format
    output_path = args.output

    # Find the session file
    session_path = _find_session_file(logs_dir, session_id)

    if session_path is None:
        print(f"Session not found: {session_id}")
        print(f"Use 'miragepot sessions list' to see available sessions.")
        return 1

    # Determine output path
    if output_path is None:
        ext = {"text": "txt", "json": "json", "html": "html"}[format_type]
        output_path = Path(f"{session_id}.{ext}")
    else:
        output_path = Path(output_path)

    try:
        export_session(session_path, output_path, format=format_type)
        print(f"Session exported to: {output_path}")

        if format_type == "html":
            print(f"Open in browser: file://{output_path.absolute()}")

        return 0
    except Exception as e:
        print(f"Error exporting session: {e}")
        return 1


def cmd_sessions_replay(args: argparse.Namespace) -> int:
    """Replay a session in the terminal."""
    from .session_export import load_session, replay_session

    config = get_config()
    logs_dir = config.logs_dir

    session_id = args.session_id
    speed = args.speed

    # Find the session file
    session_path = _find_session_file(logs_dir, session_id)

    if session_path is None:
        print(f"Session not found: {session_id}")
        print(f"Use 'miragepot sessions list' to see available sessions.")
        return 1

    try:
        session = load_session(session_path)

        print(f"\nReplaying session: {session_id}")
        print(f"Speed: {speed}x (press Ctrl+C to stop)\n")
        time.sleep(1)

        def output_callback(text: str) -> None:
            print(text, end="", flush=True)

        replay_session(
            session, output_callback, speed=speed, simulate_typing=not args.no_typing
        )

        return 0
    except KeyboardInterrupt:
        print("\n\nReplay stopped.")
        return 0
    except Exception as e:
        print(f"Error replaying session: {e}")
        return 1


def _find_session_file(logs_dir: Path, session_id: str) -> Optional[Path]:
    """Find a session file by ID (exact or partial match)."""
    if not logs_dir.exists():
        return None

    # Try exact match first
    exact_path = logs_dir / f"{session_id}.json"
    if exact_path.exists():
        return exact_path

    # Try partial match
    matches = list(logs_dir.glob(f"*{session_id}*.json"))

    if len(matches) == 1:
        return matches[0]
    elif len(matches) > 1:
        print(f"Multiple sessions match '{session_id}':")
        for m in matches[:10]:
            print(f"  - {m.stem}")
        if len(matches) > 10:
            print(f"  ... and {len(matches) - 10} more")
        print("Please be more specific.")
        return None

    return None


# =============================================================================
# Main CLI
# =============================================================================


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
    miragepot sessions list            List all captured sessions
    miragepot sessions show <id>       Show session transcript
    miragepot sessions export <id>     Export session to file
    miragepot sessions replay <id>     Replay session in terminal

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

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # sessions command
    sessions_parser = subparsers.add_parser("sessions", help="Manage captured sessions")
    sessions_subparsers = sessions_parser.add_subparsers(
        dest="sessions_command", help="Session commands"
    )

    # sessions list
    list_parser = sessions_subparsers.add_parser(
        "list", help="List all captured sessions"
    )
    list_parser.set_defaults(func=cmd_sessions_list)

    # sessions show
    show_parser = sessions_subparsers.add_parser(
        "show", help="Show session details/transcript"
    )
    show_parser.add_argument("session_id", help="Session ID (full or partial)")
    show_parser.set_defaults(func=cmd_sessions_show)

    # sessions export
    export_parser = sessions_subparsers.add_parser(
        "export", help="Export session to file"
    )
    export_parser.add_argument("session_id", help="Session ID (full or partial)")
    export_parser.add_argument(
        "--format",
        "-f",
        choices=["text", "json", "html"],
        default="text",
        help="Export format (default: text)",
    )
    export_parser.add_argument(
        "--output", "-o", help="Output file path (default: <session_id>.<ext>)"
    )
    export_parser.set_defaults(func=cmd_sessions_export)

    # sessions replay
    replay_parser = sessions_subparsers.add_parser(
        "replay", help="Replay session in terminal"
    )
    replay_parser.add_argument("session_id", help="Session ID (full or partial)")
    replay_parser.add_argument(
        "--speed",
        "-s",
        type=float,
        default=1.0,
        help="Playback speed multiplier (default: 1.0, use 2.0 for 2x speed)",
    )
    replay_parser.add_argument(
        "--no-typing",
        action="store_true",
        help="Don't simulate typing (show commands instantly)",
    )
    replay_parser.set_defaults(func=cmd_sessions_replay)

    args = parser.parse_args()

    # Handle subcommands
    if args.command == "sessions":
        if args.sessions_command is None:
            sessions_parser.print_help()
            return 0
        return args.func(args)

    # Default: run the honeypot server
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
