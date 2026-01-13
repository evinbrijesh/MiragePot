"""Main SSH honeypot server for MiragePot.

This module wires together:
- SSH transport (Paramiko)
- Command handling (fake shell + AI)
- Active defense (threat scoring + tarpit)
- Per-session JSON logging for forensics and dashboard use.
"""

from __future__ import annotations

import json
import logging
import socket
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import paramiko
from colorama import Fore, Style, init as colorama_init

from .command_handler import handle_command, init_session_state
from .defense_module import calculate_threat_score, apply_tarpit
from .ssh_interface import SSHServer, create_listening_socket, get_or_create_host_key

# Initialize color output for local console
colorama_init(autoreset=True)

# Basic logging configuration for server events (not session commands)
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

# Directories for logs
BASE_DIR = Path(__file__).resolve().parents[1]
LOG_DIR = BASE_DIR / "data" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

SSH_PORT = 2222
PROMPT = "root@miragepot:~# "


def _new_session_log(attacker_ip: str) -> Dict[str, Any]:
    """Create initial structure for a session log dict."""
    session_id = f"session_{int(time.time() * 1000)}_{threading.get_ident()}"
    return {
        "session_id": session_id,
        "attacker_ip": attacker_ip,
        "login_time": datetime.utcnow().isoformat() + "Z",
        "commands": [],
    }


def _save_session_log(session_log: Dict[str, Any]) -> None:
    """Persist a session log to JSON file."""
    session_id = session_log.get("session_id", f"session_{int(time.time())}")
    path = LOG_DIR / f"{session_id}.json"
    try:
        path.write_text(json.dumps(session_log, indent=2), encoding="utf-8")
    except Exception as exc:  # pragma: no cover
        LOGGER.error("Failed to write session log %s: %s", session_id, exc)


def _handle_client(client: socket.socket, addr, host_key: paramiko.PKey) -> None:
    attacker_ip, attacker_port = addr[0], addr[1]
    LOGGER.info("New connection from %s:%s", attacker_ip, attacker_port)

    session_log = _new_session_log(attacker_ip)
    session_state = init_session_state()

    transport = paramiko.Transport(client)
    transport.add_server_key(host_key)
    server = SSHServer()

    try:
        transport.start_server(server=server)
    except paramiko.SSHException as exc:
        LOGGER.error("SSH negotiation failed with %s: %s", attacker_ip, exc)
        transport.close()
        return

    chan = transport.accept(20)
    if chan is None:
        LOGGER.warning("No channel for %s", attacker_ip)
        transport.close()
        return

    chan.settimeout(300)

    # Send fake banner
    chan.send("Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-86-generic x86_64)\n")
    chan.send("Last login: just now from unknown\n")
    chan.send(PROMPT)

    buffer = ""
    try:
        while True:
            data = chan.recv(1024)
            if not data:
                break
            try:
                text = data.decode("utf-8", errors="ignore")
            except Exception:
                continue

            buffer += text

            while "\n" in buffer or "\r" in buffer:
                # Split on first newline or carriage return
                newline_pos = min(
                    pos
                    for pos in [
                        buffer.find("\n") if "\n" in buffer else len(buffer),
                        buffer.find("\r") if "\r" in buffer else len(buffer),
                    ]
                )
                line, buffer = buffer[:newline_pos], buffer[newline_pos + 1 :]
                command = line.strip()

                if not command:
                    chan.send(PROMPT)
                    continue

                # Active defense: threat scoring and tarpit
                score = calculate_threat_score(command)
                delay_applied = apply_tarpit(score)

                response = handle_command(command, session_state)

                # Special token indicating the session should close
                if response == "__MIRAGEPOT_EXIT__":
                    session_log["commands"].append(
                        {
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "command": command,
                            "response": "",
                            "threat_score": score,
                            "delay_applied": delay_applied,
                        }
                    )
                    chan.send("logout\n")
                    chan.close()
                    raise EOFError

                # Log this command
                session_log["commands"].append(
                    {
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "command": command,
                        "response": response,
                        "threat_score": score,
                        "delay_applied": delay_applied,
                    }
                )

                if response:
                    chan.send(response)
                chan.send(PROMPT)

    except EOFError:
        LOGGER.info("Session closed by client %s", attacker_ip)
    except Exception as exc:  # pragma: no cover - defensive
        LOGGER.error("Error in session with %s: %s", attacker_ip, exc)
    finally:
        _save_session_log(session_log)
        try:
            chan.close()
        except Exception:
            pass
        transport.close()
        LOGGER.info("Session with %s ended", attacker_ip)


def start_server(host: str = "0.0.0.0", port: int = SSH_PORT) -> None:
    """Start the MiragePot SSH honeypot server."""
    host_key = get_or_create_host_key()

    try:
        sock = create_listening_socket(host, port)
    except OSError as exc:
        LOGGER.error("Failed to bind to %s:%d - %s", host, port, exc)
        return

    print(Fore.GREEN + f"[+] MiragePot listening on {host}:{port}" + Style.RESET_ALL)

    try:
        while True:
            client, addr = sock.accept()
            thread = threading.Thread(
                target=_handle_client,
                args=(client, addr, host_key),
                daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:
        print("\n" + Fore.YELLOW + "[!] Shutting down MiragePot..." + Style.RESET_ALL)
    finally:
        sock.close()


if __name__ == "__main__":
    start_server()
