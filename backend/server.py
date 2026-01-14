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


def _make_json_safe(obj: Any) -> Any:
    """Recursively convert non-JSON-serializable types to safe forms."""
    if isinstance(obj, dict):
        return {k: _make_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, set):
        return sorted(_make_json_safe(v) for v in obj)
    if isinstance(obj, (list, tuple)):
        return [_make_json_safe(v) for v in obj]
    return obj


def _save_session_log(session_log: Dict[str, Any]) -> None:
    """Persist a session log to JSON file."""
    session_id = session_log.get("session_id", f"session_{int(time.time())}")
    path = LOG_DIR / f"{session_id}.json"
    try:
        safe_log = _make_json_safe(session_log)
        path.write_text(json.dumps(safe_log, indent=2), encoding="utf-8")
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

    # Send fake banner and initial prompt (use CRLF for terminals)
    chan.send(b"Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-86-generic x86_64)\r\n")
    chan.send(b"Last login: just now from unknown\r\n")
    chan.send(PROMPT.encode("utf-8"))

    buffer = ""
    try:
        while True:
            data = chan.recv(1024)
            if not data:
                break

            for byte in data:
                c = chr(byte)

                # Ignore non-printable control chars except CR/LF and backspace
                if c not in ("\n", "\r", "\x7f") and ord(c) < 32:
                    continue

                # Handle newline / carriage return: process the current buffer as a command
                if c in ("\n", "\r"):
                    chan.send(b"\r\n")  # move to next line on the client
                    command = buffer.strip()
                    buffer = ""

                    if not command:
                        chan.send(PROMPT.encode("utf-8"))
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
                        chan.send(b"logout\r\n")
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
                        # Ensure responses end with a newline so prompts are aligned
                        if not response.endswith("\n") and not response.endswith("\r"):
                            response = response + "\r\n"
                        else:
                            # Normalize LF to CRLF for SSH terminals
                            response = response.replace("\n", "\r\n")
                        chan.send(response.encode("utf-8"))

                    chan.send(PROMPT.encode("utf-8"))
                    continue

                # Handle backspace (DEL)
                if c == "\x7f":
                    if buffer:
                        buffer = buffer[:-1]
                        # Move cursor back, erase char, move back again
                        chan.send(b"\b \b")
                    continue

                # Regular printable character: add to buffer and echo it
                buffer += c
                chan.send(c.encode("utf-8"))

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
