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
from typing import Any, Dict, Optional

import paramiko
from colorama import Fore, Style, init as colorama_init

from .command_handler import handle_command, init_session_state
from .defense_module import calculate_threat_score, apply_tarpit
from .ssh_interface import (
    SSHServer,
    create_listening_socket,
    get_or_create_host_key,
    extract_fingerprint_from_transport,
)
from .tty_handler import TTYHandler, handle_clear_command, ANSI_CLEAR_SCREEN
from .ai_interface import verify_ollama_setup
from .config import get_config
from .ttp_detector import get_attack_summary
from .honeytokens import get_honeytokens_summary

# Initialize color output for local console
colorama_init(autoreset=True)

# Basic logging configuration for server events (not session commands)
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

# Directories for logs
config = get_config()
LOG_DIR = config.logs_dir
LOG_DIR.mkdir(parents=True, exist_ok=True)

SSH_PORT = 2222


def _new_session_log(attacker_ip: str, attacker_port: int) -> Dict[str, Any]:
    """Create initial structure for a session log dict."""
    session_id = f"session_{int(time.time() * 1000)}_{threading.get_ident()}"
    return {
        "session_id": session_id,
        "attacker_ip": attacker_ip,
        "attacker_port": attacker_port,
        "login_time": datetime.utcnow().isoformat() + "Z",
        "logout_time": None,
        "duration_seconds": None,
        "ssh_fingerprint": None,  # Will be populated after negotiation
        "auth": None,  # Will be populated with auth attempts
        "pty_info": None,  # Terminal info if PTY requested
        "commands": [],
        "download_attempts": [],  # Captured file download attempts
        "ttp_summary": None,  # TTP analysis summary
        "honeytokens_summary": None,  # Honeytoken access tracking
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

    session_log = _new_session_log(attacker_ip, attacker_port)
    session_state = init_session_state()
    start_time = time.time()

    transport = paramiko.Transport(client)
    transport.add_server_key(host_key)
    server = SSHServer()

    try:
        transport.start_server(server=server)
    except paramiko.SSHException as exc:
        LOGGER.error("SSH negotiation failed with %s: %s", attacker_ip, exc)
        transport.close()
        return

    # Capture SSH fingerprint after successful negotiation
    try:
        ssh_fingerprint = extract_fingerprint_from_transport(transport)
        session_log["ssh_fingerprint"] = ssh_fingerprint.to_dict()
        LOGGER.info(
            "Client %s version: %s",
            attacker_ip,
            ssh_fingerprint.client_version or "unknown",
        )
    except Exception as e:
        LOGGER.debug("Could not extract SSH fingerprint: %s", e)

    chan = transport.accept(20)
    if chan is None:
        LOGGER.warning("No channel for %s", attacker_ip)
        transport.close()
        return

    # Capture auth and PTY metadata from server interface
    session_log["auth"] = server.get_auth_summary()
    session_log["pty_info"] = server.pty_info

    # Log credentials for forensics
    if server.successful_username:
        LOGGER.info(
            "Attacker %s logged in as '%s' with password '%s'",
            attacker_ip,
            server.successful_username,
            server.successful_password[:20] + "..."
            if server.successful_password and len(server.successful_password) > 20
            else server.successful_password,
        )

    chan.settimeout(300)

    # Initialize TTY handler for realistic terminal emulation
    tty_handler = TTYHandler(
        session_state=session_state,
        hostname="miragepot",
        username=server.successful_username or "root",
    )

    # Send fake banner and initial prompt (use CRLF for terminals)
    chan.send(b"Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-86-generic x86_64)\r\n")
    chan.send(b"Last login: just now from unknown\r\n")
    chan.send(tty_handler.get_prompt().encode("utf-8"))

    try:
        while True:
            data = chan.recv(1024)
            if not data:
                break

            for byte in data:
                # Process byte through TTY handler
                command, output, needs_prompt = tty_handler.process_byte(byte)

                # Send any output
                if output:
                    chan.send(output.encode("utf-8"))

                # If we need to reprint prompt (after Ctrl+C, Ctrl+L, tab with multiple matches)
                if needs_prompt:
                    prompt = tty_handler.get_prompt()
                    chan.send(prompt.encode("utf-8"))
                    # Also reprint current buffer if any
                    if tty_handler.buffer:
                        chan.send(tty_handler.buffer.encode("utf-8"))

                # If command is ready to execute
                if command is not None:
                    # Handle 'clear' command specially
                    if command.strip() == "clear":
                        chan.send(ANSI_CLEAR_SCREEN.encode("utf-8"))
                        session_log["commands"].append(
                            {
                                "timestamp": datetime.utcnow().isoformat() + "Z",
                                "command": command,
                                "response": "[screen cleared]",
                                "threat_score": 0,
                                "delay_applied": 0,
                            }
                        )
                        chan.send(tty_handler.get_prompt().encode("utf-8"))
                        continue

                    # Empty command (just pressed Enter)
                    if not command:
                        chan.send(tty_handler.get_prompt().encode("utf-8"))
                        continue

                    # Active defense: threat scoring and tarpit
                    score = calculate_threat_score(command)
                    delay_applied = apply_tarpit(score)

                    try:
                        response = handle_command(command, session_state)
                    except Exception as cmd_exc:  # pragma: no cover - defensive
                        LOGGER.error(
                            "Command handling error for %s: %s", attacker_ip, cmd_exc
                        )
                        response = f"bash: internal error while handling '{command}'\n"

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

                    try:
                        if response:
                            # Ensure responses end with a newline so prompts are aligned
                            if not response.endswith("\n") and not response.endswith(
                                "\r"
                            ):
                                response = response + "\r\n"
                            else:
                                # Normalize LF to CRLF for SSH terminals
                                response = response.replace("\n", "\r\n")
                            chan.send(response.encode("utf-8"))

                        chan.send(tty_handler.get_prompt().encode("utf-8"))
                    except Exception as send_exc:  # pragma: no cover - defensive
                        LOGGER.error(
                            "Error sending response to %s: %s", attacker_ip, send_exc
                        )
                        continue

    except EOFError:
        LOGGER.info("Session closed by client %s", attacker_ip)
    except Exception as exc:  # pragma: no cover - defensive
        LOGGER.error("Error in session with %s: %s", attacker_ip, exc)
    finally:
        # Record session end time and duration
        end_time = time.time()
        session_log["logout_time"] = datetime.utcnow().isoformat() + "Z"
        session_log["duration_seconds"] = round(end_time - start_time, 2)

        # Copy download attempts from session state to session log
        session_log["download_attempts"] = session_state.get("download_attempts", [])

        # Generate TTP analysis summary
        ttp_state = session_state.get("ttp_state")
        if ttp_state:
            session_log["ttp_summary"] = get_attack_summary(ttp_state)
            risk_level = session_log["ttp_summary"].get("risk_level", "low")
            if risk_level in ("high", "critical"):
                LOGGER.warning(
                    "HIGH RISK SESSION from %s - risk: %s, stage: %s",
                    attacker_ip,
                    risk_level,
                    session_log["ttp_summary"].get("current_stage", "unknown"),
                )

        # Generate honeytokens summary
        honeytokens = session_state.get("honeytokens")
        if honeytokens:
            session_log["honeytokens_summary"] = get_honeytokens_summary(honeytokens)
            if session_log["honeytokens_summary"].get("high_risk"):
                LOGGER.warning(
                    "HONEYTOKEN EXFILTRATION DETECTED from %s - %d tokens accessed, %d exfil attempts",
                    attacker_ip,
                    session_log["honeytokens_summary"].get("unique_tokens_accessed", 0),
                    session_log["honeytokens_summary"].get("exfiltration_attempts", 0),
                )

        _save_session_log(session_log)
        try:
            chan.close()
        except Exception:
            pass
        transport.close()
        LOGGER.info(
            "Session with %s ended (duration: %.1fs, commands: %d)",
            attacker_ip,
            session_log["duration_seconds"],
            len(session_log["commands"]),
        )


def start_server(host: str = "0.0.0.0", port: int = SSH_PORT) -> None:
    """Start the MiragePot SSH honeypot server."""
    host_key = get_or_create_host_key()

    # Check Ollama setup and warn if not ready
    ollama_ok, ollama_msg = verify_ollama_setup()
    if ollama_ok:
        print(Fore.GREEN + f"[+] {ollama_msg}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + f"[!] {ollama_msg}" + Style.RESET_ALL)
        print(
            Fore.YELLOW
            + "[!] LLM responses will use fallback mode (limited commands)"
            + Style.RESET_ALL
        )

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


class HoneypotServer:
    """Object-oriented wrapper for the SSH honeypot server.

    Provides a cleaner interface for starting/stopping the server,
    especially useful for the CLI entry point.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = SSH_PORT):
        """Initialize the honeypot server.

        Args:
            host: Address to bind to (default: 0.0.0.0)
            port: Port to listen on (default: 2222)
        """
        self.host = host
        self.port = port
        self._socket: Optional[socket.socket] = None
        self._running = False
        self._host_key = get_or_create_host_key()
        self._threads: list = []

    def run(self) -> None:
        """Start the honeypot server and block until stopped."""
        try:
            self._socket = create_listening_socket(self.host, self.port)
        except OSError as exc:
            LOGGER.error("Failed to bind to %s:%d - %s", self.host, self.port, exc)
            raise

        self._running = True
        LOGGER.info("MiragePot listening on %s:%d", self.host, self.port)

        try:
            while self._running:
                try:
                    self._socket.settimeout(1.0)  # Allow periodic check of _running
                    client, addr = self._socket.accept()
                    thread = threading.Thread(
                        target=_handle_client,
                        args=(client, addr, self._host_key),
                        daemon=True,
                    )
                    thread.start()
                    self._threads.append(thread)
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            LOGGER.info("Received interrupt signal")
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        """Stop the honeypot server gracefully."""
        self._running = False
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
        LOGGER.info("MiragePot server stopped")


if __name__ == "__main__":
    start_server()
