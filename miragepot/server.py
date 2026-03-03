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
import os
import random
import re
import secrets
import socket
import tempfile
import threading
import time
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

import paramiko
from colorama import Fore, Style, init as colorama_init

from .command_handler import handle_command, init_session_state, EXIT_SENTINEL
from .defense_module import calculate_threat_score, apply_tarpit
from .ssh_interface import (
    SSHServer,
    create_listening_socket,
    get_or_create_host_key,
    get_all_host_keys,
    extract_fingerprint_from_transport,
)
from .tty_handler import TTYHandler, handle_clear_command, ANSI_CLEAR_SCREEN
from .ai_interface import verify_ollama_setup, ensure_ollama_running
from .config import get_config
from .ttp_detector import get_attack_summary
from .honeytokens import get_honeytokens_summary
from .rate_limiter import get_rate_limiter
from .metrics import get_metrics_collector, start_metrics_server

# Initialize color output for local console
colorama_init(autoreset=True)

# Basic logging configuration — level is read from config/env (MIRAGEPOT_LOG_LEVEL)
_log_level_str = get_config().logging.level.upper()
_log_level = getattr(logging, _log_level_str, logging.INFO)
logging.basicConfig(
    level=_log_level,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
LOGGER = logging.getLogger(__name__)

# Suppress Paramiko's noisy transport-level debug output unless explicitly in DEBUG mode
paramiko_logger = logging.getLogger("paramiko")
paramiko_logger.setLevel(
    logging.WARNING if _log_level > logging.DEBUG else logging.DEBUG
)

# Directories for logs
config = get_config()
LOG_DIR = config.logs_dir
LOG_DIR.mkdir(parents=True, exist_ok=True)

SSH_PORT = 2222

# Live sessions tracking for real-time dashboard
LIVE_SESSIONS_FILE = LOG_DIR / "live_sessions.json"
_live_sessions_lock = threading.Lock()

# Artificial minimum response delay (ms) for cache/builtin paths — reduces timing
# side-channel that lets attackers distinguish fast (cache) vs slow (LLM) responses.
# P3-13: All responses get at least MIN_RESPONSE_DELAY_MS ms of artificial latency.
_MIN_RESPONSE_DELAY_S = 0.05  # 50 ms baseline
_MAX_EXTRA_DELAY_S = 0.15  # up to 150 ms random jitter → total 50–200 ms

# Strip ANSI escape sequences and ASCII control characters for safe logging.
# P1-02: Attacker-controlled strings (command, username, IP) may contain \n, \r, or
# ANSI codes that would spoof log entries in aggregators like Loki/ELK.
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]|(?:\x1b\[[0-?]*[ -/]*[@-~])")


def _safe_log(s: str, max_len: int = 200) -> str:
    """Strip control/ANSI characters from attacker-controlled strings for logging."""
    cleaned = _CTRL_RE.sub("", s)
    return cleaned[:max_len] if len(cleaned) > max_len else cleaned


def _rotate_logs(log_dir: Path, max_age_days: int = 30, max_files: int = 10000) -> None:
    """P5-03: Delete session log files older than max_age_days, or if there are
    more than max_files session logs (keeps the most recent ones).

    Called once at server startup to prevent unbounded disk growth under sustained
    botnet attacks.  Only deletes session_*.json files, not live_sessions.json.
    """
    try:
        session_files = sorted(
            log_dir.glob("session_*.json"),
            key=lambda p: p.stat().st_mtime,
        )

        cutoff = datetime.utcnow() - timedelta(days=max_age_days)
        deleted = 0

        # Delete by age first
        for f in session_files:
            try:
                mtime = datetime.utcfromtimestamp(f.stat().st_mtime)
                if mtime < cutoff:
                    f.unlink()
                    deleted += 1
            except Exception:
                pass

        # Then enforce file count cap on the remainder
        remaining = sorted(
            log_dir.glob("session_*.json"),
            key=lambda p: p.stat().st_mtime,
        )
        if len(remaining) > max_files:
            to_delete = remaining[: len(remaining) - max_files]
            for f in to_delete:
                try:
                    f.unlink()
                    deleted += 1
                except Exception:
                    pass

        if deleted:
            LOGGER.info("Log rotation: deleted %d old session log(s)", deleted)
    except Exception as exc:
        LOGGER.warning("Log rotation failed: %s", exc)


def _update_live_sessions(session_log: Dict[str, Any], remove: bool = False) -> None:
    """Update the live sessions file for real-time dashboard streaming.

    Args:
        session_log: Current session data
        remove: If True, remove this session from live tracking

    P1-03: Uses atomic write (write to temp file + os.rename) to prevent the
    dashboard from reading a partially-written file and getting a JSON parse error.
    """
    try:
        with _live_sessions_lock:
            # Load existing live sessions
            live_data: Dict[str, Any] = {"sessions": [], "last_updated": ""}
            if LIVE_SESSIONS_FILE.exists():
                try:
                    live_data = json.loads(
                        LIVE_SESSIONS_FILE.read_text(encoding="utf-8")
                    )
                except Exception as parse_exc:
                    LOGGER.warning(
                        "live_sessions.json is corrupt or unreadable, resetting: %s",
                        parse_exc,
                    )

            sessions: List[Dict[str, Any]] = cast(
                List[Dict[str, Any]], live_data.get("sessions", [])
            )
            session_id = cast(str, session_log.get("session_id", ""))

            # Remove existing entry for this session
            sessions = [s for s in sessions if s.get("session_id") != session_id]

            if not remove:
                # Add/update this session with recent commands only
                live_entry = {
                    "session_id": session_id,
                    "attacker_ip": session_log.get("attacker_ip", ""),
                    "login_time": session_log.get("login_time", ""),
                    "last_activity": datetime.utcnow().isoformat() + "Z",
                    "commands": session_log.get("commands", [])[
                        -20:
                    ],  # Last 20 commands
                    "command_count": len(session_log.get("commands", [])),
                }
                sessions.append(live_entry)

            # Keep only sessions from last 10 minutes
            cutoff = datetime.utcnow().isoformat() + "Z"
            live_data = {
                "sessions": sessions[-50:],  # Max 50 live sessions
                "last_updated": cutoff,
            }

            # P1-03: Atomic write — write to a temp file in the same directory then
            # rename() to replace the target.  os.rename() is atomic on POSIX.
            payload = json.dumps(live_data, indent=2).encode("utf-8")
            tmp_fd, tmp_path = tempfile.mkstemp(
                dir=LIVE_SESSIONS_FILE.parent, suffix=".tmp"
            )
            try:
                os.write(tmp_fd, payload)
                os.fsync(tmp_fd)
                os.close(tmp_fd)
                os.rename(tmp_path, LIVE_SESSIONS_FILE)
            except Exception:
                os.close(tmp_fd)
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
                raise
    except Exception as exc:
        LOGGER.debug("Failed to update live sessions: %s", exc)


def _new_session_log(attacker_ip: str, attacker_port: int) -> Dict[str, Any]:
    """Create initial structure for a session log dict."""
    # P5-09: Use cryptographically random session IDs instead of timestamp+thread ID,
    # which is predictable and could allow an attacker to enumerate session log files.
    session_id = f"session_{secrets.token_hex(16)}"
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


def _append_command(session_log: Dict[str, Any], entry: Dict[str, Any]) -> None:
    """P5-11: Append a command entry, capping the list at 1000 to prevent unbounded
    memory growth during long-running or automated attack sessions."""
    cmds: List[Dict[str, Any]] = session_log["commands"]
    if len(cmds) >= 1000:
        cmds.pop(0)
    cmds.append(entry)


def _handle_client(
    client: socket.socket, addr, host_key: paramiko.PKey, extra_keys: list | None = None
) -> None:
    attacker_ip, attacker_port = addr[0], addr[1]
    metrics = get_metrics_collector()

    LOGGER.debug(
        "=== _handle_client() ENTRY === Connection from %s:%s",
        attacker_ip,
        attacker_port,
    )

    # Track active connection
    metrics.increment_active_connections()

    try:
        # Configure client socket for better compatibility
        client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # Set a reasonable timeout for the socket operations
        client.settimeout(60)  # 60 second timeout for SSH handshake
        LOGGER.debug("Configured client socket with keepalive and 60s timeout")
    except Exception as e:
        LOGGER.warning("Failed to configure client socket: %s", e)

    # P5-05: Atomically check + register in one lock acquisition to eliminate
    # the TOCTOU race between can_accept_connection and register_connection.
    rate_limiter = get_rate_limiter()
    can_accept, reason = rate_limiter.check_and_register(attacker_ip)
    if not can_accept:
        LOGGER.warning(
            "Connection from %s:%s rejected: %s", attacker_ip, attacker_port, reason
        )
        metrics.record_connection_attempt("rejected_ratelimit")
        metrics.decrement_active_connections()
        try:
            client.close()
        except Exception as close_exc:
            LOGGER.debug("Error closing rejected client socket: %s", close_exc)
        return

    # Connection accepted and already registered by check_and_register
    metrics.record_connection_attempt("success")
    metrics.record_attacker_ip(attacker_ip)

    LOGGER.debug(
        "Rate limiter: ACCEPTED connection from %s:%s", attacker_ip, attacker_port
    )

    LOGGER.info("New connection from %s:%s", _safe_log(attacker_ip), attacker_port)

    session_log = _new_session_log(attacker_ip, attacker_port)
    session_state = init_session_state()
    start_time = time.time()

    LOGGER.debug("Creating Paramiko transport for %s:%s", attacker_ip, attacker_port)
    transport = paramiko.Transport(client)

    # P2-01: Override Paramiko's default banner to match the configured OpenSSH version.
    # Without this, Paramiko sends "SSH-2.0-paramiko_X.Y.Z" which instantly fingerprints
    # the honeypot to any scanner.
    transport.local_version = config.ssh.banner

    # Configure transport for better compatibility with various SSH clients (including Windows)
    transport.set_keepalive(30)  # Send keepalive every 30 seconds

    # P2-02 & P2-10: Configure algorithm list to match OpenSSH 8.2 and disable weak/Paramiko-only algorithms.
    # Paramiko's defaults include 3des-cbc, hmac-md5, and non-standard KEX order which differ from OpenSSH.
    security_opts = transport.get_security_options()
    LOGGER.debug("Default key exchange algorithms: %s", security_opts.kex)
    LOGGER.debug("Default ciphers: %s", security_opts.ciphers)
    # KEX order matching OpenSSH 8.2
    _openssh_kex = [
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group18-sha512",
        "diffie-hellman-group14-sha256",
    ]
    # Cipher order matching OpenSSH 8.2 (chacha20 first, no 3des)
    _openssh_ciphers = [
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
    ]
    # MAC order matching OpenSSH 8.2 (no hmac-md5)
    _openssh_macs = [
        "hmac-sha2-256",
        "hmac-sha2-512",
        "hmac-sha1",
    ]
    try:
        # Filter to only algorithms Paramiko supports
        available_kex = list(security_opts.kex)
        available_ciphers = list(security_opts.ciphers)
        available_macs = list(security_opts.digests)
        filtered_kex = [k for k in _openssh_kex if k in available_kex]
        filtered_ciphers = [c for c in _openssh_ciphers if c in available_ciphers]
        filtered_macs = [m for m in _openssh_macs if m in available_macs]
        if filtered_kex:
            security_opts.kex = filtered_kex
        if filtered_ciphers:
            security_opts.ciphers = filtered_ciphers
        if filtered_macs:
            security_opts.digests = filtered_macs
        LOGGER.debug("Applied OpenSSH-compatible algorithm list")
    except Exception as alg_exc:
        LOGGER.debug("Could not apply algorithm preferences: %s", alg_exc)

    transport.add_server_key(host_key)
    # P2-07: Register all available key types so the server can negotiate
    # the algorithm preferred by the connecting client (Ed25519, ECDSA, RSA).
    for key in extra_keys or []:
        try:
            transport.add_server_key(key)
        except Exception:
            pass
    LOGGER.debug("Added host key(s) to transport for %s:%s", attacker_ip, attacker_port)

    server = SSHServer()

    try:
        LOGGER.debug(
            "Starting SSH server negotiation with %s:%s", attacker_ip, attacker_port
        )
        transport.start_server(server=server)
        LOGGER.debug(
            "SSH server negotiation SUCCESSFUL with %s:%s", attacker_ip, attacker_port
        )
    except paramiko.SSHException as exc:
        LOGGER.error(
            "SSH negotiation FAILED with %s:%s - Exception: %s",
            attacker_ip,
            attacker_port,
            exc,
        )
        LOGGER.error("SSH negotiation FAILED - Exception type: %s", type(exc).__name__)
        LOGGER.error(
            "SSH negotiation FAILED - Full traceback:\n%s", traceback.format_exc()
        )
        metrics.record_connection_attempt("failed")
        metrics.decrement_active_connections()
        transport.close()
        rate_limiter.unregister_connection(attacker_ip)
        return
    except Exception as exc:
        LOGGER.error(
            "Unexpected error during SSH negotiation with %s:%s - %s",
            attacker_ip,
            attacker_port,
            exc,
        )
        LOGGER.error("Unexpected error - Full traceback:\n%s", traceback.format_exc())
        metrics.record_connection_attempt("failed")
        metrics.decrement_active_connections()
        transport.close()
        rate_limiter.unregister_connection(attacker_ip)
        return

    # Capture SSH fingerprint after successful negotiation
    try:
        ssh_fingerprint = extract_fingerprint_from_transport(transport)
        session_log["ssh_fingerprint"] = ssh_fingerprint.to_dict()
        LOGGER.info(
            "Client %s version: %s",
            _safe_log(attacker_ip),
            _safe_log(ssh_fingerprint.client_version or "unknown"),
        )
    except Exception as e:
        LOGGER.debug("Could not extract SSH fingerprint: %s", e)

    LOGGER.debug(
        "Waiting for channel from %s:%s (20 second timeout)", attacker_ip, attacker_port
    )
    chan = transport.accept(20)
    if chan is None:
        LOGGER.warning(
            "No channel received from %s:%s within 20 seconds",
            attacker_ip,
            attacker_port,
        )
        metrics.decrement_active_connections()
        transport.close()
        rate_limiter.unregister_connection(attacker_ip)
        return
    LOGGER.debug("Channel accepted from %s:%s", attacker_ip, attacker_port)

    # Capture auth and PTY metadata from server interface
    session_log["auth"] = server.get_auth_summary()
    session_log["pty_info"] = server.pty_info

    # Record authentication metrics for ALL attempts (success + failure)
    for attempt in server.auth_attempts:
        metrics.record_auth_attempt(attempt.username, attempt.credential or "")

    # Record session start
    metrics.record_session_start()

    # Log credentials for forensics (only when explicitly enabled in config)
    security_config = config.security
    if server.successful_username:
        if security_config.log_passwords:
            LOGGER.info(
                "Attacker %s logged in as '%s' with password '%s'",
                _safe_log(attacker_ip),
                _safe_log(server.successful_username),
                _safe_log(
                    server.successful_password[:20] + "..."
                    if server.successful_password
                    and len(server.successful_password) > 20
                    else server.successful_password or ""
                ),
            )

    # P2-11: Use a bounded channel timeout derived from max_session_duration.
    # A static 300-second timeout is independent of the configured session limit;
    # cap at 30 s of idle wait so sessions don't linger past their deadline.
    _chan_timeout = (
        min(security_config.max_session_duration, 30)
        if security_config.max_session_duration > 0
        else 30
    )
    chan.settimeout(_chan_timeout)

    # Store username in session_state so command handlers can access it
    session_state["username"] = server.successful_username or "root"

    # Initialize TTY handler for realistic terminal emulation
    tty_handler = TTYHandler(
        session_state=session_state,
        hostname=config.honeypot.hostname,
        username=server.successful_username or "root",
    )

    # Send fake banner and initial prompt (use CRLF for terminals)
    os_banner = (
        f"Welcome to {config.honeypot.os_name} {config.honeypot.os_version} "
        f"(GNU/Linux {config.honeypot.kernel_version} x86_64)"
    )
    chan.send((os_banner + "\r\n").encode("utf-8"))
    chan.send(b"Last login: just now from unknown\r\n")
    chan.send(tty_handler.get_prompt().encode("utf-8"))

    # Register this session as live for real-time dashboard
    _update_live_sessions(session_log)

    max_session_duration = security_config.max_session_duration

    try:
        while True:
            # Check session timeout
            if max_session_duration > 0:
                elapsed = time.time() - start_time
                if elapsed > max_session_duration:
                    LOGGER.warning(
                        "Session from %s exceeded max duration (%d seconds), terminating",
                        attacker_ip,
                        max_session_duration,
                    )
                    chan.send(b"\r\nSession timeout. Connection closed.\r\n")
                    chan.close()
                    break

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
                        _append_command(
                            session_log,
                            {
                                "timestamp": datetime.utcnow().isoformat() + "Z",
                                "command": command,
                                "response": "[screen cleared]",
                                "threat_score": 0,
                                "delay_applied": 0,
                                "cwd": session_state.get("cwd", "/root"),
                            },
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
                            "Command handling error for %s: %s",
                            _safe_log(attacker_ip),
                            cmd_exc,
                        )
                        # P3-16: Return a generic shell error that doesn't reveal the
                        # honeypot's internal architecture or the sentinel string.
                        _first = command.split()[0] if command.split() else "bash"
                        response = f"bash: {_safe_log(_first)}: command not found\n"

                    # Special token indicating the session should close
                    if response == EXIT_SENTINEL:
                        _append_command(
                            session_log,
                            {
                                "timestamp": datetime.utcnow().isoformat() + "Z",
                                "command": command,
                                "response": "",
                                "threat_score": score,
                                "delay_applied": delay_applied,
                                "cwd": session_state.get("cwd", "/root"),
                            },
                        )
                        chan.send(b"logout\r\n")
                        chan.close()
                        raise EOFError

                    # Log this command
                    _append_command(
                        session_log,
                        {
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "command": command,
                            "response": response,
                            "threat_score": score,
                            "delay_applied": delay_applied,
                            "cwd": session_state.get("cwd", "/root"),
                        },
                    )

                    # Update live sessions for real-time dashboard
                    _update_live_sessions(session_log)

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

                        # P3-13: Uniform minimum response delay for all paths (cache,
                        # builtins, LLM).  Without this, an attacker can distinguish fast
                        # (cached/builtin) from slow (LLM) responses and infer that an
                        # AI backend is in use, or map the cache.
                        time.sleep(
                            _MIN_RESPONSE_DELAY_S
                            + random.uniform(0, _MAX_EXTRA_DELAY_S)
                        )

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
        # Unregister the connection from rate limiter
        rate_limiter = get_rate_limiter()
        rate_limiter.unregister_connection(attacker_ip)

        # Record session end time and duration
        end_time = time.time()
        session_log["logout_time"] = datetime.utcnow().isoformat() + "Z"
        session_log["duration_seconds"] = round(end_time - start_time, 2)

        # Record metrics for session end
        metrics.record_session_end(session_log["duration_seconds"])
        metrics.decrement_active_connections()

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

        # Remove from live sessions tracking
        _update_live_sessions(session_log, remove=True)

        try:
            chan.close()
        except Exception as chan_exc:
            LOGGER.debug("Error closing SSH channel for %s: %s", attacker_ip, chan_exc)
        transport.close()
        LOGGER.info(
            "Session with %s ended (duration: %.1fs, commands: %d)",
            attacker_ip,
            session_log["duration_seconds"],
            len(session_log["commands"]),
        )


def start_server(host: str = "0.0.0.0", port: int = SSH_PORT) -> None:
    """Start the MiragePot SSH honeypot server."""
    # P2-07: Generate/load all key types; use Ed25519 as primary.
    host_key = get_or_create_host_key()
    all_host_keys = get_all_host_keys()

    # P5-03: Rotate old session logs at startup to prevent unbounded disk growth.
    _rotate_logs(LOG_DIR)

    # P4-05: Bind metrics server to loopback only — it has no auth and should not
    # be reachable from the network.
    metrics_port = 9090
    try:
        start_metrics_server(port=metrics_port, host="127.0.0.1")
        print(
            Fore.GREEN
            + f"[+] Prometheus metrics available at http://127.0.0.1:{metrics_port}/metrics"
            + Style.RESET_ALL
        )
    except Exception as e:
        print(
            Fore.YELLOW + f"[!] Failed to start metrics server: {e}" + Style.RESET_ALL
        )

    # Ensure Ollama is running; auto-start it if not
    ollama_ok, ollama_msg = ensure_ollama_running()
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

    # P2-06: Pre-check rate limiter before spawning a thread so we never allocate a
    # thread for a connection that will be immediately rejected.
    _rate_limiter = get_rate_limiter()

    try:
        while True:
            client, addr = sock.accept()
            LOGGER.debug(
                "=== SOCKET ACCEPT === New TCP connection from %s:%s", addr[0], addr[1]
            )
            # P2-06: Check rate limit before creating a thread
            _can_accept, _reason = _rate_limiter.can_accept_connection(addr[0])
            if not _can_accept:
                LOGGER.warning(
                    "Connection from %s:%s rejected before thread: %s",
                    addr[0],
                    addr[1],
                    _reason,
                )
                try:
                    client.close()
                except Exception:
                    pass
                continue
            thread = threading.Thread(
                target=_handle_client,
                args=(client, addr, host_key, all_host_keys),
                daemon=True,
            )
            thread.start()
            LOGGER.debug("Started handler thread for %s:%s", addr[0], addr[1])
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
        # P2-07: Load all key types for multi-algorithm support.
        self._all_host_keys = get_all_host_keys()
        self._threads: list = []

    def run(self) -> None:
        """Start the honeypot server and block until stopped."""
        # P5-03: Rotate old session logs at startup.
        _rotate_logs(LOG_DIR)

        # P4-05: Bind metrics server to loopback only.
        metrics_port = 9090
        try:
            start_metrics_server(port=metrics_port, host="127.0.0.1")
            LOGGER.info(
                "Prometheus metrics available at http://127.0.0.1:%d/metrics",
                metrics_port,
            )
        except Exception as e:
            LOGGER.warning("Failed to start metrics server: %s", e)

        # Ensure Ollama is running; auto-start it if not
        ollama_ok, ollama_msg = ensure_ollama_running()
        if ollama_ok:
            LOGGER.info(ollama_msg)
        else:
            LOGGER.warning(ollama_msg)
            LOGGER.warning("LLM responses will use fallback mode (limited commands)")

        try:
            self._socket = create_listening_socket(self.host, self.port)
        except OSError as exc:
            LOGGER.error("Failed to bind to %s:%d - %s", self.host, self.port, exc)
            raise

        self._running = True
        LOGGER.info("MiragePot listening on %s:%d", self.host, self.port)

        # Start cleanup thread for finished threads
        cleanup_thread = threading.Thread(target=self._cleanup_threads, daemon=True)
        cleanup_thread.start()

        # P2-06: Pre-check rate limiter before spawning a thread.
        _rate_limiter = get_rate_limiter()

        try:
            while self._running:
                try:
                    self._socket.settimeout(1.0)  # Allow periodic check of _running
                    client, addr = self._socket.accept()
                    LOGGER.debug(
                        "=== SOCKET ACCEPT === New TCP connection from %s:%s",
                        addr[0],
                        addr[1],
                    )
                    # P2-06: Check rate limit before creating a thread
                    _can_accept, _reason = _rate_limiter.can_accept_connection(addr[0])
                    if not _can_accept:
                        LOGGER.warning(
                            "Connection from %s:%s rejected before thread: %s",
                            addr[0],
                            addr[1],
                            _reason,
                        )
                        try:
                            client.close()
                        except Exception:
                            pass
                        continue
                    thread = threading.Thread(
                        target=_handle_client,
                        args=(client, addr, self._host_key, self._all_host_keys),
                        daemon=True,
                    )
                    thread.start()
                    LOGGER.debug("Started handler thread for %s:%s", addr[0], addr[1])
                    self._threads.append(thread)
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            LOGGER.info("Received interrupt signal")
        finally:
            self.shutdown()

    def _cleanup_threads(self) -> None:
        """Periodically clean up finished threads to prevent accumulation."""
        while self._running:
            time.sleep(30)  # Cleanup every 30 seconds
            if not self._threads:
                continue

            # Remove finished threads
            active_threads = [t for t in self._threads if t.is_alive()]
            removed = len(self._threads) - len(active_threads)
            self._threads = active_threads

            if removed > 0:
                LOGGER.debug("Cleaned up %d finished thread(s)", removed)

    def shutdown(self) -> None:
        """Stop the honeypot server gracefully."""
        self._running = False
        if self._socket:
            try:
                self._socket.close()
            except Exception as sock_exc:
                LOGGER.debug("Error closing server socket: %s", sock_exc)
            self._socket = None
        LOGGER.info("MiragePot server stopped")


if __name__ == "__main__":
    start_server()
