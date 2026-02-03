"""Paramiko-based SSH server interface for MiragePot.

This module defines the SSHServer class that accepts any username/password
and provides an interactive shell channel over which MiragePot runs its
fake terminal. It also captures SSH client fingerprinting data for forensics.
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import paramiko

LOGGER = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
HOST_KEY_PATH = DATA_DIR / "host.key"


@dataclass
class SSHFingerprint:
    """Captures SSH client fingerprint data for forensic analysis.

    This data helps identify:
    - Specific SSH client software and version
    - Attacker tooling (e.g., libssh, paramiko, putty)
    - Potential bot/automated attack signatures
    """

    client_version: str = ""
    kex_algorithms: List[str] = field(default_factory=list)
    ciphers: List[str] = field(default_factory=list)
    macs: List[str] = field(default_factory=list)
    compression: List[str] = field(default_factory=list)
    host_key_types: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "client_version": self.client_version,
            "kex_algorithms": self.kex_algorithms,
            "ciphers": self.ciphers,
            "macs": self.macs,
            "compression": self.compression,
            "host_key_types": self.host_key_types,
        }


@dataclass
class AuthAttempt:
    """Records a single authentication attempt."""

    method: str  # "password", "publickey", "keyboard-interactive"
    username: str
    credential: str  # password or key fingerprint
    success: bool
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "method": self.method,
            "username": self.username,
            "credential": self.credential,
            "success": self.success,
            "timestamp": self.timestamp,
        }


def get_or_create_host_key() -> paramiko.PKey:
    """Load the SSH host key from disk, generating it if missing.

    This ensures the honeypot has a persistent identity between runs,
    which feels more realistic to attackers.
    """
    if HOST_KEY_PATH.exists():
        try:
            return paramiko.RSAKey(filename=str(HOST_KEY_PATH))
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.error("Failed to load host key, regenerating: %s", exc)

    # Generate and save a new 4096-bit RSA key for better security
    key = paramiko.RSAKey.generate(4096)
    # Ensure parent directory exists
    HOST_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    key.write_private_key_file(str(HOST_KEY_PATH))
    LOGGER.info("Generated new 4096-bit RSA host key")
    return key


def extract_fingerprint_from_transport(transport: paramiko.Transport) -> SSHFingerprint:
    """Extract SSH fingerprint data from an active transport.

    This should be called after the transport has completed negotiation.

    Args:
        transport: Active Paramiko transport after start_server()

    Returns:
        SSHFingerprint with captured client metadata
    """
    fingerprint = SSHFingerprint()

    try:
        # Get client version string (e.g., "SSH-2.0-OpenSSH_8.9p1")
        fingerprint.client_version = transport.remote_version or ""
    except Exception:
        pass

    # Try to extract security options from transport
    # These are negotiated during key exchange
    try:
        # Get the security options that were offered by client
        # Note: Paramiko stores the agreed-upon algorithms, not full client list
        sec_opts = transport.get_security_options()

        # These are the server's preferences, but we can infer client support
        # from what was negotiated (intersection of client and server)
        fingerprint.kex_algorithms = list(sec_opts.kex) if sec_opts.kex else []
        fingerprint.ciphers = list(sec_opts.ciphers) if sec_opts.ciphers else []
        fingerprint.macs = list(sec_opts.digests) if sec_opts.digests else []
        fingerprint.compression = (
            list(sec_opts.compression) if sec_opts.compression else []
        )
        fingerprint.host_key_types = (
            list(sec_opts.key_types) if sec_opts.key_types else []
        )
    except Exception as e:
        LOGGER.debug("Could not extract security options: %s", e)

    return fingerprint


class SSHServer(paramiko.ServerInterface):
    """Paramiko ServerInterface that accepts all passwords.

    Authentication is intentionally trivial because this is a honeypot.
    Also captures authentication attempts and client metadata for forensics.
    """

    def __init__(self) -> None:
        super().__init__()
        self.event = None

        # Forensic data collection
        self.auth_attempts: List[AuthAttempt] = []
        self.successful_username: Optional[str] = None
        self.successful_password: Optional[str] = None
        self.pty_info: Dict[str, Any] = {}
        self.exec_command: Optional[str] = None

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        """Accept any password and record the attempt for forensics."""
        from datetime import datetime, timezone

        attempt = AuthAttempt(
            method="password",
            username=username,
            credential=password,
            success=True,
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
        self.auth_attempts.append(attempt)

        # Store successful credentials for session log
        self.successful_username = username
        self.successful_password = password

        LOGGER.info("Auth attempt: user=%s (accepted)", username)
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        """Reject public key auth but record the attempt."""
        from datetime import datetime, timezone

        # Get key fingerprint for logging
        try:
            key_fp = key.get_fingerprint().hex()
        except Exception:
            key_fp = "unknown"

        attempt = AuthAttempt(
            method="publickey",
            username=username,
            credential=f"key:{key_fp}",
            success=False,
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
        self.auth_attempts.append(attempt)

        LOGGER.info("Auth attempt: user=%s pubkey=%s (rejected)", username, key_fp[:16])
        # Reject public key auth to force password auth (more intel)
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        """Grant PTY and capture terminal info for forensics."""
        # Decode term safely
        try:
            term_str = (
                term.decode("utf-8", errors="replace")
                if isinstance(term, bytes)
                else str(term)
            )
        except Exception:
            term_str = "unknown"

        self.pty_info = {
            "term": term_str,
            "width": width,
            "height": height,
            "pixelwidth": pixelwidth,
            "pixelheight": pixelheight,
        }
        LOGGER.debug("PTY request: term=%s size=%dx%d", term_str, width, height)
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        # Accept shell requests.
        return True

    def check_channel_exec_request(
        self, channel: paramiko.Channel, command: bytes
    ) -> bool:
        """Accept exec requests and capture the command."""
        try:
            self.exec_command = command.decode("utf-8", errors="replace")
        except Exception:
            self.exec_command = str(command)

        LOGGER.debug("Exec request: %s", self.exec_command)
        return True

    def get_auth_summary(self) -> Dict[str, Any]:
        """Get a summary of authentication data for session logging."""
        return {
            "attempts": [a.to_dict() for a in self.auth_attempts],
            "successful_username": self.successful_username,
            "successful_password": self.successful_password,
            "attempt_count": len(self.auth_attempts),
        }

    def get_session_metadata(self) -> Dict[str, Any]:
        """Get all captured session metadata."""
        return {
            "auth": self.get_auth_summary(),
            "pty": self.pty_info,
            "exec_command": self.exec_command,
        }


def create_listening_socket(host: str, port: int) -> socket.socket:
    """Create, bind, and listen on a TCP socket for SSH.

    Caller is responsible for closing the socket.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Enable TCP keepalive for better connection stability
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    # Disable Nagle's algorithm for lower latency (better for interactive SSH)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    sock.bind((host, port))
    sock.listen(100)
    return sock


__all__ = [
    "SSHServer",
    "SSHFingerprint",
    "AuthAttempt",
    "get_or_create_host_key",
    "create_listening_socket",
    "extract_fingerprint_from_transport",
]
