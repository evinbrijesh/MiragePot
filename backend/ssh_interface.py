"""Paramiko-based SSH server interface for MiragePot.

This module defines the SSHServer class that accepts any username/password
and provides an interactive shell channel over which MiragePot runs its
fake terminal.
"""

from __future__ import annotations

import logging
import socket
from pathlib import Path
from typing import Tuple

import paramiko

LOGGER = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
HOST_KEY_PATH = DATA_DIR / "host.key"


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

    # Generate and save a new key using Paramiko's helper
    key = paramiko.RSAKey.generate(2048)
    # Ensure parent directory exists
    HOST_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    key.write_private_key_file(str(HOST_KEY_PATH))
    return key


class SSHServer(paramiko.ServerInterface):
    """Paramiko ServerInterface that accepts all passwords.

    Authentication is intentionally trivial because this is a honeypot.
    """

    def __init__(self) -> None:
        super().__init__()
        self.event = None

    def check_channel_request(self, kind: str, chanid: int) -> int:  # type: ignore[override]
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:  # type: ignore[override]
        # Accept any username/password.
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username: str) -> str:  # type: ignore[override]
        return "password"

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: str,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes,
    ) -> bool:  # type: ignore[override]
        # Always grant a PTY to make the session look real.
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:  # type: ignore[override]
        # Accept shell requests.
        return True


def create_listening_socket(host: str, port: int) -> socket.socket:
    """Create, bind, and listen on a TCP socket for SSH.

    Caller is responsible for closing the socket.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)
    return sock
