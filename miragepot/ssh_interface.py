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
from typing import Any, Dict, List, Optional, Tuple, cast

import paramiko
from paramiko.common import (
    AUTH_FAILED,
    AUTH_SUCCESSFUL,
    OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED,
    OPEN_SUCCEEDED,
)

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


def _ensure_key_dir(key_path: Path) -> None:
    """Create key directory with owner-only permissions (P2-03).

    Creates the parent directory if missing (mode 0o700), then enforces
    0o700 even if the directory already existed.
    """
    key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        key_path.parent.chmod(0o700)
    except Exception as chmod_exc:
        LOGGER.warning(
            "Could not set directory permissions on %s: %s", key_path.parent, chmod_exc
        )


def _check_key_permissions(key_path: Path) -> None:
    """Warn if a key file has unsafe permissions (P2-03)."""
    mode = key_path.stat().st_mode & 0o177
    if mode & 0o077:
        LOGGER.warning(
            "Host key %s has unsafe permissions %o — expected 0600",
            key_path,
            mode,
        )


def _generate_ed25519_key() -> bytes:
    """Generate an Ed25519 key using the ``cryptography`` library.

    paramiko 4.x does not expose ``Ed25519Key.generate()``, so we generate
    the key via ``cryptography`` directly and return the raw PEM bytes.
    The caller is responsible for writing the bytes to disk and loading back
    via ``paramiko.Ed25519Key.from_private_key_file()``.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    priv = Ed25519PrivateKey.generate()
    return priv.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())


def _generate_ecdsa_key() -> bytes:
    """Generate an ECDSA nistp256 key using the ``cryptography`` library.

    Returns the raw PEM bytes.  The caller is responsible for writing the bytes
    to disk and loading back via ``paramiko.ECDSAKey.from_private_key_file()``.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1,
        generate_private_key,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    priv = generate_private_key(SECP256R1())
    return priv.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())


def get_or_create_host_key() -> paramiko.PKey:
    """Load (or generate) SSH host keys and return the primary Ed25519 key.

    P2-07: Generates three key types — Ed25519 (primary), ECDSA (nistp256),
    and RSA-4096 — each stored in its own file.  All three are available for
    callers that register additional keys to the transport (see
    ``get_all_host_keys()``), which lets the server present the key type
    preferred by the connecting client.

    P2-03: The key directory is created with mode 0o700 (owner-only).
    P2-05: Key path is read from config rather than hardcoded.
    """
    from miragepot.config import get_config

    base_path = get_config().ssh.host_key_path  # e.g. data/host.key

    # Derive sibling paths for each algorithm
    ed25519_path = base_path.parent / (base_path.stem + "_ed25519" + base_path.suffix)
    ecdsa_path = base_path.parent / (base_path.stem + "_ecdsa" + base_path.suffix)
    rsa_path = base_path.parent / (base_path.stem + "_rsa" + base_path.suffix)

    # Ensure the key directory exists with safe permissions
    _ensure_key_dir(base_path)

    # -- Ed25519 (primary) --
    if ed25519_path.exists():
        try:
            _check_key_permissions(ed25519_path)
            ed25519_key: paramiko.PKey = paramiko.Ed25519Key.from_private_key_file(
                str(ed25519_path)
            )
            LOGGER.debug("Loaded Ed25519 host key from %s", ed25519_path)
        except Exception as exc:
            LOGGER.error("Failed to load Ed25519 key, regenerating: %s", exc)
            ed25519_path.write_bytes(_generate_ed25519_key())
            ed25519_path.chmod(0o600)
            ed25519_key = paramiko.Ed25519Key.from_private_key_file(str(ed25519_path))
            LOGGER.info("Regenerated Ed25519 host key at %s", ed25519_path)
    else:
        ed25519_path.write_bytes(_generate_ed25519_key())
        ed25519_path.chmod(0o600)
        ed25519_key = paramiko.Ed25519Key.from_private_key_file(str(ed25519_path))
        LOGGER.info("Generated new Ed25519 host key at %s", ed25519_path)

    # -- ECDSA nistp256 --
    if ecdsa_path.exists():
        try:
            _check_key_permissions(ecdsa_path)
            paramiko.ECDSAKey.from_private_key_file(str(ecdsa_path))
            LOGGER.debug("Loaded ECDSA host key from %s", ecdsa_path)
        except Exception as exc:
            LOGGER.error("Failed to load ECDSA key, regenerating: %s", exc)
            ecdsa_path.write_bytes(_generate_ecdsa_key())
            ecdsa_path.chmod(0o600)
            LOGGER.info("Regenerated ECDSA host key at %s", ecdsa_path)
    else:
        ecdsa_path.write_bytes(_generate_ecdsa_key())
        ecdsa_path.chmod(0o600)
        LOGGER.info("Generated new ECDSA host key at %s", ecdsa_path)

    # -- RSA-4096 (kept for legacy client compatibility) --
    if rsa_path.exists():
        try:
            _check_key_permissions(rsa_path)
            paramiko.RSAKey.from_private_key_file(str(rsa_path))
            LOGGER.debug("Loaded RSA host key from %s", rsa_path)
        except Exception as exc:
            LOGGER.error("Failed to load RSA key, regenerating: %s", exc)
            rsa_key = paramiko.RSAKey.generate(4096)
            rsa_key.write_private_key_file(str(rsa_path))
            LOGGER.info("Regenerated RSA host key at %s", rsa_path)
    else:
        rsa_key = paramiko.RSAKey.generate(4096)
        rsa_key.write_private_key_file(str(rsa_path))
        LOGGER.info("Generated new RSA-4096 host key at %s", rsa_path)

    # Backward-compat: if the legacy single-key file still exists, leave it
    # in place but do not use it — new code uses the algorithm-specific files.

    return ed25519_key


def get_all_host_keys() -> List[paramiko.PKey]:
    """Return all host keys (Ed25519, ECDSA, RSA) in preference order.

    P2-07: Callers should add every key to the transport so the server can
    negotiate the best algorithm the client supports::

        for key in get_all_host_keys():
            transport.add_server_key(key)
    """
    from miragepot.config import get_config

    base_path = get_config().ssh.host_key_path
    ed25519_path = base_path.parent / (base_path.stem + "_ed25519" + base_path.suffix)
    ecdsa_path = base_path.parent / (base_path.stem + "_ecdsa" + base_path.suffix)
    rsa_path = base_path.parent / (base_path.stem + "_rsa" + base_path.suffix)

    keys: List[paramiko.PKey] = []

    loaders: List[Tuple[Path, Any]] = [
        (ed25519_path, paramiko.Ed25519Key),
        (ecdsa_path, paramiko.ECDSAKey),
        (rsa_path, paramiko.RSAKey),
    ]
    for path, cls in loaders:
        if path.exists():
            try:
                keys.append(cls.from_private_key_file(str(path)))
            except Exception as exc:
                LOGGER.warning("Could not load host key %s: %s", path, exc)

    return keys


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

    # P2-04: Reject the first N password attempts before accepting.
    # Real OpenSSH rejects wrong passwords; instant acceptance on attempt #1 is a
    # classic honeypot detection signal used by automated scanners and Cowrie-detectors.
    # Default: fail the first 2 attempts, accept on attempt 3 (realistic brute-force).
    _FAIL_BEFORE_ACCEPT: int = 2
    # Maximum total auth attempts per connection (OpenSSH default is 6)
    _MAX_AUTH_ATTEMPTS: int = 6

    def __init__(self) -> None:
        super().__init__()
        self.event = None

        # P2-04: Track attempt count for fail-before-accept behaviour
        self._attempt_count: int = 0

        # Forensic data collection
        self.auth_attempts: List[AuthAttempt] = []
        self.successful_username: Optional[str] = None
        self.successful_password: Optional[str] = None
        self.pty_info: Dict[str, Any] = {}
        self.exec_command: Optional[str] = None

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return OPEN_SUCCEEDED
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        """Accept password after a realistic number of failed attempts.

        P2-04: Real OpenSSH rejects wrong passwords on first attempt.  Instant
        success on attempt #1 is a classic honeypot signature.  We fail the first
        _FAIL_BEFORE_ACCEPT attempts and then accept, simulating a valid login
        discovered by brute-force.  All attempts (success and failure) are recorded.
        """
        from datetime import datetime, timezone

        self._attempt_count += 1

        # P2-04: Hard-cap total attempts per connection (mirrors OpenSSH MaxAuthTries=6)
        if self._attempt_count > self._MAX_AUTH_ATTEMPTS:
            LOGGER.info(
                "Auth attempt: user=%s (rejected — max attempts exceeded)", username
            )
            return AUTH_FAILED

        # P2-04: Fail the first N attempts to avoid instant-accept detection
        if self._attempt_count <= self._FAIL_BEFORE_ACCEPT:
            attempt = AuthAttempt(
                method="password",
                username=username,
                credential=password,
                success=False,
                timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            )
            self.auth_attempts.append(attempt)
            LOGGER.info(
                "Auth attempt: user=%s attempt=%d (rejected — fail-before-accept)",
                username,
                self._attempt_count,
            )
            return AUTH_FAILED

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

        LOGGER.info(
            "Auth attempt: user=%s attempt=%d (accepted)", username, self._attempt_count
        )
        return AUTH_SUCCESSFUL

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
        return AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        # P2-08: Only advertise password auth.  Advertising publickey causes
        # many clients to attempt key-based auth first, reducing the password
        # credentials we can capture.  check_auth_publickey() still records any
        # pubkey attempts that clients make unsolicited.
        return "password"

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
    "get_all_host_keys",
    "create_listening_socket",
    "extract_fingerprint_from_transport",
]
