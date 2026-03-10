"""Tests for SSH interface and fingerprinting functionality."""

import pytest
from miragepot.ssh_interface import (
    SSHFingerprint,
    AuthAttempt,
    SSHServer,
)


class TestSSHFingerprint:
    """Tests for SSHFingerprint dataclass."""

    def test_default_values(self):
        """SSHFingerprint initializes with empty defaults."""
        fp = SSHFingerprint()
        assert fp.client_version == ""
        assert fp.kex_algorithms == []
        assert fp.ciphers == []
        assert fp.macs == []
        assert fp.compression == []
        assert fp.host_key_types == []

    def test_to_dict(self):
        """SSHFingerprint converts to dict correctly."""
        fp = SSHFingerprint(
            client_version="SSH-2.0-OpenSSH_8.9p1",
            kex_algorithms=["curve25519-sha256", "ecdh-sha2-nistp256"],
            ciphers=["aes256-gcm@openssh.com", "aes128-ctr"],
            macs=["hmac-sha2-256"],
            compression=["none", "zlib"],
            host_key_types=["rsa-sha2-512", "ecdsa-sha2-nistp256"],
        )
        d = fp.to_dict()
        assert d["client_version"] == "SSH-2.0-OpenSSH_8.9p1"
        assert len(d["kex_algorithms"]) == 2
        assert "aes256-gcm@openssh.com" in d["ciphers"]
        assert d["macs"] == ["hmac-sha2-256"]

    def test_to_dict_is_json_serializable(self):
        """SSHFingerprint.to_dict() returns JSON-serializable data."""
        import json

        fp = SSHFingerprint(
            client_version="SSH-2.0-libssh_0.9.6",
            ciphers=["aes128-ctr"],
        )
        # Should not raise
        json_str = json.dumps(fp.to_dict())
        assert "libssh" in json_str


class TestAuthAttempt:
    """Tests for AuthAttempt dataclass."""

    def test_password_attempt(self):
        """AuthAttempt records password authentication."""
        attempt = AuthAttempt(
            method="password",
            username="root",
            credential="admin123",
            success=True,
            timestamp="2026-01-20T10:00:00Z",
        )
        assert attempt.method == "password"
        assert attempt.username == "root"
        assert attempt.credential == "admin123"
        assert attempt.success is True

    def test_publickey_attempt(self):
        """AuthAttempt records public key authentication."""
        attempt = AuthAttempt(
            method="publickey",
            username="admin",
            credential="key:abc123def456",
            success=False,
        )
        assert attempt.method == "publickey"
        assert not attempt.success

    def test_to_dict(self):
        """AuthAttempt converts to dict correctly."""
        attempt = AuthAttempt(
            method="password",
            username="test",
            credential="test123",
            success=True,
            timestamp="2026-01-20T12:00:00Z",
        )
        d = attempt.to_dict()
        assert d["method"] == "password"
        assert d["username"] == "test"
        assert d["credential"] == "test123"
        assert d["success"] is True
        assert d["timestamp"] == "2026-01-20T12:00:00Z"


class TestSSHServer:
    """Tests for SSHServer class."""

    def test_init(self):
        """SSHServer initializes with empty forensic data."""
        server = SSHServer()
        assert server.auth_attempts == []
        assert server.successful_username is None
        assert server.successful_password is None
        assert server.pty_info == {}
        assert server.exec_command is None

    def test_check_auth_password_records_attempt(self):
        """check_auth_password records all attempts and accepts after fail-before-accept.

        P2-04: The server deliberately fails the first _fail_before_accept attempts
        before accepting, to avoid the honeypot fingerprint of instant acceptance.
        We call enough times to reach the acceptance attempt and verify the last
        call succeeds and records a successful attempt.
        """
        server = SSHServer()
        n = server._fail_before_accept  # 1-3 failing attempts before acceptance

        # Exhaust the fail-before-accept window with throwaway attempts
        for _ in range(n):
            server.check_auth_password("root", "wrong")

        # The next attempt should be accepted
        result = server.check_auth_password("root", "toor")

        # Should accept (AUTH_SUCCESSFUL = 0)
        assert result == 0

        # Should record all attempts (n failures + 1 success)
        assert len(server.auth_attempts) == n + 1
        success_attempt = server.auth_attempts[-1]
        assert success_attempt.username == "root"
        assert success_attempt.credential == "toor"
        assert success_attempt.method == "password"
        assert success_attempt.success is True

        # Should store successful credentials
        assert server.successful_username == "root"
        assert server.successful_password == "toor"

    def test_multiple_auth_attempts(self):
        """Multiple auth attempts are all recorded including failures.

        P2-04: All attempts (failed and successful) are recorded. We exhaust the
        fail-before-accept window so the final attempt is guaranteed to succeed.
        """
        server = SSHServer()
        n = server._fail_before_accept

        # Exhaust fail-before-accept window, then add a successful attempt
        server.check_auth_password("admin", "admin")
        for _ in range(max(0, n - 1)):
            server.check_auth_password("root", "password")
        server.check_auth_password("root", "toor")

        assert len(server.auth_attempts) == n + 1
        # Last successful credentials are stored
        assert server.successful_username == "root"
        assert server.successful_password == "toor"

    def test_get_auth_summary(self):
        """get_auth_summary returns complete auth data including successful credentials.

        P2-04: Must call enough times to pass the fail-before-accept window.
        """
        server = SSHServer()
        n = server._fail_before_accept

        for _ in range(n):
            server.check_auth_password("root", "wrong")
        server.check_auth_password("root", "secret123")

        summary = server.get_auth_summary()
        assert summary["successful_username"] == "root"
        assert summary["successful_password"] == "secret123"
        assert summary["attempt_count"] == n + 1
        assert len(summary["attempts"]) == n + 1

    def test_get_session_metadata(self):
        """get_session_metadata returns all captured metadata."""
        server = SSHServer()
        server.check_auth_password("admin", "pass")
        server.pty_info = {"term": "xterm-256color", "width": 80, "height": 24}
        server.exec_command = "id"

        metadata = server.get_session_metadata()
        assert "auth" in metadata
        assert metadata["pty"]["term"] == "xterm-256color"
        assert metadata["exec_command"] == "id"

    def test_check_channel_request_accepts_session(self):
        """check_channel_request accepts 'session' type."""
        import paramiko

        server = SSHServer()
        result = server.check_channel_request("session", 0)
        assert result == paramiko.OPEN_SUCCEEDED

    def test_check_channel_request_rejects_other(self):
        """check_channel_request rejects non-session types."""
        import paramiko

        server = SSHServer()
        result = server.check_channel_request("direct-tcpip", 0)
        assert result == paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def test_get_allowed_auths(self):
        """get_allowed_auths returns password auth only.

        P2-08: Only advertise password auth. Advertising publickey causes many
        clients to attempt key-based auth first, reducing credential capture.
        """
        server = SSHServer()
        allowed = server.get_allowed_auths("root")
        assert "password" in allowed

    def test_check_channel_shell_request(self):
        """check_channel_shell_request accepts shell requests."""
        server = SSHServer()
        result = server.check_channel_shell_request(None)
        assert result is True


class TestSSHFingerprintIntegration:
    """Integration tests for fingerprinting with real-ish data."""

    def test_common_client_versions(self):
        """Test recognizing common SSH client version strings."""
        clients = [
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
            "SSH-2.0-PuTTY_Release_0.78",
            "SSH-2.0-libssh_0.9.6",
            "SSH-2.0-paramiko_3.4.0",
            "SSH-2.0-Go",
            "SSH-2.0-JSCH-0.1.54",
        ]
        for version in clients:
            fp = SSHFingerprint(client_version=version)
            assert fp.client_version == version
            d = fp.to_dict()
            assert d["client_version"] == version

    def test_fingerprint_uniqueness(self):
        """Different clients should have different fingerprints."""
        openssh = SSHFingerprint(
            client_version="SSH-2.0-OpenSSH_8.9p1",
            kex_algorithms=["curve25519-sha256", "ecdh-sha2-nistp256"],
            ciphers=["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"],
        )

        putty = SSHFingerprint(
            client_version="SSH-2.0-PuTTY_Release_0.78",
            kex_algorithms=["ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"],
            ciphers=["aes256-ctr", "aes128-ctr"],
        )

        # They should be distinguishable
        assert openssh.client_version != putty.client_version
        assert openssh.to_dict() != putty.to_dict()
