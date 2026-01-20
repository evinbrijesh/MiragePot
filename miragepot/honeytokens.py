"""Honeytoken generation and tracking for MiragePot.

This module provides mechanisms to generate and track deception artifacts
(honeytokens) such as fake credentials, API keys, and tokens. When attackers
access or exfiltrate these tokens, it provides strong evidence of malicious
intent and can be used for attribution and alerting.

Key features:
1. Per-session unique token generation
2. Multiple token types (AWS keys, API tokens, passwords, SSH keys, etc.)
3. Access tracking and logging
4. Token embedding in fake files
"""

from __future__ import annotations

import hashlib
import random
import secrets
import string
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set


@dataclass
class HoneytokenAccess:
    """Record of a honeytoken being accessed."""

    token_id: str
    token_type: str
    access_time: str
    command: str
    context: str  # How it was accessed (cat, grep, exfiltrate, etc.)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "token_id": self.token_id,
            "token_type": self.token_type,
            "access_time": self.access_time,
            "command": self.command,
            "context": self.context,
        }


@dataclass
class Honeytoken:
    """A single honeytoken."""

    token_id: str
    token_type: str
    value: str
    location: str  # Where it's embedded (file path)
    created_time: str
    access_count: int = 0
    last_accessed: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "token_id": self.token_id,
            "token_type": self.token_type,
            "value": self.value,
            "location": self.location,
            "created_time": self.created_time,
            "access_count": self.access_count,
            "last_accessed": self.last_accessed,
        }


@dataclass
class SessionHoneytokens:
    """Container for all honeytokens in a session."""

    session_id: str
    tokens: Dict[str, Honeytoken] = field(default_factory=dict)
    accesses: List[HoneytokenAccess] = field(default_factory=list)
    exfiltration_attempts: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "session_id": self.session_id,
            "tokens": {k: v.to_dict() for k, v in self.tokens.items()},
            "accesses": [a.to_dict() for a in self.accesses],
            "exfiltration_attempts": self.exfiltration_attempts,
            "total_tokens": len(self.tokens),
            "total_accesses": len(self.accesses),
        }


# Token type constants
TOKEN_TYPE_AWS_ACCESS_KEY = "aws_access_key"
TOKEN_TYPE_AWS_SECRET_KEY = "aws_secret_key"
TOKEN_TYPE_API_KEY = "api_key"
TOKEN_TYPE_PASSWORD = "password"
TOKEN_TYPE_DATABASE_PASSWORD = "database_password"
TOKEN_TYPE_SSH_PRIVATE_KEY = "ssh_private_key"
TOKEN_TYPE_JWT_SECRET = "jwt_secret"
TOKEN_TYPE_GITHUB_TOKEN = "github_token"
TOKEN_TYPE_SLACK_TOKEN = "slack_token"
TOKEN_TYPE_STRIPE_KEY = "stripe_key"


def generate_session_id() -> str:
    """Generate a unique session ID."""
    return secrets.token_hex(8)


def generate_aws_access_key(session_id: str) -> str:
    """Generate a fake AWS access key ID.

    Format: AKIA + 16 uppercase alphanumeric characters
    The key includes session-specific entropy for uniqueness.
    """
    # Use session ID as seed for reproducibility within session
    random.seed(f"{session_id}_aws_access")
    chars = string.ascii_uppercase + string.digits
    suffix = "".join(random.choices(chars, k=16))
    return f"AKIA{suffix}"


def generate_aws_secret_key(session_id: str) -> str:
    """Generate a fake AWS secret access key.

    Format: 40 character base64-like string
    """
    random.seed(f"{session_id}_aws_secret")
    chars = string.ascii_letters + string.digits + "+/"
    return "".join(random.choices(chars, k=40))


def generate_api_key(session_id: str, service: str = "internal") -> str:
    """Generate a fake API key.

    Format: prefix_base64string (e.g., api_key_xxx, sk_live_xxx)
    """
    random.seed(f"{session_id}_api_{service}")

    # Different prefixes for different "services"
    prefixes = {
        "internal": "api_key_",
        "stripe": "sk_live_",
        "openai": "sk-",
        "sendgrid": "SG.",
        "twilio": "SK",
        "generic": "key_",
    }
    prefix = prefixes.get(service, "api_")

    chars = string.ascii_letters + string.digits
    suffix = "".join(random.choices(chars, k=32))
    return f"{prefix}{suffix}"


def generate_password(session_id: str, context: str = "default") -> str:
    """Generate a realistic-looking fake password.

    Passwords look human-created (memorable patterns) to be more believable.
    """
    random.seed(f"{session_id}_password_{context}")

    # Common password patterns that look human-created
    patterns = [
        # Word + numbers + special
        lambda: f"{random.choice(['Admin', 'User', 'Password', 'Secret', 'Root', 'System', 'Server'])}{random.randint(100, 9999)}{random.choice(['!', '@', '#', '$'])}",
        # Word + year + special
        lambda: f"{random.choice(['Summer', 'Winter', 'Spring', 'Fall', 'Company', 'Project'])}{random.randint(2020, 2025)}{random.choice(['!', '@', '#'])}",
        # CamelCase + numbers
        lambda: f"{random.choice(['MySecret', 'P@ssw0rd', 'Qwerty', 'Welcome', 'Changeme'])}{random.randint(1, 999)}",
        # Keyboard pattern + numbers
        lambda: f"{random.choice(['Qwerty', 'Asdfgh', 'Zxcvbn'])}{random.randint(100, 999)}{random.choice(['!', '123', '@'])}",
    ]

    return random.choice(patterns)()


def generate_database_password(session_id: str) -> str:
    """Generate a database connection password."""
    return generate_password(session_id, "database")


def generate_jwt_secret(session_id: str) -> str:
    """Generate a fake JWT secret key."""
    random.seed(f"{session_id}_jwt")
    chars = string.ascii_letters + string.digits
    return "".join(random.choices(chars, k=64))


def generate_github_token(session_id: str) -> str:
    """Generate a fake GitHub personal access token.

    Format: ghp_ + 36 alphanumeric characters (classic token format)
    """
    random.seed(f"{session_id}_github")
    chars = string.ascii_letters + string.digits
    suffix = "".join(random.choices(chars, k=36))
    return f"ghp_{suffix}"


def generate_slack_token(session_id: str) -> str:
    """Generate a fake Slack bot token.

    Format: xoxb- + groups of alphanumeric characters
    """
    random.seed(f"{session_id}_slack")
    chars = string.ascii_letters + string.digits
    parts = [
        "".join(random.choices(chars, k=12)),
        "".join(random.choices(chars, k=12)),
        "".join(random.choices(chars, k=24)),
    ]
    return f"xoxb-{'-'.join(parts)}"


def generate_stripe_key(session_id: str, live: bool = True) -> str:
    """Generate a fake Stripe API key.

    Format: sk_live_ or sk_test_ + 24 alphanumeric characters
    """
    random.seed(f"{session_id}_stripe")
    prefix = "sk_live_" if live else "sk_test_"
    chars = string.ascii_letters + string.digits
    suffix = "".join(random.choices(chars, k=24))
    return f"{prefix}{suffix}"


def generate_ssh_private_key_snippet(session_id: str) -> str:
    """Generate a fake SSH private key (just the header and first few lines).

    This looks like a real key but is not valid.
    """
    random.seed(f"{session_id}_ssh")

    # Generate fake base64 content
    chars = string.ascii_letters + string.digits + "+/"
    lines = []
    for _ in range(5):
        lines.append("".join(random.choices(chars, k=64)))

    return f"""-----BEGIN OPENSSH PRIVATE KEY-----
{lines[0]}
{lines[1]}
{lines[2]}
{lines[3]}
{lines[4]}
... (truncated for security)
-----END OPENSSH PRIVATE KEY-----"""


def init_honeytokens(session_id: str) -> SessionHoneytokens:
    """Initialize honeytokens for a new session.

    Creates a set of unique tokens for this session.
    """
    tokens = SessionHoneytokens(session_id=session_id)
    created_time = datetime.now().isoformat()

    # Generate AWS credentials
    aws_access = generate_aws_access_key(session_id)
    aws_secret = generate_aws_secret_key(session_id)

    tokens.tokens["aws_creds"] = Honeytoken(
        token_id="aws_creds",
        token_type=TOKEN_TYPE_AWS_ACCESS_KEY,
        value=f"AWS_ACCESS_KEY_ID={aws_access}\nAWS_SECRET_ACCESS_KEY={aws_secret}",
        location="/root/.aws/credentials",
        created_time=created_time,
    )

    # Generate API keys for various "services"
    tokens.tokens["internal_api"] = Honeytoken(
        token_id="internal_api",
        token_type=TOKEN_TYPE_API_KEY,
        value=generate_api_key(session_id, "internal"),
        location="/var/www/html/.env",
        created_time=created_time,
    )

    tokens.tokens["stripe_api"] = Honeytoken(
        token_id="stripe_api",
        token_type=TOKEN_TYPE_STRIPE_KEY,
        value=generate_stripe_key(session_id),
        location="/var/www/html/config.php",
        created_time=created_time,
    )

    # Generate passwords
    tokens.tokens["db_password"] = Honeytoken(
        token_id="db_password",
        token_type=TOKEN_TYPE_DATABASE_PASSWORD,
        value=generate_database_password(session_id),
        location="/var/www/html/.env",
        created_time=created_time,
    )

    tokens.tokens["admin_password"] = Honeytoken(
        token_id="admin_password",
        token_type=TOKEN_TYPE_PASSWORD,
        value=generate_password(session_id, "admin"),
        location="/root/passwords.txt",
        created_time=created_time,
    )

    # Generate GitHub token
    tokens.tokens["github_token"] = Honeytoken(
        token_id="github_token",
        token_type=TOKEN_TYPE_GITHUB_TOKEN,
        value=generate_github_token(session_id),
        location="/root/.gitconfig",
        created_time=created_time,
    )

    # Generate JWT secret
    tokens.tokens["jwt_secret"] = Honeytoken(
        token_id="jwt_secret",
        token_type=TOKEN_TYPE_JWT_SECRET,
        value=generate_jwt_secret(session_id),
        location="/var/www/html/.env",
        created_time=created_time,
    )

    return tokens


def record_token_access(
    honeytokens: SessionHoneytokens,
    token_id: str,
    command: str,
    context: str = "read",
) -> None:
    """Record that a honeytoken was accessed.

    Args:
        honeytokens: The session's honeytoken container
        token_id: Which token was accessed
        command: The command that accessed it
        context: How it was accessed (read, grep, exfiltrate, etc.)
    """
    if token_id not in honeytokens.tokens:
        return

    token = honeytokens.tokens[token_id]
    access_time = datetime.now().isoformat()

    # Update token access count
    token.access_count += 1
    token.last_accessed = access_time

    # Record the access
    access = HoneytokenAccess(
        token_id=token_id,
        token_type=token.token_type,
        access_time=access_time,
        command=command,
        context=context,
    )
    honeytokens.accesses.append(access)


def record_exfiltration_attempt(
    honeytokens: SessionHoneytokens,
    token_ids: List[str],
    command: str,
    destination: Optional[str] = None,
) -> None:
    """Record an attempt to exfiltrate honeytokens.

    This is triggered when tokens are sent via network commands
    (curl, wget, nc, etc.) or copied to external locations.

    Args:
        honeytokens: The session's honeytoken container
        token_ids: Which tokens were potentially exfiltrated
        command: The command used
        destination: Where the data was sent (URL, IP, etc.)
    """
    honeytokens.exfiltration_attempts.append(
        {
            "timestamp": datetime.now().isoformat(),
            "token_ids": token_ids,
            "command": command,
            "destination": destination,
        }
    )

    # Also record as accesses with exfiltrate context
    for token_id in token_ids:
        record_token_access(honeytokens, token_id, command, "exfiltrate")


def check_command_for_token_access(
    command: str,
    honeytokens: SessionHoneytokens,
) -> List[str]:
    """Check if a command might access honeytokens.

    Returns list of token IDs that may have been accessed.
    """
    accessed_tokens = []
    command_lower = command.lower()

    # Commands that read files
    read_commands = ["cat", "less", "more", "head", "tail", "grep", "awk", "sed"]

    # Check if any token locations are being accessed
    for token_id, token in honeytokens.tokens.items():
        location = token.location

        # Check if the location is in the command
        if location in command:
            accessed_tokens.append(token_id)
            continue

        # Check for partial path matches
        location_parts = location.split("/")
        filename = location_parts[-1] if location_parts else ""

        if filename and filename in command:
            # Additional check: is this a read/grep command?
            for read_cmd in read_commands:
                if command_lower.startswith(read_cmd):
                    accessed_tokens.append(token_id)
                    break

    return accessed_tokens


def check_for_exfiltration(
    command: str,
    honeytokens: SessionHoneytokens,
) -> tuple[bool, Optional[str]]:
    """Check if a command might be exfiltrating data.

    Returns (is_exfiltration, destination).
    """
    command_lower = command.lower()

    # Network exfiltration commands
    exfil_patterns = [
        ("curl", r"curl\s+.*(-d|--data|--data-raw|--data-binary)"),
        ("wget", r"wget\s+.*--post"),
        ("nc", r"nc\s+"),
        ("ncat", r"ncat\s+"),
        ("netcat", r"netcat\s+"),
        ("scp", r"scp\s+.*@"),
        ("rsync", r"rsync\s+.*@"),
        ("ftp", r"ftp\s+"),
    ]

    import re

    for cmd_name, pattern in exfil_patterns:
        if re.search(pattern, command_lower):
            # Try to extract destination
            destination = None

            # For curl/wget, look for URL
            url_match = re.search(r"https?://[^\s]+", command)
            if url_match:
                destination = url_match.group(0)

            # For scp/rsync, look for user@host
            host_match = re.search(r"(\w+@[\w\.\-]+)", command)
            if host_match:
                destination = host_match.group(1)

            # For nc, look for host/port (handle piped commands)
            nc_match = re.search(
                r"nc\s+(?:[\-\w]*\s+)?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}|[\w\.\-]+)\s+(\d+)",
                command_lower,
            )
            if nc_match:
                destination = f"{nc_match.group(1)}:{nc_match.group(2)}"

            return True, destination

    return False, None


def get_honeytokens_summary(honeytokens: SessionHoneytokens) -> Dict[str, Any]:
    """Get a summary of honeytoken activity for logging."""
    accessed_types = set()
    for access in honeytokens.accesses:
        accessed_types.add(access.token_type)

    return {
        "total_tokens": len(honeytokens.tokens),
        "total_accesses": len(honeytokens.accesses),
        "unique_tokens_accessed": len(set(a.token_id for a in honeytokens.accesses)),
        "accessed_token_types": list(accessed_types),
        "exfiltration_attempts": len(honeytokens.exfiltration_attempts),
        "high_risk": len(honeytokens.exfiltration_attempts) > 0,
    }


def generate_env_file_content(honeytokens: SessionHoneytokens) -> str:
    """Generate realistic .env file content with embedded honeytokens."""
    tokens = honeytokens.tokens

    api_key = tokens.get("internal_api")
    db_pass = tokens.get("db_password")
    jwt = tokens.get("jwt_secret")
    stripe = tokens.get("stripe_api")

    return f"""# Application Configuration
APP_ENV=production
APP_DEBUG=false
APP_URL=https://miragepot.internal.local

# Database Configuration
DB_CONNECTION=mysql
DB_HOST=db.internal.local
DB_PORT=3306
DB_DATABASE=miragepot_production
DB_USERNAME=mirage_app
DB_PASSWORD={db_pass.value if db_pass else "FAKE_DB_PASSWORD"}

# API Keys
INTERNAL_API_KEY={api_key.value if api_key else "FAKE_API_KEY"}
STRIPE_SECRET_KEY={stripe.value if stripe else "sk_live_FAKE"}

# Security
JWT_SECRET={jwt.value if jwt else "FAKE_JWT_SECRET"}
APP_KEY=base64:FAKE_APP_KEY_DO_NOT_USE_IN_PRODUCTION

# AWS Configuration (for S3 backups)
AWS_ACCESS_KEY_ID={generate_aws_access_key(honeytokens.session_id)}
AWS_SECRET_ACCESS_KEY={generate_aws_secret_key(honeytokens.session_id)}
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=miragepot-backups

# Mail Configuration
MAIL_DRIVER=smtp
MAIL_HOST=smtp.internal.local
MAIL_PORT=587
MAIL_USERNAME=noreply@miragepot.local
MAIL_PASSWORD={generate_password(honeytokens.session_id, "mail")}
"""


def generate_passwords_file_content(honeytokens: SessionHoneytokens) -> str:
    """Generate realistic passwords.txt file content."""
    admin_pass = honeytokens.tokens.get("admin_password")

    return f"""# System Credentials - CONFIDENTIAL
# Last updated: 2024-01-15
# DO NOT SHARE - Internal use only

# Web Portal Admin
admin:{admin_pass.value if admin_pass else "FakeAdmin123!"}

# Backup User
backup:{generate_password(honeytokens.session_id, "backup")}

# Database Admin (for emergency access)
dba:{generate_password(honeytokens.session_id, "dba")}

# Legacy System Access
legacy_admin:{generate_password(honeytokens.session_id, "legacy")}

# VPN Service Account
vpn_service:{generate_password(honeytokens.session_id, "vpn")}

# NOTE: Use HashiCorp Vault for new credentials
# These are legacy passwords pending migration
"""


def generate_aws_credentials_content(honeytokens: SessionHoneytokens) -> str:
    """Generate realistic AWS credentials file content."""
    return f"""[default]
aws_access_key_id = {generate_aws_access_key(honeytokens.session_id)}
aws_secret_access_key = {generate_aws_secret_key(honeytokens.session_id)}
region = us-east-1

[backup]
aws_access_key_id = {generate_aws_access_key(honeytokens.session_id + "_backup")}
aws_secret_access_key = {generate_aws_secret_key(honeytokens.session_id + "_backup")}
region = us-west-2

# Production account - USE WITH CAUTION
[production]
aws_access_key_id = {generate_aws_access_key(honeytokens.session_id + "_prod")}
aws_secret_access_key = {generate_aws_secret_key(honeytokens.session_id + "_prod")}
region = us-east-1
"""
