"""Download capture module for MiragePot.

Detects and logs file download attempts via common tools:
- wget: HTTP/FTP downloads
- curl: HTTP/FTP transfers
- scp: Secure copy over SSH
- tftp: Trivial FTP (often used for malware staging)
- ftp: Standard FTP
- rsync: Remote sync

Each detected download attempt is logged with:
- Tool used (wget, curl, scp, etc.)
- Source URL or remote path
- Destination path (if specified)
- Timestamp
- Additional flags/options used
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


@dataclass
class DownloadAttempt:
    """Represents a captured download attempt."""

    tool: str  # wget, curl, scp, tftp, ftp, rsync
    source: str  # URL or remote path
    destination: Optional[str] = None  # Local destination path
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    raw_command: str = ""  # The full command as entered
    flags: List[str] = field(default_factory=list)  # Additional flags used
    method: Optional[str] = None  # HTTP method for curl (GET, POST, etc.)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "tool": self.tool,
            "source": self.source,
            "destination": self.destination,
            "timestamp": self.timestamp,
            "raw_command": self.raw_command,
            "flags": self.flags,
            "method": self.method,
        }


def parse_wget_command(command: str) -> Optional[DownloadAttempt]:
    """Parse wget command and extract download details.

    Handles common wget patterns:
    - wget http://example.com/file
    - wget -O output.sh http://example.com/file
    - wget --output-document=file.sh http://example.com/file
    - wget -q -O- http://example.com/script | bash
    - wget -P /tmp http://example.com/file
    """
    try:
        # Use shlex to properly parse the command
        parts = shlex.split(command)
    except ValueError:
        # Fallback to simple split if shlex fails (unbalanced quotes, etc.)
        parts = command.split()

    if not parts or parts[0] != "wget":
        return None

    source = None
    destination = None
    flags = []

    i = 1
    while i < len(parts):
        part = parts[i]

        # Skip flags we don't care about, but track some important ones
        if part in ("-q", "--quiet", "-v", "--verbose", "-nv", "--no-verbose"):
            flags.append(part)
            i += 1
            continue

        if part in ("-c", "--continue"):
            flags.append(part)
            i += 1
            continue

        if part in ("-b", "--background"):
            flags.append(part)
            i += 1
            continue

        # Output file: -O filename or --output-document=filename
        if part == "-O" and i + 1 < len(parts):
            destination = parts[i + 1]
            i += 2
            continue

        if part.startswith("-O"):
            destination = part[2:]  # -Ofilename
            i += 1
            continue

        if part.startswith("--output-document="):
            destination = part[18:]
            i += 1
            continue

        # Directory prefix: -P directory
        if part == "-P" and i + 1 < len(parts):
            # -P sets the directory, not full path
            dest_dir = parts[i + 1]
            if destination:
                destination = dest_dir.rstrip("/") + "/" + destination
            else:
                destination = dest_dir  # Will be combined with filename later
            i += 2
            continue

        if part.startswith("-P"):
            dest_dir = part[2:]
            destination = dest_dir
            i += 1
            continue

        # Skip other flags that take arguments
        if part in (
            "-t",
            "--tries",
            "-T",
            "--timeout",
            "-w",
            "--wait",
            "-U",
            "--user-agent",
            "--header",
            "-e",
        ):
            i += 2  # Skip flag and its argument
            continue

        # Skip flags that don't take arguments
        if part.startswith("-") or part.startswith("--"):
            flags.append(part)
            i += 1
            continue

        # This should be a URL
        if not source and (
            part.startswith("http://")
            or part.startswith("https://")
            or part.startswith("ftp://")
            or "://" in part
            or "." in part
        ):  # Could be hostname like example.com/file
            source = part
            i += 1
            continue

        # If it's not a flag and not identified as URL, might be URL without protocol
        if not source and "/" in part:
            source = part
            i += 1
            continue

        i += 1

    if not source:
        return None

    # If destination is "-", it means stdout (pipe to another command)
    if destination == "-":
        destination = "stdout (piped)"

    return DownloadAttempt(
        tool="wget",
        source=source,
        destination=destination,
        raw_command=command,
        flags=flags,
    )


def parse_curl_command(command: str) -> Optional[DownloadAttempt]:
    """Parse curl command and extract download details.

    Handles common curl patterns:
    - curl http://example.com/file
    - curl -o output.sh http://example.com/file
    - curl -O http://example.com/file (use remote filename)
    - curl http://example.com/script | bash
    - curl -X POST -d "data" http://example.com/api
    - curl -L http://example.com/redirect
    """
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()

    if not parts or parts[0] != "curl":
        return None

    source = None
    destination = None
    flags = []
    method = "GET"  # Default HTTP method

    i = 1
    while i < len(parts):
        part = parts[i]

        # Silent/quiet mode
        if part in ("-s", "--silent", "-S", "--show-error"):
            flags.append(part)
            i += 1
            continue

        # Follow redirects
        if part in ("-L", "--location"):
            flags.append(part)
            i += 1
            continue

        # Remote name output: -O or --remote-name
        if part in ("-O", "--remote-name"):
            destination = "[remote filename]"
            i += 1
            continue

        # Output file: -o filename
        if part == "-o" and i + 1 < len(parts):
            destination = parts[i + 1]
            i += 2
            continue

        if part.startswith("-o"):
            destination = part[2:]
            i += 1
            continue

        if part.startswith("--output="):
            destination = part[9:]
            i += 1
            continue

        # HTTP method: -X METHOD
        if part == "-X" and i + 1 < len(parts):
            method = parts[i + 1]
            i += 2
            continue

        if part.startswith("-X"):
            method = part[2:]
            i += 1
            continue

        # Skip data flags
        if part in ("-d", "--data", "--data-raw", "--data-binary", "-F", "--form"):
            flags.append(part)
            i += 2  # Skip flag and data
            continue

        # Skip header flags
        if part in ("-H", "--header", "-A", "--user-agent"):
            i += 2
            continue

        # Skip other flags with arguments
        if part in (
            "-u",
            "--user",
            "-b",
            "--cookie",
            "-c",
            "--cookie-jar",
            "-T",
            "--upload-file",
            "-e",
            "--referer",
            "--connect-timeout",
            "-m",
            "--max-time",
            "-x",
            "--proxy",
        ):
            i += 2
            continue

        # Skip flags without arguments
        if part.startswith("-") or part.startswith("--"):
            flags.append(part)
            i += 1
            continue

        # This should be a URL
        if not source:
            source = part

        i += 1

    if not source:
        return None

    return DownloadAttempt(
        tool="curl",
        source=source,
        destination=destination,
        raw_command=command,
        flags=flags,
        method=method,
    )


def parse_scp_command(command: str) -> Optional[DownloadAttempt]:
    """Parse scp command and extract transfer details.

    Handles common scp patterns:
    - scp user@host:/path/file /local/path
    - scp -r user@host:/path/dir /local/path
    - scp /local/file user@host:/remote/path (upload - still log it)
    - scp -P 2222 user@host:file ./
    """
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()

    if not parts or parts[0] != "scp":
        return None

    flags = []
    paths = []

    i = 1
    while i < len(parts):
        part = parts[i]

        # Recursive flag
        if part in ("-r", "-R"):
            flags.append(part)
            i += 1
            continue

        # Port flag
        if part == "-P" and i + 1 < len(parts):
            flags.append(f"-P {parts[i + 1]}")
            i += 2
            continue

        # Preserve flags
        if part == "-p":
            flags.append(part)
            i += 1
            continue

        # Identity file
        if part == "-i" and i + 1 < len(parts):
            i += 2
            continue

        # Skip other flags
        if part.startswith("-"):
            flags.append(part)
            i += 1
            continue

        # This is a path (source or destination)
        paths.append(part)
        i += 1

    if len(paths) < 2:
        # Need at least source and destination
        if len(paths) == 1:
            # Single path - likely incomplete command, but log it
            return DownloadAttempt(
                tool="scp",
                source=paths[0],
                destination=None,
                raw_command=command,
                flags=flags,
            )
        return None

    # In scp, last path is destination, everything else is source
    source = paths[0] if len(paths) == 2 else " ".join(paths[:-1])
    destination = paths[-1]

    return DownloadAttempt(
        tool="scp",
        source=source,
        destination=destination,
        raw_command=command,
        flags=flags,
    )


def parse_tftp_command(command: str) -> Optional[DownloadAttempt]:
    """Parse tftp command and extract transfer details.

    Handles common tftp patterns:
    - tftp -g -r remotefile host
    - tftp host -c get remotefile
    - tftp -i host GET remotefile
    """
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()

    if not parts or parts[0] != "tftp":
        return None

    host = None
    remote_file = None
    flags = []
    mode = None  # get or put

    i = 1
    while i < len(parts):
        part = parts[i]
        part_lower = part.lower()

        # Get mode flag
        if part == "-g":
            mode = "get"
            i += 1
            continue

        # Put mode flag
        if part == "-p":
            mode = "put"
            i += 1
            continue

        # Remote filename
        if part == "-r" and i + 1 < len(parts):
            remote_file = parts[i + 1]
            i += 2
            continue

        # Local filename
        if part == "-l" and i + 1 < len(parts):
            i += 2  # Skip, we care more about remote
            continue

        # Command mode: -c get/put
        if part == "-c" and i + 1 < len(parts):
            next_cmd = parts[i + 1].lower()
            if next_cmd in ("get", "put"):
                mode = next_cmd
                i += 2
                # Next should be filename
                if i < len(parts):
                    remote_file = parts[i]
                    i += 1
                continue
            i += 2
            continue

        # Interactive GET/PUT command
        if part_lower in ("get", "put"):
            mode = part_lower
            if i + 1 < len(parts):
                remote_file = parts[i + 1]
                i += 2
            else:
                i += 1
            continue

        # Binary mode
        if part == "-i":
            flags.append("-i")
            i += 1
            continue

        # Skip other flags
        if part.startswith("-"):
            flags.append(part)
            i += 1
            continue

        # This should be host or filename
        if not host and (
            "." in part or part.isdigit() or any(c.isalpha() for c in part)
        ):
            host = part
            i += 1
            continue

        if host and not remote_file:
            remote_file = part
            i += 1
            continue

        i += 1

    if not host:
        return None

    # Construct source
    source = f"tftp://{host}"
    if remote_file:
        source = f"tftp://{host}/{remote_file}"

    return DownloadAttempt(
        tool="tftp",
        source=source,
        destination=remote_file,
        raw_command=command,
        flags=flags,
        method=mode or "get",
    )


def parse_ftp_command(command: str) -> Optional[DownloadAttempt]:
    """Parse ftp command and extract connection details.

    FTP is interactive, so we mostly capture the connection attempt.
    - ftp host
    - ftp -n host
    - ftp user@host
    """
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()

    if not parts or parts[0] != "ftp":
        return None

    host = None
    flags = []

    i = 1
    while i < len(parts):
        part = parts[i]

        # No auto-login
        if part == "-n":
            flags.append(part)
            i += 1
            continue

        # Skip other flags
        if part.startswith("-"):
            flags.append(part)
            i += 1
            continue

        # This should be host (possibly with user@)
        if not host:
            host = part

        i += 1

    if not host:
        return None

    return DownloadAttempt(
        tool="ftp",
        source=f"ftp://{host}",
        destination=None,
        raw_command=command,
        flags=flags,
    )


def parse_rsync_command(command: str) -> Optional[DownloadAttempt]:
    """Parse rsync command and extract transfer details.

    Handles common rsync patterns:
    - rsync -avz user@host:/path /local/
    - rsync -avz /local/ user@host:/path
    - rsync -e "ssh -p 2222" user@host:/path /local/
    """
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()

    if not parts or parts[0] != "rsync":
        return None

    flags = []
    paths = []

    i = 1
    while i < len(parts):
        part = parts[i]

        # Combined flags like -avz
        if part.startswith("-") and not part.startswith("--"):
            flags.append(part)
            i += 1
            continue

        # Long flags
        if part.startswith("--"):
            flags.append(part)
            # Some long flags have values with =
            i += 1
            continue

        # Shell command: -e "ssh command"
        if part == "-e" and i + 1 < len(parts):
            i += 2  # Skip -e and its argument
            continue

        # This is a path
        paths.append(part)
        i += 1

    if len(paths) < 2:
        if len(paths) == 1:
            return DownloadAttempt(
                tool="rsync",
                source=paths[0],
                destination=None,
                raw_command=command,
                flags=flags,
            )
        return None

    source = paths[0]
    destination = paths[-1]

    return DownloadAttempt(
        tool="rsync",
        source=source,
        destination=destination,
        raw_command=command,
        flags=flags,
    )


# List of download tool parsers
DOWNLOAD_PARSERS = [
    ("wget", parse_wget_command),
    ("curl", parse_curl_command),
    ("scp", parse_scp_command),
    ("tftp", parse_tftp_command),
    ("ftp", parse_ftp_command),
    ("rsync", parse_rsync_command),
]


def detect_download_attempt(command: str) -> Optional[DownloadAttempt]:
    """Check if command is a download attempt and parse it.

    Returns DownloadAttempt if detected, None otherwise.
    """
    stripped = command.strip()
    if not stripped:
        return None

    # Get the first word (command name)
    first_word = stripped.split()[0] if stripped else ""

    # Quick check if this is a download-related command
    download_tools = {"wget", "curl", "scp", "tftp", "ftp", "rsync"}
    if first_word not in download_tools:
        return None

    # Try appropriate parser
    for tool_name, parser in DOWNLOAD_PARSERS:
        if first_word == tool_name:
            return parser(stripped)

    return None


def is_download_command(command: str) -> bool:
    """Quick check if command is a download-related command."""
    stripped = command.strip()
    if not stripped:
        return False

    first_word = stripped.split()[0] if stripped else ""
    return first_word in {"wget", "curl", "scp", "tftp", "ftp", "rsync"}


def extract_urls_from_command(command: str) -> List[str]:
    """Extract all URLs from a command string.

    Useful for commands that might have multiple URLs or for
    detecting URLs in piped commands.
    """
    # URL pattern - matches http, https, ftp URLs
    url_pattern = r'https?://[^\s\'"<>]+|ftp://[^\s\'"<>]+'
    urls = re.findall(url_pattern, command)

    # Clean up URLs (remove trailing punctuation that might have been captured)
    cleaned = []
    for url in urls:
        # Remove common trailing chars that aren't part of URLs
        url = url.rstrip(".,;:'\")]}>")
        if url:
            cleaned.append(url)

    return cleaned


def get_url_domain(url: str) -> Optional[str]:
    """Extract domain from a URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split("/")[0]
    except Exception:
        return None


def classify_download_risk(attempt: DownloadAttempt) -> str:
    """Classify the risk level of a download attempt.

    Returns: 'low', 'medium', 'high', or 'critical'
    """
    source = attempt.source.lower()

    # Critical: Known malicious patterns
    critical_patterns = [
        "pastebin.com/raw",
        "hastebin.com/raw",
        "gist.githubusercontent.com",
        ".onion",  # Tor hidden services
        "transfer.sh",
        "file.io",
        "/shell",
        "/backdoor",
        "/payload",
        "/exploit",
        "reverse",
        "meterpreter",
    ]
    for pattern in critical_patterns:
        if pattern in source:
            return "critical"

    # High: Executable downloads or piped to shell
    high_patterns = [
        ".sh",
        ".py",
        ".pl",
        ".rb",
        ".exe",
        ".elf",
        ".bin",
        "/bash",
        "| sh",
        "| bash",
        "|sh",
        "|bash",
        "; sh",
        "; bash",
    ]
    raw_cmd = attempt.raw_command.lower()
    for pattern in high_patterns:
        if pattern in source or pattern in raw_cmd:
            return "high"

    # High: scp/rsync from unknown hosts (data exfiltration risk)
    if attempt.tool in ("scp", "rsync"):
        if "@" in source:  # Remote host involved
            return "high"

    # Medium: General file downloads
    medium_patterns = [
        ".tar",
        ".gz",
        ".zip",
        ".7z",
        ".rar",
        ".deb",
        ".rpm",
    ]
    for pattern in medium_patterns:
        if pattern in source:
            return "medium"

    # Default: low risk
    return "low"
