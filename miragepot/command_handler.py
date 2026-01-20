"""Command handling logic for MiragePot.

Implements the hybrid engine:
- Cache lookup for known commands (fast path).
- AI-backed responses for everything else.
- In-memory fake filesystem / session state (cwd, dirs, files).

The session_state dict (per connection) has the following structure:
{
    "cwd": str,                        # current working directory (e.g. "/root")
    "directories": set[str],           # known directories (as absolute paths)
    "files": dict[str, str],           # known files (abs path -> content)
    "file_metadata": dict[str, FileMetadata],  # path -> metadata
}
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Tuple, Optional

from .ai_interface import query_llm
from .filesystem import (
    FileMetadata,
    create_default_metadata,
    init_filesystem_metadata,
    handle_stat_command,
    handle_chmod_command,
    handle_chown_command,
    handle_find_command,
)
from .system_state import (
    SystemState,
    init_system_state,
    handle_ps_command,
    handle_top_command,
    handle_netstat_command,
    handle_ss_command,
    handle_free_command,
    handle_uptime_command,
    handle_w_command,
    handle_who_command,
    handle_id_command,
    handle_hostname_command,
    handle_uname_command,
    handle_whoami_command,
)
from .download_capture import (
    DownloadAttempt,
    detect_download_attempt,
    is_download_command,
    classify_download_risk,
    get_url_domain,
)
from .ttp_detector import (
    SessionTTPState,
    init_ttp_state,
    analyze_command,
    get_attack_summary,
    is_high_risk_command,
)
from .honeytokens import (
    SessionHoneytokens,
    init_honeytokens,
    check_command_for_token_access,
    check_for_exfiltration,
    record_token_access,
    record_exfiltration_attempt,
    generate_env_file_content,
    generate_passwords_file_content,
    generate_aws_credentials_content,
    generate_session_id,
)

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
CACHE_PATH = DATA_DIR / "cache.json"


# Known valid Linux commands (subset) - commands that exist on a typical system
KNOWN_COMMANDS = {
    # Core utilities
    "ls",
    "cd",
    "pwd",
    "cat",
    "echo",
    "mkdir",
    "rmdir",
    "rm",
    "cp",
    "mv",
    "touch",
    "chmod",
    "chown",
    "chgrp",
    "ln",
    "readlink",
    "stat",
    "file",
    "head",
    "tail",
    "less",
    "more",
    "wc",
    "sort",
    "uniq",
    "cut",
    "tr",
    "grep",
    "egrep",
    "fgrep",
    "sed",
    "awk",
    "find",
    "locate",
    "which",
    "whereis",
    "type",
    "xargs",
    "tee",
    "diff",
    "patch",
    "tar",
    "gzip",
    "gunzip",
    "bzip2",
    "zip",
    "unzip",
    "xz",
    # System info
    "uname",
    "hostname",
    "uptime",
    "date",
    "cal",
    "whoami",
    "id",
    "groups",
    "w",
    "who",
    "last",
    "lastlog",
    "finger",
    "users",
    # Process management
    "ps",
    "top",
    "htop",
    "kill",
    "killall",
    "pkill",
    "pgrep",
    "nice",
    "renice",
    "nohup",
    "bg",
    "fg",
    "jobs",
    # Networking
    "ip",
    "ifconfig",
    "netstat",
    "ss",
    "ping",
    "traceroute",
    "tracepath",
    "dig",
    "nslookup",
    "host",
    "curl",
    "wget",
    "ssh",
    "scp",
    "rsync",
    "ftp",
    "sftp",
    "nc",
    "netcat",
    "ncat",
    "telnet",
    "nmap",
    # Disk and filesystem
    "df",
    "du",
    "mount",
    "umount",
    "fdisk",
    "parted",
    "lsblk",
    "blkid",
    "mkfs",
    "fsck",
    "dd",
    # Package management
    "apt",
    "apt-get",
    "apt-cache",
    "dpkg",
    "snap",
    "pip",
    "pip3",
    "npm",
    "yarn",
    "gem",
    # Services and system
    "systemctl",
    "service",
    "journalctl",
    "dmesg",
    "crontab",
    "at",
    # User management
    "useradd",
    "userdel",
    "usermod",
    "groupadd",
    "groupdel",
    "passwd",
    "su",
    "sudo",
    # Text editors (interactive)
    "vi",
    "vim",
    "nano",
    "emacs",
    "ed",
    # Shells and scripting
    "bash",
    "sh",
    "zsh",
    "python",
    "python3",
    "perl",
    "ruby",
    "php",
    "node",
    "java",
    "gcc",
    "g++",
    "make",
    "git",
    # Environment
    "env",
    "printenv",
    "export",
    "set",
    "unset",
    "source",
    "alias",
    "history",
    "clear",
    "reset",
    # Misc
    "man",
    "info",
    "help",
    "exit",
    "logout",
    "true",
    "false",
    "yes",
    "no",
    "sleep",
    "watch",
    "time",
    "timeout",
    "seq",
    "basename",
    "dirname",
    "realpath",
    "mktemp",
    "test",
    "expr",
    "[",
    "[[",
    # Security tools
    "iptables",
    "ufw",
    "firewall-cmd",
    "tcpdump",
    # Databases
    "mysql",
    "psql",
    "sqlite3",
    "mongo",
    "redis-cli",
    # Cloud/DevOps
    "docker",
    "docker-compose",
    "kubectl",
    "aws",
    "gcloud",
    "az",
    "terraform",
    "ansible",
    "vagrant",
    # Archive
    "ar",
    "cpio",
    "zcat",
    "bzcat",
    "xzcat",
    # Other common
    "free",
    "vmstat",
    "iostat",
    "mpstat",
    "sar",
    "lsof",
    "strace",
    "ltrace",
    "strings",
    "hexdump",
    "xxd",
    "od",
    "base64",
    "md5sum",
    "sha256sum",
    "openssl",
    "gpg",
}

# Prompt injection patterns to detect and block
INJECTION_PATTERNS = [
    # Direct instruction override attempts (must be at start of input)
    r"^ignore\s+(all\s+)?(previous|prior|above)",
    r"^forget\s+(everything|all|previous)",
    r"^disregard\s+(all\s+)?(previous|prior|instructions)",
    r"^you\s+are\s+(now|a|an|my)",
    r"^pretend\s+(to\s+be|you)",
    r"^act\s+(as|like)",
    r"^roleplay\s+as",
    r"^imagine\s+you",
    r"^from\s+now\s+on",
    r"^new\s+instructions?:",
    # Role/persona assignment markers (must be at start)
    r"^system\s*:",
    r"^assistant\s*:",
    r"^human\s*:",
    r"^user\s*:",
    r"^ai\s*:",
    r"^bot\s*:",
    r"^chatgpt\s*:",
    r"^gpt\s*:",
    r"^claude\s*:",
    r"^llm\s*:",
    # Instruction injection - requires both keywords in suspicious context
    r"\bignore\b.{0,20}\binstructions?\b",
    r"\boverride\b.{0,20}\brules?\b",
    r"\bbypass\b.{0,20}\b(restrictions?|filters?|rules?)\b",
    r"\bdisable\b.{0,20}\b(safety|restrictions?|filters?)\b",
    # XML/HTML-style injection markers
    r"<system",
    r"<\|system",
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"<\|endoftext\|>",
    r"<<SYS>>",
    r"<</SYS>>",
    r"\[INST\]",
    r"\[/INST\]",
    r"###\s*(instruction|system|human|assistant)",
    # Bracket/delimiter injection
    r"\[system\]",
    r"\{system\}",
    r"\[instruction\]",
    r"\{instruction\}",
    r"\[prompt\]",
    r"\{prompt\}",
    # Jailbreak attempt patterns
    r"\bdan\s*mode\b",
    r"\bdeveloper\s*mode\b",
    r"\bjailbreak\b",
    r"\bdo\s+anything\s+now\b",
    r"\bno\s+restrictions?\s+(mode|enabled|on)\b",
    r"\bno\s+limitations?\s+(mode|enabled|on)\b",
    r"\bno\s+guidelines?\s+(mode|enabled|on)\b",
    r"\bunrestricted\s+mode\b",
    r"\bgod\s*mode\b",
    r"\badmin\s*mode\b",
    r"\bsudo\s*mode\b",
    r"\broot\s*mode\b",
    # Roleplay/persona attacks
    r"you\s+are\s+not\s+(an?\s+)?(ai|assistant|chatbot|language\s+model)",
    r"stop\s+being\s+(an?\s+)?(ai|assistant|chatbot)",
    r"you\s+are\s+(an?\s+)?(human|person|real)",
    r"\breal\s+(person|human)\s+(not|terminal)\b",
    # Output manipulation (must be at start or after newline)
    r"^print\s+(only|just)\s+the",
    r"^output\s+(only|just)",
    r"^respond\s+(only|just)\s+with",
    r"^say\s+(only|just)",
    r"^reply\s+(only|just)\s+with",
    r"^answer\s+(only|just)\s+with",
    # Context injection (must be at start of line - these are prompt-style headers)
    r"^context\s*:",
    r"^background\s*:",
    r"^scenario\s*:",
    r"^setting\s*:",
    r"^situation\s*:",
    # Token manipulation attempts
    r"<\|[a-z_]+\|>",
    r"\[\[[a-z_]+\]\]",
    r"\{\{[a-z_]+\}\}",
    # Multi-language injection attempts (common obfuscation)
    r"(忽略|忘记|无视|假装|扮演)",  # Chinese: ignore, forget, disregard, pretend, roleplay
    r"(игнорир|забудь|притвор)",  # Russian: ignore, forget, pretend
]

# Additional patterns for encoded/obfuscated injections
ENCODED_INJECTION_PATTERNS = [
    # Base64 encoded common phrases (decoded: "ignore", "system", etc.)
    r"aWdub3Jl",  # "ignore" base64
    r"c3lzdGVt",  # "system" base64
    r"cHJldGVuZA",  # "pretend" base64
    r"aW5zdHJ1Y3Rpb24",  # "instruction" base64
    # Hex encoded patterns
    r"\\x69\\x67\\x6e\\x6f\\x72\\x65",  # "ignore" hex
    r"\\x73\\x79\\x73\\x74\\x65\\x6d",  # "system" hex
    # URL encoded patterns
    r"%69%67%6e%6f%72%65",  # "ignore" URL encoded
    r"%73%79%73%74%65%6d",  # "system" URL encoded
    # Character splitting (requires spaces between EACH character)
    r"\bi\s+g\s+n\s+o\s+r\s+e\b",
    r"\bs\s+y\s+s\s+t\s+e\s+m\b",
    r"\bp\s+r\s+e\s+t\s+e\s+n\s+d\b",
    # Leetspeak/substitution (more specific patterns)
    r"\b1gn0r3\b",
    r"\bsyst3m\b",
    r"\bpr3t3nd\b",
    r"!gnore\b",  # ! at start doesn't need word boundary
    r"\bign0re\b",
]

# Compile patterns for efficiency
INJECTION_REGEX = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]
ENCODED_INJECTION_REGEX = [
    re.compile(p, re.IGNORECASE) for p in ENCODED_INJECTION_PATTERNS
]


def _load_cache() -> Dict[str, str]:
    """Load cached command outputs from JSON.

    If the file is missing or invalid, return an empty dict.
    """
    try:
        raw = CACHE_PATH.read_text(encoding="utf-8")
        if not raw.strip():
            return {}
        return json.loads(raw)
    except Exception:
        return {}


CACHE = _load_cache()


def init_session_state() -> Dict[str, Any]:
    """Initialize a new session state for a connection.

    This seeds a minimal but realistic Linux-like filesystem tree so that
    common reconnaissance commands (ls /, ls /home, cat /etc/os-release,
    etc.) behave as expected from an attacker's point of view.

    Honeytokens are generated per-session for unique credential tracking.
    """
    # Generate unique session ID and honeytokens for this session
    session_id = generate_session_id()
    honeytokens = init_honeytokens(session_id)

    directories = {
        "/",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/home/user",
        "/home/user/Documents",
        "/home/user/.ssh",
        "/lib",
        "/lib64",
        "/media",
        "/mnt",
        "/opt",
        "/proc",
        "/root",
        "/root/.aws",
        "/root/.ssh",
        "/run",
        "/sbin",
        "/srv",
        "/sys",
        "/tmp",
        "/usr",
        "/usr/local",
        "/var",
        "/var/www",
        "/var/www/html",
        "/var/log",
        "/opt/legacy_backup",
    }

    # Generate file contents using honeytokens
    env_content = generate_env_file_content(honeytokens)
    passwords_content = generate_passwords_file_content(honeytokens)
    aws_credentials_content = generate_aws_credentials_content(honeytokens)

    files: Dict[str, str] = {
        "/etc/hostname": "miragepot\n",
        "/etc/os-release": (
            'NAME="Ubuntu"\n'
            'VERSION="20.04.6 LTS (Focal Fossa)"\n'
            "ID=ubuntu\n"
            "ID_LIKE=debian\n"
            'PRETTY_NAME="Ubuntu 20.04.6 LTS"\n'
            'VERSION_ID="20.04"\n'
            'HOME_URL="https://www.ubuntu.com/"\n'
            'SUPPORT_URL="https://help.ubuntu.com/"\n'
            'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
        ),
        "/etc/passwd": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "sync:x:4:65534:sync:/bin:/bin/sync\n"
            "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
            "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
            "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
            "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "sshd:x:100:65534::/run/sshd:/usr/sbin/nologin\n"
            "user:x:1000:1000:Mirage User:/home/user:/bin/bash\n"
        ),
        "/root/notes.txt": (
            "TODO: migrate old customer database from /opt/legacy_backup/db_backup.sql\n"
            "NOTE: web app config under /var/www/html/.env and config.php\n"
            "NOTE: AWS credentials in ~/.aws/credentials\n"
        ),
        # Use honeytoken-generated passwords file
        "/root/passwords.txt": passwords_content,
        "/home/user/Documents/passwords.txt": (
            "# Personal passwords (legacy, do not use)\n"
            "email:user@example.local:UserMail!2021\n"
            "forum:user_forum:ForumPass#42\n"
            "old_vpn:user_vpn:VPN-Access-Temp1\n"
        ),
        "/home/user/Documents/creds.txt": (
            "DB_HOST=db.internal.local\n"
            "DB_USER=mirage_user\n"
            "DB_PASSWORD=FAKE_DB_PASSWORD_12345\n"
            "API_KEY=DUMMY_INTERNAL_API_KEY_XYZ123\n"
        ),
        "/var/www/html/index.php": ("<?php echo 'Hello from MiragePot!'; ?>\n"),
        # Use honeytoken-generated .env file
        "/var/www/html/.env": env_content,
        "/var/www/html/config.php": (
            "<?php\n"
            "$db_host = 'db.internal.local';\n"
            "$db_user = 'mirage_user';\n"
            "$db_pass = '"
            + (
                honeytokens.tokens.get("db_password").value
                if honeytokens.tokens.get("db_password")
                else "FAKE_DB_PASS"
            )
            + "';\n"
            "$db_name = 'legacy_app';\n"
            "// Stripe integration\n"
            "$stripe_secret = '"
            + (
                honeytokens.tokens.get("stripe_api").value
                if honeytokens.tokens.get("stripe_api")
                else "sk_live_FAKE"
            )
            + "';\n"
            "// legacy config, do not remove\n"
            "?>\n"
        ),
        "/opt/legacy_backup/db_backup.sql": (
            "-- Fake legacy database backup for MiragePot honeypot\n"
            "CREATE TABLE users (id INT, username VARCHAR(32), password VARCHAR(64));\n"
            "INSERT INTO users VALUES (1, 'admin', 'FAKE_HASHED_PASSWORD');\n"
        ),
        "/home/user/.ssh/authorized_keys": (
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFakeMiragePotKey user@miragepot\n"
        ),
        # Use honeytoken-generated AWS credentials
        "/root/.aws/credentials": aws_credentials_content,
        "/root/.aws/config": ("[default]\nregion = us-east-1\noutput = json\n"),
    }

    return {
        "cwd": "/root",
        "directories": directories,
        # files store path -> content; content is plain text
        "files": files,
        # Metadata for files/directories (permissions, ownership, timestamps)
        "file_metadata": init_filesystem_metadata(),
        # System state (processes, network, memory)
        "system_state": init_system_state(),
        # Download attempts tracking (for forensics)
        "download_attempts": [],
        # TTP tracking state (attack stage detection)
        "ttp_state": init_ttp_state(),
        # Honeytokens for credential tracking
        "honeytokens": honeytokens,
        "session_id": session_id,
    }


def _normalize_path(cwd: str, target: str) -> str:
    """Convert a target path (absolute or relative) into an absolute path.

    This is a minimal, safe normalizer just for fake paths.
    """
    if not target:
        return cwd
    if target.startswith("/"):
        path = target
    else:
        if cwd.endswith("/"):
            path = cwd + target
        else:
            path = cwd + "/" + target

    # Normalize any "//" or trailing "/"
    while "//" in path:
        path = path.replace("//", "/")
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path


# ---------- Built-in command handlers (fake FS) ----------


def _handle_cd(args: str, state: Dict[str, Any]) -> str:
    cwd = state.get("cwd", "/root")
    target = args.strip() or "/root"

    if target in ("~", "~/"):
        target = "/root"

    new_path = _normalize_path(cwd, target)
    directories = state.get("directories", set())

    if new_path not in directories:
        # For simplicity, pretend any path accessed actually exists.
        directories.add(new_path)
        state["directories"] = directories

    state["cwd"] = new_path
    return ""


def _handle_pwd(state: Dict[str, Any]) -> str:
    return state.get("cwd", "/root") + "\n"


def _handle_mkdir(args: str, state: Dict[str, Any]) -> str:
    cwd = state.get("cwd", "/root")
    directories = state.get("directories", set())

    parts = [p for p in args.split() if p]
    if not parts:
        return "mkdir: missing operand\n"

    output_lines = []
    for name in parts:
        new_path = _normalize_path(cwd, name)
        if new_path in directories:
            output_lines.append(f"mkdir: cannot create directory '{name}': File exists")
        else:
            directories.add(new_path)
    state["directories"] = directories
    if output_lines:
        return "\n".join(output_lines) + "\n"
    return ""


def _handle_touch(args: str, state: Dict[str, Any]) -> str:
    cwd = state.get("cwd", "/root")
    files: Dict[str, str] = state.get("files", {})

    parts = [p for p in args.split() if p]
    if not parts:
        return "touch: missing file operand\n"

    for name in parts:
        path = _normalize_path(cwd, name)
        # If file doesn't exist, create empty content
        if path not in files:
            files[path] = ""
    state["files"] = files
    return ""


def _handle_ls(args: str, state: Dict[str, Any]) -> str:
    """Handle ls command with basic flag support (-l, -a, -la, -al, etc.)."""
    cwd = state.get("cwd", "/root")
    directories = state.get("directories", set())
    files: Dict[str, str] = state.get("files", {})
    file_metadata: Dict[str, FileMetadata] = state.get("file_metadata", {})

    # Parse flags and target path
    parts = args.strip().split()
    flags = ""
    target = cwd

    for part in parts:
        if part.startswith("-"):
            flags += part[1:]  # Accumulate flags without the dash
        else:
            target = part

    show_hidden = "a" in flags
    long_format = "l" in flags

    target_path = _normalize_path(cwd, target)

    if target_path not in directories and target_path not in files:
        return f"ls: cannot access '{target}': No such file or directory\n"

    # If target is a file, just show the file
    if target_path in files and target_path not in directories:
        name = target_path.split("/")[-1]
        if long_format:
            meta = file_metadata.get(target_path)
            if meta:
                return meta.format_ls_long(name) + "\n"
            return f"-rw-r--r-- 1 root root {len(files[target_path]):>8} Jan 20 12:00 {name}\n"
        return f"{name}\n"

    # Collect children
    children = []
    prefix = target_path + "/" if target_path != "/" else "/"

    for d in directories:
        if d.startswith(prefix) and d != target_path:
            rel = d[len(prefix) :]
            if "/" not in rel and rel:
                children.append((rel, "d", d))  # directory

    for fpath in files.keys():
        if fpath.startswith(prefix):
            rel = fpath[len(prefix) :]
            if "/" not in rel and rel:
                children.append((rel, "f", fpath))  # file

    # Filter hidden files unless -a flag
    if not show_hidden:
        children = [
            (name, typ, path)
            for name, typ, path in children
            if not name.startswith(".")
        ]

    if not children:
        return "\n" if not long_format else "total 0\n"

    children = sorted(set(children), key=lambda x: x[0])

    if long_format:
        # Calculate total blocks (fake)
        total_blocks = len(children) * 4
        lines = [f"total {total_blocks}"]

        for name, typ, full_path in children:
            meta = file_metadata.get(full_path)
            if meta:
                lines.append(meta.format_ls_long(name))
            else:
                # Create default metadata
                if typ == "d":
                    meta = create_default_metadata("", is_dir=True)
                else:
                    content = files.get(full_path, "")
                    meta = create_default_metadata(content, is_dir=False)
                file_metadata[full_path] = meta
                state["file_metadata"] = file_metadata
                lines.append(meta.format_ls_long(name))

        return "\n".join(lines) + "\n"
    else:
        return "  ".join(name for name, _, _ in children) + "\n"


def _handle_cat(args: str, state: Dict[str, Any]) -> str:
    cwd = state.get("cwd", "/root")
    files: Dict[str, str] = state.get("files", {})

    parts = [p for p in args.split() if p]
    if not parts:
        return "cat: missing file operand\n"

    output_parts = []
    for name in parts:
        path = _normalize_path(cwd, name)
        if path not in files:
            output_parts.append(f"cat: {name}: No such file or directory")
        else:
            # Show file content exactly
            output_parts.append(files[path].rstrip("\n"))
    return "\n".join(output_parts) + ("\n" if output_parts else "")


def _handle_rm(args: str, state: Dict[str, Any]) -> str:
    """Simulate a very simple rm for files and empty directories.

    Only affects the in-memory fake filesystem; never touches real disk.
    """
    cwd = state.get("cwd", "/root")
    directories = state.get("directories", set())
    files: Dict[str, str] = state.get("files", {})

    # We will not simulate complex flags like -rf accurately;
    # for safety and simplicity we treat everything as best effort.
    parts = [p for p in args.split() if p]
    if not parts:
        return "rm: missing operand\n"

    output_lines = []
    for name in parts:
        path = _normalize_path(cwd, name)
        if path in files:
            del files[path]
            continue
        if path in directories:
            # If directory has children, mimic "Directory not empty"
            prefix = path + "/" if path != "/" else "/"
            has_children = any(
                d.startswith(prefix) and d != path for d in directories
            ) or any(fp.startswith(prefix) for fp in files.keys())
            if has_children:
                output_lines.append(f"rm: cannot remove '{name}': Is a directory")
            else:
                directories.remove(path)
        else:
            output_lines.append(
                f"rm: cannot remove '{name}': No such file or directory"
            )

    state["directories"] = directories
    state["files"] = files

    if output_lines:
        return "\n".join(output_lines) + "\n"
    return ""


# ---------- Simple redirection parsing ----------


def _handle_echo_redirection(
    full_command: str, state: Dict[str, Any]
) -> Tuple[bool, str]:
    """Handle very simple forms of: echo TEXT > file and echo TEXT >> file.

    We do NOT implement full shell parsing; this is intentionally basic and
    should not execute anything for real. Only handles one '>' or '>>'.
    """
    stripped = full_command.strip()
    if not stripped.startswith("echo "):
        return False, ""

    # Determine redirection operator
    if ">>" in stripped:
        operator = ">>"
    elif ">" in stripped:
        operator = ">"
    else:
        return False, ""

    before, after = stripped.split(operator, 1)
    before = before.strip()  # "echo ... "
    after = after.strip()  # filename

    if not after:
        return True, "bash: syntax error near unexpected token `newline'\n"

    # Extract the text after "echo "
    text_part = before[5:].strip()  # remove 'echo '
    # Remove simple surrounding quotes
    if (
        len(text_part) >= 2
        and text_part[0] == text_part[-1]
        and text_part[0] in ("'", '"')
    ):
        text_part = text_part[1:-1]

    cwd = state.get("cwd", "/root")
    files: Dict[str, str] = state.get("files", {})

    target_path = _normalize_path(cwd, after)

    if operator == ">":
        files[target_path] = text_part + "\n"
    else:  # >>
        old = files.get(target_path, "")
        files[target_path] = old + text_part + "\n"

    state["files"] = files
    # echo normally prints the text as well
    return True, text_part + "\n"


def _handle_download_command(command: str, state: Dict[str, Any]) -> str:
    """Handle download commands (wget, curl, scp, tftp, ftp, rsync).

    Captures download attempt details for forensics and returns realistic
    fake output to make the honeypot appear genuine.
    """
    attempt = detect_download_attempt(command)
    if attempt is None:
        # Shouldn't happen if is_download_command() returned True, but handle gracefully
        return ""

    # Store the download attempt in session state
    download_attempts: list = state.get("download_attempts", [])
    download_attempts.append(attempt.to_dict())
    state["download_attempts"] = download_attempts

    # Generate realistic fake output based on the tool
    return _generate_download_response(attempt, state)


def _generate_download_response(attempt: DownloadAttempt, state: Dict[str, Any]) -> str:
    """Generate realistic fake output for download commands."""
    tool = attempt.tool
    source = attempt.source
    destination = attempt.destination

    if tool == "wget":
        return _generate_wget_response(attempt, state)
    elif tool == "curl":
        return _generate_curl_response(attempt, state)
    elif tool == "scp":
        return _generate_scp_response(attempt, state)
    elif tool == "tftp":
        return _generate_tftp_response(attempt, state)
    elif tool == "ftp":
        return _generate_ftp_response(attempt, state)
    elif tool == "rsync":
        return _generate_rsync_response(attempt, state)

    return ""


def _generate_wget_response(attempt: DownloadAttempt, state: Dict[str, Any]) -> str:
    """Generate realistic wget output."""
    source = attempt.source
    destination = attempt.destination
    flags = attempt.flags

    # Extract filename from URL
    filename = source.split("/")[-1] if "/" in source else "index.html"
    if not filename or filename == source:
        filename = "index.html"

    # Get domain
    domain = get_url_domain(source) or "unknown"

    # Check for quiet mode
    quiet = "-q" in flags or "--quiet" in flags

    if quiet:
        # Quiet mode - no output on success
        return ""

    # Check if output is to stdout (piped)
    if destination == "stdout (piped)" or destination == "-":
        # When piped, wget outputs to stdout which goes to next command
        return ""

    # Use specified destination filename or default
    output_file = destination or filename

    # Simulate realistic wget output
    output_lines = [
        f"--2024-01-15 12:00:00--  {source}",
        f"Resolving {domain} ({domain})... 93.184.216.34",
        f"Connecting to {domain} ({domain})|93.184.216.34|:80... connected.",
        "HTTP request sent, awaiting response... 200 OK",
        "Length: 1256 (1.2K) [text/html]",
        f"Saving to: '{output_file}'",
        "",
        f"{output_file}        100%[===================>]   1.23K  --.-KB/s    in 0s",
        "",
        "2024-01-15 12:00:01 (12.3 MB/s) - '{output_file}' saved [1256/1256]",
        "",
    ]

    # Create the fake file in the filesystem
    cwd = state.get("cwd", "/root")
    if destination and destination.startswith("/"):
        file_path = destination
    elif destination:
        file_path = _normalize_path(cwd, destination)
    else:
        file_path = _normalize_path(cwd, filename)

    files = state.get("files", {})
    files[file_path] = (
        f"# Downloaded content from {source}\n# (simulated by MiragePot)\n"
    )
    state["files"] = files

    return "\n".join(output_lines)


def _generate_curl_response(attempt: DownloadAttempt, state: Dict[str, Any]) -> str:
    """Generate realistic curl output."""
    source = attempt.source
    destination = attempt.destination
    flags = attempt.flags
    method = attempt.method or "GET"

    # Check for silent mode
    silent = "-s" in flags or "--silent" in flags

    # If no output file specified, curl outputs to stdout
    if destination is None:
        # Return fake HTML content (simulating stdout output)
        return f"""<!DOCTYPE html>
<html>
<head><title>Example</title></head>
<body>
<h1>Welcome</h1>
<p>This is a simulated response from {source}</p>
</body>
</html>
"""

    # If output file specified, show progress
    if not silent:
        output = f"""  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1256  100  1256    0     0  12560      0 --:--:-- --:--:-- --:--:-- 12560
"""
    else:
        output = ""

    # Create the fake file in the filesystem
    cwd = state.get("cwd", "/root")
    if destination == "[remote filename]":
        # -O flag - use filename from URL
        filename = source.split("/")[-1] if "/" in source else "downloaded"
        file_path = _normalize_path(cwd, filename)
    elif destination.startswith("/"):
        file_path = destination
    else:
        file_path = _normalize_path(cwd, destination)

    files = state.get("files", {})
    files[file_path] = (
        f"# Downloaded content from {source}\n# (simulated by MiragePot)\n"
    )
    state["files"] = files

    return output


def _generate_scp_response(attempt: DownloadAttempt, state: Dict[str, Any]) -> str:
    """Generate realistic scp output."""
    source = attempt.source
    destination = attempt.destination

    if not destination:
        return "scp: missing destination\n"

    # Extract filename
    if ":" in source:
        # Remote source: user@host:/path/file
        filename = source.split(":")[-1].split("/")[-1]
    else:
        filename = source.split("/")[-1]

    if not filename:
        filename = "file"

    # Create the fake file
    cwd = state.get("cwd", "/root")
    if destination.startswith("/"):
        file_path = destination
        if destination.endswith("/"):
            file_path = destination + filename
    else:
        file_path = _normalize_path(cwd, destination)
        if destination.endswith("/") or destination in (".", "./"):
            file_path = _normalize_path(cwd, filename)

    files = state.get("files", {})
    files[file_path] = f"# Content copied from {source}\n# (simulated by MiragePot)\n"
    state["files"] = files

    # scp shows progress
    return f"{filename}                                     100% 1256     1.2KB/s   00:00\n"


def _generate_tftp_response(attempt: DownloadAttempt, state: Dict[str, Any]) -> str:
    """Generate realistic tftp output."""
    source = attempt.source
    destination = attempt.destination
    method = attempt.method or "get"

    if method == "get":
        filename = destination or "file"
        return f"Received 1256 bytes in 0.1 seconds\n"
    else:
        return f"Sent 1256 bytes in 0.1 seconds\n"


def _generate_ftp_response(attempt: DownloadAttempt, state: Dict[str, Any]) -> str:
    """Generate realistic ftp connection output.

    FTP is interactive, so we simulate the initial connection.
    """
    source = attempt.source

    # Extract host from ftp://host format
    host = source.replace("ftp://", "").split("/")[0]

    return f"""Connected to {host}.
220 (vsFTPd 3.0.3)
Name ({host}:root): """


def _generate_rsync_response(attempt: DownloadAttempt, state: Dict[str, Any]) -> str:
    """Generate realistic rsync output."""
    source = attempt.source
    destination = attempt.destination

    if not destination:
        return "rsync: missing destination\n"

    # Extract filename from source
    if ":" in source:
        filename = source.split(":")[-1].split("/")[-1]
    else:
        filename = source.split("/")[-1]

    if not filename:
        filename = "files"

    # Create the fake file/directory
    cwd = state.get("cwd", "/root")
    if destination.startswith("/"):
        file_path = destination
    else:
        file_path = _normalize_path(cwd, destination)

    files = state.get("files", {})
    if filename:
        # If destination looks like a directory (ends with /), put file inside
        if file_path.endswith("/"):
            file_path = file_path + filename
        files[file_path] = f"# Synced from {source}\n# (simulated by MiragePot)\n"
    state["files"] = files

    return f"""sending incremental file list
{filename}
              1,256 100%    0.00kB/s    0:00:00 (xfr#1, to-chk=0/1)
"""


def handle_builtin(command: str, state: Dict[str, Any]) -> Tuple[bool, str]:
    """Handle built-in filesystem-related commands.

    Returns (handled, output).
    """
    stripped = command.strip()
    if not stripped:
        return True, ""  # empty command, just re-prompt

    # echo with redirection (very simple)
    handled_redir, out_redir = _handle_echo_redirection(stripped, state)
    if handled_redir:
        return True, out_redir

    if stripped == "pwd":
        return True, _handle_pwd(state)

    if stripped.startswith("cd"):
        args = stripped[2:].strip()
        return True, _handle_cd(args, state)

    if stripped.startswith("mkdir"):
        args = stripped[5:].strip()
        return True, _handle_mkdir(args, state)

    if stripped.startswith("touch "):
        args = stripped[6:].strip()
        return True, _handle_touch(args, state)

    if stripped.startswith("ls"):
        args = stripped[2:].strip()
        return True, _handle_ls(args, state)

    if stripped.startswith("cat"):
        args = stripped[3:].strip()
        return True, _handle_cat(args, state)

    if stripped.startswith("rm"):
        args = stripped[2:].strip()
        return True, _handle_rm(args, state)

    # Filesystem metadata commands
    if stripped.startswith("stat "):
        args = stripped[5:].strip()
        return True, handle_stat_command(args, state)

    if stripped.startswith("chmod "):
        args = stripped[6:].strip()
        return True, handle_chmod_command(args, state)

    if stripped.startswith("chown "):
        args = stripped[6:].strip()
        return True, handle_chown_command(args, state)

    if stripped.startswith("find"):
        args = stripped[4:].strip()
        return True, handle_find_command(args, state)

    # System state commands
    sys_state: SystemState = state.get("system_state")
    if sys_state is None:
        sys_state = init_system_state()
        state["system_state"] = sys_state

    if stripped.startswith("ps"):
        args = stripped[2:].strip()
        return True, handle_ps_command(args, sys_state)

    if stripped == "top" or stripped.startswith("top "):
        return True, handle_top_command(sys_state)

    if stripped.startswith("netstat"):
        args = stripped[7:].strip()
        return True, handle_netstat_command(args, sys_state)

    if stripped.startswith("ss"):
        args = stripped[2:].strip()
        return True, handle_ss_command(args, sys_state)

    if stripped.startswith("free"):
        args = stripped[4:].strip()
        return True, handle_free_command(args, sys_state)

    if stripped == "uptime":
        return True, handle_uptime_command(sys_state)

    if stripped == "w":
        return True, handle_w_command(sys_state)

    if stripped == "who":
        return True, handle_who_command(sys_state)

    if stripped.startswith("id"):
        args = stripped[2:].strip()
        return True, handle_id_command(args)

    if stripped == "hostname":
        return True, handle_hostname_command()

    if stripped.startswith("uname"):
        args = stripped[5:].strip()
        return True, handle_uname_command(args)

    if stripped == "whoami":
        return True, handle_whoami_command()

    # Download command handlers (wget, curl, scp, tftp, ftp, rsync)
    if is_download_command(stripped):
        return True, _handle_download_command(stripped, state)

    return False, ""


def _is_prompt_injection(command: str) -> bool:
    """Check if command looks like a prompt injection attempt.

    Detects:
    - Direct injection patterns (ignore instructions, roleplay, etc.)
    - XML/HTML-style injection markers
    - Jailbreak attempt patterns
    - Encoded/obfuscated injections (base64, hex, URL encoding, leetspeak)
    - Character splitting attempts
    - Unicode homoglyph substitutions
    """
    # Check standard patterns
    for pattern in INJECTION_REGEX:
        if pattern.search(command):
            return True

    # Check encoded/obfuscated patterns
    for pattern in ENCODED_INJECTION_REGEX:
        if pattern.search(command):
            return True

    # Check for suspicious characteristics
    if _has_suspicious_encoding(command):
        return True

    return False


def _has_suspicious_encoding(command: str) -> bool:
    """Detect suspicious encoding patterns that might indicate obfuscated injection.

    Looks for:
    - High ratio of escape sequences
    - Base64-like strings in unusual places
    - URL encoding in commands
    - Unicode characters mixed with ASCII in suspicious ways
    """
    # Count escape sequences
    escape_count = command.count("\\x") + command.count("\\u") + command.count("%")
    if len(command) > 10 and escape_count > len(command) * 0.1:
        return True

    # Check for base64-like strings (at least 20 chars of base64 alphabet)
    import re

    base64_pattern = r"[A-Za-z0-9+/=]{20,}"
    base64_matches = re.findall(base64_pattern, command)
    for match in base64_matches:
        # Try to decode and check for injection keywords
        try:
            import base64

            decoded = base64.b64decode(match).decode("utf-8", errors="ignore").lower()
            injection_keywords = [
                "ignore",
                "system",
                "pretend",
                "instruction",
                "roleplay",
                "forget",
            ]
            if any(kw in decoded for kw in injection_keywords):
                return True
        except Exception:
            pass

    # Check for excessive unicode characters (potential homoglyph attack)
    non_ascii_count = sum(1 for c in command if ord(c) > 127)
    if len(command) > 5 and non_ascii_count > len(command) * 0.3:
        # High ratio of non-ASCII might indicate homoglyph substitution
        return True

    return False


def _get_first_word(command: str) -> str:
    """Extract the first word (command name) from input."""
    parts = command.split()
    return parts[0] if parts else command


def _is_valid_command_name(cmd_name: str) -> bool:
    """Check if the command name looks like a valid Linux command.

    Valid command names:
    - Are in our known commands list
    - Start with ./ or / (path execution)
    - Contain only valid characters (alphanumeric, dash, underscore, dot)
    """
    if cmd_name in KNOWN_COMMANDS:
        return True

    # Path-based execution
    if cmd_name.startswith("./") or cmd_name.startswith("/"):
        return True

    # Check if it looks like a reasonable command name
    # Must start with letter or dot, contain only valid chars
    if not cmd_name:
        return False

    # Commands with special prefixes
    if cmd_name.startswith("."):
        return True  # Could be . (source) or ./script

    # Check character validity - real commands are alphanumeric with dash/underscore
    if re.match(r"^[a-zA-Z_][a-zA-Z0-9_\-\.]*$", cmd_name):
        # Additional check: reject things that look like natural language
        # Real commands are typically short and don't look like English words
        natural_language_words = {
            "hi",
            "hello",
            "hey",
            "please",
            "thanks",
            "thank",
            "sorry",
            "what",
            "who",
            "where",
            "when",
            "why",
            "how",
            "can",
            "could",
            "would",
            "should",
            "will",
            "shall",
            "may",
            "might",
            "must",
            "is",
            "are",
            "am",
            "was",
            "were",
            "be",
            "been",
            "being",
            "have",
            "has",
            "had",
            "do",
            "does",
            "did",
            "the",
            "a",
            "an",
            "this",
            "that",
            "these",
            "those",
            "it",
            "its",
            "i",
            "you",
            "he",
            "she",
            "we",
            "they",
            "me",
            "him",
            "her",
            "us",
            "them",
            "my",
            "your",
            "his",
            "our",
            "their",
            "mine",
            "yours",
            "ours",
            "tell",
            "show",
            "give",
            "help",
            "want",
            "need",
            "like",
            "know",
            "think",
            "say",
            "said",
            "ask",
            "asked",
            "answer",
            "respond",
            "ignore",
            "forget",
            "pretend",
            "imagine",
            "act",
            "roleplay",
            "yeah",
            "yes",
            "no",
            "ok",
            "okay",
            "sure",
            "nope",
            "yep",
        }
        if cmd_name.lower() in natural_language_words:
            return False
        return True

    return False


def _handle_interactive_command(command: str, state: Dict[str, Any]) -> Optional[str]:
    """Handle interactive commands like vi, vim, nano, etc.

    Returns response string if handled, None otherwise.
    """
    parts = command.split()
    if not parts:
        return None

    cmd = parts[0]
    args = parts[1:] if len(parts) > 1 else []

    # Text editors - in non-interactive SSH, these would typically fail or
    # show a brief message. We'll simulate them opening and immediately returning.
    if cmd in ("vi", "vim"):
        if not args:
            # Just "vi" with no file - opens empty buffer
            return ""  # Editor opens, no stdout

        filename = args[0]
        filepath = _normalize_path(state.get("cwd", "/root"), filename)
        files = state.get("files", {})

        if filepath in files:
            # File exists - editor would open it
            return ""  # No stdout when opening existing file
        else:
            # New file
            return f'"{filename}" [New File]\n'

    if cmd == "nano":
        if not args:
            return ""
        filename = args[0]
        filepath = _normalize_path(state.get("cwd", "/root"), filename)
        files = state.get("files", {})

        if filepath not in files:
            return f"  [ New File ]\n"
        return ""

    if cmd in ("less", "more"):
        if not args:
            return "Missing filename\n"
        filename = args[0]
        filepath = _normalize_path(state.get("cwd", "/root"), filename)
        files = state.get("files", {})

        if filepath not in files:
            return f"{cmd}: {filename}: No such file or directory\n"
        # Would show file content in pager - just return content
        return files[filepath]

    if cmd in ("top", "htop"):
        # These are interactive - in non-interactive context, return snapshot
        return """top - 12:00:00 up 42 days,  3:15,  1 user,  load average: 0.08, 0.12, 0.10
Tasks:  95 total,   1 running,  94 sleeping,   0 stopped,   0 zombie
%Cpu(s):  2.3 us,  1.0 sy,  0.0 ni, 96.5 id,  0.2 wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem :   3934.0 total,   1487.0 free,   1216.0 used,   1230.0 buff/cache
MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   2424.0 avail Mem

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
      1 root      20   0  169260  11560   8448 S   0.0   0.3   0:01.50 systemd
    512 root      20   0   15420   6400   5632 S   0.0   0.2   0:00.10 sshd
    650 root      20   0   11264   3200   2944 S   0.0   0.1   0:00.05 cron
    900 www-data  20   0   55280  10240   8192 S   0.0   0.3   0:00.20 nginx
   1024 root      20   0   25000   6400   3584 S   0.0   0.2   0:00.02 bash
"""

    return None


def handle_command(command: str, session_state: Dict[str, Any]) -> str:
    """Main command processing entry point.

    - Cleans the command.
    - Detects prompt injection attempts.
    - Handles built-ins and special cases (exit/logout).
    - Performs cache lookup.
    - Falls back to AI for everything else.
    - Analyzes command for TTP indicators.
    - Tracks honeytoken access and exfiltration attempts.
    """
    cmd = command.strip()
    if not cmd:
        return ""  # just re-prompt

    # Analyze command for TTP indicators
    ttp_state: SessionTTPState = session_state.get("ttp_state")
    if ttp_state is None:
        ttp_state = init_ttp_state()
        session_state["ttp_state"] = ttp_state
    analyze_command(cmd, ttp_state)

    # Check for honeytoken access
    honeytokens: SessionHoneytokens = session_state.get("honeytokens")
    if honeytokens is not None:
        # Check if command accesses any honeytokens
        accessed_tokens = check_command_for_token_access(cmd, honeytokens)
        for token_id in accessed_tokens:
            record_token_access(honeytokens, token_id, cmd, "read")

        # Check for exfiltration attempts
        is_exfil, destination = check_for_exfiltration(cmd, honeytokens)
        if is_exfil and accessed_tokens:
            record_exfiltration_attempt(honeytokens, accessed_tokens, cmd, destination)

    if cmd in ("exit", "logout"):
        # Signal upstream that session should close by returning
        # a specific token. The caller can treat it specially.
        return "__MIRAGEPOT_EXIT__"

    # Extract the command name (first word)
    first_word = _get_first_word(cmd)

    # Check for prompt injection attempts
    if _is_prompt_injection(cmd):
        return f"bash: {first_word}: command not found\n"

    # Check if the command name is valid
    if not _is_valid_command_name(first_word):
        return f"bash: {first_word}: command not found\n"

    # First, try built-in fake filesystem commands.
    handled, output = handle_builtin(cmd, session_state)
    if handled:
        return output

    # Handle interactive commands specially
    interactive_output = _handle_interactive_command(cmd, session_state)
    if interactive_output is not None:
        return interactive_output

    # Next, try the cache JSON.
    cached = CACHE.get(cmd)
    if cached is not None:
        return cached

    # Finally, fall back to the AI model.
    return query_llm(cmd, session_state)
