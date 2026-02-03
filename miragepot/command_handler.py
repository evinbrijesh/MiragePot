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
import unicodedata
from pathlib import Path
from typing import Any, Dict, Tuple, Optional, cast

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


def _generate_realistic_bash_history() -> str:
    """Generate a realistic-looking bash history for a server admin."""
    return """cd /var/www/html
ls -la
vim config.php
systemctl status nginx
tail -f /var/log/nginx/error.log
df -h
free -m
top
htop
ps aux | grep nginx
systemctl restart nginx
cat /etc/nginx/sites-available/default
nano /etc/nginx/sites-available/default
nginx -t
systemctl reload nginx
mysql -u root -p
cd /home/user
ls -la
chown -R www-data:www-data /var/www/html
chmod 755 /var/www/html
apt update
apt upgrade -y
apt install htop
cd ~
ssh-keygen -t rsa -b 4096
cat ~/.ssh/id_rsa.pub
vim ~/.ssh/authorized_keys
history
clear
ls
pwd
whoami
uname -a
cat /etc/os-release
ip addr
netstat -tulpn
ss -tulpn
crontab -l
crontab -e
vim /etc/crontab
tail -100 /var/log/auth.log
grep "Failed password" /var/log/auth.log
fail2ban-client status sshd
iptables -L -n
ufw status
docker ps
docker images
git pull origin main
npm install
npm run build
pm2 list
pm2 restart all
"""


def _generate_auth_log() -> str:
    """Generate realistic auth.log entries."""
    from datetime import datetime, timedelta
    import random

    lines = []
    base_time = datetime.now() - timedelta(days=7)

    # Some successful logins
    users = ["root", "user", "admin"]
    ips = ["192.168.1.100", "10.0.0.50", "172.16.0.25"]

    for i in range(50):
        ts = base_time + timedelta(hours=random.randint(0, 168))
        ts_str = ts.strftime("%b %d %H:%M:%S")

        if random.random() < 0.7:  # 70% successful
            user = random.choice(users)
            ip = random.choice(ips)
            lines.append(
                f"{ts_str} miragepot sshd[{random.randint(1000, 9999)}]: Accepted password for {user} from {ip} port {random.randint(40000, 60000)} ssh2"
            )
            lines.append(
                f"{ts_str} miragepot sshd[{random.randint(1000, 9999)}]: pam_unix(sshd:session): session opened for user {user} by (uid=0)"
            )
        else:  # 30% failed
            fake_user = random.choice(
                ["admin", "test", "guest", "ubuntu", "postgres", "mysql"]
            )
            fake_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            lines.append(
                f"{ts_str} miragepot sshd[{random.randint(1000, 9999)}]: Failed password for invalid user {fake_user} from {fake_ip} port {random.randint(40000, 60000)} ssh2"
            )

    lines.sort()
    return "\n".join(lines[-30:]) + "\n"  # Return last 30 entries


def _generate_syslog() -> str:
    """Generate realistic syslog entries."""
    from datetime import datetime, timedelta
    import random

    lines = []
    base_time = datetime.now() - timedelta(hours=24)

    services = ["systemd", "kernel", "cron", "nginx", "mysql", "snapd"]

    messages = [
        ("systemd", "Started Session {} of user root."),
        ("systemd", "Starting Daily apt download activities..."),
        ("systemd", "Started Daily apt download activities."),
        ("kernel", "[UFW BLOCK] IN=eth0 OUT= MAC=... SRC={} DST=10.0.0.1 LEN=40"),
        (
            "cron",
            "(root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))",
        ),
        ("nginx", '10.0.0.1 - - [{}] "GET / HTTP/1.1" 200 612'),
        ("snapd", "autorefresh.go:540: auto-refresh: all snaps are up-to-date"),
    ]

    for i in range(40):
        ts = base_time + timedelta(minutes=random.randint(0, 1440))
        ts_str = ts.strftime("%b %d %H:%M:%S")
        service, msg_template = random.choice(messages)

        if "{}" in msg_template:
            msg = msg_template.format(random.randint(1, 100))
        else:
            msg = msg_template

        lines.append(
            f"{ts_str} miragepot {service}[{random.randint(100, 9999)}]: {msg}"
        )

    lines.sort()
    return "\n".join(lines[-25:]) + "\n"


def init_session_state() -> Dict[str, Any]:
    """Initialize a new session state for a connection.

    This seeds a comprehensive, realistic Ubuntu 20.04 server filesystem that
    would be indistinguishable from a real production server. Includes:
    - Standard XDG user directories
    - Realistic dot files (.bashrc, .profile, .bash_history, etc.)
    - System configuration files
    - Log files with realistic entries
    - Honeytokens placed in natural locations

    Honeytokens are generated per-session for unique credential tracking.
    """
    # Generate unique session ID and honeytokens for this session
    session_id = generate_session_id()
    honeytokens = init_honeytokens(session_id)

    # Comprehensive Ubuntu 20.04 directory structure
    directories = {
        # Root filesystem
        "/",
        "/bin",
        "/boot",
        "/boot/grub",
        "/dev",
        "/dev/pts",
        "/dev/shm",
        # /etc and subdirs
        "/etc",
        "/etc/apt",
        "/etc/apt/sources.list.d",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/default",
        "/etc/init.d",
        "/etc/logrotate.d",
        "/etc/network",
        "/etc/nginx",
        "/etc/nginx/sites-available",
        "/etc/nginx/sites-enabled",
        "/etc/ssh",
        "/etc/ssl",
        "/etc/ssl/certs",
        "/etc/ssl/private",
        "/etc/systemd",
        "/etc/systemd/system",
        # /home directory
        "/home",
        "/home/user",
        "/home/user/.cache",
        "/home/user/.config",
        "/home/user/.local",
        "/home/user/.local/share",
        "/home/user/.ssh",
        "/home/user/Desktop",
        "/home/user/Documents",
        "/home/user/Downloads",
        "/home/user/Music",
        "/home/user/Pictures",
        "/home/user/Public",
        "/home/user/Templates",
        "/home/user/Videos",
        # Standard directories
        "/lib",
        "/lib/x86_64-linux-gnu",
        "/lib64",
        "/media",
        "/mnt",
        "/opt",
        "/opt/backup",
        "/proc",
        # /root directory (admin home)
        "/root",
        "/root/.aws",
        "/root/.cache",
        "/root/.config",
        "/root/.local",
        "/root/.local/share",
        "/root/.ssh",
        "/root/Desktop",
        "/root/Documents",
        "/root/Downloads",
        "/root/scripts",
        "/run",
        "/run/lock",
        "/run/sshd",
        "/sbin",
        "/snap",
        "/srv",
        "/sys",
        "/tmp",
        # /usr hierarchy
        "/usr",
        "/usr/bin",
        "/usr/include",
        "/usr/lib",
        "/usr/local",
        "/usr/local/bin",
        "/usr/local/lib",
        "/usr/sbin",
        "/usr/share",
        # /var hierarchy
        "/var",
        "/var/backups",
        "/var/cache",
        "/var/cache/apt",
        "/var/lib",
        "/var/lib/mysql",
        "/var/log",
        "/var/log/nginx",
        "/var/mail",
        "/var/run",
        "/var/spool",
        "/var/spool/cron",
        "/var/tmp",
        "/var/www",
        "/var/www/html",
        "/var/www/html/assets",
    }

    # Generate file contents using honeytokens
    env_content = generate_env_file_content(honeytokens)
    passwords_content = generate_passwords_file_content(honeytokens)
    aws_credentials_content = generate_aws_credentials_content(honeytokens)

    # Get honeytoken values safely
    db_password_token = honeytokens.tokens.get("db_password")
    db_password = (
        db_password_token.value if db_password_token else "Prod_DB_2024!secure"
    )

    stripe_key_token = honeytokens.tokens.get("stripe_api")
    stripe_key = (
        stripe_key_token.value if stripe_key_token else "sk_live_51ABC123def456"
    )

    aws_key_token = honeytokens.tokens.get("aws_access_key")
    aws_key = aws_key_token.value if aws_key_token else "AKIAIOSFODNN7EXAMPLE"

    aws_secret_token = honeytokens.tokens.get("aws_secret_key")
    aws_secret = (
        aws_secret_token.value
        if aws_secret_token
        else "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    )

    files: Dict[str, str] = {
        # =====================================================================
        # /etc - System configuration files
        # =====================================================================
        "/etc/hostname": "miragepot\n",
        "/etc/hosts": (
            "127.0.0.1\tlocalhost\n"
            "127.0.1.1\tmiragepot\n"
            "10.0.0.5\tdb.internal.local\n"
            "10.0.0.10\tcache.internal.local\n"
            "\n"
            "# The following lines are desirable for IPv6 capable hosts\n"
            "::1     localhost ip6-localhost ip6-loopback\n"
            "ff02::1 ip6-allnodes\n"
            "ff02::2 ip6-allrouters\n"
        ),
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
            'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
            "VERSION_CODENAME=focal\n"
            "UBUNTU_CODENAME=focal\n"
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
            "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
            "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n"
            "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
            "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n"
            "irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin\n"
            "gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\n"
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
            "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"
            "systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n"
            "systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\n"
            "messagebus:x:103:106::/nonexistent:/usr/sbin/nologin\n"
            "syslog:x:104:110::/home/syslog:/usr/sbin/nologin\n"
            "_apt:x:105:65534::/nonexistent:/usr/sbin/nologin\n"
            "sshd:x:106:65534::/run/sshd:/usr/sbin/nologin\n"
            "mysql:x:107:115:MySQL Server,,,:/nonexistent:/bin/false\n"
            "user:x:1000:1000:System User,,,:/home/user:/bin/bash\n"
        ),
        "/etc/shadow": (
            "root:$6$rounds=4096$randomsalt$hashedpasswordhere:19500:0:99999:7:::\n"
            "daemon:*:19000:0:99999:7:::\n"
            "bin:*:19000:0:99999:7:::\n"
            "sys:*:19000:0:99999:7:::\n"
            "sync:*:19000:0:99999:7:::\n"
            "www-data:*:19000:0:99999:7:::\n"
            "sshd:*:19000:0:99999:7:::\n"
            "mysql:!:19200:0:99999:7:::\n"
            "user:$6$rounds=4096$anothersalt$userhashhere:19400:0:99999:7:::\n"
        ),
        "/etc/group": (
            "root:x:0:\n"
            "daemon:x:1:\n"
            "bin:x:2:\n"
            "sys:x:3:\n"
            "adm:x:4:syslog,user\n"
            "tty:x:5:\n"
            "disk:x:6:\n"
            "lp:x:7:\n"
            "mail:x:8:\n"
            "news:x:9:\n"
            "uucp:x:10:\n"
            "man:x:12:\n"
            "proxy:x:13:\n"
            "kmem:x:15:\n"
            "dialout:x:20:\n"
            "fax:x:21:\n"
            "voice:x:22:\n"
            "cdrom:x:24:user\n"
            "floppy:x:25:\n"
            "tape:x:26:\n"
            "sudo:x:27:user\n"
            "audio:x:29:\n"
            "dip:x:30:user\n"
            "www-data:x:33:\n"
            "backup:x:34:\n"
            "operator:x:37:\n"
            "list:x:38:\n"
            "irc:x:39:\n"
            "src:x:40:\n"
            "gnats:x:41:\n"
            "shadow:x:42:\n"
            "utmp:x:43:\n"
            "video:x:44:\n"
            "sasl:x:45:\n"
            "plugdev:x:46:user\n"
            "staff:x:50:\n"
            "games:x:60:\n"
            "users:x:100:\n"
            "nogroup:x:65534:\n"
            "mysql:x:115:\n"
            "ssh:x:116:\n"
            "user:x:1000:\n"
        ),
        "/etc/resolv.conf": (
            "# Generated by NetworkManager\n"
            "nameserver 8.8.8.8\n"
            "nameserver 8.8.4.4\n"
            "search internal.local\n"
        ),
        "/etc/fstab": (
            "# /etc/fstab: static file system information.\n"
            "#\n"
            "# <file system> <mount point>   <type>  <options>       <dump>  <pass>\n"
            "UUID=a1b2c3d4-e5f6-7890-abcd-ef1234567890 /               ext4    errors=remount-ro 0       1\n"
            "UUID=b2c3d4e5-f6a7-8901-bcde-f12345678901 /boot           ext4    defaults        0       2\n"
            "/swap.img\tnone\tswap\tsw\t0\t0\n"
        ),
        "/etc/crontab": (
            "# /etc/crontab: system-wide crontab\n"
            "SHELL=/bin/sh\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
            "\n"
            "# m h dom mon dow user  command\n"
            "17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n"
            "25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
            "47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )\n"
            "52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )\n"
            "#\n"
            "# Custom jobs\n"
            "0 2 * * * root /root/scripts/backup.sh >> /var/log/backup.log 2>&1\n"
            "*/5 * * * * root /usr/bin/python3 /opt/monitor/check_services.py\n"
        ),
        "/etc/ssh/sshd_config": (
            "# OpenSSH server configuration\n"
            "Port 22\n"
            "AddressFamily any\n"
            "ListenAddress 0.0.0.0\n"
            "ListenAddress ::\n"
            "\n"
            "HostKey /etc/ssh/ssh_host_rsa_key\n"
            "HostKey /etc/ssh/ssh_host_ecdsa_key\n"
            "HostKey /etc/ssh/ssh_host_ed25519_key\n"
            "\n"
            "# Authentication\n"
            "PermitRootLogin yes\n"
            "PubkeyAuthentication yes\n"
            "PasswordAuthentication yes\n"
            "PermitEmptyPasswords no\n"
            "ChallengeResponseAuthentication no\n"
            "\n"
            "UsePAM yes\n"
            "X11Forwarding yes\n"
            "PrintMotd no\n"
            "AcceptEnv LANG LC_*\n"
            "Subsystem\tsftp\t/usr/lib/openssh/sftp-server\n"
        ),
        "/etc/timezone": "Etc/UTC\n",
        "/etc/localtime": "UTC\n",
        "/etc/environment": 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"\n',
        "/etc/issue": "Ubuntu 20.04.6 LTS \\n \\l\n\n",
        "/etc/issue.net": "Ubuntu 20.04.6 LTS\n",
        "/etc/apt/sources.list": (
            "deb http://archive.ubuntu.com/ubuntu focal main restricted\n"
            "deb http://archive.ubuntu.com/ubuntu focal-updates main restricted\n"
            "deb http://archive.ubuntu.com/ubuntu focal universe\n"
            "deb http://archive.ubuntu.com/ubuntu focal-updates universe\n"
            "deb http://archive.ubuntu.com/ubuntu focal multiverse\n"
            "deb http://archive.ubuntu.com/ubuntu focal-updates multiverse\n"
            "deb http://archive.ubuntu.com/ubuntu focal-backports main restricted universe multiverse\n"
            "deb http://security.ubuntu.com/ubuntu focal-security main restricted\n"
            "deb http://security.ubuntu.com/ubuntu focal-security universe\n"
            "deb http://security.ubuntu.com/ubuntu focal-security multiverse\n"
        ),
        "/etc/nginx/nginx.conf": (
            "user www-data;\n"
            "worker_processes auto;\n"
            "pid /run/nginx.pid;\n"
            "include /etc/nginx/modules-enabled/*.conf;\n"
            "\n"
            "events {\n"
            "    worker_connections 768;\n"
            "}\n"
            "\n"
            "http {\n"
            "    sendfile on;\n"
            "    tcp_nopush on;\n"
            "    tcp_nodelay on;\n"
            "    keepalive_timeout 65;\n"
            "    types_hash_max_size 2048;\n"
            "\n"
            "    include /etc/nginx/mime.types;\n"
            "    default_type application/octet-stream;\n"
            "\n"
            "    ssl_protocols TLSv1.2 TLSv1.3;\n"
            "    ssl_prefer_server_ciphers on;\n"
            "\n"
            "    access_log /var/log/nginx/access.log;\n"
            "    error_log /var/log/nginx/error.log;\n"
            "\n"
            "    gzip on;\n"
            "\n"
            "    include /etc/nginx/conf.d/*.conf;\n"
            "    include /etc/nginx/sites-enabled/*;\n"
            "}\n"
        ),
        "/etc/nginx/sites-available/default": (
            "server {\n"
            "    listen 80 default_server;\n"
            "    listen [::]:80 default_server;\n"
            "\n"
            "    root /var/www/html;\n"
            "    index index.php index.html index.htm;\n"
            "\n"
            "    server_name _;\n"
            "\n"
            "    location / {\n"
            "        try_files $uri $uri/ =404;\n"
            "    }\n"
            "\n"
            "    location ~ \\.php$ {\n"
            "        include snippets/fastcgi-php.conf;\n"
            "        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;\n"
            "    }\n"
            "}\n"
        ),
        # =====================================================================
        # /root - Root user home directory (realistic admin setup)
        # =====================================================================
        "/root/.bashrc": (
            "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
            "\n"
            "# If not running interactively, don't do anything\n"
            "case $- in\n"
            "    *i*) ;;\n"
            "      *) return;;\n"
            "esac\n"
            "\n"
            "# don't put duplicate lines or lines starting with space in the history\n"
            "HISTCONTROL=ignoreboth\n"
            "\n"
            "# append to the history file, don't overwrite it\n"
            "shopt -s histappend\n"
            "\n"
            "# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)\n"
            "HISTSIZE=1000\n"
            "HISTFILESIZE=2000\n"
            "\n"
            "# check the window size after each command\n"
            "shopt -s checkwinsize\n"
            "\n"
            "# make less more friendly for non-text input files\n"
            '[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"\n'
            "\n"
            "# set a fancy prompt\n"
            "PS1='${debian_chroot:+($debian_chroot)}\\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '\n"
            "\n"
            "# enable color support of ls\n"
            "if [ -x /usr/bin/dircolors ]; then\n"
            '    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"\n'
            "    alias ls='ls --color=auto'\n"
            "    alias grep='grep --color=auto'\n"
            "fi\n"
            "\n"
            "# some more ls aliases\n"
            "alias ll='ls -alF'\n"
            "alias la='ls -A'\n"
            "alias l='ls -CF'\n"
            "\n"
            "# Custom aliases\n"
            "alias update='apt update && apt upgrade -y'\n"
            "alias ports='netstat -tulpn'\n"
            "alias myip='curl -s ifconfig.me'\n"
        ),
        "/root/.profile": (
            "# ~/.profile: executed by Bourne-compatible login shells.\n"
            "\n"
            'if [ "$BASH" ]; then\n'
            "  if [ -f ~/.bashrc ]; then\n"
            "    . ~/.bashrc\n"
            "  fi\n"
            "fi\n"
            "\n"
            "mesg n 2> /dev/null || true\n"
        ),
        "/root/.bash_history": _generate_realistic_bash_history(),
        "/root/.vimrc": (
            '" Basic vim configuration\n'
            "set number\n"
            "set autoindent\n"
            "set tabstop=4\n"
            "set shiftwidth=4\n"
            "set expandtab\n"
            "set hlsearch\n"
            "set incsearch\n"
            "syntax on\n"
            "set background=dark\n"
        ),
        "/root/.gitconfig": (
            "[user]\n"
            "\tname = Admin\n"
            "\temail = admin@miragepot.local\n"
            "[core]\n"
            "\teditor = vim\n"
            "[alias]\n"
            "\tst = status\n"
            "\tco = checkout\n"
            "\tbr = branch\n"
        ),
        "/root/.ssh/authorized_keys": (
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7fake_key_data_here_for_miragepot_honeypot_system admin@workstation\n"
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake_ed25519_key_for_backup backup@miragepot\n"
        ),
        "/root/.ssh/known_hosts": (
            "github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmd...\n"
            "10.0.0.5 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdH...\n"
            "db.internal.local ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...\n"
        ),
        "/root/.ssh/config": (
            "Host db\n"
            "    HostName db.internal.local\n"
            "    User admin\n"
            "    IdentityFile ~/.ssh/id_rsa\n"
            "\n"
            "Host github.com\n"
            "    IdentityFile ~/.ssh/id_rsa_github\n"
        ),
        # AWS credentials (honeytoken)
        "/root/.aws/credentials": aws_credentials_content,
        "/root/.aws/config": (
            "[default]\n"
            "region = us-east-1\n"
            "output = json\n"
            "\n"
            "[profile production]\n"
            "region = us-west-2\n"
            "output = json\n"
        ),
        # Admin notes - breadcrumbs to honeytokens (moved from obvious location)
        "/root/Documents/server-notes.txt": (
            "Server Setup Notes - Last updated 2024-01-15\n"
            "=============================================\n"
            "\n"
            "Web Application:\n"
            "- Config: /var/www/html/config.php\n"
            "- Environment: /var/www/html/.env\n"
            "- Logs: /var/log/nginx/\n"
            "\n"
            "Database:\n"
            "- MySQL running on db.internal.local:3306\n"
            "- Credentials in /var/www/html/.env\n"
            "- Backup script: /root/scripts/backup.sh\n"
            "\n"
            "AWS:\n"
            "- Credentials in ~/.aws/credentials\n"
            "- S3 bucket: company-backups-prod\n"
            "\n"
            "TODO:\n"
            "- [ ] Rotate database passwords\n"
            "- [ ] Update SSL certificates (expires March)\n"
            "- [ ] Migrate legacy data from /opt/backup/\n"
        ),
        # Backup script (realistic admin tool)
        "/root/scripts/backup.sh": (
            "#!/bin/bash\n"
            "# Daily backup script\n"
            "# Run via cron at 2 AM\n"
            "\n"
            "BACKUP_DIR=/var/backups\n"
            "DATE=$(date +%Y%m%d)\n"
            "MYSQL_USER=backup_user\n"
            f"MYSQL_PASS={db_password}\n"
            "\n"
            "# Backup MySQL databases\n"
            "mysqldump -u $MYSQL_USER -p$MYSQL_PASS --all-databases > $BACKUP_DIR/mysql_$DATE.sql\n"
            "\n"
            "# Backup web files\n"
            "tar -czf $BACKUP_DIR/www_$DATE.tar.gz /var/www/html\n"
            "\n"
            "# Upload to S3\n"
            "aws s3 cp $BACKUP_DIR/mysql_$DATE.sql s3://company-backups-prod/mysql/\n"
            "aws s3 cp $BACKUP_DIR/www_$DATE.tar.gz s3://company-backups-prod/www/\n"
            "\n"
            "# Cleanup old backups (keep 7 days)\n"
            "find $BACKUP_DIR -name '*.sql' -mtime +7 -delete\n"
            "find $BACKUP_DIR -name '*.tar.gz' -mtime +7 -delete\n"
            "\n"
            'echo "Backup completed: $DATE"\n'
        ),
        # MySQL history (honeytoken - reveals database activity)
        "/root/.mysql_history": (
            "show databases;\n"
            "use production_db;\n"
            "show tables;\n"
            "SELECT * FROM users LIMIT 10;\n"
            "SELECT username, email FROM users WHERE role='admin';\n"
            "UPDATE users SET password='temp123' WHERE id=1;\n"
            f"CREATE USER 'app_user'@'localhost' IDENTIFIED BY '{db_password}';\n"
            "GRANT ALL PRIVILEGES ON production_db.* TO 'app_user'@'localhost';\n"
            "FLUSH PRIVILEGES;\n"
            "exit\n"
        ),
        # =====================================================================
        # /home/user - Regular user home directory
        # =====================================================================
        "/home/user/.bashrc": (
            "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
            "\n"
            "case $- in\n"
            "    *i*) ;;\n"
            "      *) return;;\n"
            "esac\n"
            "\n"
            "HISTCONTROL=ignoreboth\n"
            "shopt -s histappend\n"
            "HISTSIZE=1000\n"
            "HISTFILESIZE=2000\n"
            "shopt -s checkwinsize\n"
            "\n"
            "PS1='${debian_chroot:+($debian_chroot)}\\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '\n"
            "\n"
            "if [ -x /usr/bin/dircolors ]; then\n"
            '    eval "$(dircolors -b)"\n'
            "    alias ls='ls --color=auto'\n"
            "    alias grep='grep --color=auto'\n"
            "fi\n"
            "\n"
            "alias ll='ls -alF'\n"
            "alias la='ls -A'\n"
        ),
        "/home/user/.profile": (
            "# ~/.profile: executed by the command interpreter for login shells.\n"
            "\n"
            'if [ -n "$BASH_VERSION" ]; then\n'
            '    if [ -f "$HOME/.bashrc" ]; then\n'
            '        . "$HOME/.bashrc"\n'
            "    fi\n"
            "fi\n"
            "\n"
            'if [ -d "$HOME/bin" ] ; then\n'
            '    PATH="$HOME/bin:$PATH"\n'
            "fi\n"
        ),
        "/home/user/.bash_history": (
            "ls\n"
            "cd Documents\n"
            "ls -la\n"
            "cat readme.txt\n"
            "cd ..\n"
            "pwd\n"
            "whoami\n"
            "sudo apt update\n"
            "history\n"
        ),
        "/home/user/.ssh/authorized_keys": (
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFakeMiragePotUserKey user@miragepot\n"
        ),
        "/home/user/.ssh/known_hosts": (
            "github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq...\n"
        ),
        "/home/user/Documents/readme.txt": (
            "Welcome to the system!\n"
            "\n"
            "For help, contact the system administrator.\n"
            "Email: admin@company.local\n"
        ),
        "/home/user/Documents/work-notes.txt": (
            "Meeting notes - 2024-01-10\n"
            "- Discussed Q1 roadmap\n"
            "- Need to update deployment scripts\n"
            "- Review security audit findings\n"
        ),
        # Hidden credentials in user's config (looks realistic)
        "/home/user/.config/development.env": (
            "# Development environment settings\n"
            "DEV_API_URL=http://localhost:3000\n"
            "DEV_DB_HOST=localhost\n"
            "DEV_DB_USER=dev_user\n"
            "DEV_DB_PASS=DevPass123!\n"
            "DEBUG=true\n"
        ),
        # =====================================================================
        # /var/www/html - Web application
        # =====================================================================
        "/var/www/html/index.php": (
            "<?php\n"
            "/**\n"
            " * Main entry point for the web application\n"
            " * @version 2.1.0\n"
            " */\n"
            "\n"
            "require_once 'config.php';\n"
            "\n"
            "echo '<h1>Welcome to Our Application</h1>';\n"
            "echo '<p>Server time: ' . date('Y-m-d H:i:s') . '</p>';\n"
            "?>\n"
        ),
        "/var/www/html/.env": env_content,
        "/var/www/html/config.php": (
            "<?php\n"
            "/**\n"
            " * Application Configuration\n"
            " * WARNING: Do not commit this file to version control!\n"
            " */\n"
            "\n"
            "// Database configuration\n"
            "$db_config = [\n"
            "    'host' => 'db.internal.local',\n"
            "    'port' => 3306,\n"
            "    'database' => 'production_db',\n"
            "    'username' => 'app_user',\n"
            f"    'password' => '{db_password}',\n"
            "    'charset' => 'utf8mb4',\n"
            "];\n"
            "\n"
            "// API Keys\n"
            f"define('STRIPE_SECRET_KEY', '{stripe_key}');\n"
            "define('STRIPE_PUBLIC_KEY', 'pk_live_51ABC123def456');\n"
            "\n"
            "// Application settings\n"
            "define('APP_DEBUG', false);\n"
            "define('APP_URL', 'https://app.company.com');\n"
            "\n"
            "// Session configuration\n"
            "ini_set('session.cookie_httponly', 1);\n"
            "ini_set('session.cookie_secure', 1);\n"
            "?>\n"
        ),
        "/var/www/html/.htaccess": (
            "RewriteEngine On\n"
            "RewriteCond %{REQUEST_FILENAME} !-f\n"
            "RewriteCond %{REQUEST_FILENAME} !-d\n"
            "RewriteRule ^(.*)$ index.php [QSA,L]\n"
            "\n"
            "# Deny access to sensitive files\n"
            '<FilesMatch "^\\.(env|htaccess|htpasswd)$">\n'
            "    Order allow,deny\n"
            "    Deny from all\n"
            "</FilesMatch>\n"
        ),
        "/var/www/html/assets/style.css": (
            "/* Main application styles */\n"
            "body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }\n"
            "h1 { color: #333; }\n"
        ),
        # =====================================================================
        # /var/log - System logs
        # =====================================================================
        "/var/log/auth.log": _generate_auth_log(),
        "/var/log/syslog": _generate_syslog(),
        "/var/log/nginx/access.log": (
            '10.0.0.1 - - [15/Jan/2024:10:30:45 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"\n'
            '10.0.0.1 - - [15/Jan/2024:10:30:46 +0000] "GET /assets/style.css HTTP/1.1" 200 456 "-" "Mozilla/5.0"\n'
            '192.168.1.100 - - [15/Jan/2024:11:15:22 +0000] "POST /api/login HTTP/1.1" 200 89 "-" "curl/7.68.0"\n'
        ),
        "/var/log/nginx/error.log": (
            "2024/01/15 08:00:01 [notice] 1234#1234: signal process started\n"
            '2024/01/15 09:15:33 [error] 1234#1234: *1 open() "/var/www/html/favicon.ico" failed (2: No such file or directory)\n'
        ),
        "/var/log/mysql/error.log": (
            "2024-01-15T00:00:01.123456Z 0 [System] [MY-010116] [Server] /usr/sbin/mysqld (mysqld 8.0.35) starting as process 1234\n"
            "2024-01-15T00:00:02.234567Z 0 [System] [MY-010931] [Server] /usr/sbin/mysqld: ready for connections.\n"
        ),
        "/var/log/dpkg.log": (
            "2024-01-10 09:15:22 startup packages configure\n"
            "2024-01-10 09:15:23 configure nginx:amd64 1.18.0-0ubuntu1.4 <none>\n"
            "2024-01-10 09:15:24 status installed nginx:amd64 1.18.0-0ubuntu1.4\n"
            "2024-01-12 14:30:15 startup packages configure\n"
            "2024-01-12 14:30:16 upgrade openssl:amd64 1.1.1f-1ubuntu2.19 1.1.1f-1ubuntu2.20\n"
        ),
        # =====================================================================
        # /opt - Optional application data and backups
        # =====================================================================
        "/opt/backup/db_backup_20240110.sql": (
            "-- MySQL dump 8.0.35\n"
            "-- Server version: 8.0.35-0ubuntu0.20.04.1\n"
            "\n"
            "CREATE DATABASE IF NOT EXISTS `production_db`;\n"
            "USE `production_db`;\n"
            "\n"
            "CREATE TABLE `users` (\n"
            "  `id` int NOT NULL AUTO_INCREMENT,\n"
            "  `username` varchar(50) NOT NULL,\n"
            "  `email` varchar(100) NOT NULL,\n"
            "  `password_hash` varchar(255) NOT NULL,\n"
            "  `role` enum('user','admin') DEFAULT 'user',\n"
            "  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,\n"
            "  PRIMARY KEY (`id`)\n"
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
            "\n"
            "INSERT INTO `users` VALUES\n"
            "(1,'admin','admin@company.com','$2y$10$hashedpassword...','admin','2023-06-15 10:00:00'),\n"
            "(2,'john.doe','john@company.com','$2y$10$anotherhash...','user','2023-07-20 14:30:00'),\n"
            "(3,'jane.smith','jane@company.com','$2y$10$yetanother...','user','2023-08-05 09:15:00');\n"
        ),
        # =====================================================================
        # /proc - Process information (limited fake entries)
        # =====================================================================
        "/proc/version": "Linux version 5.15.0-86-generic (buildd@lcy02-amd64-086) (gcc (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0, GNU ld (GNU Binutils for Ubuntu) 2.34) #96-Ubuntu SMP Wed Sep 20 08:23:49 UTC 2023\n",
        "/proc/cpuinfo": (
            "processor\t: 0\n"
            "vendor_id\t: GenuineIntel\n"
            "cpu family\t: 6\n"
            "model\t\t: 85\n"
            "model name\t: Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz\n"
            "stepping\t: 4\n"
            "microcode\t: 0x5003604\n"
            "cpu MHz\t\t: 2499.998\n"
            "cache size\t: 33792 KB\n"
            "physical id\t: 0\n"
            "siblings\t: 2\n"
            "core id\t\t: 0\n"
            "cpu cores\t: 1\n"
            "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon rep_good nopl xtopology\n"
            "bogomips\t: 4999.99\n"
            "\n"
            "processor\t: 1\n"
            "vendor_id\t: GenuineIntel\n"
            "cpu family\t: 6\n"
            "model\t\t: 85\n"
            "model name\t: Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz\n"
            "cpu MHz\t\t: 2499.998\n"
            "cache size\t: 33792 KB\n"
            "cpu cores\t: 1\n"
        ),
        "/proc/meminfo": (
            "MemTotal:        4028440 kB\n"
            "MemFree:         1524680 kB\n"
            "MemAvailable:    2847320 kB\n"
            "Buffers:          145892 kB\n"
            "Cached:          1356744 kB\n"
            "SwapCached:            0 kB\n"
            "Active:          1523456 kB\n"
            "Inactive:         723456 kB\n"
            "SwapTotal:       2097148 kB\n"
            "SwapFree:        2097148 kB\n"
        ),
        "/proc/uptime": "1234567.89 2345678.90\n",
        "/proc/loadavg": "0.15 0.10 0.05 1/234 5678\n",
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
    sys_state_raw = state.get("system_state")
    if sys_state_raw is None:
        sys_state = init_system_state()
        state["system_state"] = sys_state
    else:
        sys_state = cast(SystemState, sys_state_raw)

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
    # Normalize Unicode to prevent homoglyph attacks
    # NFKC normalization converts visually similar characters to their canonical forms
    normalized = unicodedata.normalize("NFKC", command)
    
    # Also normalize whitespace to prevent obfuscation via tabs, zero-width spaces, etc.
    # Replace all whitespace variations with single space
    normalized = re.sub(r'\s+', ' ', normalized)
    
    # Check standard patterns on normalized input
    for pattern in INJECTION_REGEX:
        if pattern.search(normalized):
            return True

    # Check encoded/obfuscated patterns
    for pattern in ENCODED_INJECTION_REGEX:
        if pattern.search(normalized):
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
    ttp_state_raw = session_state.get("ttp_state")
    if ttp_state_raw is None:
        ttp_state = init_ttp_state()
        session_state["ttp_state"] = ttp_state
    else:
        ttp_state = cast(SessionTTPState, ttp_state_raw)
    analyze_command(cmd, ttp_state)

    # Check for honeytoken access
    honeytokens_raw = session_state.get("honeytokens")
    honeytokens = (
        cast(SessionHoneytokens, honeytokens_raw)
        if honeytokens_raw is not None
        else None
    )
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
