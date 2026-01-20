"""TTP (Tactics, Techniques, and Procedures) detection for MiragePot.

Tracks command sequences to identify attack stages and patterns based on
MITRE ATT&CK framework concepts:

Attack Stages:
- reconnaissance: System enumeration, user discovery, network scanning
- credential_access: Password file access, credential harvesting
- persistence: Cron jobs, SSH keys, startup scripts, backdoors
- privilege_escalation: Sudo abuse, SUID exploitation, kernel exploits
- defense_evasion: Log tampering, history clearing, process hiding
- lateral_movement: SSH to other hosts, network pivoting
- collection: Data gathering, file archiving
- exfiltration: Data transfer out, curl/wget to external hosts
- impact: File deletion, system modification, ransomware indicators

Each command is analyzed individually and in context of the session history
to detect multi-step attack patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum


class AttackStage(Enum):
    """Attack stages based on MITRE ATT&CK kill chain."""

    RECONNAISSANCE = "reconnaissance"
    CREDENTIAL_ACCESS = "credential_access"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    UNKNOWN = "unknown"


@dataclass
class TTPIndicator:
    """A detected TTP indicator."""

    technique_id: str  # MITRE ATT&CK technique ID (e.g., T1087)
    technique_name: str  # Human-readable name
    stage: AttackStage  # Attack stage
    confidence: str  # low, medium, high
    command: str  # The command that triggered this
    description: str  # What was detected
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "stage": self.stage.value,
            "confidence": self.confidence,
            "command": self.command,
            "description": self.description,
            "timestamp": self.timestamp,
        }


@dataclass
class SessionTTPState:
    """Tracks TTP state across a session."""

    commands_history: List[str] = field(default_factory=list)
    indicators: List[TTPIndicator] = field(default_factory=list)
    stages_seen: Set[str] = field(default_factory=set)
    current_stage: AttackStage = AttackStage.UNKNOWN

    # Track specific activities for pattern detection
    recon_commands: int = 0
    credential_commands: int = 0
    persistence_commands: int = 0
    files_accessed: List[str] = field(default_factory=list)
    hosts_contacted: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "commands_history": self.commands_history,
            "indicators": [i.to_dict() for i in self.indicators],
            "stages_seen": list(self.stages_seen),
            "current_stage": self.current_stage.value,
            "recon_commands": self.recon_commands,
            "credential_commands": self.credential_commands,
            "persistence_commands": self.persistence_commands,
            "files_accessed": self.files_accessed,
            "hosts_contacted": self.hosts_contacted,
        }


# TTP detection patterns - command patterns mapped to techniques
# Format: (regex_pattern, technique_id, technique_name, stage, confidence, description)

SINGLE_COMMAND_PATTERNS: List[Tuple[str, str, str, AttackStage, str, str]] = [
    # Reconnaissance - System Information Discovery (T1082)
    (
        r"^uname\b",
        "T1082",
        "System Information Discovery",
        AttackStage.RECONNAISSANCE,
        "medium",
        "System information gathering",
    ),
    (
        r"^cat\s+/etc/os-release",
        "T1082",
        "System Information Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "OS version discovery",
    ),
    (
        r"^cat\s+/etc/issue",
        "T1082",
        "System Information Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "OS identification",
    ),
    (
        r"^hostnamectl",
        "T1082",
        "System Information Discovery",
        AttackStage.RECONNAISSANCE,
        "medium",
        "Hostname and OS discovery",
    ),
    (
        r"^lsb_release",
        "T1082",
        "System Information Discovery",
        AttackStage.RECONNAISSANCE,
        "medium",
        "Linux distribution discovery",
    ),
    (
        r"^cat\s+/proc/version",
        "T1082",
        "System Information Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "Kernel version discovery",
    ),
    # Reconnaissance - Account Discovery (T1087)
    (
        r"^cat\s+/etc/passwd",
        "T1087.001",
        "Local Account Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "User account enumeration",
    ),
    (
        r"^cat\s+/etc/group",
        "T1087.001",
        "Local Account Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "Group enumeration",
    ),
    (
        r"^getent\s+passwd",
        "T1087.001",
        "Local Account Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "User account enumeration via getent",
    ),
    (
        r"^whoami",
        "T1087.001",
        "Local Account Discovery",
        AttackStage.RECONNAISSANCE,
        "low",
        "Current user identification",
    ),
    (
        r"^id\b",
        "T1087.001",
        "Local Account Discovery",
        AttackStage.RECONNAISSANCE,
        "low",
        "Current user/group identification",
    ),
    (
        r"^w\b",
        "T1087.001",
        "Local Account Discovery",
        AttackStage.RECONNAISSANCE,
        "medium",
        "Logged-in users discovery",
    ),
    (
        r"^who\b",
        "T1087.001",
        "Local Account Discovery",
        AttackStage.RECONNAISSANCE,
        "medium",
        "Logged-in users discovery",
    ),
    (
        r"^last\b",
        "T1087.001",
        "Local Account Discovery",
        AttackStage.RECONNAISSANCE,
        "medium",
        "Login history discovery",
    ),
    (
        r"^users\b",
        "T1087.001",
        "Local Account Discovery",
        AttackStage.RECONNAISSANCE,
        "medium",
        "Current users discovery",
    ),
    # Reconnaissance - System Network Configuration Discovery (T1016)
    (
        r"^ifconfig",
        "T1016",
        "System Network Configuration Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "Network interface enumeration",
    ),
    (
        r"^ip\s+addr",
        "T1016",
        "System Network Configuration Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "Network interface enumeration",
    ),
    (
        r"^ip\s+a\b",
        "T1016",
        "System Network Configuration Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "Network interface enumeration",
    ),
    (
        r"^ip\s+route",
        "T1016",
        "System Network Configuration Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "Routing table discovery",
    ),
    (
        r"^netstat",
        "T1016",
        "System Network Configuration Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "Network connections enumeration",
    ),
    (
        r"^ss\s",
        "T1016",
        "System Network Configuration Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "Socket statistics enumeration",
    ),
    (
        r"^cat\s+/etc/resolv\.conf",
        "T1016",
        "System Network Configuration Discovery",
        AttackStage.RECONNAISSANCE,
        "medium",
        "DNS configuration discovery",
    ),
    (
        r"^cat\s+/etc/hosts",
        "T1016",
        "System Network Configuration Discovery",
        AttackStage.RECONNAISSANCE,
        "medium",
        "Hosts file discovery",
    ),
    (
        r"^arp\s+-a",
        "T1016",
        "System Network Configuration Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "ARP cache enumeration",
    ),
    # Reconnaissance - Process Discovery (T1057)
    (
        r"^ps\s+aux",
        "T1057",
        "Process Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "Process enumeration",
    ),
    (
        r"^ps\s+-ef",
        "T1057",
        "Process Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "Process enumeration",
    ),
    (
        r"^top\b",
        "T1057",
        "Process Discovery",
        AttackStage.RECONNAISSANCE,
        "medium",
        "Process monitoring",
    ),
    (
        r"^pgrep\b",
        "T1057",
        "Process Discovery",
        AttackStage.RECONNAISSANCE,
        "medium",
        "Process search",
    ),
    # Reconnaissance - File and Directory Discovery (T1083)
    (
        r"^ls\s+/",
        "T1083",
        "File and Directory Discovery",
        AttackStage.RECONNAISSANCE,
        "low",
        "Root filesystem enumeration",
    ),
    (
        r"^ls\s+/home",
        "T1083",
        "File and Directory Discovery",
        AttackStage.RECONNAISSANCE,
        "medium",
        "Home directory enumeration",
    ),
    (
        r"^ls\s+/root",
        "T1083",
        "File and Directory Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "Root home enumeration",
    ),
    (
        r"^find\s+/\s+-name",
        "T1083",
        "File and Directory Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "System-wide file search",
    ),
    (
        r"^locate\s",
        "T1083",
        "File and Directory Discovery",
        AttackStage.RECONNAISSANCE,
        "medium",
        "File location search",
    ),
    (
        r"^ls\s+-la\s+/var/www",
        "T1083",
        "File and Directory Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "Web directory enumeration",
    ),
    (
        r"^ls\s+/var/log",
        "T1083",
        "File and Directory Discovery",
        AttackStage.RECONNAISSANCE,
        "medium",
        "Log directory enumeration",
    ),
    # Reconnaissance - Software Discovery (T1518)
    (
        r"^dpkg\s+-l",
        "T1518",
        "Software Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "Installed packages enumeration",
    ),
    (
        r"^apt\s+list\s+--installed",
        "T1518",
        "Software Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "Installed packages enumeration",
    ),
    (
        r"^rpm\s+-qa",
        "T1518",
        "Software Discovery",
        AttackStage.RECONNAISSANCE,
        "high",
        "Installed packages enumeration",
    ),
    (
        r"^which\s",
        "T1518",
        "Software Discovery",
        AttackStage.RECONNAISSANCE,
        "low",
        "Binary location discovery",
    ),
    (
        r"^whereis\s",
        "T1518",
        "Software Discovery",
        AttackStage.RECONNAISSANCE,
        "low",
        "Binary location discovery",
    ),
    # Credential Access - Credential Dumping (T1003)
    (
        r"^cat\s+/etc/shadow",
        "T1003.008",
        "Credential Dumping",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "Shadow file access attempt",
    ),
    (
        r"^cat\s+/etc/master\.passwd",
        "T1003.008",
        "Credential Dumping",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "BSD password file access",
    ),
    (
        r"^unshadow\b",
        "T1003.008",
        "Credential Dumping",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "Password hash extraction",
    ),
    (
        r"^john\b",
        "T1003.008",
        "Credential Dumping",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "Password cracking attempt",
    ),
    (
        r"^hashcat\b",
        "T1003.008",
        "Credential Dumping",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "Password cracking attempt",
    ),
    # Credential Access - Credentials in Files (T1552.001)
    (
        r"grep.*password",
        "T1552.001",
        "Credentials in Files",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "Password string search",
    ),
    (
        r"grep.*passwd",
        "T1552.001",
        "Credentials in Files",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "Password string search",
    ),
    (
        r"grep.*secret",
        "T1552.001",
        "Credentials in Files",
        AttackStage.CREDENTIAL_ACCESS,
        "medium",
        "Secret string search",
    ),
    (
        r"grep.*api.?key",
        "T1552.001",
        "Credentials in Files",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "API key search",
    ),
    (
        r"grep.*token",
        "T1552.001",
        "Credentials in Files",
        AttackStage.CREDENTIAL_ACCESS,
        "medium",
        "Token string search",
    ),
    (
        r"cat.*\.env",
        "T1552.001",
        "Credentials in Files",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "Environment file access",
    ),
    (
        r"cat.*config.*\.php",
        "T1552.001",
        "Credentials in Files",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "PHP config file access",
    ),
    (
        r"cat.*\.htpasswd",
        "T1552.001",
        "Credentials in Files",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "HTTP auth file access",
    ),
    (
        r"cat.*/\.ssh/",
        "T1552.001",
        "Credentials in Files",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "SSH directory access",
    ),
    (
        r"cat.*id_rsa",
        "T1552.004",
        "Private Keys",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "SSH private key access",
    ),
    (
        r"cat.*\.pem",
        "T1552.004",
        "Private Keys",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "PEM key file access",
    ),
    (
        r"cat.*credentials",
        "T1552.001",
        "Credentials in Files",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "Credentials file access",
    ),
    (
        r"cat.*/\.aws/",
        "T1552.001",
        "Credentials in Files",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "AWS credentials access",
    ),
    (
        r"cat.*/\.azure/",
        "T1552.001",
        "Credentials in Files",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "Azure credentials access",
    ),
    (
        r"cat.*/\.gcp/",
        "T1552.001",
        "Credentials in Files",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "GCP credentials access",
    ),
    (
        r"cat.*password",
        "T1552.001",
        "Credentials in Files",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "Password file access",
    ),
    # Persistence - Cron (T1053.003)
    (
        r"crontab\s+-e",
        "T1053.003",
        "Scheduled Task/Job: Cron",
        AttackStage.PERSISTENCE,
        "high",
        "Cron job modification",
    ),
    (
        r"crontab\s+-l",
        "T1053.003",
        "Scheduled Task/Job: Cron",
        AttackStage.PERSISTENCE,
        "medium",
        "Cron job enumeration",
    ),
    (
        r"echo.*>>.*/cron",
        "T1053.003",
        "Scheduled Task/Job: Cron",
        AttackStage.PERSISTENCE,
        "high",
        "Cron job creation",
    ),
    (
        r"cat\s+/etc/crontab",
        "T1053.003",
        "Scheduled Task/Job: Cron",
        AttackStage.PERSISTENCE,
        "medium",
        "System cron enumeration",
    ),
    (
        r"ls\s+/etc/cron\.",
        "T1053.003",
        "Scheduled Task/Job: Cron",
        AttackStage.PERSISTENCE,
        "medium",
        "Cron directories enumeration",
    ),
    # Persistence - SSH Authorized Keys (T1098.004)
    (
        r"echo.*>>.*authorized_keys",
        "T1098.004",
        "SSH Authorized Keys",
        AttackStage.PERSISTENCE,
        "high",
        "SSH key injection",
    ),
    (
        r"cat.*>>.*authorized_keys",
        "T1098.004",
        "SSH Authorized Keys",
        AttackStage.PERSISTENCE,
        "high",
        "SSH key injection",
    ),
    (
        r"echo.*>.*authorized_keys",
        "T1098.004",
        "SSH Authorized Keys",
        AttackStage.PERSISTENCE,
        "high",
        "SSH key replacement",
    ),
    # Persistence - Boot/Init Scripts (T1037)
    (
        r"echo.*>>.*/etc/rc\.local",
        "T1037.004",
        "RC Scripts",
        AttackStage.PERSISTENCE,
        "high",
        "RC script modification",
    ),
    (
        r"echo.*>>.*/etc/init\.d/",
        "T1037.004",
        "RC Scripts",
        AttackStage.PERSISTENCE,
        "high",
        "Init script creation",
    ),
    (
        r"systemctl\s+enable",
        "T1543.002",
        "Systemd Service",
        AttackStage.PERSISTENCE,
        "high",
        "Service persistence",
    ),
    (
        r"update-rc\.d.*enable",
        "T1543.002",
        "Systemd Service",
        AttackStage.PERSISTENCE,
        "high",
        "Service persistence",
    ),
    # Persistence - Backdoor User (T1136)
    (
        r"useradd\b",
        "T1136.001",
        "Local Account",
        AttackStage.PERSISTENCE,
        "high",
        "User account creation",
    ),
    (
        r"adduser\b",
        "T1136.001",
        "Local Account",
        AttackStage.PERSISTENCE,
        "high",
        "User account creation",
    ),
    (
        r"usermod.*-aG.*sudo",
        "T1136.001",
        "Local Account",
        AttackStage.PERSISTENCE,
        "high",
        "Privilege assignment",
    ),
    (
        r"usermod.*-aG.*wheel",
        "T1136.001",
        "Local Account",
        AttackStage.PERSISTENCE,
        "high",
        "Privilege assignment",
    ),
    (
        r"echo.*>>.*/etc/passwd",
        "T1136.001",
        "Local Account",
        AttackStage.PERSISTENCE,
        "high",
        "Direct passwd modification",
    ),
    (
        r"echo.*>>.*/etc/sudoers",
        "T1136.001",
        "Local Account",
        AttackStage.PERSISTENCE,
        "high",
        "Sudoers modification",
    ),
    # Persistence - Shell Config (T1546.004)
    (
        r"echo.*>>.*\.bashrc",
        "T1546.004",
        "Unix Shell Configuration Modification",
        AttackStage.PERSISTENCE,
        "high",
        "Bashrc backdoor",
    ),
    (
        r"echo.*>>.*\.bash_profile",
        "T1546.004",
        "Unix Shell Configuration Modification",
        AttackStage.PERSISTENCE,
        "high",
        "Bash profile backdoor",
    ),
    (
        r"echo.*>>.*\.profile",
        "T1546.004",
        "Unix Shell Configuration Modification",
        AttackStage.PERSISTENCE,
        "high",
        "Profile backdoor",
    ),
    (
        r"echo.*>>.*\.zshrc",
        "T1546.004",
        "Unix Shell Configuration Modification",
        AttackStage.PERSISTENCE,
        "high",
        "Zshrc backdoor",
    ),
    # Privilege Escalation - SUID (T1548.001)
    (
        r"find.*-perm.*4000",
        "T1548.001",
        "Setuid and Setgid",
        AttackStage.PRIVILEGE_ESCALATION,
        "high",
        "SUID binary search",
    ),
    (
        r"find.*-perm.*/4000",
        "T1548.001",
        "Setuid and Setgid",
        AttackStage.PRIVILEGE_ESCALATION,
        "high",
        "SUID binary search",
    ),
    (
        r"find.*-perm.*u=s",
        "T1548.001",
        "Setuid and Setgid",
        AttackStage.PRIVILEGE_ESCALATION,
        "high",
        "SUID binary search",
    ),
    (
        r"chmod\s+[0-7]*4[0-7]{3}",
        "T1548.001",
        "Setuid and Setgid",
        AttackStage.PRIVILEGE_ESCALATION,
        "high",
        "SUID bit setting",
    ),
    (
        r"chmod\s+u\+s",
        "T1548.001",
        "Setuid and Setgid",
        AttackStage.PRIVILEGE_ESCALATION,
        "high",
        "SUID bit setting",
    ),
    # Privilege Escalation - Sudo (T1548.003)
    (
        r"sudo\s+-l",
        "T1548.003",
        "Sudo and Sudo Caching",
        AttackStage.PRIVILEGE_ESCALATION,
        "high",
        "Sudo capabilities check",
    ),
    (
        r"sudo\s+su",
        "T1548.003",
        "Sudo and Sudo Caching",
        AttackStage.PRIVILEGE_ESCALATION,
        "high",
        "Root shell via sudo",
    ),
    (
        r"sudo\s+-i",
        "T1548.003",
        "Sudo and Sudo Caching",
        AttackStage.PRIVILEGE_ESCALATION,
        "high",
        "Root shell via sudo",
    ),
    (
        r"sudo\s+bash",
        "T1548.003",
        "Sudo and Sudo Caching",
        AttackStage.PRIVILEGE_ESCALATION,
        "high",
        "Root shell via sudo",
    ),
    (
        r"sudo\s+/bin/sh",
        "T1548.003",
        "Sudo and Sudo Caching",
        AttackStage.PRIVILEGE_ESCALATION,
        "high",
        "Root shell via sudo",
    ),
    # Privilege Escalation - Exploitation (T1068)
    (
        r"gcc.*-o.*exploit",
        "T1068",
        "Exploitation for Privilege Escalation",
        AttackStage.PRIVILEGE_ESCALATION,
        "high",
        "Exploit compilation",
    ),
    (
        r"\./exploit",
        "T1068",
        "Exploitation for Privilege Escalation",
        AttackStage.PRIVILEGE_ESCALATION,
        "high",
        "Exploit execution",
    ),
    (
        r"dirtycow",
        "T1068",
        "Exploitation for Privilege Escalation",
        AttackStage.PRIVILEGE_ESCALATION,
        "high",
        "Dirty COW exploit",
    ),
    (
        r"pwnkit",
        "T1068",
        "Exploitation for Privilege Escalation",
        AttackStage.PRIVILEGE_ESCALATION,
        "high",
        "PwnKit exploit",
    ),
    # Defense Evasion - Clear History (T1070.003)
    (
        r"history\s+-c",
        "T1070.003",
        "Clear Command History",
        AttackStage.DEFENSE_EVASION,
        "high",
        "Command history cleared",
    ),
    (
        r">\s*~?/\.bash_history",
        "T1070.003",
        "Clear Command History",
        AttackStage.DEFENSE_EVASION,
        "high",
        "Bash history cleared",
    ),
    (
        r"rm.*\.bash_history",
        "T1070.003",
        "Clear Command History",
        AttackStage.DEFENSE_EVASION,
        "high",
        "Bash history deleted",
    ),
    (
        r"unset\s+HISTFILE",
        "T1070.003",
        "Clear Command History",
        AttackStage.DEFENSE_EVASION,
        "high",
        "History file unset",
    ),
    (
        r"export\s+HISTSIZE=0",
        "T1070.003",
        "Clear Command History",
        AttackStage.DEFENSE_EVASION,
        "high",
        "History disabled",
    ),
    (
        r"set\s+\+o\s+history",
        "T1070.003",
        "Clear Command History",
        AttackStage.DEFENSE_EVASION,
        "high",
        "History disabled",
    ),
    # Defense Evasion - Log Tampering (T1070.002)
    (
        r">\s*/var/log/",
        "T1070.002",
        "Clear Linux or Mac System Logs",
        AttackStage.DEFENSE_EVASION,
        "high",
        "Log file cleared",
    ),
    (
        r"rm.*-rf.*/var/log",
        "T1070.002",
        "Clear Linux or Mac System Logs",
        AttackStage.DEFENSE_EVASION,
        "high",
        "Log directory deleted",
    ),
    (
        r"truncate.*/var/log",
        "T1070.002",
        "Clear Linux or Mac System Logs",
        AttackStage.DEFENSE_EVASION,
        "high",
        "Log file truncated",
    ),
    (
        r"shred.*/var/log",
        "T1070.002",
        "Clear Linux or Mac System Logs",
        AttackStage.DEFENSE_EVASION,
        "high",
        "Log file shredded",
    ),
    # Defense Evasion - Timestomping (T1070.006)
    (
        r"touch\s+-t",
        "T1070.006",
        "Timestomp",
        AttackStage.DEFENSE_EVASION,
        "medium",
        "File timestamp modification",
    ),
    (
        r"touch\s+-d",
        "T1070.006",
        "Timestomp",
        AttackStage.DEFENSE_EVASION,
        "medium",
        "File timestamp modification",
    ),
    (
        r"touch\s+-r",
        "T1070.006",
        "Timestomp",
        AttackStage.DEFENSE_EVASION,
        "high",
        "Timestamp copied from another file",
    ),
    # Defense Evasion - Disable Security Tools (T1562.001)
    (
        r"systemctl\s+stop.*firewall",
        "T1562.001",
        "Disable or Modify Tools",
        AttackStage.DEFENSE_EVASION,
        "high",
        "Firewall disabled",
    ),
    (
        r"systemctl\s+stop.*iptables",
        "T1562.001",
        "Disable or Modify Tools",
        AttackStage.DEFENSE_EVASION,
        "high",
        "Firewall disabled",
    ),
    (
        r"systemctl\s+stop.*auditd",
        "T1562.001",
        "Disable or Modify Tools",
        AttackStage.DEFENSE_EVASION,
        "high",
        "Audit daemon disabled",
    ),
    (
        r"service.*stop",
        "T1562.001",
        "Disable or Modify Tools",
        AttackStage.DEFENSE_EVASION,
        "medium",
        "Service stopped",
    ),
    (
        r"iptables\s+-F",
        "T1562.001",
        "Disable or Modify Tools",
        AttackStage.DEFENSE_EVASION,
        "high",
        "Firewall rules flushed",
    ),
    (
        r"ufw\s+disable",
        "T1562.001",
        "Disable or Modify Tools",
        AttackStage.DEFENSE_EVASION,
        "high",
        "UFW firewall disabled",
    ),
    (
        r"setenforce\s+0",
        "T1562.001",
        "Disable or Modify Tools",
        AttackStage.DEFENSE_EVASION,
        "high",
        "SELinux disabled",
    ),
    # Lateral Movement - SSH (T1021.004)
    (
        r"^ssh\s+\w+@",
        "T1021.004",
        "SSH",
        AttackStage.LATERAL_MOVEMENT,
        "high",
        "SSH to remote host",
    ),
    (
        r"^ssh\s+-i.*@",
        "T1021.004",
        "SSH",
        AttackStage.LATERAL_MOVEMENT,
        "high",
        "SSH with key to remote host",
    ),
    (
        r"^scp\s+.*@.*:",
        "T1021.004",
        "SSH",
        AttackStage.LATERAL_MOVEMENT,
        "high",
        "SCP file transfer",
    ),
    # Collection - Archive (T1560)
    (
        r"tar\s+.*cf",
        "T1560.001",
        "Archive via Utility",
        AttackStage.COLLECTION,
        "medium",
        "Archive creation",
    ),
    (
        r"tar\s+.*czf",
        "T1560.001",
        "Archive via Utility",
        AttackStage.COLLECTION,
        "medium",
        "Compressed archive creation",
    ),
    (
        r"zip\s+-r",
        "T1560.001",
        "Archive via Utility",
        AttackStage.COLLECTION,
        "medium",
        "Zip archive creation",
    ),
    (
        r"7z\s+a",
        "T1560.001",
        "Archive via Utility",
        AttackStage.COLLECTION,
        "medium",
        "7z archive creation",
    ),
    # Collection - Data from Local System (T1005)
    (
        r"cp.*\.ssh",
        "T1005",
        "Data from Local System",
        AttackStage.COLLECTION,
        "high",
        "SSH directory copied",
    ),
    (
        r"cp.*/etc/passwd",
        "T1005",
        "Data from Local System",
        AttackStage.COLLECTION,
        "high",
        "Password file copied",
    ),
    (
        r"cp.*/etc/shadow",
        "T1005",
        "Data from Local System",
        AttackStage.COLLECTION,
        "high",
        "Shadow file copied",
    ),
    # Exfiltration - Transfer (T1048)
    (
        r"curl.*-F.*@",
        "T1048",
        "Exfiltration Over Alternative Protocol",
        AttackStage.EXFILTRATION,
        "high",
        "File upload via curl",
    ),
    (
        r"curl.*--upload-file",
        "T1048",
        "Exfiltration Over Alternative Protocol",
        AttackStage.EXFILTRATION,
        "high",
        "File upload via curl",
    ),
    (
        r"curl.*-X\s*POST.*-d\s*@",
        "T1048",
        "Exfiltration Over Alternative Protocol",
        AttackStage.EXFILTRATION,
        "high",
        "Data exfiltration via POST",
    ),
    (
        r"nc\s+.*<",
        "T1048",
        "Exfiltration Over Alternative Protocol",
        AttackStage.EXFILTRATION,
        "high",
        "Netcat data transfer",
    ),
    (
        r"base64.*\|.*curl",
        "T1048",
        "Exfiltration Over Alternative Protocol",
        AttackStage.EXFILTRATION,
        "high",
        "Base64 encoded exfiltration",
    ),
    # Impact - Data Destruction (T1485)
    (
        r"rm\s+-rf\s+/",
        "T1485",
        "Data Destruction",
        AttackStage.IMPACT,
        "high",
        "System destruction attempt",
    ),
    (
        r"dd\s+if=/dev/zero",
        "T1485",
        "Data Destruction",
        AttackStage.IMPACT,
        "high",
        "Disk wiping",
    ),
    (
        r"dd\s+if=/dev/urandom",
        "T1485",
        "Data Destruction",
        AttackStage.IMPACT,
        "high",
        "Disk wiping",
    ),
    (
        r"shred\s+-",
        "T1485",
        "Data Destruction",
        AttackStage.IMPACT,
        "high",
        "Secure deletion",
    ),
    (
        r"mkfs\s+",
        "T1485",
        "Data Destruction",
        AttackStage.IMPACT,
        "high",
        "Filesystem recreation",
    ),
    # Impact - Service Stop (T1489)
    (
        r"systemctl\s+stop\s+\w+",
        "T1489",
        "Service Stop",
        AttackStage.IMPACT,
        "medium",
        "Service stopped",
    ),
    (
        r"killall\s+",
        "T1489",
        "Service Stop",
        AttackStage.IMPACT,
        "medium",
        "Process kill all",
    ),
    (
        r"pkill\s+",
        "T1489",
        "Service Stop",
        AttackStage.IMPACT,
        "medium",
        "Process pattern kill",
    ),
    # Execution - Command and Scripting Interpreter (T1059)
    (
        r"python.*-c",
        "T1059.006",
        "Python",
        AttackStage.RECONNAISSANCE,
        "medium",
        "Python one-liner execution",
    ),
    (
        r"perl.*-e",
        "T1059.004",
        "Unix Shell",
        AttackStage.RECONNAISSANCE,
        "medium",
        "Perl one-liner execution",
    ),
    (
        r"ruby.*-e",
        "T1059.006",
        "Ruby",
        AttackStage.RECONNAISSANCE,
        "medium",
        "Ruby one-liner execution",
    ),
    (
        r"bash\s+-c",
        "T1059.004",
        "Unix Shell",
        AttackStage.RECONNAISSANCE,
        "low",
        "Bash command execution",
    ),
    (
        r"sh\s+-c",
        "T1059.004",
        "Unix Shell",
        AttackStage.RECONNAISSANCE,
        "low",
        "Shell command execution",
    ),
    (
        r"\|.*bash",
        "T1059.004",
        "Unix Shell",
        AttackStage.RECONNAISSANCE,
        "high",
        "Piped to bash execution",
    ),
    (
        r"\|.*sh\b",
        "T1059.004",
        "Unix Shell",
        AttackStage.RECONNAISSANCE,
        "high",
        "Piped to shell execution",
    ),
]

# Multi-command patterns (command chains that together indicate an attack)
COMMAND_CHAIN_PATTERNS: List[Tuple[List[str], str, str, AttackStage, str, str]] = [
    # Recon chain
    (
        ["whoami", "id", "cat /etc/passwd"],
        "T1087",
        "Account Discovery Chain",
        AttackStage.RECONNAISSANCE,
        "high",
        "Classic reconnaissance sequence",
    ),
    (
        ["uname", "cat /etc/os-release", "ps"],
        "T1082",
        "System Discovery Chain",
        AttackStage.RECONNAISSANCE,
        "high",
        "System enumeration sequence",
    ),
    (
        ["ifconfig", "netstat", "arp"],
        "T1016",
        "Network Discovery Chain",
        AttackStage.RECONNAISSANCE,
        "high",
        "Network enumeration sequence",
    ),
    # Credential harvesting chain
    (
        ["cat /etc/passwd", "cat /etc/shadow"],
        "T1003",
        "Credential Harvesting",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "Password file access sequence",
    ),
    (
        ["find", "grep.*password"],
        "T1552",
        "Credential Search",
        AttackStage.CREDENTIAL_ACCESS,
        "high",
        "Credential file search sequence",
    ),
    # Payload download and execution
    (
        ["wget", "chmod +x"],
        "T1105",
        "Ingress Tool Transfer",
        AttackStage.PERSISTENCE,
        "high",
        "Download and prepare execution",
    ),
    (
        ["curl", "chmod +x"],
        "T1105",
        "Ingress Tool Transfer",
        AttackStage.PERSISTENCE,
        "high",
        "Download and prepare execution",
    ),
    (
        ["wget", "bash"],
        "T1059",
        "Command and Scripting Interpreter",
        AttackStage.PERSISTENCE,
        "high",
        "Download and execute script",
    ),
    # Persistence chain
    (
        ["useradd", "passwd"],
        "T1136",
        "Create Account",
        AttackStage.PERSISTENCE,
        "high",
        "Backdoor user creation",
    ),
    (
        ["echo", "authorized_keys"],
        "T1098.004",
        "SSH Authorized Keys",
        AttackStage.PERSISTENCE,
        "high",
        "SSH key injection",
    ),
    # Defense evasion chain
    (
        ["history -c", "rm.*history"],
        "T1070.003",
        "Clear Command History",
        AttackStage.DEFENSE_EVASION,
        "high",
        "Complete history removal",
    ),
    (
        ["unset HISTFILE", "export HISTSIZE=0"],
        "T1070.003",
        "Clear Command History",
        AttackStage.DEFENSE_EVASION,
        "high",
        "History logging disabled",
    ),
]

# Compile single command patterns for efficiency
COMPILED_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), tech_id, tech_name, stage, conf, desc)
    for pattern, tech_id, tech_name, stage, conf, desc in SINGLE_COMMAND_PATTERNS
]


def init_ttp_state() -> SessionTTPState:
    """Initialize TTP tracking state for a new session."""
    return SessionTTPState()


def analyze_command(command: str, ttp_state: SessionTTPState) -> List[TTPIndicator]:
    """Analyze a single command for TTP indicators.

    Args:
        command: The command to analyze
        ttp_state: The session's TTP tracking state

    Returns:
        List of detected TTP indicators
    """
    indicators: List[TTPIndicator] = []
    stripped = command.strip()

    if not stripped:
        return indicators

    # Add to command history
    ttp_state.commands_history.append(stripped)

    # Check single command patterns
    for (
        pattern,
        tech_id,
        tech_name,
        stage,
        confidence,
        description,
    ) in COMPILED_PATTERNS:
        if pattern.search(stripped):
            indicator = TTPIndicator(
                technique_id=tech_id,
                technique_name=tech_name,
                stage=stage,
                confidence=confidence,
                command=stripped,
                description=description,
            )
            indicators.append(indicator)
            ttp_state.stages_seen.add(stage.value)

            # Update stage-specific counters
            if stage == AttackStage.RECONNAISSANCE:
                ttp_state.recon_commands += 1
            elif stage == AttackStage.CREDENTIAL_ACCESS:
                ttp_state.credential_commands += 1
            elif stage == AttackStage.PERSISTENCE:
                ttp_state.persistence_commands += 1

    # Check command chain patterns
    chain_indicators = _check_command_chains(ttp_state)
    indicators.extend(chain_indicators)

    # Store all indicators
    ttp_state.indicators.extend(indicators)

    # Update current stage based on what we've seen
    ttp_state.current_stage = _determine_current_stage(ttp_state)

    return indicators


def _check_command_chains(ttp_state: SessionTTPState) -> List[TTPIndicator]:
    """Check for multi-command attack patterns."""
    indicators: List[TTPIndicator] = []
    history = ttp_state.commands_history

    if len(history) < 2:
        return indicators

    # Check each chain pattern against recent history
    for (
        chain_pattern,
        tech_id,
        tech_name,
        stage,
        confidence,
        description,
    ) in COMMAND_CHAIN_PATTERNS:
        if _matches_chain(history, chain_pattern):
            # Check if we already detected this chain
            chain_key = f"{tech_id}:{tech_name}"
            already_detected = any(
                f"{i.technique_id}:{i.technique_name}" == chain_key
                for i in ttp_state.indicators
            )
            if not already_detected:
                indicator = TTPIndicator(
                    technique_id=tech_id,
                    technique_name=tech_name,
                    stage=stage,
                    confidence=confidence,
                    command=f"[chain: {' -> '.join(chain_pattern)}]",
                    description=description,
                )
                indicators.append(indicator)
                ttp_state.stages_seen.add(stage.value)

    return indicators


def _matches_chain(history: List[str], chain: List[str]) -> bool:
    """Check if command history contains the chain pattern.

    The chain commands don't need to be consecutive, just in order.
    """
    chain_idx = 0
    for cmd in history:
        if chain_idx >= len(chain):
            break
        # Check if current command matches current chain element (substring match)
        if chain[chain_idx].lower() in cmd.lower():
            chain_idx += 1

    return chain_idx >= len(chain)


def _determine_current_stage(ttp_state: SessionTTPState) -> AttackStage:
    """Determine the current attack stage based on indicators."""
    stages_seen = ttp_state.stages_seen

    # Priority order for determining "current" stage
    stage_priority = [
        AttackStage.IMPACT,
        AttackStage.EXFILTRATION,
        AttackStage.LATERAL_MOVEMENT,
        AttackStage.COLLECTION,
        AttackStage.DEFENSE_EVASION,
        AttackStage.PERSISTENCE,
        AttackStage.PRIVILEGE_ESCALATION,
        AttackStage.CREDENTIAL_ACCESS,
        AttackStage.RECONNAISSANCE,
    ]

    for stage in stage_priority:
        if stage.value in stages_seen:
            return stage

    return AttackStage.UNKNOWN


def get_attack_summary(ttp_state: SessionTTPState) -> Dict[str, Any]:
    """Get a summary of the attack based on TTP state.

    Returns a dictionary with:
    - current_stage: The most advanced attack stage detected
    - stages_seen: List of all attack stages observed
    - technique_count: Number of unique techniques detected
    - risk_level: Overall risk assessment (low/medium/high/critical)
    - key_indicators: Most significant TTP indicators
    """
    # Count unique techniques
    techniques = set(i.technique_id for i in ttp_state.indicators)

    # Determine risk level
    high_confidence_count = sum(
        1 for i in ttp_state.indicators if i.confidence == "high"
    )
    stages_count = len(ttp_state.stages_seen)

    if (
        AttackStage.IMPACT.value in ttp_state.stages_seen
        or AttackStage.EXFILTRATION.value in ttp_state.stages_seen
        or high_confidence_count >= 5
    ):
        risk_level = "critical"
    elif (
        AttackStage.PERSISTENCE.value in ttp_state.stages_seen
        or AttackStage.LATERAL_MOVEMENT.value in ttp_state.stages_seen
        or high_confidence_count >= 3
    ):
        risk_level = "high"
    elif stages_count >= 2 or high_confidence_count >= 1:
        risk_level = "medium"
    else:
        risk_level = "low"

    # Get key indicators (high confidence only)
    key_indicators = [
        i.to_dict() for i in ttp_state.indicators if i.confidence == "high"
    ][:10]  # Limit to top 10

    return {
        "current_stage": ttp_state.current_stage.value,
        "stages_seen": list(ttp_state.stages_seen),
        "technique_count": len(techniques),
        "total_indicators": len(ttp_state.indicators),
        "risk_level": risk_level,
        "key_indicators": key_indicators,
        "recon_commands": ttp_state.recon_commands,
        "credential_commands": ttp_state.credential_commands,
        "persistence_commands": ttp_state.persistence_commands,
    }


def is_high_risk_command(command: str) -> bool:
    """Quick check if a command is high-risk without full TTP analysis.

    Useful for immediate threat assessment.
    """
    high_risk_patterns = [
        r"rm\s+-rf\s+/",
        r"cat\s+/etc/shadow",
        r"echo.*authorized_keys",
        r"useradd\b",
        r"chmod\s+[0-7]*4[0-7]{3}",
        r"history\s+-c",
        r"\|.*bash",
        r"wget.*\|.*sh",
        r"curl.*\|.*bash",
        r"nc\s+.*-e",  # Netcat reverse shell
        r"python.*socket",  # Python reverse shell
        r"perl.*socket",  # Perl reverse shell
        r"mkfifo",  # Named pipe (often used for reverse shells)
    ]

    for pattern in high_risk_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            return True

    return False
