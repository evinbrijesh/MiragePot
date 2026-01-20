"""Virtual filesystem with realistic file metadata for MiragePot.

This module provides a more realistic fake filesystem with:
- File/directory permissions (mode bits)
- Owner/group information (uid/gid and names)
- Timestamps (mtime, atime, ctime)
- File sizes
- Hard link counts
- Support for stat, chmod, chown, find commands
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class FileMetadata:
    """Metadata for a file or directory in the virtual filesystem.

    Attributes:
        mode: Unix permission mode (e.g., 0o755 for rwxr-xr-x)
        is_dir: Whether this is a directory
        uid: Owner user ID
        gid: Owner group ID
        owner: Owner username
        group: Group name
        size: File size in bytes
        nlink: Number of hard links
        mtime: Modification time (Unix timestamp)
        atime: Access time (Unix timestamp)
        ctime: Change time (Unix timestamp)
        inode: Fake inode number
    """

    mode: int = 0o644
    is_dir: bool = False
    uid: int = 0
    gid: int = 0
    owner: str = "root"
    group: str = "root"
    size: int = 0
    nlink: int = 1
    mtime: float = 0.0
    atime: float = 0.0
    ctime: float = 0.0
    inode: int = 0

    def __post_init__(self):
        """Set default timestamps if not provided."""
        now = time.time()
        if self.mtime == 0.0:
            # Random time in the past 90 days
            self.mtime = now - random.randint(0, 90 * 24 * 3600)
        if self.atime == 0.0:
            self.atime = self.mtime + random.randint(0, 3600)
        if self.ctime == 0.0:
            self.ctime = self.mtime
        if self.inode == 0:
            self.inode = random.randint(100000, 999999)
        if self.is_dir:
            self.nlink = 2  # . and ..
            if self.mode == 0o644:
                self.mode = 0o755  # Default dir permissions

    def format_mode_string(self) -> str:
        """Format mode as ls -l style string (e.g., drwxr-xr-x)."""
        type_char = "d" if self.is_dir else "-"

        # Owner permissions
        owner = ""
        owner += "r" if self.mode & 0o400 else "-"
        owner += "w" if self.mode & 0o200 else "-"
        owner += "x" if self.mode & 0o100 else "-"

        # Group permissions
        group = ""
        group += "r" if self.mode & 0o040 else "-"
        group += "w" if self.mode & 0o020 else "-"
        group += "x" if self.mode & 0o010 else "-"

        # Other permissions
        other = ""
        other += "r" if self.mode & 0o004 else "-"
        other += "w" if self.mode & 0o002 else "-"
        other += "x" if self.mode & 0o001 else "-"

        return f"{type_char}{owner}{group}{other}"

    def format_mtime(self) -> str:
        """Format mtime for ls -l output."""
        dt = datetime.fromtimestamp(self.mtime)
        now = datetime.now()

        # If within last 6 months, show month day time
        # Otherwise show month day year
        if (now - dt).days < 180:
            return dt.strftime("%b %d %H:%M")
        else:
            return dt.strftime("%b %d  %Y")

    def format_ls_long(self, name: str) -> str:
        """Format for ls -l output."""
        mode_str = self.format_mode_string()
        mtime_str = self.format_mtime()
        return f"{mode_str} {self.nlink:>2} {self.owner:<8} {self.group:<8} {self.size:>8} {mtime_str} {name}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "mode": oct(self.mode),
            "is_dir": self.is_dir,
            "uid": self.uid,
            "gid": self.gid,
            "owner": self.owner,
            "group": self.group,
            "size": self.size,
            "nlink": self.nlink,
            "mtime": self.mtime,
            "atime": self.atime,
            "ctime": self.ctime,
            "inode": self.inode,
        }


def create_default_metadata(
    content: str = "",
    is_dir: bool = False,
    mode: Optional[int] = None,
    owner: str = "root",
    group: str = "root",
) -> FileMetadata:
    """Create FileMetadata with sensible defaults.

    Args:
        content: File content (used to calculate size)
        is_dir: Whether this is a directory
        mode: Unix mode, or None for default
        owner: Owner username
        group: Group name

    Returns:
        FileMetadata instance
    """
    if mode is None:
        mode = 0o755 if is_dir else 0o644

    size = 4096 if is_dir else len(content)

    return FileMetadata(
        mode=mode,
        is_dir=is_dir,
        owner=owner,
        group=group,
        size=size,
    )


def init_filesystem_metadata() -> Dict[str, FileMetadata]:
    """Initialize metadata for the default filesystem.

    Returns a dict mapping paths to FileMetadata.
    """
    now = time.time()
    # System directories - created long ago
    old_time = now - (365 * 24 * 3600)  # 1 year ago
    boot_time = now - (42 * 24 * 3600)  # 42 days ago (uptime)

    metadata: Dict[str, FileMetadata] = {}

    # System directories
    system_dirs = [
        "/",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/lib64",
        "/media",
        "/mnt",
        "/opt",
        "/proc",
        "/run",
        "/sbin",
        "/srv",
        "/sys",
        "/tmp",
        "/usr",
        "/usr/local",
        "/var",
    ]
    for d in system_dirs:
        metadata[d] = FileMetadata(
            mode=0o755,
            is_dir=True,
            mtime=old_time + random.randint(0, 30 * 24 * 3600),
        )

    # /tmp should be writable by all
    metadata["/tmp"].mode = 0o1777

    # User directories
    user_dirs = ["/root", "/home/user", "/home/user/Documents"]
    for d in user_dirs:
        owner = "root" if d.startswith("/root") else "user"
        uid = 0 if owner == "root" else 1000
        metadata[d] = FileMetadata(
            mode=0o700 if d == "/root" else 0o755,
            is_dir=True,
            uid=uid,
            owner=owner,
            group=owner,
            mtime=boot_time + random.randint(0, 7 * 24 * 3600),
        )

    # Web directories
    web_dirs = ["/var/www", "/var/www/html", "/var/log", "/opt/legacy_backup"]
    for d in web_dirs:
        owner = "www-data" if "www" in d else "root"
        gid = 33 if owner == "www-data" else 0
        metadata[d] = FileMetadata(
            mode=0o755,
            is_dir=True,
            uid=33 if owner == "www-data" else 0,
            gid=gid,
            owner=owner,
            group=owner,
            mtime=boot_time - random.randint(0, 30 * 24 * 3600),
        )

    # SSH directory
    metadata["/home/user/.ssh"] = FileMetadata(
        mode=0o700,
        is_dir=True,
        uid=1000,
        owner="user",
        group="user",
    )

    return metadata


# User and group databases for lookups
USERS = {
    0: "root",
    1: "daemon",
    2: "bin",
    33: "www-data",
    100: "sshd",
    1000: "user",
}

GROUPS = {
    0: "root",
    1: "daemon",
    2: "bin",
    33: "www-data",
    100: "nogroup",
    1000: "user",
}


def get_username(uid: int) -> str:
    """Get username for a UID."""
    return USERS.get(uid, str(uid))


def get_groupname(gid: int) -> str:
    """Get group name for a GID."""
    return GROUPS.get(gid, str(gid))


def format_stat_output(path: str, meta: FileMetadata, content: str = "") -> str:
    """Format output for the stat command.

    Args:
        path: File/directory path
        meta: FileMetadata for the path
        content: File content (for calculating actual size)

    Returns:
        stat command output string
    """
    # Determine file type
    if meta.is_dir:
        file_type = "directory"
    else:
        file_type = "regular file"
        if content and not content.strip():
            file_type = "regular empty file"

    # Size
    size = meta.size if meta.is_dir else len(content)
    blocks = (size + 511) // 512  # Round up to 512-byte blocks

    # Device (fake)
    device = "801h/2049d"

    # Format times
    def format_time(ts: float) -> str:
        dt = datetime.fromtimestamp(ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " +0000"

    access_time = format_time(meta.atime)
    modify_time = format_time(meta.mtime)
    change_time = format_time(meta.ctime)
    birth_time = "-"  # Linux typically doesn't track birth time

    name = path.split("/")[-1] if path != "/" else "/"

    output = f"""  File: {path}
  Size: {size:<15} Blocks: {blocks:<10} IO Block: 4096   {file_type}
Device: {device:<15} Inode: {meta.inode:<11} Links: {meta.nlink}
Access: ({oct(meta.mode)[2:]:>04}/{meta.format_mode_string()})  Uid: ({meta.uid:>5}/{meta.owner:<8})   Gid: ({meta.gid:>5}/{meta.group:<8})
Access: {access_time}
Modify: {modify_time}
Change: {change_time}
 Birth: {birth_time}"""

    return output


def handle_stat_command(
    args: str,
    state: Dict[str, Any],
) -> str:
    """Handle the stat command.

    Args:
        args: Command arguments
        state: Session state

    Returns:
        stat command output
    """
    cwd = state.get("cwd", "/root")
    directories = state.get("directories", set())
    files = state.get("files", {})
    file_metadata = state.get("file_metadata", {})

    parts = [p for p in args.split() if p and not p.startswith("-")]
    if not parts:
        return "stat: missing operand\n"

    outputs = []
    for target in parts:
        # Normalize path
        if target.startswith("/"):
            path = target
        else:
            path = cwd.rstrip("/") + "/" + target

        # Clean up path
        while "//" in path:
            path = path.replace("//", "/")
        if len(path) > 1 and path.endswith("/"):
            path = path[:-1]

        # Check if exists
        if path not in directories and path not in files:
            outputs.append(f"stat: cannot stat '{target}': No such file or directory")
            continue

        # Get or create metadata
        if path in file_metadata:
            meta = file_metadata[path]
        else:
            is_dir = path in directories
            content = files.get(path, "")
            meta = create_default_metadata(content, is_dir)
            file_metadata[path] = meta

        content = files.get(path, "")
        outputs.append(format_stat_output(path, meta, content))

    state["file_metadata"] = file_metadata
    return "\n".join(outputs) + "\n"


def handle_chmod_command(
    args: str,
    state: Dict[str, Any],
) -> str:
    """Handle the chmod command (simulated).

    Args:
        args: Command arguments (e.g., "755 file.txt")
        state: Session state

    Returns:
        chmod command output (usually empty on success)
    """
    cwd = state.get("cwd", "/root")
    directories = state.get("directories", set())
    files = state.get("files", {})
    file_metadata = state.get("file_metadata", {})

    parts = args.split()
    if len(parts) < 2:
        return "chmod: missing operand\n"

    # Parse mode (simplified - just numeric modes)
    mode_str = parts[0]
    targets = parts[1:]

    # Parse numeric mode
    try:
        if mode_str.startswith("0"):
            mode = int(mode_str, 8)
        else:
            mode = int(mode_str, 8)
    except ValueError:
        # Symbolic mode (simplified)
        return ""  # Accept but don't actually change

    outputs = []
    for target in targets:
        # Normalize path
        if target.startswith("/"):
            path = target
        else:
            path = cwd.rstrip("/") + "/" + target

        while "//" in path:
            path = path.replace("//", "/")
        if len(path) > 1 and path.endswith("/"):
            path = path[:-1]

        if path not in directories and path not in files:
            outputs.append(
                f"chmod: cannot access '{target}': No such file or directory"
            )
            continue

        # Update metadata
        if path not in file_metadata:
            is_dir = path in directories
            content = files.get(path, "")
            file_metadata[path] = create_default_metadata(content, is_dir)

        file_metadata[path].mode = mode
        file_metadata[path].ctime = time.time()

    state["file_metadata"] = file_metadata

    if outputs:
        return "\n".join(outputs) + "\n"
    return ""


def handle_chown_command(
    args: str,
    state: Dict[str, Any],
) -> str:
    """Handle the chown command (simulated).

    Args:
        args: Command arguments (e.g., "root:root file.txt")
        state: Session state

    Returns:
        chown command output (usually empty on success)
    """
    cwd = state.get("cwd", "/root")
    directories = state.get("directories", set())
    files = state.get("files", {})
    file_metadata = state.get("file_metadata", {})

    parts = args.split()
    if len(parts) < 2:
        return "chown: missing operand\n"

    # Parse owner[:group]
    owner_spec = parts[0]
    targets = parts[1:]

    if ":" in owner_spec:
        owner, group = owner_spec.split(":", 1)
    else:
        owner = owner_spec
        group = None

    # Lookup uid/gid
    uid = None
    gid = None
    for u, name in USERS.items():
        if name == owner:
            uid = u
            break
    if uid is None:
        try:
            uid = int(owner)
        except ValueError:
            return f"chown: invalid user: '{owner}'\n"

    if group:
        for g, name in GROUPS.items():
            if name == group:
                gid = g
                break
        if gid is None:
            try:
                gid = int(group)
            except ValueError:
                return f"chown: invalid group: '{group}'\n"

    outputs = []
    for target in targets:
        # Normalize path
        if target.startswith("/"):
            path = target
        else:
            path = cwd.rstrip("/") + "/" + target

        while "//" in path:
            path = path.replace("//", "/")
        if len(path) > 1 and path.endswith("/"):
            path = path[:-1]

        if path not in directories and path not in files:
            outputs.append(
                f"chown: cannot access '{target}': No such file or directory"
            )
            continue

        # Update metadata
        if path not in file_metadata:
            is_dir = path in directories
            content = files.get(path, "")
            file_metadata[path] = create_default_metadata(content, is_dir)

        file_metadata[path].uid = uid
        file_metadata[path].owner = get_username(uid)
        if gid is not None:
            file_metadata[path].gid = gid
            file_metadata[path].group = get_groupname(gid)
        file_metadata[path].ctime = time.time()

    state["file_metadata"] = file_metadata

    if outputs:
        return "\n".join(outputs) + "\n"
    return ""


def handle_find_command(
    args: str,
    state: Dict[str, Any],
) -> str:
    """Handle the find command (simplified).

    Args:
        args: Command arguments
        state: Session state

    Returns:
        find command output
    """
    cwd = state.get("cwd", "/root")
    directories = state.get("directories", set())
    files = state.get("files", {})

    parts = args.split()

    # Determine starting path
    start_path = cwd
    name_pattern = None
    type_filter = None  # 'f' for file, 'd' for directory

    i = 0
    while i < len(parts):
        part = parts[i]
        if part == "-name" and i + 1 < len(parts):
            name_pattern = parts[i + 1].replace("*", "")  # Simplified glob
            i += 2
        elif part == "-type" and i + 1 < len(parts):
            type_filter = parts[i + 1]
            i += 2
        elif not part.startswith("-"):
            start_path = part if part.startswith("/") else cwd.rstrip("/") + "/" + part
            i += 1
        else:
            i += 1

    # Normalize start path
    while "//" in start_path:
        start_path = start_path.replace("//", "/")
    if len(start_path) > 1 and start_path.endswith("/"):
        start_path = start_path[:-1]

    if start_path not in directories:
        return f"find: '{start_path}': No such file or directory\n"

    results = []

    # Find matching directories
    if type_filter != "f":
        for d in sorted(directories):
            if d.startswith(start_path):
                name = d.split("/")[-1]
                if name_pattern is None or name_pattern in name:
                    results.append(d)

    # Find matching files
    if type_filter != "d":
        for f in sorted(files.keys()):
            if f.startswith(start_path):
                name = f.split("/")[-1]
                if name_pattern is None or name_pattern in name:
                    results.append(f)

    if not results:
        return ""

    return "\n".join(sorted(results)) + "\n"


__all__ = [
    "FileMetadata",
    "create_default_metadata",
    "init_filesystem_metadata",
    "format_stat_output",
    "handle_stat_command",
    "handle_chmod_command",
    "handle_chown_command",
    "handle_find_command",
    "USERS",
    "GROUPS",
    "get_username",
    "get_groupname",
]
