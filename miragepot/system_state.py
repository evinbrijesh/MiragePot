"""Virtual system state for realistic process and network simulation.

This module provides consistent fake system state including:
- Process list (ps, top)
- Network connections (netstat, ss)
- Memory usage (free)
- System uptime
- Logged in users (w, who)

The state is session-consistent, meaning the same PID refers to the
same process throughout a session, and system metrics are realistic.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class FakeProcess:
    """Represents a fake process in the virtual system."""

    pid: int
    user: str
    cpu: float
    mem: float
    vsz: int  # Virtual memory size in KB
    rss: int  # Resident set size in KB
    tty: str
    stat: str  # Process state (S, R, D, Z, etc.)
    start: str  # Start time
    time: str  # CPU time
    command: str
    ppid: int = 1  # Parent PID
    nice: int = 0
    priority: int = 20


@dataclass
class FakeConnection:
    """Represents a fake network connection."""

    proto: str  # tcp, tcp6, udp, udp6
    recv_q: int
    send_q: int
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str  # LISTEN, ESTABLISHED, TIME_WAIT, etc.
    pid: Optional[int] = None
    program: Optional[str] = None


@dataclass
class SystemState:
    """Maintains consistent system state for a session.

    This ensures that process lists, network connections, and system
    metrics remain consistent throughout the session.
    """

    # System boot time (for uptime calculation)
    boot_time: float = field(
        default_factory=lambda: time.time() - (42 * 24 * 3600 + 3 * 3600 + 15 * 60)
    )

    # Process list
    processes: List[FakeProcess] = field(default_factory=list)

    # Network connections
    connections: List[FakeConnection] = field(default_factory=list)

    # Memory stats (in MB)
    mem_total: int = 3934
    mem_used: int = 1216
    mem_free: int = 1487
    mem_buffers: int = 89
    mem_cached: int = 1141
    swap_total: int = 2048
    swap_used: int = 0

    # CPU info
    cpu_count: int = 2
    load_avg: Tuple[float, float, float] = (0.08, 0.12, 0.10)

    # Session info
    session_user: str = "root"
    session_tty: str = "pts/0"
    session_from: str = "unknown"

    def __post_init__(self):
        """Initialize default processes and connections if empty."""
        if not self.processes:
            self.processes = self._create_default_processes()
        if not self.connections:
            self.connections = self._create_default_connections()

    def _create_default_processes(self) -> List[FakeProcess]:
        """Create a realistic set of default processes."""
        now = datetime.now()
        boot = datetime.fromtimestamp(self.boot_time)

        processes = [
            FakeProcess(
                pid=1,
                user="root",
                cpu=0.0,
                mem=0.3,
                vsz=169260,
                rss=11560,
                tty="?",
                stat="Ss",
                start=boot.strftime("%b%d"),
                time="0:01",
                command="/sbin/init",
                ppid=0,
            ),
            FakeProcess(
                pid=2,
                user="root",
                cpu=0.0,
                mem=0.0,
                vsz=0,
                rss=0,
                tty="?",
                stat="S",
                start=boot.strftime("%b%d"),
                time="0:00",
                command="[kthreadd]",
                ppid=0,
            ),
            FakeProcess(
                pid=512,
                user="root",
                cpu=0.0,
                mem=0.2,
                vsz=15420,
                rss=6400,
                tty="?",
                stat="Ss",
                start=boot.strftime("%b%d"),
                time="0:00",
                command="/usr/sbin/sshd -D",
                ppid=1,
            ),
            FakeProcess(
                pid=650,
                user="root",
                cpu=0.0,
                mem=0.1,
                vsz=11264,
                rss=3200,
                tty="?",
                stat="Ss",
                start=boot.strftime("%b%d"),
                time="0:00",
                command="/usr/sbin/cron -f",
                ppid=1,
            ),
            FakeProcess(
                pid=720,
                user="syslog",
                cpu=0.0,
                mem=0.1,
                vsz=224344,
                rss=4608,
                tty="?",
                stat="Ssl",
                start=boot.strftime("%b%d"),
                time="0:02",
                command="/usr/sbin/rsyslogd -n",
                ppid=1,
            ),
            FakeProcess(
                pid=900,
                user="www-data",
                cpu=0.0,
                mem=0.3,
                vsz=55280,
                rss=10240,
                tty="?",
                stat="S",
                start=boot.strftime("%b%d"),
                time="0:00",
                command="nginx: worker process",
                ppid=899,
            ),
            FakeProcess(
                pid=899,
                user="root",
                cpu=0.0,
                mem=0.1,
                vsz=55028,
                rss=5120,
                tty="?",
                stat="Ss",
                start=boot.strftime("%b%d"),
                time="0:00",
                command="nginx: master process /usr/sbin/nginx",
                ppid=1,
            ),
            FakeProcess(
                pid=950,
                user="mysql",
                cpu=0.1,
                mem=2.5,
                vsz=1256000,
                rss=98304,
                tty="?",
                stat="Ssl",
                start=boot.strftime("%b%d"),
                time="1:23",
                command="/usr/sbin/mysqld",
                ppid=1,
            ),
        ]

        # Add the attacker's SSH session
        session_start = (now - timedelta(minutes=random.randint(1, 10))).strftime(
            "%H:%M"
        )
        processes.extend(
            [
                FakeProcess(
                    pid=1024,
                    user="root",
                    cpu=0.0,
                    mem=0.2,
                    vsz=15824,
                    rss=7168,
                    tty="?",
                    stat="Ss",
                    start=session_start,
                    time="0:00",
                    command="sshd: root@pts/0",
                    ppid=512,
                ),
                FakeProcess(
                    pid=1025,
                    user="root",
                    cpu=0.0,
                    mem=0.2,
                    vsz=25000,
                    rss=6400,
                    tty="pts/0",
                    stat="Ss",
                    start=session_start,
                    time="0:00",
                    command="-bash",
                    ppid=1024,
                ),
            ]
        )

        return processes

    def _create_default_connections(self) -> List[FakeConnection]:
        """Create a realistic set of default network connections."""
        return [
            # SSH server listening
            FakeConnection(
                proto="tcp",
                recv_q=0,
                send_q=0,
                local_addr="0.0.0.0",
                local_port=22,
                remote_addr="0.0.0.0",
                remote_port=0,
                state="LISTEN",
                pid=512,
                program="sshd",
            ),
            FakeConnection(
                proto="tcp6",
                recv_q=0,
                send_q=0,
                local_addr="::",
                local_port=22,
                remote_addr="::",
                remote_port=0,
                state="LISTEN",
                pid=512,
                program="sshd",
            ),
            # Nginx listening
            FakeConnection(
                proto="tcp",
                recv_q=0,
                send_q=0,
                local_addr="0.0.0.0",
                local_port=80,
                remote_addr="0.0.0.0",
                remote_port=0,
                state="LISTEN",
                pid=899,
                program="nginx",
            ),
            FakeConnection(
                proto="tcp6",
                recv_q=0,
                send_q=0,
                local_addr="::",
                local_port=80,
                remote_addr="::",
                remote_port=0,
                state="LISTEN",
                pid=899,
                program="nginx",
            ),
            # MySQL listening (local only)
            FakeConnection(
                proto="tcp",
                recv_q=0,
                send_q=0,
                local_addr="127.0.0.1",
                local_port=3306,
                remote_addr="0.0.0.0",
                remote_port=0,
                state="LISTEN",
                pid=950,
                program="mysqld",
            ),
            # Current SSH connection
            FakeConnection(
                proto="tcp",
                recv_q=0,
                send_q=0,
                local_addr="10.0.2.15",
                local_port=22,
                remote_addr="10.0.2.2",
                remote_port=random.randint(40000, 60000),
                state="ESTABLISHED",
                pid=1024,
                program="sshd",
            ),
        ]

    def get_uptime_seconds(self) -> float:
        """Get system uptime in seconds."""
        return time.time() - self.boot_time

    def add_process(self, command: str, user: str = "root") -> FakeProcess:
        """Add a new process to the list."""
        max_pid = max(p.pid for p in self.processes)
        new_pid = max_pid + random.randint(1, 10)

        proc = FakeProcess(
            pid=new_pid,
            user=user,
            cpu=random.uniform(0, 5),
            mem=random.uniform(0.1, 1.0),
            vsz=random.randint(10000, 100000),
            rss=random.randint(1000, 10000),
            tty="pts/0",
            stat="R",
            start=datetime.now().strftime("%H:%M"),
            time="0:00",
            command=command,
            ppid=1025,  # Child of bash
        )
        self.processes.append(proc)
        return proc


def init_system_state(
    session_user: str = "root", attacker_ip: str = "unknown"
) -> SystemState:
    """Initialize system state for a new session.

    Args:
        session_user: The username for this session
        attacker_ip: The attacker's IP address

    Returns:
        Initialized SystemState
    """
    state = SystemState(
        session_user=session_user,
        session_from=attacker_ip,
    )

    # Update the SSH connection with actual attacker IP
    for conn in state.connections:
        if conn.state == "ESTABLISHED" and conn.local_port == 22:
            conn.remote_addr = attacker_ip if attacker_ip != "unknown" else "10.0.2.2"

    return state


def format_uptime(sys_state: SystemState) -> str:
    """Format uptime command output."""
    uptime_secs = sys_state.get_uptime_seconds()

    days = int(uptime_secs // (24 * 3600))
    hours = int((uptime_secs % (24 * 3600)) // 3600)
    mins = int((uptime_secs % 3600) // 60)

    now = datetime.now().strftime("%H:%M:%S")

    if days > 0:
        uptime_str = f"{days} days, {hours:2d}:{mins:02d}"
    else:
        uptime_str = f"{hours:2d}:{mins:02d}"

    load = sys_state.load_avg

    return f" {now} up {uptime_str},  1 user,  load average: {load[0]:.2f}, {load[1]:.2f}, {load[2]:.2f}\n"


def format_free(sys_state: SystemState, human: bool = False) -> str:
    """Format free command output.

    Args:
        sys_state: System state
        human: Use human-readable format (-h flag)
    """
    m = sys_state

    if human:
        # Human-readable format
        return f"""              total        used        free      shared  buff/cache   available
Mem:          {m.mem_total / 1024:.1f}Gi      {m.mem_used / 1024:.1f}Gi      {m.mem_free / 1024:.1f}Gi      0.0Gi      {(m.mem_buffers + m.mem_cached) / 1024:.1f}Gi      {(m.mem_free + m.mem_cached) / 1024:.1f}Gi
Swap:         {m.swap_total / 1024:.1f}Gi      {m.swap_used / 1024:.1f}Gi      {m.swap_total / 1024:.1f}Gi
"""
    else:
        # Default KB format
        return f"""              total        used        free      shared  buff/cache   available
Mem:        {m.mem_total * 1024:>8}   {m.mem_used * 1024:>8}   {m.mem_free * 1024:>8}      {16384:>8}   {(m.mem_buffers + m.mem_cached) * 1024:>8}   {(m.mem_free + m.mem_cached) * 1024:>8}
Swap:       {m.swap_total * 1024:>8}   {m.swap_used * 1024:>8}   {m.swap_total * 1024:>8}
"""


def format_ps_aux(sys_state: SystemState) -> str:
    """Format ps aux output."""
    lines = [
        "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
    ]

    for p in sorted(sys_state.processes, key=lambda x: x.pid):
        line = f"{p.user:<8} {p.pid:>6} {p.cpu:>4.1f} {p.mem:>4.1f} {p.vsz:>6} {p.rss:>5} {p.tty:<8} {p.stat:<4} {p.start:<5} {p.time:>6} {p.command}"
        lines.append(line)

    return "\n".join(lines) + "\n"


def format_ps_ef(sys_state: SystemState) -> str:
    """Format ps -ef output."""
    lines = ["UID          PID    PPID  C STIME TTY          TIME CMD"]

    for p in sorted(sys_state.processes, key=lambda x: x.pid):
        c = int(p.cpu) if p.cpu >= 1 else 0
        line = f"{p.user:<8} {p.pid:>6} {p.ppid:>6}  {c} {p.start:<5} {p.tty:<8} {p.time:>8} {p.command}"
        lines.append(line)

    return "\n".join(lines) + "\n"


def format_top(sys_state: SystemState) -> str:
    """Format top command output (snapshot mode)."""
    uptime_secs = sys_state.get_uptime_seconds()
    days = int(uptime_secs // (24 * 3600))
    hours = int((uptime_secs % (24 * 3600)) // 3600)
    mins = int((uptime_secs % 3600) // 60)

    now = datetime.now().strftime("%H:%M:%S")
    load = sys_state.load_avg
    m = sys_state

    # Count process states
    total = len(sys_state.processes)
    running = sum(1 for p in sys_state.processes if "R" in p.stat)
    sleeping = sum(1 for p in sys_state.processes if "S" in p.stat)
    stopped = sum(1 for p in sys_state.processes if "T" in p.stat)
    zombie = sum(1 for p in sys_state.processes if "Z" in p.stat)

    header = f"""top - {now} up {days} days, {hours:2d}:{mins:02d},  1 user,  load average: {load[0]:.2f}, {load[1]:.2f}, {load[2]:.2f}
Tasks: {total:>3} total,   {running} running,  {sleeping} sleeping,   {stopped} stopped,   {zombie} zombie
%Cpu(s):  2.3 us,  1.0 sy,  0.0 ni, 96.5 id,  0.2 wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem :   {m.mem_total:.1f} total,   {m.mem_free:.1f} free,   {m.mem_used:.1f} used,   {m.mem_buffers + m.mem_cached:.1f} buff/cache
MiB Swap:   {m.swap_total:.1f} total,   {m.swap_total - m.swap_used:.1f} free,      {m.swap_used:.1f} used.   {m.mem_free + m.mem_cached:.1f} avail Mem

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND"""

    lines = [header]

    # Sort by CPU usage, show top processes
    sorted_procs = sorted(sys_state.processes, key=lambda x: x.cpu, reverse=True)[:15]

    for p in sorted_procs:
        # Estimate shared memory as ~80% of RSS
        shr = int(p.rss * 0.8)
        state = p.stat[0] if p.stat else "S"
        line = f"  {p.pid:>5} {p.user:<9} {p.priority:>2}   {p.nice:>2} {p.vsz:>7} {p.rss:>6} {shr:>6} {state}   {p.cpu:>4.1f}  {p.mem:>4.1f}   {p.time:>7} {p.command.split()[0]}"
        lines.append(line)

    return "\n".join(lines) + "\n"


def format_netstat(sys_state: SystemState, flags: str = "") -> str:
    """Format netstat command output.

    Args:
        sys_state: System state
        flags: Command flags (e.g., "tulpn")
    """
    show_listening = "l" in flags
    show_tcp = "t" in flags or not flags
    show_udp = "u" in flags
    show_pid = "p" in flags
    numeric = "n" in flags

    lines = ["Active Internet connections (servers and established)"]

    if show_pid:
        lines.append(
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name"
        )
    else:
        lines.append(
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State"
        )

    for c in sys_state.connections:
        # Filter by protocol
        if show_tcp and not c.proto.startswith("tcp"):
            if not show_udp:
                continue
        if show_udp and not c.proto.startswith("udp"):
            if not show_tcp:
                continue

        # Filter by listening
        if show_listening and c.state != "LISTEN":
            continue

        # Format addresses
        if c.local_addr == "0.0.0.0":
            local = f"*:{c.local_port}" if not numeric else f"0.0.0.0:{c.local_port}"
        elif c.local_addr == "::":
            local = f"[::]:{c.local_port}"
        else:
            local = f"{c.local_addr}:{c.local_port}"

        if c.remote_addr == "0.0.0.0" or c.remote_port == 0:
            remote = "*:*" if not numeric else "0.0.0.0:*"
        elif c.remote_addr == "::":
            remote = "[::]:*"
        else:
            remote = f"{c.remote_addr}:{c.remote_port}"

        if show_pid and c.pid:
            pid_prog = f"{c.pid}/{c.program}"
            line = f"{c.proto:<5} {c.recv_q:>6} {c.send_q:>6} {local:<23} {remote:<23} {c.state:<11} {pid_prog}"
        else:
            line = f"{c.proto:<5} {c.recv_q:>6} {c.send_q:>6} {local:<23} {remote:<23} {c.state}"

        lines.append(line)

    return "\n".join(lines) + "\n"


def format_ss(sys_state: SystemState, flags: str = "") -> str:
    """Format ss command output.

    Args:
        sys_state: System state
        flags: Command flags (e.g., "tulpn")
    """
    show_listening = "l" in flags
    show_tcp = "t" in flags
    show_udp = "u" in flags
    show_pid = "p" in flags
    numeric = "n" in flags

    lines = [
        "Netid  State   Recv-Q  Send-Q   Local Address:Port     Peer Address:Port  Process"
    ]

    for c in sys_state.connections:
        # Filter by protocol
        proto_match = False
        if show_tcp and c.proto.startswith("tcp"):
            proto_match = True
        if show_udp and c.proto.startswith("udp"):
            proto_match = True
        if not show_tcp and not show_udp:
            proto_match = True
        if not proto_match:
            continue

        # Filter by listening
        if show_listening and c.state != "LISTEN":
            continue

        # Format addresses
        if c.local_addr == "0.0.0.0":
            local = f"*:{c.local_port}"
        elif c.local_addr == "::":
            local = f"*:{c.local_port}"
        else:
            local = f"{c.local_addr}:{c.local_port}"

        if c.remote_addr == "0.0.0.0" or c.remote_port == 0:
            peer = "*:*"
        elif c.remote_addr == "::":
            peer = "*:*"
        else:
            peer = f"{c.remote_addr}:{c.remote_port}"

        netid = c.proto
        state = c.state if c.state != "LISTEN" else "LISTEN"

        if show_pid and c.pid:
            proc = f'users:(("{c.program}",pid={c.pid},fd=3))'
        else:
            proc = ""

        line = f"{netid:<6} {state:<7} {c.recv_q:>6}  {c.send_q:>6}   {local:<20} {peer:<18} {proc}"
        lines.append(line)

    return "\n".join(lines) + "\n"


def format_w(sys_state: SystemState) -> str:
    """Format w command output."""
    uptime_secs = sys_state.get_uptime_seconds()
    days = int(uptime_secs // (24 * 3600))
    hours = int((uptime_secs % (24 * 3600)) // 3600)
    mins = int((uptime_secs % 3600) // 60)

    now = datetime.now().strftime("%H:%M:%S")
    load = sys_state.load_avg

    header = f" {now} up {days} days, {hours:2d}:{mins:02d},  1 user,  load average: {load[0]:.2f}, {load[1]:.2f}, {load[2]:.2f}"

    lines = [
        header,
        "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT",
        f"{sys_state.session_user:<8} {sys_state.session_tty:<8} {sys_state.session_from:<16} {datetime.now().strftime('%H:%M')}    0.00s  0.05s  0.00s w",
    ]

    return "\n".join(lines) + "\n"


def format_who(sys_state: SystemState) -> str:
    """Format who command output."""
    login_time = datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"{sys_state.session_user:<8} {sys_state.session_tty:<8} {login_time} ({sys_state.session_from})\n"


def format_id(username: str = "root") -> str:
    """Format id command output."""
    if username == "root":
        return "uid=0(root) gid=0(root) groups=0(root)\n"
    elif username == "user":
        return "uid=1000(user) gid=1000(user) groups=1000(user),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)\n"
    elif username == "www-data":
        return "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
    else:
        return f"uid=1000({username}) gid=1000({username}) groups=1000({username})\n"


def format_hostname() -> str:
    """Format hostname command output."""
    return "miragepot\n"


def format_uname(flags: str = "") -> str:
    """Format uname command output."""
    if "a" in flags or flags == "-a":
        return "Linux miragepot 5.15.0-86-generic #96-Ubuntu SMP Wed Sep 20 08:23:49 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"
    elif "r" in flags:
        return "5.15.0-86-generic\n"
    elif "n" in flags:
        return "miragepot\n"
    elif "s" in flags or not flags:
        return "Linux\n"
    elif "m" in flags:
        return "x86_64\n"
    else:
        return "Linux\n"


# Command handlers


def handle_ps_command(args: str, sys_state: SystemState) -> str:
    """Handle ps command."""
    args = args.strip()

    if "aux" in args or "ax" in args:
        return format_ps_aux(sys_state)
    elif "-ef" in args or "-e" in args:
        return format_ps_ef(sys_state)
    else:
        # Default: show just current user's processes
        lines = ["    PID TTY          TIME CMD"]
        for p in sys_state.processes:
            if p.tty.startswith("pts"):
                lines.append(
                    f"  {p.pid:>5} {p.tty:<8} {p.time:>8} {p.command.split()[0]}"
                )
        return "\n".join(lines) + "\n"


def handle_top_command(sys_state: SystemState) -> str:
    """Handle top command (returns snapshot)."""
    return format_top(sys_state)


def handle_netstat_command(args: str, sys_state: SystemState) -> str:
    """Handle netstat command."""
    # Extract flags
    flags = ""
    for part in args.split():
        if part.startswith("-"):
            flags += part[1:]
    return format_netstat(sys_state, flags)


def handle_ss_command(args: str, sys_state: SystemState) -> str:
    """Handle ss command."""
    flags = ""
    for part in args.split():
        if part.startswith("-"):
            flags += part[1:]
    return format_ss(sys_state, flags)


def handle_free_command(args: str, sys_state: SystemState) -> str:
    """Handle free command."""
    human = "-h" in args or "--human" in args
    return format_free(sys_state, human)


def handle_uptime_command(sys_state: SystemState) -> str:
    """Handle uptime command."""
    return format_uptime(sys_state)


def handle_w_command(sys_state: SystemState) -> str:
    """Handle w command."""
    return format_w(sys_state)


def handle_who_command(sys_state: SystemState) -> str:
    """Handle who command."""
    return format_who(sys_state)


def handle_id_command(args: str = "") -> str:
    """Handle id command."""
    username = args.strip() if args.strip() else "root"
    return format_id(username)


def handle_hostname_command() -> str:
    """Handle hostname command."""
    return format_hostname()


def handle_uname_command(args: str = "") -> str:
    """Handle uname command."""
    return format_uname(args.strip())


def handle_whoami_command() -> str:
    """Handle whoami command."""
    return "root\n"


__all__ = [
    "SystemState",
    "FakeProcess",
    "FakeConnection",
    "init_system_state",
    "handle_ps_command",
    "handle_top_command",
    "handle_netstat_command",
    "handle_ss_command",
    "handle_free_command",
    "handle_uptime_command",
    "handle_w_command",
    "handle_who_command",
    "handle_id_command",
    "handle_hostname_command",
    "handle_uname_command",
    "handle_whoami_command",
]
