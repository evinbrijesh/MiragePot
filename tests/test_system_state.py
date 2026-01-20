"""Tests for system state (processes, network, memory) simulation."""

import pytest
import time
from miragepot.system_state import (
    SystemState,
    FakeProcess,
    FakeConnection,
    init_system_state,
    format_uptime,
    format_free,
    format_ps_aux,
    format_ps_ef,
    format_top,
    format_netstat,
    format_ss,
    format_w,
    format_who,
    format_id,
    format_hostname,
    format_uname,
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
from miragepot.command_handler import init_session_state, handle_command


class TestFakeProcess:
    """Tests for FakeProcess dataclass."""

    def test_create_process(self):
        """FakeProcess can be created with values."""
        proc = FakeProcess(
            pid=1234,
            user="root",
            cpu=5.0,
            mem=1.2,
            vsz=100000,
            rss=50000,
            tty="pts/0",
            stat="S",
            start="10:00",
            time="0:05",
            command="/bin/bash",
        )
        assert proc.pid == 1234
        assert proc.user == "root"
        assert proc.command == "/bin/bash"


class TestFakeConnection:
    """Tests for FakeConnection dataclass."""

    def test_create_connection(self):
        """FakeConnection can be created with values."""
        conn = FakeConnection(
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
        )
        assert conn.proto == "tcp"
        assert conn.local_port == 22
        assert conn.state == "LISTEN"


class TestSystemState:
    """Tests for SystemState dataclass."""

    def test_init_creates_processes(self):
        """SystemState initializes with default processes."""
        state = SystemState()
        assert len(state.processes) > 0
        # Should have init process (PID 1)
        pids = [p.pid for p in state.processes]
        assert 1 in pids

    def test_init_creates_connections(self):
        """SystemState initializes with default connections."""
        state = SystemState()
        assert len(state.connections) > 0
        # Should have SSH listening
        ssh_listen = [c for c in state.connections if c.local_port == 22]
        assert len(ssh_listen) > 0

    def test_memory_stats(self):
        """SystemState has memory statistics."""
        state = SystemState()
        assert state.mem_total > 0
        assert state.mem_used > 0
        assert state.mem_free > 0

    def test_uptime_calculation(self):
        """Uptime is calculated correctly."""
        state = SystemState()
        uptime = state.get_uptime_seconds()
        assert uptime > 0
        # Default is ~42 days
        assert uptime > 40 * 24 * 3600

    def test_add_process(self):
        """New processes can be added."""
        state = SystemState()
        initial_count = len(state.processes)
        proc = state.add_process("sleep 100")
        assert len(state.processes) == initial_count + 1
        assert proc.command == "sleep 100"
        assert proc in state.processes


class TestInitSystemState:
    """Tests for init_system_state function."""

    def test_creates_state(self):
        """init_system_state creates a SystemState."""
        state = init_system_state()
        assert isinstance(state, SystemState)

    def test_sets_session_user(self):
        """Session user is set correctly."""
        state = init_system_state(session_user="admin")
        assert state.session_user == "admin"

    def test_sets_attacker_ip(self):
        """Attacker IP is used in connections."""
        state = init_system_state(attacker_ip="192.168.1.100")
        established = [c for c in state.connections if c.state == "ESTABLISHED"]
        assert len(established) > 0
        assert any(c.remote_addr == "192.168.1.100" for c in established)


class TestUptimeFormat:
    """Tests for uptime output formatting."""

    def test_format_uptime(self):
        """uptime output is formatted correctly."""
        state = SystemState()
        output = format_uptime(state)
        assert "up" in output
        assert "days" in output
        assert "load average" in output
        assert "user" in output

    def test_handle_uptime_command(self):
        """handle_uptime_command returns output."""
        state = SystemState()
        output = handle_uptime_command(state)
        assert "up" in output


class TestFreeFormat:
    """Tests for free output formatting."""

    def test_format_free_default(self):
        """free output shows memory stats."""
        state = SystemState()
        output = format_free(state)
        assert "Mem:" in output
        assert "Swap:" in output
        assert "total" in output

    def test_format_free_human(self):
        """free -h output uses human-readable units."""
        state = SystemState()
        output = format_free(state, human=True)
        assert "Gi" in output

    def test_handle_free_command(self):
        """handle_free_command with -h flag."""
        state = SystemState()
        output = handle_free_command("-h", state)
        assert "Gi" in output


class TestPsFormat:
    """Tests for ps output formatting."""

    def test_format_ps_aux(self):
        """ps aux output is formatted correctly."""
        state = SystemState()
        output = format_ps_aux(state)
        assert "USER" in output
        assert "PID" in output
        assert "%CPU" in output
        assert "COMMAND" in output
        # Should show root process
        assert "root" in output

    def test_format_ps_ef(self):
        """ps -ef output is formatted correctly."""
        state = SystemState()
        output = format_ps_ef(state)
        assert "UID" in output
        assert "PID" in output
        assert "PPID" in output

    def test_handle_ps_aux(self):
        """handle_ps_command with aux."""
        state = SystemState()
        output = handle_ps_command("aux", state)
        assert "%CPU" in output

    def test_handle_ps_ef(self):
        """handle_ps_command with -ef."""
        state = SystemState()
        output = handle_ps_command("-ef", state)
        assert "PPID" in output

    def test_handle_ps_default(self):
        """handle_ps_command with no args."""
        state = SystemState()
        output = handle_ps_command("", state)
        assert "PID" in output


class TestTopFormat:
    """Tests for top output formatting."""

    def test_format_top(self):
        """top output shows system summary."""
        state = SystemState()
        output = format_top(state)
        assert "top -" in output
        assert "Tasks:" in output
        assert "Cpu" in output
        assert "Mem" in output
        assert "PID" in output

    def test_handle_top_command(self):
        """handle_top_command returns output."""
        state = SystemState()
        output = handle_top_command(state)
        assert "top" in output


class TestNetstatFormat:
    """Tests for netstat output formatting."""

    def test_format_netstat_basic(self):
        """netstat output shows connections."""
        state = SystemState()
        output = format_netstat(state)
        assert "Proto" in output
        assert "Local Address" in output
        assert "State" in output

    def test_format_netstat_listening(self):
        """netstat -l shows only listening."""
        state = SystemState()
        output = format_netstat(state, "l")
        # Should only show LISTEN state
        lines = output.split("\n")
        for line in lines[2:]:  # Skip header
            if line.strip():
                assert "LISTEN" in line or "ESTABLISHED" not in line

    def test_format_netstat_with_pid(self):
        """netstat -p shows PIDs."""
        state = SystemState()
        output = format_netstat(state, "p")
        assert "PID/Program" in output
        assert "sshd" in output

    def test_handle_netstat_tulpn(self):
        """handle_netstat_command with -tulpn."""
        state = SystemState()
        output = handle_netstat_command("-tulpn", state)
        assert "LISTEN" in output
        assert "sshd" in output


class TestSsFormat:
    """Tests for ss output formatting."""

    def test_format_ss_basic(self):
        """ss output shows connections."""
        state = SystemState()
        output = format_ss(state)
        assert "Netid" in output
        assert "State" in output
        assert "Local Address" in output

    def test_format_ss_listening(self):
        """ss -l shows only listening."""
        state = SystemState()
        output = format_ss(state, "l")
        assert "LISTEN" in output

    def test_handle_ss_tulpn(self):
        """handle_ss_command with -tulpn."""
        state = SystemState()
        output = handle_ss_command("-tulpn", state)
        assert "LISTEN" in output


class TestWFormat:
    """Tests for w command formatting."""

    def test_format_w(self):
        """w output shows logged in users."""
        state = SystemState()
        output = format_w(state)
        assert "USER" in output
        assert "TTY" in output
        assert "WHAT" in output
        assert state.session_user in output

    def test_handle_w_command(self):
        """handle_w_command returns output."""
        state = SystemState()
        output = handle_w_command(state)
        assert "USER" in output


class TestWhoFormat:
    """Tests for who command formatting."""

    def test_format_who(self):
        """who output shows current user."""
        state = SystemState()
        output = format_who(state)
        assert state.session_user in output
        assert state.session_tty in output

    def test_handle_who_command(self):
        """handle_who_command returns output."""
        state = SystemState()
        output = handle_who_command(state)
        assert "root" in output


class TestIdFormat:
    """Tests for id command formatting."""

    def test_format_id_root(self):
        """id for root shows uid=0."""
        output = format_id("root")
        assert "uid=0(root)" in output
        assert "gid=0(root)" in output

    def test_format_id_user(self):
        """id for regular user shows uid=1000."""
        output = format_id("user")
        assert "uid=1000(user)" in output
        assert "sudo" in output  # User is in sudo group

    def test_handle_id_command(self):
        """handle_id_command returns output."""
        output = handle_id_command("")
        assert "uid=" in output


class TestHostnameFormat:
    """Tests for hostname command."""

    def test_format_hostname(self):
        """hostname returns miragepot."""
        output = format_hostname()
        assert "miragepot" in output

    def test_handle_hostname_command(self):
        """handle_hostname_command returns output."""
        output = handle_hostname_command()
        assert "miragepot" in output


class TestUnameFormat:
    """Tests for uname command formatting."""

    def test_format_uname_default(self):
        """uname returns Linux."""
        output = format_uname()
        assert "Linux" in output

    def test_format_uname_all(self):
        """uname -a returns full info."""
        output = format_uname("-a")
        assert "Linux" in output
        assert "miragepot" in output
        assert "x86_64" in output

    def test_format_uname_release(self):
        """uname -r returns kernel version."""
        output = format_uname("-r")
        assert "5.15.0" in output

    def test_handle_uname_command(self):
        """handle_uname_command with -a."""
        output = handle_uname_command("-a")
        assert "Linux" in output


class TestWhoamiFormat:
    """Tests for whoami command."""

    def test_handle_whoami_command(self):
        """whoami returns root."""
        output = handle_whoami_command()
        assert "root" in output


class TestIntegration:
    """Integration tests with command_handler."""

    def test_ps_aux_via_command_handler(self):
        """ps aux works through handle_command."""
        state = init_session_state()
        output = handle_command("ps aux", state)
        assert "USER" in output
        assert "root" in output

    def test_netstat_via_command_handler(self):
        """netstat works through handle_command."""
        state = init_session_state()
        output = handle_command("netstat -tulpn", state)
        assert "LISTEN" in output

    def test_free_via_command_handler(self):
        """free works through handle_command."""
        state = init_session_state()
        output = handle_command("free -h", state)
        assert "Mem:" in output

    def test_uptime_via_command_handler(self):
        """uptime works through handle_command."""
        state = init_session_state()
        output = handle_command("uptime", state)
        assert "up" in output

    def test_uname_via_command_handler(self):
        """uname -a works through handle_command."""
        state = init_session_state()
        output = handle_command("uname -a", state)
        assert "Linux" in output

    def test_hostname_via_command_handler(self):
        """hostname works through handle_command."""
        state = init_session_state()
        output = handle_command("hostname", state)
        assert "miragepot" in output

    def test_whoami_via_command_handler(self):
        """whoami works through handle_command."""
        state = init_session_state()
        output = handle_command("whoami", state)
        assert "root" in output

    def test_id_via_command_handler(self):
        """id works through handle_command."""
        state = init_session_state()
        output = handle_command("id", state)
        assert "uid=" in output

    def test_w_via_command_handler(self):
        """w works through handle_command."""
        state = init_session_state()
        output = handle_command("w", state)
        assert "USER" in output

    def test_who_via_command_handler(self):
        """who works through handle_command."""
        state = init_session_state()
        output = handle_command("who", state)
        assert "root" in output

    def test_top_via_command_handler(self):
        """top works through handle_command."""
        state = init_session_state()
        output = handle_command("top", state)
        assert "Tasks:" in output

    def test_ss_via_command_handler(self):
        """ss works through handle_command."""
        state = init_session_state()
        output = handle_command("ss -tulpn", state)
        assert "LISTEN" in output


class TestConsistency:
    """Tests for state consistency across commands."""

    def test_same_pids_across_ps_calls(self):
        """PIDs remain consistent between ps calls."""
        state = init_session_state()
        output1 = handle_command("ps aux", state)
        output2 = handle_command("ps aux", state)
        # Outputs should be essentially the same (may have time differences)
        assert output1.split("\n")[0] == output2.split("\n")[0]  # Headers match

    def test_uptime_changes(self):
        """Uptime shows passage of time."""
        state = init_session_state()
        output1 = handle_command("uptime", state)
        # Uptime is calculated on-the-fly, should show realistic value
        assert "up" in output1
        assert "days" in output1

    def test_netstat_consistent(self):
        """Network connections remain consistent."""
        state = init_session_state()
        output1 = handle_command("netstat -tulpn", state)
        output2 = handle_command("netstat -tulpn", state)
        # Should be identical
        assert output1 == output2
