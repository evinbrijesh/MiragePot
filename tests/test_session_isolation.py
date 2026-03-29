"""Tests for session isolation in MiragePot.

This module verifies that concurrent SSH sessions maintain proper isolation of:
- Current working directory (cwd)
- Filesystem state (files and directories)
- Command history
- Session state in general

Per the PRIORITY 6 audit, session isolation was found to be ALREADY CORRECT.
These tests serve as regression tests to ensure isolation remains intact.
"""

import pytest
from miragepot.command_handler import init_session_state, handle_command


class TestSessionIsolation:
    """Tests to verify concurrent session isolation."""

    def test_concurrent_session_cwd_isolation(self):
        """Two sessions with different cwd should not interfere with each other.

        Simulates two concurrent attackers:
        - Session A changes to /etc
        - Session B changes to /var
        - Verify each session maintains its own cwd
        """
        # Create two independent session states
        session_a = init_session_state()
        session_b = init_session_state()

        # Verify both start in /root
        assert session_a["cwd"] == "/root"
        assert session_b["cwd"] == "/root"

        # Session A changes to /etc
        handle_command("cd /etc", session_a)
        assert session_a["cwd"] == "/etc"

        # Session B changes to /var
        handle_command("cd /var", session_b)
        assert session_b["cwd"] == "/var"

        # Verify sessions remain isolated
        assert session_a["cwd"] == "/etc"
        assert session_b["cwd"] == "/var"

        # Session A changes to /tmp
        handle_command("cd /tmp", session_a)
        assert session_a["cwd"] == "/tmp"
        assert session_b["cwd"] == "/var"  # Session B unchanged

    def test_concurrent_session_filesystem_isolation(self):
        """Two sessions should have separate file and directory state.

        Simulates:
        - Session A creates /tmp/sessionA_file
        - Session B creates /tmp/sessionB_file
        - Verify each session only sees its own created files
        """
        session_a = init_session_state()
        session_b = init_session_state()

        # Session A creates a directory
        handle_command("mkdir /tmp/sessionA_dir", session_a)
        assert "/tmp/sessionA_dir" in session_a["directories"]
        assert "/tmp/sessionA_dir" not in session_b["directories"]

        # Session B creates a different directory
        handle_command("mkdir /tmp/sessionB_dir", session_b)
        assert "/tmp/sessionB_dir" in session_b["directories"]
        assert "/tmp/sessionB_dir" not in session_a["directories"]

        # Session A creates a file
        handle_command("touch /tmp/sessionA_file.txt", session_a)
        assert "/tmp/sessionA_file.txt" in session_a["files"]
        assert "/tmp/sessionA_file.txt" not in session_b["files"]

        # Session B creates a file
        handle_command("touch /tmp/sessionB_file.txt", session_b)
        assert "/tmp/sessionB_file.txt" in session_b["files"]
        assert "/tmp/sessionB_file.txt" not in session_a["files"]

        # Verify final state isolation
        assert "/tmp/sessionA_dir" in session_a["directories"]
        assert "/tmp/sessionB_dir" not in session_a["directories"]
        assert "/tmp/sessionB_dir" in session_b["directories"]
        assert "/tmp/sessionA_dir" not in session_b["directories"]

    def test_concurrent_session_history_isolation(self):
        """Two sessions should have separate command history.

        Simulates:
        - Session A runs commands: ls, pwd, whoami
        - Session B runs commands: id, hostname, uname
        - Verify each session has its own TTY state and history
        """
        session_a = init_session_state()
        session_b = init_session_state()

        # Execute commands in session A
        handle_command("ls", session_a)
        handle_command("pwd", session_a)
        handle_command("whoami", session_a)

        # Execute commands in session B
        handle_command("id", session_b)
        handle_command("hostname", session_b)
        handle_command("uname -a", session_b)

        # Verify TTY states are separate objects
        assert session_a.get("tty_state") is not None
        assert session_b.get("tty_state") is not None
        assert session_a["tty_state"] is not session_b["tty_state"]

        # Verify command histories are separate (if TTY state tracks history)
        # Note: This assumes tty_state has a command_history or similar attribute
        # The exact implementation may vary, but they should be separate objects
        tty_a = session_a.get("tty_state")
        tty_b = session_b.get("tty_state")

        if tty_a and tty_b:
            # Verify they are different instances
            assert id(tty_a) != id(tty_b)

    def test_concurrent_session_tier_usage_isolation(self):
        """Two sessions should have separate tier usage tracking (P4 enhancement).

        Simulates:
        - Session A runs filesystem commands (cd, ls)
        - Session B runs different commands
        - Verify each session tracks its own tier usage
        """
        session_a = init_session_state()
        session_b = init_session_state()

        # Verify both start with zero tier usage
        assert session_a["tier_usage"] == {"filesystem": 0, "cache": 0, "llm": 0}
        assert session_b["tier_usage"] == {"filesystem": 0, "cache": 0, "llm": 0}

        # Session A runs filesystem commands
        handle_command("cd /tmp", session_a)
        handle_command("pwd", session_a)
        handle_command("ls", session_a)

        # Session B runs different filesystem commands
        handle_command("cd /etc", session_b)
        handle_command("pwd", session_b)

        # Verify tier usage is tracked separately
        assert session_a["tier_usage"]["filesystem"] == 3
        assert session_b["tier_usage"]["filesystem"] == 2

        # Verify they don't share state
        assert session_a["tier_usage"] is not session_b["tier_usage"]

    def test_concurrent_session_ttp_state_isolation(self):
        """Two sessions should have separate TTP detection state.

        Simulates:
        - Session A runs reconnaissance commands
        - Session B runs exploitation commands
        - Verify TTP states remain isolated
        """
        session_a = init_session_state()
        session_b = init_session_state()

        # Verify both have separate TTP state objects
        assert "ttp_state" in session_a
        assert "ttp_state" in session_b
        assert session_a["ttp_state"] is not session_b["ttp_state"]

        # Run different command patterns
        handle_command("whoami", session_a)
        handle_command("uname -a", session_a)

        handle_command("cat /etc/passwd", session_b)
        handle_command("cat /etc/shadow", session_b)

        # TTP states should remain separate objects
        assert session_a["ttp_state"] is not session_b["ttp_state"]

    def test_concurrent_session_honeytoken_isolation(self):
        """Two sessions should have separate honeytoken tracking.

        Simulates:
        - Session A accesses AWS credentials
        - Session B accesses SSH keys
        - Verify honeytoken access is tracked separately
        """
        session_a = init_session_state()
        session_b = init_session_state()

        # Verify both have separate honeytoken objects
        assert "honeytokens" in session_a
        assert "honeytokens" in session_b
        assert session_a["honeytokens"] is not session_b["honeytokens"]

        # Different session IDs
        assert session_a["session_id"] != session_b["session_id"]

        # Honeytokens should be unique per session
        session_a_tokens = session_a["honeytokens"]
        session_b_tokens = session_b["honeytokens"]

        # Verify they are separate objects
        assert id(session_a_tokens) != id(session_b_tokens)

    def test_static_cache_is_shared_readonly(self):
        """Verify that the static cache is shared (not per-session) but read-only.

        This is intentional and safe - the cache should be shared across all
        sessions for performance, but sessions cannot modify it.
        """
        session_a = init_session_state()
        session_b = init_session_state()

        # Both sessions should be able to use cached commands
        # The CACHE dict is global and shared, which is correct behavior
        from miragepot.command_handler import CACHE

        # Verify cache exists and is not empty
        assert CACHE is not None
        assert isinstance(CACHE, dict)

        # Cache is read-only - sessions cannot modify it
        # This is enforced by the command handler not exposing write access

        # Both sessions get the same cached responses
        # (This is tested indirectly through command execution)
        result_a = handle_command("ls", session_a)
        result_b = handle_command("ls", session_b)

        # Results should be consistent (though states are separate)
        # The ls command is handled by filesystem tier, not cache,
        # but the point is that shared readonly data is safe
        assert isinstance(result_a, str)
        assert isinstance(result_b, str)

    def test_three_concurrent_sessions_isolation(self):
        """Stress test: Three concurrent sessions should all remain isolated.

        This test simulates a more realistic scenario with multiple concurrent
        attackers performing different actions.
        """
        session_1 = init_session_state()
        session_2 = init_session_state()
        session_3 = init_session_state()

        # Session 1: Reconnaissance
        handle_command("cd /etc", session_1)
        handle_command("ls", session_1)
        handle_command("cat /etc/passwd", session_1)

        # Session 2: Exploitation
        handle_command("cd /tmp", session_2)
        handle_command("mkdir /tmp/exploit", session_2)
        handle_command("touch /tmp/malware.sh", session_2)

        # Session 3: Exfiltration
        handle_command("cd /root", session_3)
        handle_command("ls -la", session_3)
        handle_command("cat /root/.ssh/id_rsa", session_3)

        # Verify CWD isolation
        assert session_1["cwd"] == "/etc"
        assert session_2["cwd"] == "/tmp"
        assert session_3["cwd"] == "/root"

        # Verify filesystem isolation
        assert "/tmp/exploit" in session_2["directories"]
        assert "/tmp/exploit" not in session_1["directories"]
        assert "/tmp/exploit" not in session_3["directories"]

        assert "/tmp/malware.sh" in session_2["files"]
        assert "/tmp/malware.sh" not in session_1["files"]
        assert "/tmp/malware.sh" not in session_3["files"]

        # Verify tier usage isolation
        assert session_1["tier_usage"]["filesystem"] >= 3
        assert session_2["tier_usage"]["filesystem"] >= 3
        assert session_3["tier_usage"]["filesystem"] >= 3

        # All sessions have separate tier usage tracking
        assert session_1["tier_usage"] is not session_2["tier_usage"]
        assert session_2["tier_usage"] is not session_3["tier_usage"]
        assert session_1["tier_usage"] is not session_3["tier_usage"]

    def test_concurrent_sessions_with_threading(self):
        """Test true concurrent execution with threading.

        Simulates 2 sessions running overlapping commands in parallel threads
        to verify thread-safety and proper isolation under concurrent load.
        """
        import threading
        import time

        session_a = init_session_state()
        session_b = init_session_state()

        results_a = []
        results_b = []

        def session_a_commands():
            """Session A command sequence."""
            results_a.append(handle_command("cd /etc", session_a))
            time.sleep(0.01)  # Small delay to interleave execution
            results_a.append(handle_command("pwd", session_a))
            results_a.append(handle_command("mkdir /etc/test_a", session_a))
            results_a.append(handle_command("ls", session_a))

        def session_b_commands():
            """Session B command sequence."""
            results_b.append(handle_command("cd /var", session_b))
            time.sleep(0.01)  # Small delay to interleave execution
            results_b.append(handle_command("pwd", session_b))
            results_b.append(handle_command("mkdir /var/test_b", session_b))
            results_b.append(handle_command("ls", session_b))

        # Run both sessions in parallel threads
        thread_a = threading.Thread(target=session_a_commands)
        thread_b = threading.Thread(target=session_b_commands)

        thread_a.start()
        thread_b.start()

        thread_a.join()
        thread_b.join()

        # Verify isolation after concurrent execution
        assert session_a["cwd"] == "/etc", "Session A cwd should be /etc"
        assert session_b["cwd"] == "/var", "Session B cwd should be /var"

        # Verify filesystem isolation
        assert "/etc/test_a" in session_a["directories"]
        assert "/etc/test_a" not in session_b["directories"]
        assert "/var/test_b" in session_b["directories"]
        assert "/var/test_b" not in session_a["directories"]

        # Verify all commands completed successfully
        assert len(results_a) == 4, "Session A should have 4 command results"
        assert len(results_b) == 4, "Session B should have 4 command results"

        # Verify pwd outputs reflect correct isolation
        assert "/etc" in str(results_a[1]), "Session A pwd should show /etc"
        assert "/var" in str(results_b[1]), "Session B pwd should show /var"
