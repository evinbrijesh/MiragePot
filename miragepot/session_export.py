"""Session export and replay functionality for MiragePot.

This module provides mechanisms to export captured sessions in various formats
and replay them for analysis and demonstration purposes.

Key features:
1. Export sessions as plain text transcripts
2. Export sessions as JSON for programmatic analysis
3. Export sessions as HTML for web viewing
4. Replay sessions with timing simulation
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional


@dataclass
class SessionCommand:
    """A single command from a session."""

    timestamp: str
    command: str
    response: str
    threat_score: int
    delay_applied: float

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionCommand":
        """Create from dictionary."""
        return cls(
            timestamp=data.get("timestamp", ""),
            command=data.get("command", ""),
            response=data.get("response", ""),
            threat_score=data.get("threat_score", 0),
            delay_applied=data.get("delay_applied", 0.0),
        )


@dataclass
class SessionData:
    """Complete session data for export/replay."""

    session_id: str
    attacker_ip: str
    attacker_port: int
    login_time: str
    logout_time: Optional[str]
    duration_seconds: Optional[float]
    ssh_fingerprint: Optional[Dict[str, Any]]
    auth: Optional[Dict[str, Any]]
    pty_info: Optional[Dict[str, Any]]
    commands: List[SessionCommand]
    download_attempts: List[Dict[str, Any]]
    ttp_summary: Optional[Dict[str, Any]]
    honeytokens_summary: Optional[Dict[str, Any]]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionData":
        """Create from dictionary (e.g., loaded from JSON file)."""
        commands = [SessionCommand.from_dict(cmd) for cmd in data.get("commands", [])]
        return cls(
            session_id=data.get("session_id", "unknown"),
            attacker_ip=data.get("attacker_ip", "unknown"),
            attacker_port=data.get("attacker_port", 0),
            login_time=data.get("login_time", ""),
            logout_time=data.get("logout_time"),
            duration_seconds=data.get("duration_seconds"),
            ssh_fingerprint=data.get("ssh_fingerprint"),
            auth=data.get("auth"),
            pty_info=data.get("pty_info"),
            commands=commands,
            download_attempts=data.get("download_attempts", []),
            ttp_summary=data.get("ttp_summary"),
            honeytokens_summary=data.get("honeytokens_summary"),
        )

    @classmethod
    def from_json_file(cls, path: Path) -> "SessionData":
        """Load session data from a JSON file."""
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
        return cls.from_dict(data)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "session_id": self.session_id,
            "attacker_ip": self.attacker_ip,
            "attacker_port": self.attacker_port,
            "login_time": self.login_time,
            "logout_time": self.logout_time,
            "duration_seconds": self.duration_seconds,
            "ssh_fingerprint": self.ssh_fingerprint,
            "auth": self.auth,
            "pty_info": self.pty_info,
            "commands": [
                {
                    "timestamp": cmd.timestamp,
                    "command": cmd.command,
                    "response": cmd.response,
                    "threat_score": cmd.threat_score,
                    "delay_applied": cmd.delay_applied,
                }
                for cmd in self.commands
            ],
            "download_attempts": self.download_attempts,
            "ttp_summary": self.ttp_summary,
            "honeytokens_summary": self.honeytokens_summary,
        }


def export_as_text(session: SessionData, include_metadata: bool = True) -> str:
    """Export session as plain text transcript.

    Args:
        session: The session data to export
        include_metadata: Whether to include session metadata header

    Returns:
        Plain text transcript of the session
    """
    lines = []

    if include_metadata:
        lines.append("=" * 70)
        lines.append(f"MiragePot Session Transcript")
        lines.append("=" * 70)
        lines.append(f"Session ID:    {session.session_id}")
        lines.append(f"Attacker IP:   {session.attacker_ip}:{session.attacker_port}")
        lines.append(f"Login Time:    {session.login_time}")
        lines.append(f"Logout Time:   {session.logout_time or 'N/A'}")
        lines.append(f"Duration:      {session.duration_seconds or 0:.2f} seconds")
        lines.append(f"Total Commands: {len(session.commands)}")

        # Auth info
        if session.auth:
            auth_attempts = session.auth.get("auth_attempts", 0)
            username = session.auth.get("successful_username", "unknown")
            lines.append(f"Auth Attempts: {auth_attempts}")
            lines.append(f"Username:      {username}")

        # SSH fingerprint
        if session.ssh_fingerprint:
            client_version = session.ssh_fingerprint.get("client_version", "unknown")
            lines.append(f"SSH Client:    {client_version}")

        # TTP summary
        if session.ttp_summary:
            risk_level = session.ttp_summary.get("risk_level", "unknown")
            current_stage = session.ttp_summary.get("current_stage", "unknown")
            lines.append(f"Risk Level:    {risk_level}")
            lines.append(f"Attack Stage:  {current_stage}")

        # Honeytokens summary
        if session.honeytokens_summary:
            tokens_accessed = session.honeytokens_summary.get(
                "unique_tokens_accessed", 0
            )
            exfil_attempts = session.honeytokens_summary.get("exfiltration_attempts", 0)
            if tokens_accessed > 0:
                lines.append(f"Tokens Accessed: {tokens_accessed}")
            if exfil_attempts > 0:
                lines.append(f"Exfil Attempts:  {exfil_attempts}")

        lines.append("=" * 70)
        lines.append("")

    # Add command transcript
    lines.append("--- Session Transcript ---")
    lines.append("")

    for cmd in session.commands:
        # Show timestamp and command
        time_str = (
            cmd.timestamp.split("T")[1].split(".")[0]
            if "T" in cmd.timestamp
            else cmd.timestamp
        )
        lines.append(f"[{time_str}] root@miragepot:~# {cmd.command}")

        # Show response (indented)
        if cmd.response:
            for line in cmd.response.split("\n"):
                lines.append(f"  {line}")

        # Show threat score if significant
        if cmd.threat_score > 0:
            lines.append(f"  [Threat Score: {cmd.threat_score}]")

        lines.append("")

    # Download attempts
    if session.download_attempts:
        lines.append("--- Download Attempts ---")
        for attempt in session.download_attempts:
            tool = attempt.get("tool", "unknown")
            source = attempt.get("source", "unknown")
            risk = attempt.get("risk_level", "unknown")
            lines.append(f"  [{risk}] {tool}: {source}")
        lines.append("")

    return "\n".join(lines)


def export_as_json(session: SessionData, pretty: bool = True) -> str:
    """Export session as JSON.

    Args:
        session: The session data to export
        pretty: Whether to format JSON with indentation

    Returns:
        JSON string of the session
    """
    data = session.to_dict()
    if pretty:
        return json.dumps(data, indent=2)
    return json.dumps(data)


def export_as_html(session: SessionData) -> str:
    """Export session as HTML for web viewing.

    Args:
        session: The session data to export

    Returns:
        HTML string of the session
    """

    # Escape HTML characters
    def escape_html(text: str) -> str:
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )

    # Determine risk color
    risk_level = "low"
    if session.ttp_summary:
        risk_level = session.ttp_summary.get("risk_level", "low")

    risk_colors = {
        "low": "#28a745",
        "medium": "#ffc107",
        "high": "#fd7e14",
        "critical": "#dc3545",
    }
    risk_color = risk_colors.get(risk_level, "#6c757d")

    html_parts = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "  <meta charset='UTF-8'>",
        "  <meta name='viewport' content='width=device-width, initial-scale=1.0'>",
        f"  <title>MiragePot Session: {escape_html(session.session_id)}</title>",
        "  <style>",
        "    body { font-family: 'Monaco', 'Consolas', monospace; background: #1a1a2e; color: #eee; margin: 0; padding: 20px; }",
        "    .header { background: #16213e; padding: 20px; border-radius: 8px; margin-bottom: 20px; }",
        "    .header h1 { margin: 0 0 10px 0; color: #00d9ff; }",
        "    .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; }",
        "    .meta-item { background: #0f3460; padding: 10px; border-radius: 4px; }",
        "    .meta-label { color: #888; font-size: 0.8em; }",
        "    .meta-value { color: #fff; font-size: 1.1em; }",
        f"    .risk-badge {{ background: {risk_color}; color: #fff; padding: 4px 12px; border-radius: 4px; font-weight: bold; }}",
        "    .terminal { background: #0d0d0d; border-radius: 8px; padding: 20px; margin-top: 20px; }",
        "    .terminal-header { color: #888; margin-bottom: 10px; border-bottom: 1px solid #333; padding-bottom: 10px; }",
        "    .command { margin: 15px 0; }",
        "    .prompt { color: #00ff00; }",
        "    .cmd-text { color: #fff; }",
        "    .response { color: #ccc; white-space: pre-wrap; margin-left: 20px; }",
        "    .timestamp { color: #666; font-size: 0.8em; }",
        "    .threat-score { color: #ff6b6b; font-size: 0.8em; margin-left: 10px; }",
        "    .download-alert { background: #ff6b6b22; border-left: 4px solid #ff6b6b; padding: 10px; margin: 10px 0; }",
        "    .honeytoken-alert { background: #ffc10722; border-left: 4px solid #ffc107; padding: 10px; margin: 10px 0; }",
        "  </style>",
        "</head>",
        "<body>",
        "  <div class='header'>",
        f"    <h1>MiragePot Session: {escape_html(session.session_id)}</h1>",
        "    <div class='meta'>",
        f"      <div class='meta-item'><div class='meta-label'>Attacker IP</div><div class='meta-value'>{escape_html(session.attacker_ip)}:{session.attacker_port}</div></div>",
        f"      <div class='meta-item'><div class='meta-label'>Login Time</div><div class='meta-value'>{escape_html(session.login_time)}</div></div>",
        f"      <div class='meta-item'><div class='meta-label'>Duration</div><div class='meta-value'>{session.duration_seconds or 0:.2f}s</div></div>",
        f"      <div class='meta-item'><div class='meta-label'>Commands</div><div class='meta-value'>{len(session.commands)}</div></div>",
        f"      <div class='meta-item'><div class='meta-label'>Risk Level</div><div class='meta-value'><span class='risk-badge'>{risk_level.upper()}</span></div></div>",
    ]

    # SSH fingerprint
    if session.ssh_fingerprint:
        client_version = escape_html(
            session.ssh_fingerprint.get("client_version", "unknown")
        )
        html_parts.append(
            f"      <div class='meta-item'><div class='meta-label'>SSH Client</div><div class='meta-value'>{client_version}</div></div>"
        )

    # TTP stage
    if session.ttp_summary:
        current_stage = escape_html(session.ttp_summary.get("current_stage", "unknown"))
        html_parts.append(
            f"      <div class='meta-item'><div class='meta-label'>Attack Stage</div><div class='meta-value'>{current_stage}</div></div>"
        )

    html_parts.extend(
        [
            "    </div>",
            "  </div>",
        ]
    )

    # Honeytokens alert
    if session.honeytokens_summary:
        tokens_accessed = session.honeytokens_summary.get("unique_tokens_accessed", 0)
        exfil_attempts = session.honeytokens_summary.get("exfiltration_attempts", 0)
        if tokens_accessed > 0 or exfil_attempts > 0:
            html_parts.append("  <div class='honeytoken-alert'>")
            html_parts.append(
                f"    <strong>Honeytoken Activity:</strong> {tokens_accessed} tokens accessed"
            )
            if exfil_attempts > 0:
                html_parts.append(
                    f", <strong style='color:#dc3545'>{exfil_attempts} exfiltration attempts!</strong>"
                )
            html_parts.append("  </div>")

    # Download attempts alert
    if session.download_attempts:
        html_parts.append("  <div class='download-alert'>")
        html_parts.append(
            f"    <strong>Download Attempts:</strong> {len(session.download_attempts)} file download(s) detected"
        )
        html_parts.append("  </div>")

    # Terminal transcript
    html_parts.extend(
        [
            "  <div class='terminal'>",
            "    <div class='terminal-header'>Session Transcript</div>",
        ]
    )

    for cmd in session.commands:
        time_str = (
            cmd.timestamp.split("T")[1].split(".")[0]
            if "T" in cmd.timestamp
            else cmd.timestamp
        )
        html_parts.append("    <div class='command'>")
        html_parts.append(
            f"      <span class='timestamp'>[{escape_html(time_str)}]</span>"
        )
        html_parts.append(f"      <span class='prompt'>root@miragepot:~#</span>")
        html_parts.append(
            f"      <span class='cmd-text'>{escape_html(cmd.command)}</span>"
        )
        if cmd.threat_score > 0:
            html_parts.append(
                f"      <span class='threat-score'>[Threat: {cmd.threat_score}]</span>"
            )
        if cmd.response:
            html_parts.append(
                f"      <div class='response'>{escape_html(cmd.response)}</div>"
            )
        html_parts.append("    </div>")

    html_parts.extend(
        [
            "  </div>",
            "</body>",
            "</html>",
        ]
    )

    return "\n".join(html_parts)


def replay_session(
    session: SessionData,
    output_callback: Callable[[str], None],
    speed: float = 1.0,
    simulate_typing: bool = True,
) -> None:
    """Replay a session with timing simulation.

    This function blocks and replays the session in real-time (or adjusted speed).

    Args:
        session: The session data to replay
        output_callback: Function to call with each output chunk
        speed: Speed multiplier (1.0 = real-time, 2.0 = 2x speed)
        simulate_typing: Whether to simulate typing each character
    """
    output_callback(f"\n=== Replaying session {session.session_id} ===\n")
    output_callback(f"Attacker: {session.attacker_ip}\n")
    output_callback(f"Time: {session.login_time}\n")
    output_callback(f"Speed: {speed}x\n")
    output_callback("=" * 50 + "\n\n")

    # Send initial banner
    output_callback(
        "Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-86-generic x86_64)\n"
    )
    output_callback("Last login: just now from unknown\n")

    prev_time = None

    for cmd in session.commands:
        # Calculate delay from previous command
        if prev_time is not None:
            try:
                curr_dt = datetime.fromisoformat(cmd.timestamp.replace("Z", "+00:00"))
                prev_dt = datetime.fromisoformat(prev_time.replace("Z", "+00:00"))
                delay = (curr_dt - prev_dt).total_seconds()
                if delay > 0:
                    time.sleep(delay / speed)
            except ValueError:
                pass

        prev_time = cmd.timestamp

        # Output prompt
        output_callback("root@miragepot:~# ")

        # Simulate typing if enabled
        if simulate_typing:
            for char in cmd.command:
                output_callback(char)
                time.sleep(0.05 / speed)  # 50ms per character
        else:
            output_callback(cmd.command)

        output_callback("\n")

        # Apply any tarpit delay
        if cmd.delay_applied > 0:
            time.sleep(cmd.delay_applied / speed)

        # Output response
        if cmd.response:
            output_callback(cmd.response)
            if not cmd.response.endswith("\n"):
                output_callback("\n")

    output_callback("\n=== Session replay complete ===\n")


def iter_replay_session(
    session: SessionData,
    speed: float = 1.0,
) -> Iterator[Dict[str, Any]]:
    """Iterate through session for replay without blocking.

    Yields dictionaries with timing and output information that can be
    used by callers to implement their own replay logic.

    Args:
        session: The session data to replay
        speed: Speed multiplier for delay calculations

    Yields:
        Dict with 'type', 'content', and 'delay' keys
    """
    yield {
        "type": "banner",
        "content": "Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-86-generic x86_64)\n"
        "Last login: just now from unknown\n",
        "delay": 0,
    }

    prev_time = None

    for i, cmd in enumerate(session.commands):
        # Calculate delay from previous command
        delay = 0.0
        if prev_time is not None:
            try:
                curr_dt = datetime.fromisoformat(cmd.timestamp.replace("Z", "+00:00"))
                prev_dt = datetime.fromisoformat(prev_time.replace("Z", "+00:00"))
                delay = max(0, (curr_dt - prev_dt).total_seconds() / speed)
            except ValueError:
                pass

        prev_time = cmd.timestamp

        yield {
            "type": "prompt",
            "content": "root@miragepot:~# ",
            "delay": delay,
        }

        yield {
            "type": "command",
            "content": cmd.command,
            "delay": 0,
            "threat_score": cmd.threat_score,
        }

        yield {
            "type": "newline",
            "content": "\n",
            "delay": 0,
        }

        if cmd.response:
            yield {
                "type": "response",
                "content": cmd.response,
                "delay": cmd.delay_applied / speed if cmd.delay_applied else 0,
            }

    yield {
        "type": "end",
        "content": "",
        "delay": 0,
    }


def load_session(session_path: Path) -> SessionData:
    """Load a session from a JSON file.

    Args:
        session_path: Path to the session JSON file

    Returns:
        SessionData object
    """
    return SessionData.from_json_file(session_path)


def list_sessions(logs_dir: Path) -> List[Dict[str, Any]]:
    """List all available sessions in the logs directory.

    Args:
        logs_dir: Path to the logs directory

    Returns:
        List of session summaries (id, attacker_ip, login_time, duration, command_count)
    """
    sessions = []

    for path in sorted(logs_dir.glob("session_*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            sessions.append(
                {
                    "session_id": data.get("session_id", path.stem),
                    "attacker_ip": data.get("attacker_ip", "unknown"),
                    "login_time": data.get("login_time", ""),
                    "duration_seconds": data.get("duration_seconds", 0),
                    "command_count": len(data.get("commands", [])),
                    "risk_level": data.get("ttp_summary", {}).get(
                        "risk_level", "unknown"
                    )
                    if data.get("ttp_summary")
                    else "unknown",
                    "path": str(path),
                }
            )
        except (json.JSONDecodeError, IOError):
            continue

    return sessions


def export_session(
    session_path: Path,
    output_path: Path,
    format: str = "text",
    include_metadata: bool = True,
) -> None:
    """Export a session to a file.

    Args:
        session_path: Path to the session JSON file
        output_path: Path to write the export
        format: Export format ('text', 'json', 'html')
        include_metadata: Whether to include metadata (for text format)
    """
    session = load_session(session_path)

    if format == "text":
        content = export_as_text(session, include_metadata)
    elif format == "json":
        content = export_as_json(session)
    elif format == "html":
        content = export_as_html(session)
    else:
        raise ValueError(f"Unknown format: {format}")

    output_path.write_text(content, encoding="utf-8")
