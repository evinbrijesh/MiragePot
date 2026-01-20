"""TTY emulation for realistic terminal behavior.

This module provides TTY handling including:
- ANSI escape sequences (clear screen, cursor movement)
- Control character handling (Ctrl+C, Ctrl+D, Ctrl+L)
- Arrow key support with command history
- TAB completion
- Dynamic prompt generation

These features make the honeypot more convincing to attackers
and help capture more detailed interaction data.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

LOGGER = logging.getLogger(__name__)

# ANSI Escape Sequences
ANSI_CLEAR_SCREEN = "\033[2J\033[H"  # Clear screen and move cursor to home
ANSI_CLEAR_LINE = "\033[2K"  # Clear entire line
ANSI_CURSOR_UP = "\033[A"
ANSI_CURSOR_DOWN = "\033[B"
ANSI_CURSOR_FORWARD = "\033[C"
ANSI_CURSOR_BACK = "\033[D"
ANSI_SAVE_CURSOR = "\033[s"
ANSI_RESTORE_CURSOR = "\033[u"
ANSI_ERASE_TO_END = "\033[K"

# Control characters
CTRL_C = "\x03"
CTRL_D = "\x04"
CTRL_L = "\x0c"  # Form feed, typically clears screen
TAB = "\x09"
BACKSPACE = "\x7f"
ESC = "\x1b"

# Arrow key escape sequences (after ESC [)
ARROW_UP = "A"
ARROW_DOWN = "B"
ARROW_RIGHT = "C"
ARROW_LEFT = "D"


@dataclass
class TTYState:
    """Tracks TTY state for a session.

    Attributes:
        command_history: List of previously executed commands
        history_index: Current position in history (-1 = not browsing)
        current_buffer: Current input buffer
        cursor_pos: Cursor position within buffer
        hostname: Fake hostname for prompt
        username: Current username for prompt
    """

    command_history: List[str] = field(default_factory=list)
    history_index: int = -1
    current_buffer: str = ""
    saved_buffer: str = ""  # Buffer saved when entering history mode
    cursor_pos: int = 0
    hostname: str = "miragepot"
    username: str = "root"

    # Maximum history size
    max_history: int = 100


def generate_prompt(tty_state: TTYState, cwd: str) -> str:
    """Generate a dynamic bash-like prompt.

    Args:
        tty_state: Current TTY state
        cwd: Current working directory

    Returns:
        Prompt string like "root@miragepot:/home# "
    """
    # Shorten home directory to ~
    display_cwd = cwd
    home_dir = (
        "/root" if tty_state.username == "root" else f"/home/{tty_state.username}"
    )
    if cwd == home_dir:
        display_cwd = "~"
    elif cwd.startswith(home_dir + "/"):
        display_cwd = "~" + cwd[len(home_dir) :]

    # Root gets #, regular users get $
    prompt_char = "#" if tty_state.username == "root" else "$"

    return f"{tty_state.username}@{tty_state.hostname}:{display_cwd}{prompt_char} "


def add_to_history(tty_state: TTYState, command: str) -> None:
    """Add a command to history.

    Args:
        tty_state: Current TTY state
        command: Command to add
    """
    # Don't add empty or whitespace-only commands
    if not command or not command.strip():
        return

    # Don't add duplicates of the last command
    if tty_state.command_history and tty_state.command_history[-1] == command:
        return

    tty_state.command_history.append(command)

    # Trim history if too long
    if len(tty_state.command_history) > tty_state.max_history:
        tty_state.command_history = tty_state.command_history[-tty_state.max_history :]

    # Reset history browsing state
    tty_state.history_index = -1
    tty_state.saved_buffer = ""


def handle_arrow_up(tty_state: TTYState) -> Tuple[str, str]:
    """Handle up arrow - navigate to previous command in history.

    Returns:
        Tuple of (new_buffer, terminal_output)
    """
    if not tty_state.command_history:
        return tty_state.current_buffer, ""

    # First time pressing up - save current buffer
    if tty_state.history_index == -1:
        tty_state.saved_buffer = tty_state.current_buffer
        tty_state.history_index = len(tty_state.command_history) - 1
    elif tty_state.history_index > 0:
        tty_state.history_index -= 1
    else:
        # Already at oldest - do nothing
        return tty_state.current_buffer, ""

    # Get command from history
    new_buffer = tty_state.command_history[tty_state.history_index]

    # Generate terminal output to replace current line
    # Move to start, clear line, print new content
    clear_current = "\r" + ANSI_ERASE_TO_END

    tty_state.current_buffer = new_buffer
    tty_state.cursor_pos = len(new_buffer)

    return new_buffer, clear_current


def handle_arrow_down(tty_state: TTYState) -> Tuple[str, str]:
    """Handle down arrow - navigate to next command in history.

    Returns:
        Tuple of (new_buffer, terminal_output)
    """
    if tty_state.history_index == -1:
        # Not in history mode
        return tty_state.current_buffer, ""

    if tty_state.history_index < len(tty_state.command_history) - 1:
        tty_state.history_index += 1
        new_buffer = tty_state.command_history[tty_state.history_index]
    else:
        # Back to current input
        tty_state.history_index = -1
        new_buffer = tty_state.saved_buffer

    clear_current = "\r" + ANSI_ERASE_TO_END

    tty_state.current_buffer = new_buffer
    tty_state.cursor_pos = len(new_buffer)

    return new_buffer, clear_current


def get_tab_completions(partial: str, session_state: Dict[str, Any]) -> List[str]:
    """Get possible completions for partial input.

    Args:
        partial: The partial command/path to complete
        session_state: Session state containing filesystem info

    Returns:
        List of possible completions
    """
    completions = []

    # Common commands for command completion
    common_commands = [
        "ls",
        "cd",
        "pwd",
        "cat",
        "echo",
        "mkdir",
        "rm",
        "cp",
        "mv",
        "touch",
        "chmod",
        "chown",
        "find",
        "grep",
        "ps",
        "top",
        "kill",
        "whoami",
        "id",
        "uname",
        "hostname",
        "ifconfig",
        "ip",
        "netstat",
        "ss",
        "curl",
        "wget",
        "scp",
        "ssh",
        "tar",
        "gzip",
        "gunzip",
        "head",
        "tail",
        "less",
        "more",
        "vi",
        "vim",
        "nano",
        "history",
        "export",
        "env",
        "which",
        "whereis",
        "file",
        "stat",
        "df",
        "du",
        "free",
        "uptime",
        "w",
        "who",
        "last",
        "exit",
        "logout",
        "clear",
    ]

    parts = partial.split()

    if len(parts) == 0 or (len(parts) == 1 and not partial.endswith(" ")):
        # Complete command name
        prefix = parts[0] if parts else ""
        completions = [cmd for cmd in common_commands if cmd.startswith(prefix)]
    else:
        # Complete path/filename
        # Get the part to complete
        to_complete = parts[-1] if not partial.endswith(" ") else ""

        # Get directory listing from session state
        cwd = session_state.get("cwd", "/root")
        directories = session_state.get("directories", set())
        files = session_state.get("files", {})

        # Determine base path
        if "/" in to_complete:
            base_path = "/".join(to_complete.rsplit("/", 1)[:-1])
            prefix = to_complete.rsplit("/", 1)[-1]
            if not base_path:
                base_path = "/"
        else:
            base_path = cwd
            prefix = to_complete

        # Normalize base path
        if not base_path.startswith("/"):
            base_path = cwd.rstrip("/") + "/" + base_path

        # Find matching entries
        for d in directories:
            if d.startswith(base_path.rstrip("/") + "/"):
                # Get entry name relative to base_path
                rel = d[len(base_path.rstrip("/")) + 1 :]
                if "/" not in rel:  # Direct child only
                    if rel.startswith(prefix):
                        completions.append(rel + "/")

        for f in files.keys():
            if f.startswith(base_path.rstrip("/") + "/"):
                rel = f[len(base_path.rstrip("/")) + 1 :]
                if "/" not in rel:
                    if rel.startswith(prefix):
                        completions.append(rel)

    return sorted(set(completions))


def handle_tab_completion(
    tty_state: TTYState,
    session_state: Dict[str, Any],
) -> Tuple[str, str]:
    """Handle TAB key for completion.

    Args:
        tty_state: Current TTY state
        session_state: Session state containing filesystem info

    Returns:
        Tuple of (new_buffer, terminal_output)
    """
    buffer = tty_state.current_buffer
    completions = get_tab_completions(buffer, session_state)

    if not completions:
        # No completions - beep or do nothing
        return buffer, "\x07"  # Bell character

    if len(completions) == 1:
        # Single completion - complete it
        parts = buffer.split()
        if parts and not buffer.endswith(" "):
            # Replace last part
            new_buffer = " ".join(parts[:-1])
            if new_buffer:
                new_buffer += " "
            new_buffer += completions[0]
        else:
            # Add completion
            new_buffer = buffer + completions[0]

        # Add space after if it's a command (not ending with /)
        if not new_buffer.endswith("/"):
            new_buffer += " "

        # Calculate output
        added = new_buffer[len(buffer) :]
        tty_state.current_buffer = new_buffer
        tty_state.cursor_pos = len(new_buffer)

        return new_buffer, added

    # Multiple completions - show them
    # Find common prefix
    common = completions[0]
    for c in completions[1:]:
        while not c.startswith(common):
            common = common[:-1]
            if not common:
                break

    output = ""
    if common and len(common) > len(buffer.split()[-1] if buffer.split() else ""):
        # Can extend with common prefix
        parts = buffer.split()
        if parts and not buffer.endswith(" "):
            new_buffer = " ".join(parts[:-1])
            if new_buffer:
                new_buffer += " "
            new_buffer += common
        else:
            new_buffer = buffer + common

        added = new_buffer[len(buffer) :]
        tty_state.current_buffer = new_buffer
        tty_state.cursor_pos = len(new_buffer)
        output = added
    else:
        # Show all completions
        output = "\r\n" + "  ".join(completions) + "\r\n"
        # Don't change buffer, output will need prompt reprint

    return tty_state.current_buffer, output


def handle_ctrl_c(tty_state: TTYState) -> Tuple[str, str]:
    """Handle Ctrl+C - cancel current input.

    Returns:
        Tuple of (new_buffer, terminal_output)
    """
    # Show ^C and move to new line
    tty_state.current_buffer = ""
    tty_state.cursor_pos = 0
    tty_state.history_index = -1

    return "", "^C\r\n"


def handle_ctrl_l() -> str:
    """Handle Ctrl+L - clear screen.

    Returns:
        Terminal output to clear screen
    """
    return ANSI_CLEAR_SCREEN


def handle_clear_command() -> str:
    """Handle 'clear' command.

    Returns:
        ANSI sequence to clear the screen
    """
    return ANSI_CLEAR_SCREEN


class TTYHandler:
    """Handles TTY input/output for a session.

    This class manages:
    - Escape sequence parsing
    - Control character handling
    - Command history
    - Tab completion
    - Prompt generation
    """

    def __init__(
        self,
        session_state: Dict[str, Any],
        hostname: str = "miragepot",
        username: str = "root",
    ):
        """Initialize TTY handler.

        Args:
            session_state: Session state dict for filesystem access
            hostname: Fake hostname for prompt
            username: Username for prompt
        """
        self.session_state = session_state
        self.tty_state = TTYState(hostname=hostname, username=username)
        self.buffer = ""
        self.escape_buffer = ""  # For collecting escape sequences
        self.in_escape = False

    def get_prompt(self) -> str:
        """Get the current prompt string."""
        cwd = self.session_state.get("cwd", "/root")
        return generate_prompt(self.tty_state, cwd)

    def process_byte(self, byte: int) -> Tuple[Optional[str], str, bool]:
        """Process a single input byte.

        Args:
            byte: Input byte value

        Returns:
            Tuple of:
            - command: Complete command if Enter pressed, None otherwise
            - output: Terminal output to send
            - needs_prompt: Whether to reprint the prompt
        """
        c = chr(byte)
        output = ""
        command = None
        needs_prompt = False

        # Handle escape sequences
        if self.in_escape:
            return self._handle_escape_byte(c)

        if c == ESC:
            self.in_escape = True
            self.escape_buffer = ""
            return None, "", False

        # Handle Ctrl+C
        if c == CTRL_C:
            self.buffer, output = handle_ctrl_c(self.tty_state)
            return None, output, True

        # Handle Ctrl+D (EOF) - only if buffer is empty
        if c == CTRL_D:
            if not self.buffer:
                return "exit", "", False
            return None, "", False

        # Handle Ctrl+L (clear screen)
        if c == CTRL_L:
            output = handle_ctrl_l()
            return None, output, True

        # Handle TAB
        if c == TAB:
            new_buf, output = handle_tab_completion(self.tty_state, self.session_state)
            self.buffer = new_buf
            if "\r\n" in output:
                # Multiple completions shown, need to reprint prompt+buffer
                needs_prompt = True
            return None, output, needs_prompt

        # Handle Enter (newline/carriage return)
        if c in ("\n", "\r"):
            command = self.buffer.strip()
            if command:
                add_to_history(self.tty_state, command)
            self.buffer = ""
            self.tty_state.current_buffer = ""
            self.tty_state.cursor_pos = 0
            return command, "\r\n", False

        # Handle Backspace
        if c == BACKSPACE or c == "\x08":
            if self.buffer:
                self.buffer = self.buffer[:-1]
                self.tty_state.current_buffer = self.buffer
                self.tty_state.cursor_pos = len(self.buffer)
                output = "\b \b"
            return None, output, False

        # Ignore other control characters
        if ord(c) < 32:
            return None, "", False

        # Regular printable character
        self.buffer += c
        self.tty_state.current_buffer = self.buffer
        self.tty_state.cursor_pos = len(self.buffer)
        return None, c, False

    def _handle_escape_byte(self, c: str) -> Tuple[Optional[str], str, bool]:
        """Handle a byte during escape sequence parsing.

        Returns:
            Tuple of (command, output, needs_prompt)
        """
        self.escape_buffer += c

        # Check for CSI sequences (ESC [)
        if len(self.escape_buffer) == 1:
            if c == "[":
                return None, "", False
            else:
                # Unknown escape, ignore
                self.in_escape = False
                self.escape_buffer = ""
                return None, "", False

        # CSI sequences end with a letter
        if c.isalpha():
            self.in_escape = False
            seq = self.escape_buffer
            self.escape_buffer = ""

            if seq == "[A":  # Up arrow
                new_buf, output = handle_arrow_up(self.tty_state)
                prompt = self.get_prompt()
                self.buffer = new_buf
                return None, output + prompt + new_buf, False

            elif seq == "[B":  # Down arrow
                new_buf, output = handle_arrow_down(self.tty_state)
                prompt = self.get_prompt()
                self.buffer = new_buf
                return None, output + prompt + new_buf, False

            elif seq == "[C":  # Right arrow
                # TODO: implement cursor movement
                return None, "", False

            elif seq == "[D":  # Left arrow
                # TODO: implement cursor movement
                return None, "", False

            # Unknown sequence, ignore
            return None, "", False

        # Still collecting sequence
        # Limit sequence length to prevent buffer overflow attacks
        if len(self.escape_buffer) > 10:
            self.in_escape = False
            self.escape_buffer = ""

        return None, "", False


# Export commonly used items
__all__ = [
    "TTYState",
    "TTYHandler",
    "generate_prompt",
    "add_to_history",
    "handle_clear_command",
    "handle_ctrl_c",
    "handle_ctrl_l",
    "handle_tab_completion",
    "get_tab_completions",
    "ANSI_CLEAR_SCREEN",
]
