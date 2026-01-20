"""Tests for TTY handling functionality."""

import pytest
from miragepot.tty_handler import (
    TTYState,
    TTYHandler,
    generate_prompt,
    add_to_history,
    handle_arrow_up,
    handle_arrow_down,
    handle_ctrl_c,
    handle_ctrl_l,
    get_tab_completions,
    handle_tab_completion,
    ANSI_CLEAR_SCREEN,
)


class TestTTYState:
    """Tests for TTYState dataclass."""

    def test_default_values(self):
        """TTYState initializes with sensible defaults."""
        state = TTYState()
        assert state.command_history == []
        assert state.history_index == -1
        assert state.current_buffer == ""
        assert state.cursor_pos == 0
        assert state.hostname == "miragepot"
        assert state.username == "root"

    def test_custom_values(self):
        """TTYState accepts custom values."""
        state = TTYState(
            hostname="honeypot",
            username="admin",
            command_history=["ls", "pwd"],
        )
        assert state.hostname == "honeypot"
        assert state.username == "admin"
        assert len(state.command_history) == 2


class TestGeneratePrompt:
    """Tests for prompt generation."""

    def test_root_prompt(self):
        """Root user gets # symbol."""
        state = TTYState(username="root", hostname="miragepot")
        prompt = generate_prompt(state, "/root")
        assert "root@miragepot" in prompt
        assert "#" in prompt

    def test_regular_user_prompt(self):
        """Regular user gets $ symbol."""
        state = TTYState(username="admin", hostname="server")
        prompt = generate_prompt(state, "/home/admin")
        assert "admin@server" in prompt
        assert "$" in prompt

    def test_home_directory_shown_as_tilde(self):
        """Home directory is displayed as ~."""
        state = TTYState(username="root")
        prompt = generate_prompt(state, "/root")
        assert "~" in prompt
        assert "/root" not in prompt

    def test_subdirectory_of_home(self):
        """Subdirectory of home starts with ~/."""
        state = TTYState(username="root")
        prompt = generate_prompt(state, "/root/scripts")
        assert "~/scripts" in prompt

    def test_other_directory(self):
        """Other directories are shown as-is."""
        state = TTYState(username="root")
        prompt = generate_prompt(state, "/var/log")
        assert "/var/log" in prompt

    def test_dynamic_prompt_changes_with_cwd(self):
        """Prompt updates when cwd changes."""
        state = TTYState(username="root")
        prompt1 = generate_prompt(state, "/root")
        prompt2 = generate_prompt(state, "/etc")
        assert prompt1 != prompt2
        assert "/etc" in prompt2


class TestCommandHistory:
    """Tests for command history management."""

    def test_add_to_history(self):
        """Commands are added to history."""
        state = TTYState()
        add_to_history(state, "ls -la")
        assert "ls -la" in state.command_history

    def test_no_duplicate_consecutive(self):
        """Duplicate consecutive commands are not added."""
        state = TTYState()
        add_to_history(state, "pwd")
        add_to_history(state, "pwd")
        assert state.command_history.count("pwd") == 1

    def test_empty_not_added(self):
        """Empty commands are not added."""
        state = TTYState()
        add_to_history(state, "")
        add_to_history(state, "   ")
        assert len(state.command_history) == 0

    def test_history_limit(self):
        """History is limited to max_history."""
        state = TTYState(max_history=5)
        for i in range(10):
            add_to_history(state, f"cmd{i}")
        assert len(state.command_history) == 5
        assert state.command_history[0] == "cmd5"

    def test_history_index_reset(self):
        """Adding command resets history index."""
        state = TTYState()
        state.history_index = 5
        add_to_history(state, "new_cmd")
        assert state.history_index == -1


class TestArrowKeys:
    """Tests for arrow key history navigation."""

    def test_arrow_up_empty_history(self):
        """Up arrow with empty history does nothing."""
        state = TTYState()
        new_buf, output = handle_arrow_up(state)
        assert new_buf == ""
        assert output == ""

    def test_arrow_up_navigates_history(self):
        """Up arrow navigates to previous command."""
        state = TTYState(command_history=["ls", "pwd", "whoami"])
        state.current_buffer = ""

        new_buf, output = handle_arrow_up(state)
        assert new_buf == "whoami"
        assert state.history_index == 2

        new_buf, output = handle_arrow_up(state)
        assert new_buf == "pwd"
        assert state.history_index == 1

    def test_arrow_up_saves_current_buffer(self):
        """Up arrow saves current input."""
        state = TTYState(command_history=["ls"])
        state.current_buffer = "partial"

        handle_arrow_up(state)
        assert state.saved_buffer == "partial"

    def test_arrow_down_returns_to_current(self):
        """Down arrow returns to current input."""
        state = TTYState(command_history=["ls", "pwd"])
        state.current_buffer = "partial"
        state.saved_buffer = "partial"

        # Go up twice
        handle_arrow_up(state)
        handle_arrow_up(state)

        # Go down twice - should return to saved buffer
        handle_arrow_down(state)
        handle_arrow_down(state)

        assert state.current_buffer == "partial"
        assert state.history_index == -1

    def test_arrow_down_not_in_history(self):
        """Down arrow when not in history does nothing."""
        state = TTYState(command_history=["ls"])
        state.history_index = -1

        new_buf, output = handle_arrow_down(state)
        assert state.history_index == -1


class TestControlCharacters:
    """Tests for control character handling."""

    def test_ctrl_c_clears_buffer(self):
        """Ctrl+C clears the current buffer."""
        state = TTYState()
        state.current_buffer = "rm -rf /"

        new_buf, output = handle_ctrl_c(state)
        assert new_buf == ""
        assert "^C" in output
        assert state.history_index == -1

    def test_ctrl_l_clears_screen(self):
        """Ctrl+L returns clear screen sequence."""
        output = handle_ctrl_l()
        assert output == ANSI_CLEAR_SCREEN


class TestTabCompletion:
    """Tests for tab completion."""

    def test_command_completion(self):
        """Tab completes command names."""
        session_state = {"cwd": "/root", "directories": set(), "files": {}}
        completions = get_tab_completions("l", session_state)
        assert "ls" in completions
        assert "less" in completions

    def test_no_completion(self):
        """Tab with no matches returns empty."""
        session_state = {"cwd": "/root", "directories": set(), "files": {}}
        completions = get_tab_completions("xyz123", session_state)
        assert completions == []

    def test_file_completion(self):
        """Tab completes file names."""
        session_state = {
            "cwd": "/root",
            "directories": {"/root", "/root/scripts"},
            "files": {"/root/file1.txt": "", "/root/file2.py": ""},
        }
        completions = get_tab_completions("cat ", session_state)
        assert "file1.txt" in completions
        assert "file2.py" in completions
        assert "scripts/" in completions

    def test_single_completion_adds_space(self):
        """Single completion adds space after command."""
        state = TTYState()
        state.current_buffer = "exi"
        session_state = {"cwd": "/root", "directories": set(), "files": {}}

        new_buf, output = handle_tab_completion(state, session_state)
        assert new_buf == "exit "
        assert "t " in output  # Added "t " to complete


class TestTTYHandler:
    """Tests for the full TTYHandler class."""

    def test_init(self):
        """TTYHandler initializes correctly."""
        session_state = {"cwd": "/root"}
        handler = TTYHandler(session_state)
        assert handler.buffer == ""
        assert handler.tty_state.username == "root"

    def test_get_prompt(self):
        """TTYHandler generates correct prompt."""
        session_state = {"cwd": "/var/log"}
        handler = TTYHandler(session_state, hostname="honeypot", username="admin")
        prompt = handler.get_prompt()
        assert "admin@honeypot" in prompt
        assert "/var/log" in prompt

    def test_process_printable_char(self):
        """Printable characters are added to buffer and echoed."""
        session_state = {"cwd": "/root"}
        handler = TTYHandler(session_state)

        cmd, output, needs_prompt = handler.process_byte(ord("a"))
        assert cmd is None
        assert output == "a"
        assert handler.buffer == "a"

    def test_process_enter(self):
        """Enter returns the command."""
        session_state = {"cwd": "/root"}
        handler = TTYHandler(session_state)
        handler.buffer = "ls -la"

        cmd, output, needs_prompt = handler.process_byte(ord("\r"))
        assert cmd == "ls -la"
        assert handler.buffer == ""

    def test_process_backspace(self):
        """Backspace removes last character."""
        session_state = {"cwd": "/root"}
        handler = TTYHandler(session_state)
        handler.buffer = "ls"

        cmd, output, needs_prompt = handler.process_byte(0x7F)
        assert handler.buffer == "l"
        assert "\b" in output

    def test_process_ctrl_c(self):
        """Ctrl+C clears buffer and signals prompt needed."""
        session_state = {"cwd": "/root"}
        handler = TTYHandler(session_state)
        handler.buffer = "dangerous command"

        cmd, output, needs_prompt = handler.process_byte(0x03)  # Ctrl+C
        assert handler.buffer == ""
        assert "^C" in output
        assert needs_prompt is True

    def test_process_ctrl_d_empty_buffer(self):
        """Ctrl+D with empty buffer returns exit."""
        session_state = {"cwd": "/root"}
        handler = TTYHandler(session_state)
        handler.buffer = ""

        cmd, output, needs_prompt = handler.process_byte(0x04)  # Ctrl+D
        assert cmd == "exit"

    def test_process_ctrl_d_non_empty_buffer(self):
        """Ctrl+D with non-empty buffer does nothing."""
        session_state = {"cwd": "/root"}
        handler = TTYHandler(session_state)
        handler.buffer = "partial"

        cmd, output, needs_prompt = handler.process_byte(0x04)
        assert cmd is None
        assert handler.buffer == "partial"

    def test_process_ctrl_l(self):
        """Ctrl+L clears screen."""
        session_state = {"cwd": "/root"}
        handler = TTYHandler(session_state)

        cmd, output, needs_prompt = handler.process_byte(0x0C)  # Ctrl+L
        assert ANSI_CLEAR_SCREEN in output
        assert needs_prompt is True

    def test_escape_sequence_up_arrow(self):
        """Up arrow escape sequence navigates history."""
        session_state = {"cwd": "/root"}
        handler = TTYHandler(session_state)
        handler.tty_state.command_history = ["ls", "pwd"]

        # Send ESC [ A (up arrow)
        handler.process_byte(0x1B)  # ESC
        handler.process_byte(ord("["))
        cmd, output, needs_prompt = handler.process_byte(ord("A"))

        assert handler.buffer == "pwd"

    def test_command_added_to_history(self):
        """Commands are added to history after Enter."""
        session_state = {"cwd": "/root"}
        handler = TTYHandler(session_state)
        handler.buffer = "whoami"

        handler.process_byte(ord("\r"))
        assert "whoami" in handler.tty_state.command_history


class TestClearCommand:
    """Tests for clear command handling."""

    def test_clear_command_detection(self):
        """The 'clear' command should be handled specially."""
        from miragepot.tty_handler import handle_clear_command

        output = handle_clear_command()
        assert output == ANSI_CLEAR_SCREEN
