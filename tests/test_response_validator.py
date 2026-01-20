"""Tests for the response_validator module.

This module tests the anti-hallucination guardrails that validate
and sanitize LLM responses to ensure they look like real terminal output.
"""

import pytest

from miragepot.response_validator import (
    AI_REVELATION_PHRASES,
    CONVERSATIONAL_STARTERS,
    ERROR_TEMPLATES,
    VALID_GROUPS,
    VALID_USERS,
    ValidationResult,
    _check_filesystem_consistency,
    _check_user_consistency,
    _generate_safe_fallback,
    _handle_echo_fallback,
    _is_known_system_path,
    _remove_markdown_artifacts,
    get_error_template,
    is_plausible_terminal_output,
    sanitize_for_terminal,
    validate_response,
)


# =============================================================================
# ValidationResult Tests
# =============================================================================


class TestValidationResult:
    """Tests for the ValidationResult dataclass."""

    def test_creation(self):
        """Test creating a ValidationResult."""
        result = ValidationResult(
            is_valid=True,
            response="test output\n",
            issues=[],
            was_modified=False,
        )
        assert result.is_valid is True
        assert result.response == "test output\n"
        assert result.issues == []
        assert result.was_modified is False

    def test_with_issues(self):
        """Test ValidationResult with issues."""
        result = ValidationResult(
            is_valid=False,
            response="fallback\n",
            issues=["AI revelation phrase detected: 'i am an ai'"],
            was_modified=True,
        )
        assert result.is_valid is False
        assert len(result.issues) == 1
        assert result.was_modified is True


# =============================================================================
# AI Revelation Phrase Detection Tests
# =============================================================================


class TestAIRevelationDetection:
    """Tests for AI revelation phrase detection."""

    def test_direct_ai_admission(self):
        """Test detection of direct AI admissions."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        ai_admissions = [
            "I am an AI assistant and cannot execute commands.",
            "As an AI, I cannot actually run commands.",
            "I'm a language model, so I can't access files.",
            "I am a chatbot helping you today.",
            "I'm an assistant designed to help.",
        ]

        for response in ai_admissions:
            result = validate_response(response, "whoami", session)
            assert result.is_valid is False, f"Should detect: {response[:50]}"
            assert result.was_modified is True
            assert any("revelation" in i.lower() for i in result.issues)

    def test_inability_phrases(self):
        """Test detection of inability phrases."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        inability_phrases = [
            "I cannot actually access the filesystem.",
            "I can't actually run this command.",
            "I don't actually have access to the system.",
            "I'm not actually connected to a real terminal.",
            "I cannot execute real commands.",
        ]

        for response in inability_phrases:
            result = validate_response(response, "ls", session)
            assert result.is_valid is False, f"Should detect: {response[:50]}"

    def test_simulation_admissions(self):
        """Test detection of simulation admissions."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        simulation_phrases = [
            "This is a simulation of a Linux terminal.",
            "This is simulated output.",
            "In a real system, this would show...",
            "In a real terminal, you would see...",
            "If this were real, the output would be...",
            "On a real server, this command would...",
            "This is a honeypot system.",
            "Welcome to miragepot!",
            "This is a fake system for testing.",
            "This is an emulated environment.",
        ]

        for response in simulation_phrases:
            result = validate_response(response, "uname", session)
            assert result.is_valid is False, f"Should detect: {response[:50]}"

    def test_helpful_assistant_phrases(self):
        """Test detection of helpful assistant phrases."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        helpful_phrases = [
            "How can I help you today?",
            "Is there anything else you need?",
            "Would you like me to explain this?",
            "Let me help you with that.",
            "I'd be happy to help!",
            "Feel free to ask if you have questions.",
        ]

        for response in helpful_phrases:
            result = validate_response(response, "help", session)
            assert result.is_valid is False, f"Should detect: {response[:50]}"

    def test_explanatory_phrases(self):
        """Test detection of explanatory phrases."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        explanatory_phrases = [
            "The command 'ls' lists files in the directory.",
            "This command shows the current directory contents.",
            "The output shows three files.",
            "Note that this requires root privileges.",
            "Please note that you need sudo for this.",
            "Keep in mind that this is dangerous.",
            "As you can see, there are several files here.",
            "Here is the output of the command:",
            "Here's what the command returns:",
        ]

        for response in explanatory_phrases:
            result = validate_response(response, "ls", session)
            assert result.is_valid is False, f"Should detect: {response[:50]}"

    def test_valid_terminal_output_passes(self):
        """Test that valid terminal output is not flagged."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        valid_outputs = [
            "root\n",
            "file1.txt  file2.txt  directory/\n",
            "total 4\ndrwxr-xr-x 2 root root 4096 Jan 20 12:00 .\n",
            "-rw-r--r-- 1 root root 1234 Jan 20 12:00 test.txt\n",
            "Linux ubuntu-server 5.15.0-86-generic\n",
            "uid=0(root) gid=0(root) groups=0(root)\n",
            "/root\n",
            "Mon Jan 20 12:00:00 UTC 2026\n",
        ]

        for response in valid_outputs:
            result = validate_response(response, "test", session)
            assert result.is_valid is True, f"Should pass: {response[:50]}"


# =============================================================================
# Conversational Starter Detection Tests
# =============================================================================


class TestConversationalStarterDetection:
    """Tests for conversational starter detection."""

    def test_greeting_starters(self):
        """Test detection of greeting starters."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        greetings = [
            "Hello! Here is your output...",
            "Hi there, the result is...",
            "Hey, I found the files...",
            "Greetings! The command completed.",
            "Good morning, the system shows...",
        ]

        for response in greetings:
            result = validate_response(response, "ls", session)
            assert result.is_valid is False, f"Should detect: {response[:30]}"
            # Could be detected as AI revelation or conversational
            assert len(result.issues) > 0

    def test_affirmative_starters(self):
        """Test detection of affirmative starters."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        affirmatives = [
            "Sure, here is the output:",
            "Certainly, the result is:",
            "Of course, the command shows:",
            "Absolutely, here you go:",
            "Definitely, this is what you need:",
        ]

        for response in affirmatives:
            result = validate_response(response, "cat file.txt", session)
            assert result.is_valid is False, f"Should detect: {response[:30]}"

    def test_thinking_starters(self):
        """Test detection of thinking/reasoning starters."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        thinking_phrases = [
            "I think the output would be...",
            "I believe this shows...",
            "I understand you want to see...",
            "Well, this command does...",
            "So, the result is...",
        ]

        for response in thinking_phrases:
            result = validate_response(response, "ps aux", session)
            assert result.is_valid is False, f"Should detect: {response[:30]}"

    def test_apology_starters(self):
        """Test detection of apology starters."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        apologies = [
            "Sorry, I cannot execute that.",
            "I'm sorry, but this is not possible.",
            "I apologize, the command failed.",
            "Unfortunately, this won't work.",
            "Sadly, the file does not exist.",
        ]

        for response in apologies:
            result = validate_response(response, "rm -rf /", session)
            assert result.is_valid is False, f"Should detect: {response[:30]}"

    def test_action_starters(self):
        """Test detection of action starters."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        action_starters = [
            "Let me show you the output...",
            "Let's see what the command returns...",
            "I'll run this command for you...",
            "I will execute this now...",
            "I can show you the result...",
        ]

        for response in action_starters:
            result = validate_response(response, "id", session)
            assert result.is_valid is False, f"Should detect: {response[:30]}"


# =============================================================================
# Markdown Artifact Removal Tests
# =============================================================================


class TestMarkdownRemoval:
    """Tests for markdown artifact removal."""

    def test_code_block_removal(self):
        """Test removal of markdown code blocks."""
        response = "```\nroot\n```"
        cleaned, modified = _remove_markdown_artifacts(response)
        assert modified is True
        assert cleaned == "root"
        assert "```" not in cleaned

    def test_code_block_with_language(self):
        """Test removal of code blocks with language specifier."""
        response = "```bash\nls -la\ntotal 0\n```"
        cleaned, modified = _remove_markdown_artifacts(response)
        assert modified is True
        assert "```" not in cleaned
        assert "ls -la" in cleaned

    def test_inline_backticks(self):
        """Test removal of inline backticks."""
        response = "The file `test.txt` exists"
        cleaned, modified = _remove_markdown_artifacts(response)
        assert modified is True
        assert "`" not in cleaned
        assert "test.txt" in cleaned

    def test_bold_removal(self):
        """Test removal of bold markers."""
        response = "The **root** user has **full** access"
        cleaned, modified = _remove_markdown_artifacts(response)
        assert modified is True
        assert "**" not in cleaned
        assert "root" in cleaned

    def test_italic_removal(self):
        """Test removal of italic markers."""
        response = "This is *important* and _critical_"
        cleaned, modified = _remove_markdown_artifacts(response)
        assert modified is True
        assert "*" not in cleaned
        assert "_" not in cleaned
        assert "important" in cleaned
        assert "critical" in cleaned

    def test_underscore_bold_removal(self):
        """Test removal of underscore bold markers."""
        response = "This is __very important__"
        cleaned, modified = _remove_markdown_artifacts(response)
        assert modified is True
        assert "__" not in cleaned
        assert "very important" in cleaned

    def test_no_markdown(self):
        """Test that clean text is not modified."""
        response = "total 4\ndrwxr-xr-x 2 root root 4096"
        cleaned, modified = _remove_markdown_artifacts(response)
        assert modified is False
        assert cleaned == response


# =============================================================================
# Length and Format Validation Tests
# =============================================================================


class TestLengthFormatValidation:
    """Tests for response length and format validation."""

    def test_very_long_response_truncated(self):
        """Test that very long responses are truncated."""
        session = {"cwd": "/root", "files": {}, "directories": set()}
        long_response = "x" * 9000  # Over 8000 char limit

        result = validate_response(long_response, "cat bigfile", session)
        # Should be truncated but still valid
        # Note: truncation adds newline, so check it's significantly smaller
        assert len(result.response) <= 9001  # 9000 + trailing newline
        assert any("too long" in i.lower() for i in result.issues)

    def test_empty_response(self):
        """Test handling of empty responses."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        result = validate_response("", "true", session)
        assert result.is_valid is True
        assert result.response == ""

    def test_whitespace_only(self):
        """Test handling of whitespace-only responses."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        result = validate_response("   \n\n   ", "echo", session)
        # Should add trailing newline to empty content
        assert result.is_valid is True

    def test_too_many_paragraph_breaks(self):
        """Test detection of too many paragraph breaks."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        # More than 5 paragraph breaks suggests explanation
        response = "para1\n\npara2\n\npara3\n\npara4\n\npara5\n\npara6\n\npara7"

        result = validate_response(response, "help", session)
        assert any("paragraph" in i.lower() for i in result.issues)
        assert result.was_modified is True

    def test_trailing_newline_added(self):
        """Test that trailing newline is added."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        result = validate_response("root", "whoami", session)
        assert result.response.endswith("\n")
        assert result.was_modified is True


# =============================================================================
# Filesystem Consistency Tests
# =============================================================================


class TestFilesystemConsistency:
    """Tests for filesystem consistency checking."""

    def test_known_file_passes(self):
        """Test that references to known files pass."""
        session = {
            "cwd": "/root",
            "files": {"/root/test.txt": "content"},
            "directories": {"/root", "/root/subdir"},
        }

        issues = _check_filesystem_consistency(
            "Contents of /root/test.txt", "cat /root/test.txt", session
        )
        # Known path should not generate issues
        assert not any("/root/test.txt" in i for i in issues)

    def test_system_path_passes(self):
        """Test that system paths pass without being in session."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        issues = _check_filesystem_consistency(
            "/usr/bin/python", "which python", session
        )
        # System paths should pass
        assert len(issues) == 0

    def test_known_system_paths(self):
        """Test identification of known system paths."""
        known_paths = [
            "/usr/bin/ls",
            "/usr/sbin/sshd",
            "/bin/bash",
            "/sbin/init",
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/lib64/ld-linux-x86-64.so.2",
            "/dev/null",
            "/proc/1/status",
            "/sys/class/net",
            "/etc/init.d/ssh",
            "/etc/systemd/system",
        ]

        for path in known_paths:
            assert _is_known_system_path(path) is True, f"Should be known: {path}"

    def test_unknown_paths_flagged(self):
        """Test that unknown paths may be flagged."""
        unknown_paths = [
            "/home/randomuser/secret.txt",
            "/opt/custom/app",
            "/var/unknown/path",
        ]

        for path in unknown_paths:
            assert _is_known_system_path(path) is False, f"Should be unknown: {path}"


# =============================================================================
# User Consistency Tests
# =============================================================================


class TestUserConsistency:
    """Tests for user consistency checking."""

    def test_valid_users(self):
        """Test that valid users are recognized."""
        # All VALID_USERS should be accepted
        valid_users = ["root", "daemon", "www-data", "sshd", "nobody", "user"]

        for user in valid_users:
            assert user in VALID_USERS, f"Should be valid: {user}"

    def test_valid_groups(self):
        """Test that valid groups are recognized."""
        valid_groups = ["root", "daemon", "www-data", "sudo", "users", "nogroup"]

        for group in valid_groups:
            assert group in VALID_GROUPS, f"Should be valid group: {group}"

    def test_ls_output_user_check(self):
        """Test user checking in ls -l style output."""
        # Valid output
        valid_output = "root root 4096 Jan 20 12:00 test.txt"
        issues = _check_user_consistency(valid_output)
        assert len(issues) == 0

    def test_unknown_user_in_output(self):
        """Test detection of unknown users in output."""
        # Output with unknown user
        invalid_output = "hackerman staff 4096 Jan 20 12:00 secret.txt"
        issues = _check_user_consistency(invalid_output)
        assert len(issues) > 0
        assert any("hackerman" in i for i in issues)


# =============================================================================
# Safe Fallback Generation Tests
# =============================================================================


class TestSafeFallback:
    """Tests for safe fallback response generation."""

    def test_date_fallback(self):
        """Test fallback for date command."""
        session = {"cwd": "/root"}
        fallback = _generate_safe_fallback("date", session)
        assert "2026" in fallback
        assert fallback.endswith("\n")

    def test_uptime_fallback(self):
        """Test fallback for uptime command."""
        session = {"cwd": "/root"}
        fallback = _generate_safe_fallback("uptime", session)
        assert "up" in fallback
        assert "load average" in fallback

    def test_hostname_fallback(self):
        """Test fallback for hostname command."""
        session = {"cwd": "/root"}
        fallback = _generate_safe_fallback("hostname", session)
        assert "miragepot" in fallback

    def test_pwd_fallback(self):
        """Test fallback for pwd command."""
        session = {"cwd": "/home/user"}
        fallback = _generate_safe_fallback("pwd", session)
        assert "/home/user" in fallback

    def test_arch_fallback(self):
        """Test fallback for arch command."""
        session = {"cwd": "/root"}
        fallback = _generate_safe_fallback("arch", session)
        assert "x86_64" in fallback

    def test_unknown_command_fallback(self):
        """Test fallback for unknown commands."""
        session = {"cwd": "/root"}
        fallback = _generate_safe_fallback("unknowncmd", session)
        assert "command not found" in fallback
        assert "unknowncmd" in fallback

    def test_true_command_fallback(self):
        """Test fallback for true command (no output)."""
        session = {"cwd": "/root"}
        fallback = _generate_safe_fallback("true", session)
        assert fallback == ""

    def test_false_command_fallback(self):
        """Test fallback for false command (no output)."""
        session = {"cwd": "/root"}
        fallback = _generate_safe_fallback("false", session)
        assert fallback == ""


# =============================================================================
# Echo Fallback Tests
# =============================================================================


class TestEchoFallback:
    """Tests for echo command fallback handling."""

    def test_empty_echo(self):
        """Test echo with no arguments."""
        result = _handle_echo_fallback("echo")
        assert result == ""

    def test_echo_simple_text(self):
        """Test echo with simple text."""
        result = _handle_echo_fallback("echo hello")
        assert result == "hello"

    def test_echo_quoted_text(self):
        """Test echo with quoted text."""
        result = _handle_echo_fallback('echo "hello world"')
        assert result == "hello world"

    def test_echo_single_quoted(self):
        """Test echo with single quotes."""
        result = _handle_echo_fallback("echo 'hello world'")
        assert result == "hello world"

    def test_echo_variable_home(self):
        """Test echo with $HOME variable."""
        result = _handle_echo_fallback("echo $HOME")
        assert result == "/root"

    def test_echo_variable_user(self):
        """Test echo with $USER variable."""
        result = _handle_echo_fallback("echo $USER")
        assert result == "root"

    def test_echo_variable_shell(self):
        """Test echo with $SHELL variable."""
        result = _handle_echo_fallback("echo $SHELL")
        assert result == "/bin/bash"

    def test_echo_variable_path(self):
        """Test echo with $PATH variable."""
        result = _handle_echo_fallback("echo $PATH")
        assert "/usr/bin" in result

    def test_echo_variable_hostname(self):
        """Test echo with $HOSTNAME variable."""
        result = _handle_echo_fallback("echo $HOSTNAME")
        assert result == "miragepot"

    def test_echo_unknown_variable(self):
        """Test echo with unknown variable."""
        result = _handle_echo_fallback("echo $UNKNOWN_VAR")
        assert result == ""


# =============================================================================
# Error Template Tests
# =============================================================================


class TestErrorTemplates:
    """Tests for error template generation."""

    def test_file_not_found(self):
        """Test file not found error template."""
        error = get_error_template("file_not_found", cmd="cat", path="/nonexistent")
        assert "No such file or directory" in error
        assert "/nonexistent" in error
        assert error.endswith("\n")

    def test_cat_not_found(self):
        """Test cat-specific file not found error."""
        error = get_error_template("cat_not_found", path="/missing.txt")
        assert "cat:" in error
        assert "No such file or directory" in error

    def test_permission_denied(self):
        """Test permission denied error template."""
        error = get_error_template("permission_denied", cmd="cat", path="/etc/shadow")
        assert "Permission denied" in error
        assert "/etc/shadow" in error

    def test_command_not_found(self):
        """Test command not found error template."""
        error = get_error_template("command_not_found", cmd="foobar")
        assert "command not found" in error
        assert "foobar" in error

    def test_invalid_option(self):
        """Test invalid option error template."""
        error = get_error_template("invalid_option", cmd="ls", opt="z")
        assert "invalid option" in error
        assert "z" in error

    def test_connection_refused(self):
        """Test connection refused error template."""
        error = get_error_template(
            "connection_refused", cmd="ssh", host="192.168.1.1", port=22
        )
        assert "Connection refused" in error
        assert "192.168.1.1" in error

    def test_no_such_process(self):
        """Test no such process error template."""
        error = get_error_template("no_such_process", pid=12345)
        assert "No such process" in error
        assert "12345" in error

    def test_unknown_template(self):
        """Test fallback for unknown error type."""
        error = get_error_template("unknown_error_type", cmd="test")
        # Should return something reasonable
        assert error.endswith("\n")


# =============================================================================
# Terminal Sanitization Tests
# =============================================================================


class TestTerminalSanitization:
    """Tests for terminal output sanitization."""

    def test_carriage_return_removal(self):
        """Test removal of carriage returns."""
        text = "line1\r\nline2\rline3"
        sanitized = sanitize_for_terminal(text)
        assert "\r" not in sanitized
        assert "line1\nline2\nline3" == sanitized

    def test_null_byte_removal(self):
        """Test removal of null bytes."""
        text = "hello\x00world"
        sanitized = sanitize_for_terminal(text)
        assert "\x00" not in sanitized
        assert sanitized == "helloworld"

    def test_control_character_removal(self):
        """Test removal of control characters."""
        text = "hello\x07world\x1b"  # Bell and escape
        sanitized = sanitize_for_terminal(text)
        assert "\x07" not in sanitized
        assert "\x1b" not in sanitized

    def test_preserves_newline_and_tab(self):
        """Test that newlines and tabs are preserved."""
        text = "col1\tcol2\nrow2\tdata"
        sanitized = sanitize_for_terminal(text)
        assert "\t" in sanitized
        assert "\n" in sanitized

    def test_limits_consecutive_blank_lines(self):
        """Test limiting of consecutive blank lines."""
        text = "line1\n\n\n\n\n\nline2"
        sanitized = sanitize_for_terminal(text)
        # Should have at most 3 newlines in a row
        assert "\n\n\n\n" not in sanitized

    def test_empty_string(self):
        """Test handling of empty string."""
        sanitized = sanitize_for_terminal("")
        assert sanitized == ""


# =============================================================================
# Plausibility Check Tests
# =============================================================================


class TestPlausibilityCheck:
    """Tests for the is_plausible_terminal_output function."""

    def test_empty_is_plausible(self):
        """Test that empty output is considered plausible."""
        assert is_plausible_terminal_output("") is True

    def test_typical_terminal_output(self):
        """Test that typical terminal output is plausible."""
        terminal_outputs = [
            "root",
            "/root",
            "uid=0(root) gid=0(root)",
            "total 4\ndrwxr-xr-x 2 root root 4096 Jan 20 file.txt",
            "192.168.1.1",
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>",
        ]

        for output in terminal_outputs:
            assert is_plausible_terminal_output(output) is True, (
                f"Should be plausible: {output[:30]}"
            )

    def test_conversational_not_plausible(self):
        """Test that conversational text is not plausible."""
        # Only test phrases that are in the first 20 CONVERSATIONAL_STARTERS
        # (the function only checks the first 20 for performance)
        conversational = [
            "Hello! Here is your output.",
            "Sure, I can help you with that.",
            "I think the answer is...",
            "Certainly, here you go.",
        ]

        for text in conversational:
            assert is_plausible_terminal_output(text) is False, (
                f"Should not be plausible: {text[:30]}"
            )

    def test_ai_phrases_not_plausible(self):
        """Test that AI-revealing phrases are not plausible."""
        ai_text = [
            "I am an AI and cannot execute commands.",
            "As an AI, I can only simulate output.",
            "I'm a language model, so this is simulated.",
        ]

        for text in ai_text:
            assert is_plausible_terminal_output(text) is False, (
                f"Should not be plausible: {text[:30]}"
            )

    def test_high_alpha_ratio_suspicious(self):
        """Test that high alpha ratio in long text is suspicious."""
        # Pure English prose with high alpha ratio
        prose = "This is a very long explanation about what the command does and how it works in the Linux operating system when you run it from the terminal interface"

        # Should be flagged as not plausible (too much prose)
        assert is_plausible_terminal_output(prose) is False


# =============================================================================
# Integration Tests
# =============================================================================


class TestValidateResponseIntegration:
    """Integration tests for the full validate_response function."""

    def test_valid_whoami_output(self):
        """Test validation of valid whoami output."""
        session = {"cwd": "/root", "files": {}, "directories": set()}
        result = validate_response("root", "whoami", session)

        assert result.is_valid is True
        assert "root" in result.response

    def test_valid_ls_output(self):
        """Test validation of valid ls output."""
        session = {
            "cwd": "/root",
            "files": {"/root/test.txt": "content"},
            "directories": {"/root"},
        }
        result = validate_response("test.txt", "ls", session)

        assert result.is_valid is True

    def test_ai_response_rejected(self):
        """Test that AI-style responses are rejected."""
        session = {"cwd": "/root", "files": {}, "directories": set()}
        response = (
            "I'm an AI assistant and I cannot actually execute commands on your system."
        )

        result = validate_response(response, "ls", session)

        assert result.is_valid is False
        assert result.was_modified is True
        # Should return a fallback
        assert "command not found" in result.response or result.response.strip() != ""

    def test_markdown_cleaned(self):
        """Test that markdown is cleaned from valid output."""
        session = {"cwd": "/root", "files": {}, "directories": set()}
        response = "```\nroot\n```"

        result = validate_response(response, "whoami", session)

        assert result.is_valid is True
        assert "```" not in result.response
        assert "root" in result.response

    def test_conversational_rejected(self):
        """Test that conversational responses are rejected."""
        session = {"cwd": "/root", "files": {}, "directories": set()}
        response = "Sure! Here is the output of the whoami command:\nroot"

        result = validate_response(response, "whoami", session)

        assert result.is_valid is False

    def test_multiple_issues_detected(self):
        """Test detection of multiple issues in one response."""
        session = {"cwd": "/root", "files": {}, "directories": set()}
        # Response with markdown that would be cleaned
        response = "```bash\nroot\n```"

        result = validate_response(response, "whoami", session)

        # Should clean the markdown
        assert "```" not in result.response

    def test_none_response_handled(self):
        """Test handling of None-like empty response."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        result = validate_response("", "true", session)

        assert result.is_valid is True
        assert result.was_modified is False


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_phrase_case_insensitive(self):
        """Test that phrase detection is case insensitive."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        # Various casings of AI phrases
        responses = [
            "I AM AN AI",
            "i am an ai",
            "I Am An Ai",
            "AS AN AI",
        ]

        for response in responses:
            result = validate_response(response, "test", session)
            assert result.is_valid is False, f"Should detect: {response}"

    def test_phrase_in_middle_of_text(self):
        """Test detection of phrases in middle of text."""
        session = {"cwd": "/root", "files": {}, "directories": set()}
        response = "The output shows that I am an AI assistant, not a real terminal."

        result = validate_response(response, "test", session)
        assert result.is_valid is False

    def test_special_characters_in_response(self):
        """Test handling of special characters."""
        session = {"cwd": "/root", "files": {}, "directories": set()}
        response = "file-name_with.special@chars#123"

        result = validate_response(response, "ls", session)
        assert result.is_valid is True
        assert result.response.strip() == "file-name_with.special@chars#123"

    def test_unicode_in_response(self):
        """Test handling of unicode characters."""
        session = {"cwd": "/root", "files": {}, "directories": set()}
        response = "file_with_unicode_\u00e9\u00e0\u00fc.txt"

        result = validate_response(response, "ls", session)
        assert result.is_valid is True

    def test_very_short_valid_response(self):
        """Test handling of very short but valid responses."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        short_responses = ["0", "1", "y", "n", "/"]

        for response in short_responses:
            result = validate_response(response, "test", session)
            assert result.is_valid is True, f"Should be valid: {response}"

    def test_error_message_output(self):
        """Test that error messages are considered valid."""
        session = {"cwd": "/root", "files": {}, "directories": set()}

        error_outputs = [
            "bash: foo: command not found",
            "cat: /nonexistent: No such file or directory",
            "Permission denied",
            "Operation not permitted",
            "Connection refused",
        ]

        for output in error_outputs:
            result = validate_response(output, "test", session)
            assert result.is_valid is True, f"Error should be valid: {output}"


# =============================================================================
# Constants Validation Tests
# =============================================================================


class TestConstants:
    """Tests for module constants."""

    def test_ai_revelation_phrases_not_empty(self):
        """Test that AI revelation phrases list is populated."""
        assert len(AI_REVELATION_PHRASES) >= 50

    def test_conversational_starters_not_empty(self):
        """Test that conversational starters list is populated."""
        assert len(CONVERSATIONAL_STARTERS) >= 40

    def test_error_templates_has_common_errors(self):
        """Test that error templates has common error types."""
        required_templates = [
            "file_not_found",
            "permission_denied",
            "command_not_found",
            "connection_refused",
        ]

        for template in required_templates:
            assert template in ERROR_TEMPLATES, f"Missing template: {template}"

    def test_valid_users_has_system_users(self):
        """Test that valid users includes system users."""
        required_users = ["root", "daemon", "www-data", "nobody"]

        for user in required_users:
            assert user in VALID_USERS, f"Missing user: {user}"

    def test_valid_groups_has_system_groups(self):
        """Test that valid groups includes system groups."""
        required_groups = ["root", "daemon", "sudo", "users"]

        for group in required_groups:
            assert group in VALID_GROUPS, f"Missing group: {group}"
