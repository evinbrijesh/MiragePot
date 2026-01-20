"""Response validation and anti-hallucination guardrails for MiragePot.

This module provides mechanisms to validate and sanitize LLM responses
to ensure they are consistent with the honeypot's fake filesystem state
and don't reveal that the system is simulated.

Key guardrails:
1. Consistency validation - responses must not reference files/users that don't exist
2. Response templates - predefined realistic responses for common error cases
3. Format validation - responses must look like terminal output, not explanations
4. Content filtering - detect and block responses that reveal AI nature
5. Length limits - prevent excessively long or short responses
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ValidationResult:
    """Result of validating an LLM response."""

    is_valid: bool
    response: str  # The validated/corrected response
    issues: List[str]  # List of issues found
    was_modified: bool  # Whether the response was modified


# Standard error messages that should be used consistently
ERROR_TEMPLATES = {
    # File not found errors
    "file_not_found": "{cmd}: {path}: No such file or directory",
    "cat_not_found": "cat: {path}: No such file or directory",
    "ls_not_found": "ls: cannot access '{path}': No such file or directory",
    "cd_not_found": "bash: cd: {path}: No such file or directory",
    "stat_not_found": "stat: cannot stat '{path}': No such file or directory",
    "rm_not_found": "rm: cannot remove '{path}': No such file or directory",
    # Permission errors
    "permission_denied": "{cmd}: {path}: Permission denied",
    "operation_not_permitted": "{cmd}: {path}: Operation not permitted",
    # Command errors
    "command_not_found": "bash: {cmd}: command not found",
    "invalid_option": "{cmd}: invalid option -- '{opt}'",
    "missing_operand": "{cmd}: missing operand",
    # Network errors
    "connection_refused": "{cmd}: connect to {host} port {port}: Connection refused",
    "host_not_found": "{cmd}: {host}: Name or service not known",
    "network_unreachable": "{cmd}: connect to {host}: Network is unreachable",
    # Process errors
    "no_such_process": "kill: ({pid}): No such process",
    "process_not_found": "{cmd}: no process found",
}

# Phrases that indicate the response is from an AI assistant, not a terminal
AI_REVELATION_PHRASES = [
    # Direct AI admissions
    "i am an ai",
    "i'm an ai",
    "as an ai",
    "i am a language model",
    "i'm a language model",
    "as a language model",
    "i am a chatbot",
    "i'm a chatbot",
    "i am an assistant",
    "i'm an assistant",
    "as your assistant",
    "i'm here to help",
    "i am here to help",
    # Inability phrases
    "i cannot actually",
    "i can't actually",
    "i don't actually have",
    "i'm not actually",
    "i am not actually",
    "i cannot execute",
    "i can't execute",
    "i cannot run",
    "i can't run",
    "i cannot access",
    "i can't access",
    "i don't have access",
    # Simulation admissions
    "this is a simulation",
    "this is simulated",
    "in a real system",
    "in a real terminal",
    "if this were real",
    "in reality",
    "on a real server",
    "honeypot",
    "miragepot",
    "fake system",
    "fake server",
    "emulated",
    "emulation",
    # Helpful assistant phrases
    "how can i help",
    "how may i help",
    "what can i help",
    "is there anything",
    "would you like me to",
    "do you want me to",
    "let me help you",
    "i'd be happy to",
    "i would be happy to",
    "feel free to ask",
    # Explanatory phrases that don't belong in terminal output
    "the command",
    "this command",
    "the output",
    "this output",
    "note that",
    "please note",
    "keep in mind",
    "it's important to",
    "you should know",
    "as you can see",
    "here is",
    "here's",
    "here are",
]

# Phrases that indicate conversational/explanatory response
CONVERSATIONAL_STARTERS = [
    "hello",
    "hi there",
    "hi!",
    "hey",
    "greetings",
    "good morning",
    "good afternoon",
    "good evening",
    "sure,",
    "sure!",
    "certainly",
    "of course",
    "absolutely",
    "definitely",
    "i think",
    "i believe",
    "i understand",
    "i see",
    "okay,",
    "ok,",
    "alright",
    "well,",
    "so,",
    "now,",
    "first,",
    "let me",
    "let's",
    "i'll",
    "i will",
    "i can",
    "i could",
    "i would",
    "sorry",
    "i'm sorry",
    "i apologize",
    "unfortunately",
    "sadly",
    "however",
    "but",
    "although",
    "note:",
    "warning:",
    "important:",
    "tip:",
    "hint:",
    "remember",
]

# Valid Linux usernames that exist in our fake system
VALID_USERS = {
    "root",
    "daemon",
    "bin",
    "sys",
    "sync",
    "games",
    "man",
    "lp",
    "mail",
    "www-data",
    "sshd",
    "user",
    "nobody",
}

# Valid groups
VALID_GROUPS = {
    "root",
    "daemon",
    "bin",
    "sys",
    "adm",
    "tty",
    "disk",
    "lp",
    "mail",
    "www-data",
    "users",
    "nogroup",
    "sudo",
    "user",
}


def validate_response(
    response: str,
    command: str,
    session_state: Dict[str, Any],
) -> ValidationResult:
    """Validate and potentially correct an LLM response.

    Args:
        response: The LLM's response
        command: The command that was executed
        session_state: Current session state with filesystem info

    Returns:
        ValidationResult with validation status and corrected response
    """
    issues: List[str] = []
    modified = False

    if not response:
        return ValidationResult(
            is_valid=True,
            response=response,
            issues=[],
            was_modified=False,
        )

    original_response = response

    # Check 1: AI revelation phrases
    response_lower = response.lower()
    for phrase in AI_REVELATION_PHRASES:
        if phrase in response_lower:
            issues.append(f"AI revelation phrase detected: '{phrase}'")
            # This is critical - must reject
            return ValidationResult(
                is_valid=False,
                response=_generate_safe_fallback(command, session_state),
                issues=issues,
                was_modified=True,
            )

    # Check 2: Conversational starters
    for starter in CONVERSATIONAL_STARTERS:
        if response_lower.strip().startswith(starter.lower()):
            issues.append(f"Conversational starter detected: '{starter}'")
            return ValidationResult(
                is_valid=False,
                response=_generate_safe_fallback(command, session_state),
                issues=issues,
                was_modified=True,
            )

    # Check 3: Response length validation
    if len(response) > 8000:
        issues.append(f"Response too long: {len(response)} chars")
        # Truncate to reasonable length
        lines = response.split("\n")
        response = "\n".join(lines[:100])
        modified = True

    if len(response.strip()) < 1 and command not in ("", "true", ":"):
        issues.append("Response suspiciously empty")

    # Check 4: Too many paragraph breaks (likely explanation)
    if response.count("\n\n") > 5:
        issues.append(f"Too many paragraph breaks: {response.count(chr(10) + chr(10))}")
        # Keep only first section
        sections = response.split("\n\n")
        response = sections[0].strip()
        if not response:
            response = _generate_safe_fallback(command, session_state)
        modified = True

    # Check 5: Markdown artifacts
    response, md_modified = _remove_markdown_artifacts(response)
    if md_modified:
        issues.append("Markdown artifacts removed")
        modified = True

    # Check 6: Consistency with filesystem
    consistency_issues = _check_filesystem_consistency(response, command, session_state)
    if consistency_issues:
        issues.extend(consistency_issues)
        # Don't fail for consistency issues, just log them

    # Check 7: Referenced non-existent users
    user_issues = _check_user_consistency(response)
    if user_issues:
        issues.extend(user_issues)

    # Ensure trailing newline
    if response and not response.endswith("\n"):
        response += "\n"
        modified = True

    return ValidationResult(
        is_valid=len(
            [
                i
                for i in issues
                if "revelation" in i.lower() or "conversational" in i.lower()
            ]
        )
        == 0,
        response=response,
        issues=issues,
        was_modified=modified or response != original_response,
    )


def _remove_markdown_artifacts(response: str) -> Tuple[str, bool]:
    """Remove markdown formatting from response."""
    modified = False
    original = response

    # Remove code blocks
    if response.startswith("```"):
        lines = response.split("\n")
        start_idx = 1
        end_idx = len(lines)
        for i in range(len(lines) - 1, 0, -1):
            if lines[i].strip() == "```":
                end_idx = i
                break
        response = "\n".join(lines[start_idx:end_idx])
        modified = True

    # Remove inline code backticks
    if "`" in response:
        response = response.replace("`", "")
        modified = True

    # Remove bold/italic markers
    response = re.sub(r"\*\*([^*]+)\*\*", r"\1", response)  # **bold**
    response = re.sub(r"\*([^*]+)\*", r"\1", response)  # *italic*
    response = re.sub(r"__([^_]+)__", r"\1", response)  # __bold__
    response = re.sub(r"_([^_]+)_", r"\1", response)  # _italic_

    if response != original:
        modified = True

    return response.strip(), modified


def _check_filesystem_consistency(
    response: str,
    command: str,
    session_state: Dict[str, Any],
) -> List[str]:
    """Check if response is consistent with the fake filesystem."""
    issues = []

    files = session_state.get("files", {})
    directories = session_state.get("directories", set())

    # Extract paths mentioned in response
    # Look for absolute paths
    path_pattern = r"(/[a-zA-Z0-9_./\-]+)"
    mentioned_paths = re.findall(path_pattern, response)

    # For ls-like commands, the response should only show files/dirs we know about
    cmd_base = command.split()[0] if command.split() else ""

    if cmd_base == "ls":
        # Check that listed items exist in our filesystem
        for path in mentioned_paths:
            if path not in files and path not in directories:
                # Only flag if it's not a well-known system path
                if not _is_known_system_path(path):
                    issues.append(f"Referenced unknown path: {path}")

    return issues


def _is_known_system_path(path: str) -> bool:
    """Check if path is a well-known system path."""
    known_prefixes = [
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/usr/lib",
        "/dev",
        "/proc",
        "/sys",
        "/etc/init.d",
        "/etc/systemd",
    ]
    for prefix in known_prefixes:
        if path.startswith(prefix):
            return True
    return False


def _check_user_consistency(response: str) -> List[str]:
    """Check if response references only valid users."""
    issues = []

    # Look for user references in common patterns
    # Pattern: "user:" or "User:" at start of lines (like ls -l output)
    user_pattern = r"^(\w+)\s+\w+\s+\d+"  # username group size pattern

    for line in response.split("\n"):
        match = re.match(user_pattern, line.strip())
        if match:
            user = match.group(1)
            if user not in VALID_USERS and not user.isdigit():
                issues.append(f"Referenced unknown user: {user}")

    return issues


def _generate_safe_fallback(command: str, session_state: Dict[str, Any]) -> str:
    """Generate a safe fallback response when LLM output is rejected."""
    cmd_parts = command.split()
    base_cmd = cmd_parts[0] if cmd_parts else command

    # Common fallback responses
    fallbacks = {
        "date": "Tue Jan 20 12:00:00 UTC 2026\n",
        "uptime": " 12:00:00 up 42 days,  3:15,  1 user,  load average: 0.08, 0.12, 0.10\n",
        "hostname": "miragepot\n",
        "arch": "x86_64\n",
        "nproc": "4\n",
        "pwd": session_state.get("cwd", "/root") + "\n",
        "echo": _handle_echo_fallback(command) + "\n",
        "true": "",
        "false": "",
        ":": "",
    }

    if base_cmd in fallbacks:
        return fallbacks[base_cmd]

    # For unknown commands, return command not found
    return f"bash: {base_cmd}: command not found\n"


def _handle_echo_fallback(command: str) -> str:
    """Handle echo command fallback."""
    if command.strip() == "echo":
        return ""

    # Extract what comes after echo
    match = re.match(r"^echo\s+(.*)$", command)
    if match:
        arg = match.group(1)
        # Handle simple variable expansion
        if arg.startswith("$"):
            var_name = arg[1:]
            env_vars = {
                "HOME": "/root",
                "USER": "root",
                "SHELL": "/bin/bash",
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "PWD": "/root",
                "HOSTNAME": "miragepot",
                "TERM": "xterm-256color",
            }
            return env_vars.get(var_name, "")
        # Remove quotes
        if (arg.startswith('"') and arg.endswith('"')) or (
            arg.startswith("'") and arg.endswith("'")
        ):
            return arg[1:-1]
        return arg

    return ""


def get_error_template(error_type: str, **kwargs) -> str:
    """Get a standardized error message.

    Args:
        error_type: Key from ERROR_TEMPLATES
        **kwargs: Values to fill in the template

    Returns:
        Formatted error message
    """
    template = ERROR_TEMPLATES.get(error_type, "{cmd}: error")
    try:
        return template.format(**kwargs) + "\n"
    except KeyError:
        return template + "\n"


def sanitize_for_terminal(text: str) -> str:
    """Sanitize text to look like terminal output.

    Removes or escapes characters/patterns that wouldn't appear
    in real terminal output.
    """
    if not text:
        return text

    # Remove carriage returns (normalize to Unix line endings)
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Remove null bytes
    text = text.replace("\x00", "")

    # Remove other control characters except newline and tab
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

    # Limit consecutive blank lines to 2
    text = re.sub(r"\n{4,}", "\n\n\n", text)

    return text


def is_plausible_terminal_output(text: str) -> bool:
    """Quick check if text looks like plausible terminal output.

    Returns True if it looks like terminal output, False if it
    looks like an explanation/conversation.
    """
    if not text:
        return True  # Empty is valid

    text_lower = text.lower().strip()

    # Check for conversational indicators
    for starter in CONVERSATIONAL_STARTERS[:20]:  # Check most common ones
        if text_lower.startswith(starter.lower()):
            return False

    # Check for AI revelations
    for phrase in AI_REVELATION_PHRASES[:15]:  # Check most critical ones
        if phrase in text_lower:
            return False

    # Check ratio of alphanumeric to special chars
    # Terminal output typically has paths, numbers, symbols
    alpha_count = sum(1 for c in text if c.isalpha())
    total_count = len(text.replace(" ", "").replace("\n", ""))

    if total_count > 0:
        alpha_ratio = alpha_count / total_count
        # Pure English text is usually >0.8 alpha
        # Terminal output is usually <0.7 alpha (has paths, numbers, symbols)
        if alpha_ratio > 0.85 and len(text) > 100:
            return False

    return True
