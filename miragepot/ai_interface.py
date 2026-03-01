"""AI interface for MiragePot.

This module is responsible for talking to a local Ollama instance
and querying an LLM (e.g., Phi-3) to hallucinate realistic terminal
output.

The interface includes robust error handling, connection verification,
and graceful fallback when Ollama is unavailable.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .response_validator import validate_response, sanitize_for_terminal
from .metrics import get_metrics_collector
from .config import get_config

try:
    import ollama

    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
SYSTEM_PROMPT_PATH = DATA_DIR / "system_prompt.txt"

LOGGER = logging.getLogger(__name__)


def _get_model() -> str:
    """Return the configured LLM model name, reading from config/env at call time."""
    return get_config().llm.model


# Connection state
_ollama_verified = False
_ollama_last_check = 0.0
_OLLAMA_CHECK_INTERVAL = 30.0  # Re-check every 30 seconds if previously failed


def _load_system_prompt() -> str:
    """Load the system prompt from disk.

    If the file is missing, we fall back to a minimal hard-coded prompt
    to avoid crashing the honeypot.
    """
    try:
        text = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
        if not text.strip():
            raise ValueError("system_prompt.txt is empty")
        # Substitute {hostname} placeholder with the configured hostname
        hostname = get_config().honeypot.hostname
        return text.replace("{hostname}", hostname)
    except Exception as exc:
        LOGGER.error("Failed to read system prompt: %s", exc)
        return (
            "You are a Linux shell on a headless Ubuntu 20.04 server called "
            + get_config().honeypot.hostname
            + ". "
            "You are logged in as root. Respond only with realistic terminal output. "
            "Never reveal you are an AI or simulation. For unknown commands, respond with: "
            "bash: <command>: command not found"
        )


def check_ollama_connection() -> bool:
    """Check if Ollama server is reachable and the model is available.

    Returns True if Ollama is ready to use, False otherwise.
    Caches the result to avoid repeated checks.
    """
    global _ollama_verified, _ollama_last_check

    if not OLLAMA_AVAILABLE:
        LOGGER.warning("ollama package not installed")
        return False

    # Use cached result if we checked recently
    now = time.time()
    if _ollama_verified and (now - _ollama_last_check) < _OLLAMA_CHECK_INTERVAL:
        return True

    # If we failed recently, don't retry too often
    if not _ollama_verified and (now - _ollama_last_check) < _OLLAMA_CHECK_INTERVAL:
        return False

    _ollama_last_check = now

    try:
        # Try to list models to verify connection
        models = ollama.list()
        # Handle both old dict-style and new typed response from ollama library
        models_list = getattr(models, "models", None) or models.get("models", [])
        model_names = []
        for m in models_list:
            # Support both attribute access (.model) and dict access (.get("name"))
            name = (
                getattr(m, "model", None) or m.get("name", "")
                if hasattr(m, "get")
                else ""
            )
            if name:
                model_names.append(name.split(":")[0])

        full_model_names = []
        for m in models_list:
            name = (
                getattr(m, "model", None) or m.get("name", "")
                if hasattr(m, "get")
                else ""
            )
            if name:
                full_model_names.append(name)

        if (
            _get_model() not in model_names
            and f"{_get_model()}:latest" not in full_model_names
        ):
            LOGGER.warning(
                "Model '%s' not found in Ollama. Available models: %s. "
                "Run 'ollama pull %s' to download it.",
                _get_model(),
                model_names,
                _get_model(),
            )
            # Still mark as verified - we'll try anyway and let ollama auto-pull if configured
            _ollama_verified = True
            return True

        _ollama_verified = True
        LOGGER.info("Ollama connection verified, model '%s' available", _get_model())
        return True

    except Exception as exc:
        LOGGER.error("Failed to connect to Ollama: %s", exc)
        _ollama_verified = False
        return False


def build_user_prompt(command: str, session_state: Dict[str, Any]) -> str:
    """Construct the user-side prompt for the LLM.

    We include a light summary of session state so the model can
    maintain plausible continuity (current directory, known files/dirs).
    """
    cwd = session_state.get("cwd", "/root")
    directories = list(session_state.get("directories", []))
    files = session_state.get("files", {})

    state_summary = {
        "cwd": cwd,
        "directories": sorted(directories),
        "files": list(files.keys()),
    }

    return (
        f"You are Ubuntu server '{get_config().honeypot.hostname}'. The following JSON describes the current session state (cwd, known directories, known files).\n"
        "Use it to stay consistent, but DO NOT echo it back.\n"
        "Session state summary (JSON):\n"
        + json.dumps(state_summary)
        + "\n\nCommand: "
        + command
        + "\n"
        + "Respond ONLY with the terminal output for this command. No explanations, no markdown, just raw terminal output."
    )


def _generate_fallback_response(command: str) -> str:
    """Generate a basic fallback response when LLM is unavailable.

    This provides minimal functionality to keep the honeypot running.
    """
    cmd_lower = command.lower().strip()
    cmd_parts = command.split()
    base_cmd = cmd_parts[0] if cmd_parts else command

    # Common commands with static fallback responses
    fallbacks = {
        "date": "Mon Jan 20 12:00:00 UTC 2026\n",
        "uptime": " 12:00:00 up 42 days,  3:15,  1 user,  load average: 0.08, 0.12, 0.10\n",
        "free": "              total        used        free      shared  buff/cache   available\nMem:        4028416     1245312     1523104       89600     1260000     2483104\nSwap:       2097148           0     2097148\n",
        "free -h": "              total        used        free      shared  buff/cache   available\nMem:           3.8Gi       1.2Gi       1.5Gi        87Mi       1.2Gi       2.4Gi\nSwap:          2.0Gi          0B       2.0Gi\n",
        "df -h": "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   12G   35G  26% /\ntmpfs           2.0G     0  2.0G   0% /dev/shm\n/dev/sda2       450G   89G  338G  21% /home\n",
        "w": " 12:00:00 up 42 days,  3:15,  1 user,  load average: 0.08, 0.12, 0.10\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nroot     pts/0    192.168.1.100    11:45    0.00s  0.02s  0.00s w\n",
        "last": "root     pts/0        192.168.1.100    Mon Jan 20 11:45   still logged in\nroot     pts/0        192.168.1.50     Sun Jan 19 14:22 - 18:45  (04:23)\nreboot   system boot  5.15.0-86-generic Sun Jan 19 10:00   still running\n",
        "cat /proc/version": "Linux version 5.15.0-86-generic (buildd@lcy02-amd64-086) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #96-Ubuntu SMP x86_64\n",
        "lsb_release -a": "Distributor ID: Ubuntu\nDescription:    Ubuntu 20.04.6 LTS\nRelease:        20.04\nCodename:       focal\n",
        "which python": "/usr/bin/python\n",
        "which python3": "/usr/bin/python3\n",
        "which bash": "/usr/bin/bash\n",
        "echo $SHELL": "/bin/bash\n",
        "echo $HOME": "/root\n",
        "echo $USER": "root\n",
        "echo $PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n",
        "groups": "root\n",
        "tty": "/dev/pts/0\n",
        "arch": "x86_64\n",
        "nproc": "4\n",
        "getconf LONG_BIT": "64\n",
    }

    # Check exact match first
    if command in fallbacks:
        return fallbacks[command]

    # Check base command for "command not found" response
    known_system_commands = {
        "grep",
        "awk",
        "sed",
        "find",
        "sort",
        "uniq",
        "wc",
        "head",
        "tail",
        "cut",
        "tr",
        "xargs",
        "tee",
        "diff",
        "patch",
        "tar",
        "gzip",
        "gunzip",
        "zip",
        "unzip",
        "nano",
        "vi",
        "vim",
        "less",
        "more",
        "man",
        "info",
        "ping",
        "traceroute",
        "dig",
        "nslookup",
        "host",
        "curl",
        "wget",
        "ssh",
        "scp",
        "rsync",
        "ftp",
        "sftp",
        "nc",
        "netcat",
        "telnet",
        "systemctl",
        "service",
        "journalctl",
        "dmesg",
        "mount",
        "umount",
        "fdisk",
        "parted",
        "mkfs",
        "fsck",
        "lsblk",
        "blkid",
        "df",
        "du",
        "top",
        "htop",
        "ps",
        "kill",
        "killall",
        "pkill",
        "nice",
        "renice",
        "crontab",
        "at",
        "batch",
        "sleep",
        "watch",
        "time",
        "timeout",
        "useradd",
        "userdel",
        "usermod",
        "groupadd",
        "groupdel",
        "passwd",
        "su",
        "sudo",
        "chown",
        "chmod",
        "chgrp",
        "umask",
        "stat",
        "file",
        "ln",
        "readlink",
        "basename",
        "dirname",
        "realpath",
        "mktemp",
        "date",
        "cal",
        "uptime",
        "w",
        "who",
        "last",
        "lastlog",
        "finger",
        "apt",
        "apt-get",
        "dpkg",
        "snap",
        "pip",
        "pip3",
        "npm",
        "yarn",
        "git",
        "svn",
        "hg",
        "docker",
        "docker-compose",
        "kubectl",
        "python",
        "python3",
        "perl",
        "ruby",
        "node",
        "php",
        "java",
        "gcc",
        "g++",
        "make",
        "iptables",
        "ufw",
        "firewall-cmd",
        "nmap",
        "tcpdump",
        "wireshark",
        "mysql",
        "psql",
        "sqlite3",
        "mongo",
        "redis-cli",
        "aws",
        "gcloud",
        "az",
        "terraform",
        "ansible",
        "vagrant",
    }

    if base_cmd in known_system_commands:
        # Return a generic but plausible response for known commands
        # when we can't use the LLM
        return f"bash: {base_cmd}: command execution unavailable\n"

    # Unknown command
    return f"bash: {base_cmd}: command not found\n"


def query_llm(
    command: str, session_state: Dict[str, Any], timeout: float = 30.0
) -> str:
    """Query the local LLM via Ollama and return the response text.

    We use a system prompt (from file) plus a user prompt that embeds
    session state. Any errors are caught and turned into a generic
    terminal-style error message.

    Args:
        command: The shell command to generate output for
        session_state: Current session state (cwd, files, directories)
        timeout: Maximum time to wait for LLM response (seconds)

    Returns:
        Terminal-like output string
    """
    metrics = get_metrics_collector()

    # Check if Ollama is available
    if not check_ollama_connection():
        LOGGER.warning("Ollama unavailable, using fallback response for: %s", command)
        metrics.record_cache_miss()  # Not really a cache miss but tracks fallback usage
        return _generate_fallback_response(command)

    system_prompt = _load_system_prompt()
    user_prompt = build_user_prompt(command, session_state)

    start_time = time.time()
    try:
        cfg = get_config().llm
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                ollama.chat,
                model=_get_model(),
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                options={
                    "temperature": cfg.temperature,
                    "num_predict": cfg.max_tokens,
                },
            )
            response = future.result(timeout=cfg.timeout)
        latency = time.time() - start_time
        content = response.get("message", {}).get("content", "")

        # Record successful LLM request
        metrics.record_llm_request(_get_model(), "success", latency)

        # Clean up the response using basic cleaning first
        content = _clean_llm_response(content, command)

        # Apply advanced validation and anti-hallucination guardrails
        validation_result = validate_response(content, command, session_state)

        if not validation_result.is_valid:
            LOGGER.warning(
                "LLM response failed validation for '%s': %s",
                command,
                validation_result.issues,
            )

        if validation_result.was_modified:
            LOGGER.debug(
                "LLM response was modified for '%s': %s",
                command,
                validation_result.issues,
            )

        content = validation_result.response

        # Final sanitization for terminal output
        content = sanitize_for_terminal(content)

        # Ensure a trailing newline to look like terminal output
        if content and not content.endswith("\n"):
            content += "\n"

        return content

    except Exception as exc:
        latency = time.time() - start_time
        LOGGER.error("Error querying LLM for command '%s': %s", command, exc)

        # Record failed LLM request
        metrics.record_llm_request(_get_model(), "error", latency)

        # Mark connection as failed so we don't keep retrying
        global _ollama_verified
        _ollama_verified = False
        return _generate_fallback_response(command)


def _clean_llm_response(content: str, command: str) -> str:
    """Clean up LLM response to remove common artifacts.

    LLMs sometimes add markdown formatting, explanations, or other
    artifacts that wouldn't appear in a real terminal.
    """
    if not content:
        return content

    original_content = content

    # Remove markdown code blocks
    if content.startswith("```"):
        lines = content.split("\n")
        # Find the actual content between ``` markers
        start_idx = 1 if lines[0].startswith("```") else 0
        end_idx = len(lines)
        for i in range(len(lines) - 1, -1, -1):
            if lines[i].strip() == "```":
                end_idx = i
                break
        content = "\n".join(lines[start_idx:end_idx])

    # Remove leading/trailing whitespace but preserve internal structure
    content = content.strip()

    # Remove common LLM artifacts at the start
    artifacts_to_remove = [
        "Here is the output:",
        "Here's the output:",
        "Here is the result:",
        "Here's the result:",
        "Output:",
        "Result:",
        "The output would be:",
        "This would output:",
        "The output is:",
        "Terminal output:",
    ]
    for artifact in artifacts_to_remove:
        if content.lower().startswith(artifact.lower()):
            content = content[len(artifact) :].strip()

    # Check for conversational/explanation responses that should be rejected
    explanation_indicators = [
        "This command",
        "The command",
        "I cannot",
        "I can't",
        "I'm sorry",
        "I apologize",
        "As an AI",
        "As a language model",
        "I don't have",
        "I'm not able",
        "I am not able",
        "Unfortunately",
        "I'm unable",
        "I am unable",
        "Hello",
        "Hi there",
        "Hi!",
        "Hello!",
        "How can I",
        "How may I",
        "What can I",
        "What would you",
        "Sure,",
        "Sure!",
        "Of course",
        "Certainly",
        "Let me",
        "I'll",
        "I will",
        "Would you like",
        "Do you want",
        "Note:",
        "Note that",
        "Please note",
        "Keep in mind",
        "Remember that",
        "It's important",
        "It is important",
    ]

    content_lower = content.lower()
    for indicator in explanation_indicators:
        if content_lower.startswith(indicator.lower()):
            LOGGER.warning(
                "LLM gave conversational response starting with '%s', using fallback",
                indicator,
            )
            return _generate_fallback_response(command)

    # Check for responses that contain obvious AI/chatbot phrases anywhere
    ai_phrases = [
        "as an ai",
        "as a language model",
        "i'm an ai",
        "i am an ai",
        "i'm a chatbot",
        "i am a chatbot",
        "i cannot actually",
        "i can't actually",
        "in a real terminal",
        "in a real system",
        "if this were real",
        "simulated",
        "simulation",
        "honeypot",
        get_config().honeypot.hostname.lower(),  # Should never mention its own name
    ]

    for phrase in ai_phrases:
        if phrase in content_lower:
            LOGGER.warning(
                "LLM response contains AI phrase '%s', using fallback", phrase
            )
            return _generate_fallback_response(command)

    # Check for excessively long responses (likely explanations)
    if len(content) > 4000:
        LOGGER.warning("LLM response too long (%d chars), truncating", len(content))
        # Truncate to reasonable length
        lines = content.split("\n")
        if len(lines) > 50:
            content = "\n".join(lines[:50])

    # Check for responses that look like they're trying to be helpful in wrong way
    # (e.g., multi-paragraph explanations)
    if content.count("\n\n") > 3:
        # Multiple paragraph breaks suggest explanatory text
        LOGGER.warning("LLM response has too many paragraph breaks, may be explanation")
        # Only keep first section
        sections = content.split("\n\n")
        if sections[0].strip():
            content = sections[0].strip()

    return content


def verify_ollama_setup() -> tuple[bool, str]:
    """Verify Ollama is properly set up and return status message.

    This is meant to be called at startup to inform the user.

    Returns:
        Tuple of (success: bool, message: str)
    """
    if not OLLAMA_AVAILABLE:
        return False, "ollama package not installed. Run: pip install ollama"

    try:
        models = ollama.list()
        # Handle both old dict-style and new typed response from ollama library
        models_list = getattr(models, "models", None) or models.get("models", [])
        model_names = []
        for m in models_list:
            # Support both attribute access (.model) and dict access (.get("name"))
            name = (
                getattr(m, "model", None) or m.get("name", "")
                if hasattr(m, "get")
                else ""
            )
            if name:
                model_names.append(name)

        # Check for our model (with or without :latest suffix)
        model_found = any(
            name == _get_model() or name.startswith(f"{_get_model()}:")
            for name in model_names
        )

        if not model_found:
            return False, (
                f"Model '{_get_model()}' not found. "
                f"Available models: {model_names}. "
                f"Run: ollama pull {_get_model()}"
            )

        return True, f"Ollama ready with model '{_get_model()}'"

    except Exception as exc:
        return False, f"Cannot connect to Ollama: {exc}. Run: ollama serve"


def ensure_ollama_running() -> tuple[bool, str]:
    """Check if Ollama is running; if not, attempt to auto-start it.

    Launches ``ollama serve`` as a detached background process so it
    keeps running independently of MiragePot's own lifecycle.

    Polls up to 10 seconds for Ollama to become reachable after
    starting it.  If it doesn't respond in time the honeypot falls
    back to cached/static responses as usual — startup is never blocked.

    Returns:
        Tuple of (success: bool, message: str)
    """
    # Already up? Nothing to do.
    ok, msg = verify_ollama_setup()
    if ok:
        return True, msg

    LOGGER.info("Ollama not running — attempting to auto-start 'ollama serve'...")

    try:
        subprocess.Popen(
            ["ollama", "serve"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,  # detach from MiragePot's process group
        )
    except FileNotFoundError:
        return (
            False,
            "ollama executable not found in PATH. "
            "Install from https://ollama.ai and run 'ollama pull phi3'.",
        )
    except Exception as exc:
        return False, f"Failed to auto-start Ollama: {exc}"

    # Poll until reachable (max 10 seconds)
    for attempt in range(1, 11):
        time.sleep(1)
        LOGGER.debug("Waiting for Ollama to start (attempt %d/10)...", attempt)
        ok, msg = verify_ollama_setup()
        if ok:
            LOGGER.info("Ollama auto-started successfully.")
            return True, f"Ollama auto-started successfully. {msg}"

    return (
        False,
        "Ollama was started but did not become reachable within 10 seconds. "
        "LLM responses will use fallback mode.",
    )
