"""AI interface for MiragePot.

This module is responsible for talking to a local Ollama instance
and querying an LLM (e.g., Phi-3) to hallucinate realistic terminal
output.

The interface is deliberately thin and easy to mock for testing.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

import ollama

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
SYSTEM_PROMPT_PATH = DATA_DIR / "system_prompt.txt"

LOGGER = logging.getLogger(__name__)

# Default model name; can be adjusted if needed.
LLM_MODEL = "phi3"


def _load_system_prompt() -> str:
    """Load the system prompt from disk.

    If the file is missing, we fall back to a minimal hard-coded prompt
    to avoid crashing the honeypot.
    """
    try:
        text = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
        if not text.strip():
            raise ValueError("system_prompt.txt is empty")
        return text
    except Exception as exc:  # pragma: no cover - defensive logging
        LOGGER.error("Failed to read system prompt: %s", exc)
        return (
            "You are a Linux shell on a headless Ubuntu server. "
            "Respond only with realistic terminal output."
        )


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
        "You are Ubuntu server 'miragepot'. The following JSON describes the current session state (cwd, known directories, known files).\n"
        "Use it to stay consistent, but DO NOT echo it back.\n"
        "Session state summary (JSON):\n"
        + json.dumps(state_summary)
        + "\n\nCommand: "
        + command
        + "\n"
        + "Respond ONLY with the terminal output for this command."
    )


def query_llm(command: str, session_state: Dict[str, Any]) -> str:
    """Query the local LLM via Ollama and return the response text.

    We use a system prompt (from file) plus a user prompt that embeds
    session state. Any errors are caught and turned into a generic
    terminal-style error message.
    """
    system_prompt = _load_system_prompt()
    user_prompt = build_user_prompt(command, session_state)

    try:
        response = ollama.chat(
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        content = response.get("message", {}).get("content", "")
        # Ensure a trailing newline to look like terminal output.
        if content and not content.endswith("\n"):
            content += "\n"
        return content
    except Exception as exc:  # pragma: no cover - defensive
        LOGGER.error("Error querying LLM: %s", exc)
        return "bash: internal emulation error\n"
