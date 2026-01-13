"""Command handling logic for MiragePot.

Implements the hybrid engine:
- Cache lookup for known commands (fast path).
- AI-backed responses for everything else.
- In-memory fake filesystem / session state (cwd, dirs, files).

The session_state dict (per connection) has the following structure:
{
    "cwd": str,                 # current working directory (e.g. "/root")
    "directories": set[str],    # known directories (as absolute paths)
    "files": dict[str, str],    # known files (abs path -> content)
}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Tuple

from .ai_interface import query_llm

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
CACHE_PATH = DATA_DIR / "cache.json"


def _load_cache() -> Dict[str, str]:
    """Load cached command outputs from JSON.

    If the file is missing or invalid, return an empty dict.
    """
    try:
        raw = CACHE_PATH.read_text(encoding="utf-8")
        if not raw.strip():
            return {}
        return json.loads(raw)
    except Exception:
        return {}


CACHE = _load_cache()


def init_session_state() -> Dict[str, Any]:
    """Initialize a new session state for a connection."""
    return {
        "cwd": "/root",
        "directories": {"/", "/root"},
        # files store path -> content; content is plain text
        "files": {},  # type: ignore[dict-annotated]
    }


def _normalize_path(cwd: str, target: str) -> str:
    """Convert a target path (absolute or relative) into an absolute path.

    This is a minimal, safe normalizer just for fake paths.
    """
    if not target:
        return cwd
    if target.startswith("/"):
        path = target
    else:
        if cwd.endswith("/"):
            path = cwd + target
        else:
            path = cwd + "/" + target

    # Normalize any "//" or trailing "/"
    while "//" in path:
        path = path.replace("//", "/")
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path


# ---------- Built-in command handlers (fake FS) ----------


def _handle_cd(args: str, state: Dict[str, Any]) -> str:
    cwd = state.get("cwd", "/root")
    target = args.strip() or "/root"

    if target in ("~", "~/"):
        target = "/root"

    new_path = _normalize_path(cwd, target)
    directories = state.get("directories", set())

    if new_path not in directories:
        # For simplicity, pretend any path accessed actually exists.
        directories.add(new_path)
        state["directories"] = directories

    state["cwd"] = new_path
    return ""


def _handle_pwd(state: Dict[str, Any]) -> str:
    return state.get("cwd", "/root") + "\n"


def _handle_mkdir(args: str, state: Dict[str, Any]) -> str:
    cwd = state.get("cwd", "/root")
    directories = state.get("directories", set())

    parts = [p for p in args.split() if p]
    if not parts:
        return "mkdir: missing operand\n"

    output_lines = []
    for name in parts:
        new_path = _normalize_path(cwd, name)
        if new_path in directories:
            output_lines.append(f"mkdir: cannot create directory '{name}': File exists")
        else:
            directories.add(new_path)
    state["directories"] = directories
    if output_lines:
        return "\n".join(output_lines) + "\n"
    return ""


def _handle_touch(args: str, state: Dict[str, Any]) -> str:
    cwd = state.get("cwd", "/root")
    files: Dict[str, str] = state.get("files", {})

    parts = [p for p in args.split() if p]
    if not parts:
        return "touch: missing file operand\n"

    for name in parts:
        path = _normalize_path(cwd, name)
        # If file doesn't exist, create empty content
        if path not in files:
            files[path] = ""
    state["files"] = files
    return ""


def _handle_ls(args: str, state: Dict[str, Any]) -> str:
    # Very simple fake ls: list directories/files known under target.
    cwd = state.get("cwd", "/root")
    target = args.strip() or cwd
    target_path = _normalize_path(cwd, target)

    directories = state.get("directories", set())
    files: Dict[str, str] = state.get("files", {})

    if target_path not in directories and target_path not in files:
        return f"ls: cannot access '{target}': No such file or directory\n"

    children = []
    prefix = target_path + "/" if target_path != "/" else "/"
    for d in directories:
        if d.startswith(prefix):
            rel = d[len(prefix) :]
            if "/" not in rel and rel:
                children.append(rel)
    for fpath in files.keys():
        if fpath.startswith(prefix):
            rel = fpath[len(prefix) :]
            if "/" not in rel and rel:
                children.append(rel)

    if not children:
        return "\n"
    children = sorted(set(children))
    return "  ".join(children) + "\n"


def _handle_cat(args: str, state: Dict[str, Any]) -> str:
    cwd = state.get("cwd", "/root")
    files: Dict[str, str] = state.get("files", {})

    parts = [p for p in args.split() if p]
    if not parts:
        return "cat: missing file operand\n"

    output_parts = []
    for name in parts:
        path = _normalize_path(cwd, name)
        if path not in files:
            output_parts.append(f"cat: {name}: No such file or directory")
        else:
            # Show file content exactly
            output_parts.append(files[path].rstrip("\n"))
    return "\n".join(output_parts) + ("\n" if output_parts else "")


def _handle_rm(args: str, state: Dict[str, Any]) -> str:
    """Simulate a very simple rm for files and empty directories.

    Only affects the in-memory fake filesystem; never touches real disk.
    """
    cwd = state.get("cwd", "/root")
    directories = state.get("directories", set())
    files: Dict[str, str] = state.get("files", {})

    # We will not simulate complex flags like -rf accurately;
    # for safety and simplicity we treat everything as best effort.
    parts = [p for p in args.split() if p]
    if not parts:
        return "rm: missing operand\n"

    output_lines = []
    for name in parts:
        path = _normalize_path(cwd, name)
        if path in files:
            del files[path]
            continue
        if path in directories:
            # If directory has children, mimic "Directory not empty"
            prefix = path + "/" if path != "/" else "/"
            has_children = any(
                d.startswith(prefix) and d != path for d in directories
            ) or any(fp.startswith(prefix) for fp in files.keys())
            if has_children:
                output_lines.append(f"rm: cannot remove '{name}': Is a directory")
            else:
                directories.remove(path)
        else:
            output_lines.append(
                f"rm: cannot remove '{name}': No such file or directory"
            )

    state["directories"] = directories
    state["files"] = files

    if output_lines:
        return "\n".join(output_lines) + "\n"
    return ""


# ---------- Simple redirection parsing ----------


def _handle_echo_redirection(
    full_command: str, state: Dict[str, Any]
) -> Tuple[bool, str]:
    """Handle very simple forms of: echo TEXT > file and echo TEXT >> file.

    We do NOT implement full shell parsing; this is intentionally basic and
    should not execute anything for real. Only handles one '>' or '>>'.
    """
    stripped = full_command.strip()
    if not stripped.startswith("echo "):
        return False, ""

    # Determine redirection operator
    if ">>" in stripped:
        operator = ">>"
    elif ">" in stripped:
        operator = ">"
    else:
        return False, ""

    before, after = stripped.split(operator, 1)
    before = before.strip()  # "echo ... "
    after = after.strip()  # filename

    if not after:
        return True, "bash: syntax error near unexpected token `newline'\n"

    # Extract the text after "echo "
    text_part = before[5:].strip()  # remove 'echo '
    # Remove simple surrounding quotes
    if (
        len(text_part) >= 2
        and text_part[0] == text_part[-1]
        and text_part[0] in ("'", '"')
    ):
        text_part = text_part[1:-1]

    cwd = state.get("cwd", "/root")
    files: Dict[str, str] = state.get("files", {})

    target_path = _normalize_path(cwd, after)

    if operator == ">":
        files[target_path] = text_part + "\n"
    else:  # >>
        old = files.get(target_path, "")
        files[target_path] = old + text_part + "\n"

    state["files"] = files
    # echo normally prints the text as well
    return True, text_part + "\n"


def handle_builtin(command: str, state: Dict[str, Any]) -> Tuple[bool, str]:
    """Handle built-in filesystem-related commands.

    Returns (handled, output).
    """
    stripped = command.strip()
    if not stripped:
        return True, ""  # empty command, just re-prompt

    # echo with redirection (very simple)
    handled_redir, out_redir = _handle_echo_redirection(stripped, state)
    if handled_redir:
        return True, out_redir

    if stripped == "pwd":
        return True, _handle_pwd(state)

    if stripped.startswith("cd"):
        args = stripped[2:].strip()
        return True, _handle_cd(args, state)

    if stripped.startswith("mkdir"):
        args = stripped[5:].strip()
        return True, _handle_mkdir(args, state)

    if stripped.startswith("touch "):
        args = stripped[5:].strip()
        return True, _handle_touch(args, state)

    if stripped.startswith("ls"):
        args = stripped[2:].strip()
        return True, _handle_ls(args, state)

    if stripped.startswith("cat"):
        args = stripped[3:].strip()
        return True, _handle_cat(args, state)

    if stripped.startswith("rm"):
        args = stripped[2:].strip()
        return True, _handle_rm(args, state)

    return False, ""


def handle_command(command: str, session_state: Dict[str, Any]) -> str:
    """Main command processing entry point.

    - Cleans the command.
    - Handles built-ins and special cases (exit/logout).
    - Performs cache lookup.
    - Falls back to AI for everything else.
    """
    cmd = command.strip()
    if not cmd:
        return ""  # just re-prompt

    if cmd in ("exit", "logout"):
        # Signal upstream that session should close by returning
        # a specific token. The caller can treat it specially.
        return "__MIRAGEPOT_EXIT__"

    # First, try built-in fake filesystem commands.
    handled, output = handle_builtin(cmd, session_state)
    if handled:
        return output

    # Next, try the cache JSON.
    cached = CACHE.get(cmd)
    if cached is not None:
        return cached

    # Finally, fall back to the AI model.
    return query_llm(cmd, session_state)
