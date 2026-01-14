#!/usr/bin/env python
"""Unified runner for MiragePot.

Starts:
- SSH honeypot backend (backend/server.py)
- Streamlit dashboard (dashboard/app.py)

Stops both on Ctrl+C.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from typing import List


def start_process(cmd: List[str], name: str) -> subprocess.Popen:
    print(f"[*] Starting {name}... ({' '.join(cmd)})")
    try:
        proc = subprocess.Popen(cmd)
    except FileNotFoundError as exc:
        print(f"[!] Failed to start {name}: {exc}")
        sys.exit(1)
    return proc


def _kill_existing_backend(port: int = 2222) -> None:
    """Terminate any existing MiragePot backend listening on the given port.

    This avoids the common "address already in use" error when the user
    restarts `python run.py` without manually killing the previous backend.
    We try to be conservative and only kill Python processes bound to the
    target port.
    """
    try:
        # Use lsof if available for a clear mapping from port -> PID.
        proc = subprocess.run(
            ["lsof", "-i", f":{port}", "-sTCP:LISTEN", "-n", "-P"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        # lsof not available; nothing we can safely do automatically.
        return

    lines = proc.stdout.strip().splitlines()
    if len(lines) <= 1:
        # No listeners (or only header line)
        return

    # Skip header, parse remaining lines
    target_pids = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        cmd_name, pid_str = parts[0], parts[1]
        if "python" not in cmd_name.lower():
            # Only consider Python-based listeners.
            continue
        try:
            pid = int(pid_str)
        except ValueError:
            continue
        target_pids.append(pid)

    if not target_pids:
        return

    # Further filter by inspecting the full command line, only killing
    # processes that look like our MiragePot backend (contain 'backend.server').
    for pid in target_pids:
        try:
            cmdline_proc = subprocess.run(
                ["ps", "-p", str(pid), "-o", "command="],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
            )
        except Exception:
            continue

        cmdline = cmdline_proc.stdout.strip()
        if not cmdline or "backend.server" not in cmdline:
            # Do not touch unrelated Python processes.
            continue

        print(
            f"[!] Existing MiragePot backend detected on port {port} (PID {pid}), terminating..."
        )
        try:
            os.kill(pid, signal.SIGTERM)
        except Exception:
            continue

    # Give the OS a moment to release the port
    time.sleep(0.5)


def main() -> None:
    _kill_existing_backend(port=2222)

    backend_cmd = [sys.executable, "-m", "backend.server"]
    dashboard_cmd = ["streamlit", "run", "dashboard/app.py"]

    backend_proc = start_process(backend_cmd, "MiragePot backend")

    # Small delay so backend starts before dashboard
    time.sleep(1.0)

    dashboard_proc = start_process(dashboard_cmd, "MiragePot dashboard")

    print("\nMiragePot is running.")
    print("- SSH honeypot: ssh root@127.0.0.1 -p 2222")
    print("- Dashboard: see URL printed by Streamlit (default http://localhost:8501)")
    print("\nPress Ctrl+C here to stop both.\n")

    try:
        # Wait on dashboard; backend runs in parallel
        dashboard_proc.wait()
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected, shutting down MiragePot...")
    finally:
        # Gracefully terminate both processes
        for proc, name in ((dashboard_proc, "dashboard"), (backend_proc, "backend")):
            if proc.poll() is None:
                try:
                    proc.terminate()
                except Exception:
                    pass
        # Give them a moment to exit
        time.sleep(1.0)
        for proc in (dashboard_proc, backend_proc):
            if proc.poll() is None:
                try:
                    proc.kill()
                except Exception:
                    pass
        print("[*] MiragePot stopped.")


if __name__ == "__main__":
    main()
