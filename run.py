#!/usr/bin/env python
"""Unified runner for MiragePot.

Starts:
- SSH honeypot backend (backend/server.py)
- Streamlit dashboard (dashboard/app.py)

Stops both on Ctrl+C.
"""

from __future__ import annotations

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


def main() -> None:
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
