"""Streamlit dashboard for MiragePot.

This app reads per-session JSON logs from data/logs/ and
presents an overview plus per-session command timelines.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import streamlit as st

BASE_DIR = Path(__file__).resolve().parents[1]
LOG_DIR = BASE_DIR / "data" / "logs"


def load_session_logs() -> List[Dict[str, Any]]:
    sessions: List[Dict[str, Any]] = []
    if not LOG_DIR.exists():
        return sessions
    for path in sorted(LOG_DIR.glob("session_*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            sessions.append(data)
        except Exception:
            continue
    return sessions


def threat_color(score: int) -> str:
    if score < 30:
        return "#2ecc71"  # green
    if score < 80:
        return "#f1c40f"  # yellow
    return "#e74c3c"  # red


def main() -> None:
    st.set_page_config(page_title="MiragePot Dashboard", layout="wide")
    st.title("MiragePot – SSH Honeypot Activity")

    sessions = load_session_logs()
    if not sessions:
        st.info("No session logs found yet. Run the honeypot and wait for connections.")
        return

    # Summary table
    summary_rows = []
    for sess in sessions:
        commands = sess.get("commands", [])
        summary_rows.append(
            {
                "Session ID": sess.get("session_id", "unknown"),
                "Attacker IP": sess.get("attacker_ip", "unknown"),
                "Login Time": sess.get("login_time", ""),
                "Commands": len(commands),
            }
        )

    st.subheader("Sessions Overview")
    st.dataframe(summary_rows, use_container_width=True)

    # Session selection
    session_ids = [s.get("session_id", "unknown") for s in sessions]
    selected_id = st.selectbox("Select a session to inspect", session_ids)
    selected = next((s for s in sessions if s.get("session_id") == selected_id), None)

    if not selected:
        st.warning("Selected session not found.")
        return

    st.subheader(f"Session Details – {selected_id}")
    st.write(f"**Attacker IP:** {selected.get('attacker_ip', 'unknown')}")
    st.write(f"**Login Time:** {selected.get('login_time', '')}")

    commands = selected.get("commands", [])
    if not commands:
        st.info("No commands recorded for this session.")
        return

    # Command timeline
    st.markdown("### Command Timeline")

    for entry in commands:
        ts = entry.get("timestamp", "")
        cmd = entry.get("command", "")
        resp = entry.get("response", "")
        score = int(entry.get("threat_score", 0))
        delay = float(entry.get("delay_applied", 0.0))

        col1, col2, col3 = st.columns([2, 6, 2])
        with col1:
            st.caption(ts)
            st.code(cmd, language="bash")
        with col2:
            st.text_area("Response", resp, height=120, key=f"resp_{ts}_{cmd}")
        with col3:
            color = threat_color(score)
            st.markdown(
                f"<div style='background-color:{color}; padding:8px; border-radius:4px;'>"
                f"Threat score: <b>{score}</b><br/>Delay: {delay:.2f}s"
                f"</div>",
                unsafe_allow_html=True,
            )


if __name__ == "__main__":
    main()
