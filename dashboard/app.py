"""MiragePot Elite Dashboard - Advanced SSH Honeypot Analysis.

A comprehensive Streamlit dashboard for MiragePot featuring:
- Real-time session streaming
- Advanced filtering and search
- TTP/Attack stage visualization
- Session risk summaries
- Payload/download capture tracking
- Credentials analytics
- SSH fingerprint insights
- GeoIP mapping
- Analytics charts

Author: Evin Brijesh
"""

from __future__ import annotations

import json
import time
import re
import hashlib
import urllib.request
import urllib.error
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

import streamlit as st
import pandas as pd

# Optional imports for enhanced features
try:
    import plotly.express as px
    import plotly.graph_objects as go

    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

# GeoIP is now handled via free IP-API (no geoip2 dependency needed)
GEOIP_AVAILABLE = True  # Always available via IP-API fallback

BASE_DIR = Path(__file__).resolve().parents[1]
LOG_DIR = BASE_DIR / "data" / "logs"
TAGS_FILE = BASE_DIR / "data" / "session_tags.json"
LIVE_SESSION_FILE = BASE_DIR / "data" / "live_sessions.json"

# Attack stages for TTP visualization
ATTACK_STAGES = [
    ("reconnaissance", "Recon", "#3498db"),
    ("credential_access", "Cred Access", "#9b59b6"),
    ("privilege_escalation", "PrivEsc", "#e67e22"),
    ("persistence", "Persistence", "#e74c3c"),
    ("defense_evasion", "Defense Evasion", "#95a5a6"),
    ("lateral_movement", "Lateral", "#1abc9c"),
    ("collection", "Collection", "#f39c12"),
    ("exfiltration", "Exfil", "#c0392b"),
    ("impact", "Impact", "#8e44ad"),
]

# ============================================================================
# Data Loading Functions
# ============================================================================


def load_session_logs() -> List[Dict[str, Any]]:
    """Load all session logs from disk."""
    sessions: List[Dict[str, Any]] = []
    if not LOG_DIR.exists():
        return sessions
    for path in sorted(LOG_DIR.glob("session_*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            sessions.append(data)
        except Exception:
            continue
    return sessions


def load_session_tags() -> Dict[str, List[str]]:
    """Load session tags from file."""
    if TAGS_FILE.exists():
        try:
            return json.loads(TAGS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_session_tags(tags: Dict[str, List[str]]) -> None:
    """Save session tags to file."""
    TAGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    TAGS_FILE.write_text(json.dumps(tags, indent=2), encoding="utf-8")


def load_live_sessions() -> List[Dict[str, Any]]:
    """Load active/live session data if available."""
    if LIVE_SESSION_FILE.exists():
        try:
            data = json.loads(LIVE_SESSION_FILE.read_text(encoding="utf-8"))
            # Filter to only truly active sessions (within last 5 minutes)
            cutoff = datetime.utcnow() - timedelta(minutes=5)
            active = []
            for sess in data.get("sessions", []):
                last_activity = sess.get("last_activity", "")
                if last_activity:
                    try:
                        last_time = datetime.fromisoformat(
                            last_activity.replace("Z", "")
                        )
                        if last_time > cutoff:
                            active.append(sess)
                    except Exception:
                        pass
            return active
        except Exception:
            pass
    return []


# ============================================================================
# Helper Functions
# ============================================================================


def threat_color(score: int) -> str:
    """Get color for threat score."""
    if score < 30:
        return "#2ecc71"  # green
    if score < 60:
        return "#f1c40f"  # yellow
    if score < 80:
        return "#e67e22"  # orange
    return "#e74c3c"  # red


def risk_badge(risk_level: str) -> str:
    """Get HTML badge for risk level."""
    colors = {
        "low": "#2ecc71",
        "medium": "#f1c40f",
        "high": "#e67e22",
        "critical": "#e74c3c",
        "unknown": "#95a5a6",
    }
    color = colors.get(risk_level.lower(), "#95a5a6")
    return f'<span style="background-color:{color};color:white;padding:4px 12px;border-radius:4px;font-weight:bold;">{risk_level.upper()}</span>'


def format_duration(seconds: Optional[float]) -> str:
    """Format duration in human-readable form."""
    if seconds is None:
        return "N/A"
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    hours = int(seconds // 3600)
    mins = int((seconds % 3600) // 60)
    return f"{hours}h {mins}m"


def parse_timestamp(ts: str) -> Optional[datetime]:
    """Parse ISO timestamp string."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def extract_ssh_client_type(version: str) -> str:
    """Extract client type from SSH version string."""
    if not version:
        return "Unknown"
    version_lower = version.lower()
    if "openssh" in version_lower:
        return "OpenSSH"
    if "putty" in version_lower:
        return "PuTTY"
    if "libssh" in version_lower:
        return "libssh"
    if "paramiko" in version_lower:
        return "Paramiko"
    if "dropbear" in version_lower:
        return "Dropbear"
    if "golang" in version_lower or "go" in version_lower:
        return "Go SSH"
    if "asyncssh" in version_lower:
        return "AsyncSSH"
    return "Other"


def get_session_risk_level(session: Dict[str, Any]) -> str:
    """Get risk level from session data."""
    ttp_summary = session.get("ttp_summary", {})
    if ttp_summary:
        return ttp_summary.get("risk_level", "unknown")

    # Fallback: calculate from threat scores
    commands = session.get("commands", [])
    if not commands:
        return "unknown"

    max_score = max((c.get("threat_score", 0) for c in commands), default=0)
    high_risk_count = sum(1 for c in commands if c.get("threat_score", 0) >= 80)

    if high_risk_count >= 5 or max_score >= 100:
        return "critical"
    if high_risk_count >= 2 or max_score >= 80:
        return "high"
    if max_score >= 50:
        return "medium"
    return "low"


def count_injection_attempts(session: Dict[str, Any]) -> int:
    """Count prompt injection attempts in session."""
    count = 0
    injection_patterns = [
        r"ignore.*previous",
        r"forget.*instructions",
        r"you are now",
        r"pretend to be",
        r"act as",
        r"system prompt",
        r"reveal.*secret",
    ]
    for cmd in session.get("commands", []):
        command = cmd.get("command", "").lower()
        for pattern in injection_patterns:
            if re.search(pattern, command):
                count += 1
                break
    return count


def get_most_suspicious_command(session: Dict[str, Any]) -> Optional[str]:
    """Get the most suspicious command from session."""
    commands = session.get("commands", [])
    if not commands:
        return None

    max_score = 0
    most_suspicious = None
    for cmd in commands:
        score = cmd.get("threat_score", 0)
        if score > max_score:
            max_score = score
            most_suspicious = cmd.get("command", "")

    return most_suspicious


# ============================================================================
# GeoIP Functions (Using free IP-API - no external DB needed)
# ============================================================================

# Cache for IP geolocation results (persists across reruns)
_geo_cache: Dict[str, Dict[str, Any]] = {}


def get_geo_info_via_api(ip: str) -> Dict[str, Any]:
    """Get geographic info for IP using free ip-api.com service.

    Rate limited to 45 requests/minute on free tier, but we cache results.
    """
    if ip in ("127.0.0.1", "::1", "localhost", ""):
        return {
            "country": "Local",
            "city": "Local",
            "latitude": 0,
            "longitude": 0,
            "isp": "Local",
        }

    # Check cache first
    if ip in _geo_cache:
        return _geo_cache[ip]

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp"
        req = urllib.request.Request(url, headers={"User-Agent": "MiragePot-Dashboard"})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())

        if data.get("status") == "success":
            result = {
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "latitude": data.get("lat", 0),
                "longitude": data.get("lon", 0),
                "isp": data.get("isp", "Unknown"),
            }
        else:
            result = {
                "country": "Unknown",
                "city": "Unknown",
                "latitude": 0,
                "longitude": 0,
            }

        # Cache the result
        _geo_cache[ip] = result
        return result

    except Exception:
        result = {
            "country": "Unknown",
            "city": "Unknown",
            "latitude": 0,
            "longitude": 0,
        }
        _geo_cache[ip] = result
        return result


@st.cache_data(ttl=3600)  # Cache for 1 hour
def batch_geolocate_ips(ips: Tuple[str, ...]) -> Dict[str, Dict[str, Any]]:
    """Batch geolocate multiple IPs with caching.

    Uses ip-api.com batch endpoint for efficiency (max 100 IPs per request).
    """
    results = {}
    unique_ips = [
        ip for ip in set(ips) if ip and ip not in ("127.0.0.1", "::1", "localhost")
    ]

    # Handle local IPs
    for ip in ips:
        if ip in ("127.0.0.1", "::1", "localhost", ""):
            results[ip] = {
                "country": "Local",
                "city": "Local",
                "latitude": 0,
                "longitude": 0,
            }

    if not unique_ips:
        return results

    # Batch API (max 100 IPs)
    try:
        batch_data = [{"query": ip} for ip in unique_ips[:100]]
        req = urllib.request.Request(
            "http://ip-api.com/batch?fields=status,query,country,city,lat,lon",
            data=json.dumps(batch_data).encode(),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "MiragePot-Dashboard",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())

        for item in data:
            ip = item.get("query", "")
            if item.get("status") == "success":
                results[ip] = {
                    "country": item.get("country", "Unknown"),
                    "city": item.get("city", "Unknown"),
                    "latitude": item.get("lat", 0),
                    "longitude": item.get("lon", 0),
                }
            else:
                results[ip] = {
                    "country": "Unknown",
                    "city": "Unknown",
                    "latitude": 0,
                    "longitude": 0,
                }

    except Exception:
        # Fallback: mark all as unknown
        for ip in unique_ips:
            if ip not in results:
                results[ip] = {
                    "country": "Unknown",
                    "city": "Unknown",
                    "latitude": 0,
                    "longitude": 0,
                }

    return results


# ============================================================================
# Page Components
# ============================================================================


def render_live_sessions_panel(sessions: List[Dict[str, Any]]) -> None:
    """Render the live sessions streaming panel."""
    st.markdown("### Live Sessions")

    live_sessions = load_live_sessions()

    if not live_sessions:
        # Show recent active sessions as approximation
        recent_cutoff = datetime.utcnow() - timedelta(minutes=10)
        active = []
        for sess in sessions[:20]:
            login_time = parse_timestamp(sess.get("login_time", ""))
            logout_time = sess.get("logout_time")
            if login_time and not logout_time:
                active.append(sess)
            elif login_time and login_time.replace(tzinfo=None) > recent_cutoff:
                active.append(sess)

        live_sessions = active[:5]

    # Live stats
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Active Sessions", len(live_sessions))
    with col2:
        total_cmds = sum(len(s.get("commands", [])) for s in live_sessions)
        st.metric("Commands (Active)", total_cmds)
    with col3:
        if live_sessions:
            latest = max(
                (parse_timestamp(s.get("login_time", "")) for s in live_sessions),
                default=None,
            )
            if latest:
                st.metric("Latest Activity", latest.strftime("%H:%M:%S"))
            else:
                st.metric("Latest Activity", "N/A")
        else:
            st.metric("Latest Activity", "No active sessions")

    # Live stream window
    if live_sessions:
        st.markdown("#### Live Terminal Feed")

        # Create terminal-style display
        terminal_css = """
        <style>
        .live-terminal {
            background: #0d0d0d;
            border-radius: 8px;
            padding: 15px;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 12px;
            max-height: 300px;
            overflow-y: auto;
            border: 1px solid #333;
        }
        .live-cmd {
            color: #00ff00;
            margin: 5px 0;
        }
        .live-time {
            color: #666;
            margin-right: 10px;
        }
        .live-ip {
            color: #00d9ff;
            margin-right: 10px;
        }
        .live-response {
            color: #ccc;
            margin-left: 20px;
            white-space: pre-wrap;
        }
        </style>
        """
        st.markdown(terminal_css, unsafe_allow_html=True)

        # Aggregate recent commands from all active sessions
        all_cmds = []
        for sess in live_sessions:
            ip = sess.get("attacker_ip", "unknown")
            for cmd in sess.get("commands", [])[-10:]:  # Last 10 per session
                ts = cmd.get("timestamp", "")
                all_cmds.append(
                    {
                        "timestamp": ts,
                        "ip": ip,
                        "command": cmd.get("command", ""),
                        "response": cmd.get("response", "")[:200],  # Truncate
                    }
                )

        # Sort by timestamp and take most recent
        all_cmds.sort(key=lambda x: x["timestamp"], reverse=True)
        recent_cmds = all_cmds[:15]

        terminal_html = '<div class="live-terminal">'
        for cmd in reversed(recent_cmds):
            ts = cmd["timestamp"]
            if ts:
                try:
                    dt = parse_timestamp(ts)
                    time_str = dt.strftime("%H:%M:%S") if dt else ts[:19]
                except Exception:
                    time_str = ts[:19]
            else:
                time_str = "??:??:??"

            terminal_html += f"""
            <div class="live-cmd">
                <span class="live-time">[{time_str}]</span>
                <span class="live-ip">{cmd["ip"]}</span>
                root@miragepot:~# {cmd["command"]}
            </div>
            """
            if cmd["response"]:
                resp = cmd["response"].replace("<", "&lt;").replace(">", "&gt;")
                terminal_html += f'<div class="live-response">{resp}</div>'

        terminal_html += "</div>"
        st.markdown(terminal_html, unsafe_allow_html=True)
    else:
        st.info("No active sessions. Waiting for attackers...")


def render_filters_panel(sessions: List[Dict[str, Any]]) -> Tuple[List[Dict], Dict]:
    """Render filtering and search controls, return filtered sessions."""
    st.markdown("### Filters & Search")

    with st.expander("Filter Sessions", expanded=False):
        col1, col2, col3 = st.columns(3)

        with col1:
            # IP filter
            all_ips = sorted(set(s.get("attacker_ip", "") for s in sessions))
            ip_filter = st.multiselect("Attacker IP", options=all_ips, default=[])

            # Risk level filter
            risk_filter = st.multiselect(
                "Risk Level", options=["low", "medium", "high", "critical"], default=[]
            )

        with col2:
            # Threat score filter
            min_threat = st.slider("Min Threat Score", 0, 100, 0)

            # Has downloads filter
            has_downloads = st.checkbox("Has Download Attempts")

            # Has injection attempts
            has_injection = st.checkbox("Has Injection Attempts")

        with col3:
            # Duration filter
            min_duration = st.number_input("Min Duration (seconds)", 0, 10000, 0)

            # Command count filter
            min_commands = st.number_input("Min Commands", 0, 1000, 0)

        # Command search
        command_search = st.text_input("Search Commands (regex)", "")

    # Apply filters
    filtered = sessions.copy()

    if ip_filter:
        filtered = [s for s in filtered if s.get("attacker_ip") in ip_filter]

    if risk_filter:
        filtered = [s for s in filtered if get_session_risk_level(s) in risk_filter]

    if min_threat > 0:
        filtered = [
            s
            for s in filtered
            if any(
                c.get("threat_score", 0) >= min_threat for c in s.get("commands", [])
            )
        ]

    if has_downloads:
        filtered = [s for s in filtered if s.get("download_attempts")]

    if has_injection:
        filtered = [s for s in filtered if count_injection_attempts(s) > 0]

    if min_duration > 0:
        filtered = [
            s for s in filtered if (s.get("duration_seconds") or 0) >= min_duration
        ]

    if min_commands > 0:
        filtered = [s for s in filtered if len(s.get("commands", [])) >= min_commands]

    if command_search:
        try:
            pattern = re.compile(command_search, re.IGNORECASE)
            filtered = [
                s
                for s in filtered
                if any(
                    pattern.search(c.get("command", "")) for c in s.get("commands", [])
                )
            ]
        except re.error:
            st.warning("Invalid regex pattern")

    # Tagging section
    st.markdown("### Session Tags")

    tags = load_session_tags()
    available_tags = [
        "Bot",
        "Human",
        "Recon",
        "Payload Dropper",
        "Brute Force",
        "Interesting",
        "False Positive",
    ]

    # Show tag filter
    tag_filter = st.multiselect("Filter by Tags", options=available_tags, default=[])

    if tag_filter:
        filtered = [
            s
            for s in filtered
            if any(t in tags.get(s.get("session_id", ""), []) for t in tag_filter)
        ]

    filters_applied = {
        "ip_filter": ip_filter,
        "risk_filter": risk_filter,
        "min_threat": min_threat,
        "has_downloads": has_downloads,
        "has_injection": has_injection,
        "min_duration": min_duration,
        "min_commands": min_commands,
        "command_search": command_search,
        "tag_filter": tag_filter,
    }

    return filtered, filters_applied


def render_ttp_timeline(session: Dict[str, Any]) -> None:
    """Render TTP/Attack stage visualization for a session."""
    st.markdown("### Attack Stage Analysis")

    ttp_summary = session.get("ttp_summary", {})
    stages_seen = set(ttp_summary.get("stages_seen", []))

    # Stage progress bar
    st.markdown("#### Attack Progression")

    cols = st.columns(len(ATTACK_STAGES))
    for i, (stage_id, stage_name, color) in enumerate(ATTACK_STAGES):
        with cols[i]:
            if stage_id in stages_seen:
                st.markdown(
                    f'<div style="text-align:center;padding:10px;background:{color};'
                    f'border-radius:4px;color:white;font-size:11px;font-weight:bold;">'
                    f"{stage_name}</div>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f'<div style="text-align:center;padding:10px;background:#2c2c2c;'
                    f'border-radius:4px;color:#666;font-size:11px;">'
                    f"{stage_name}</div>",
                    unsafe_allow_html=True,
                )

    # TTP Indicators Timeline
    indicators = ttp_summary.get("key_indicators", [])
    if indicators:
        st.markdown("#### TTP Indicators Detected")

        for ind in indicators[:10]:
            technique_id = ind.get("technique_id", "")
            technique_name = ind.get("technique_name", "")
            stage = ind.get("stage", "unknown")
            confidence = ind.get("confidence", "low")
            command = ind.get("command", "")
            description = ind.get("description", "")

            # Color by confidence
            conf_colors = {"high": "#e74c3c", "medium": "#f39c12", "low": "#3498db"}
            conf_color = conf_colors.get(confidence, "#95a5a6")

            st.markdown(
                f"""
                <div style="background:#1a1a2e;padding:10px;margin:5px 0;border-radius:4px;
                border-left:4px solid {conf_color};">
                    <strong style="color:#00d9ff;">{technique_id}</strong> - {technique_name}
                    <br><span style="color:#888;font-size:12px;">Stage: {stage} | Confidence: {confidence}</span>
                    <br><code style="color:#00ff00;font-size:11px;">{command[:80]}...</code>
                    <br><span style="color:#aaa;font-size:11px;">{description}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.info("No TTP indicators detected for this session.")

    # Summary stats
    if ttp_summary:
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Techniques Detected", ttp_summary.get("technique_count", 0))
        with col2:
            st.metric("Total Indicators", ttp_summary.get("total_indicators", 0))
        with col3:
            st.metric("Recon Commands", ttp_summary.get("recon_commands", 0))
        with col4:
            st.metric("Credential Commands", ttp_summary.get("credential_commands", 0))


def render_session_risk_summary(session: Dict[str, Any]) -> None:
    """Render session risk summary card."""
    st.markdown("### Session Risk Summary")

    risk_level = get_session_risk_level(session)
    commands = session.get("commands", [])
    download_attempts = session.get("download_attempts", [])

    # Calculate metrics
    total_commands = len(commands)
    high_risk_cmds = sum(1 for c in commands if c.get("threat_score", 0) >= 80)
    payload_urls = len(download_attempts)
    injection_attempts = count_injection_attempts(session)
    most_suspicious = get_most_suspicious_command(session)

    # Main risk badge
    col1, col2 = st.columns([1, 3])
    with col1:
        st.markdown(f"**Risk Level:**")
        st.markdown(risk_badge(risk_level), unsafe_allow_html=True)

    with col2:
        metrics_cols = st.columns(4)
        with metrics_cols[0]:
            st.metric("Total Commands", total_commands)
        with metrics_cols[1]:
            st.metric("High Risk Cmds", high_risk_cmds)
        with metrics_cols[2]:
            st.metric("Payload URLs", payload_urls)
        with metrics_cols[3]:
            st.metric("Injection Attempts", injection_attempts)

    if most_suspicious:
        st.markdown("**Most Suspicious Command:**")
        st.code(most_suspicious[:200], language="bash")

    # Honeytokens summary if available
    honeytokens = session.get("honeytokens_summary", {})
    if honeytokens and honeytokens.get("unique_tokens_accessed", 0) > 0:
        st.markdown("#### Honeytoken Activity")
        ht_cols = st.columns(3)
        with ht_cols[0]:
            st.metric("Tokens Accessed", honeytokens.get("unique_tokens_accessed", 0))
        with ht_cols[1]:
            st.metric("Total Accesses", honeytokens.get("total_accesses", 0))
        with ht_cols[2]:
            st.metric("Exfil Attempts", honeytokens.get("exfiltration_attempts", 0))


def render_downloads_tab(session: Dict[str, Any]) -> None:
    """Render payload/download capture section."""
    st.markdown("### Download Capture")

    downloads = session.get("download_attempts", [])

    if not downloads:
        st.info("No download attempts captured in this session.")
        return

    # Build download table
    rows = []
    for dl in downloads:
        # Calculate hash of URL for tracking
        url_hash = hashlib.sha256(dl.get("source", "").encode()).hexdigest()[:16]

        rows.append(
            {
                "Timestamp": dl.get("timestamp", "")[:19],
                "Tool": dl.get("tool", "unknown"),
                "Method": dl.get("method", "GET"),
                "URL/Source": dl.get("source", "")[:60] + "..."
                if len(dl.get("source", "")) > 60
                else dl.get("source", ""),
                "Destination": dl.get("destination", "N/A") or "N/A",
                "URL Hash": url_hash,
            }
        )

    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True)

    # Detailed view
    st.markdown("#### Download Details")
    for i, dl in enumerate(downloads):
        with st.expander(
            f"Download #{i + 1}: {dl.get('tool', 'unknown')} - {dl.get('source', '')[:40]}..."
        ):
            st.json(dl)


def render_credentials_analytics(sessions: List[Dict[str, Any]]) -> None:
    """Render credentials analytics page."""
    st.markdown("### Credentials Analytics")

    # Collect all auth data
    usernames = Counter()
    passwords = Counter()
    combos = Counter()
    ip_attempts = Counter()

    for sess in sessions:
        auth = sess.get("auth", {})
        ip = sess.get("attacker_ip", "unknown")

        if auth:
            for attempt in auth.get("attempts", []):
                if attempt.get("method") == "password":
                    username = attempt.get("username", "")
                    password = attempt.get("credential", "")

                    if username:
                        usernames[username] += 1
                    if password:
                        # Truncate for display
                        passwords[password[:20]] += 1
                    if username and password:
                        combos[f"{username}:{password[:15]}"] += 1

                    ip_attempts[ip] += 1

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Top Usernames")
        if usernames:
            df_users = pd.DataFrame(
                usernames.most_common(15), columns=["Username", "Count"]
            )
            st.dataframe(df_users, use_container_width=True)

            if PLOTLY_AVAILABLE and len(usernames) > 0:
                fig = px.bar(
                    df_users.head(10), x="Username", y="Count", title="Top 10 Usernames"
                )
                fig.update_layout(template="plotly_dark")
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No username data available")

    with col2:
        st.markdown("#### Top Passwords")
        if passwords:
            df_pass = pd.DataFrame(
                passwords.most_common(15), columns=["Password", "Count"]
            )
            st.dataframe(df_pass, use_container_width=True)

            if PLOTLY_AVAILABLE and len(passwords) > 0:
                fig = px.bar(
                    df_pass.head(10), x="Password", y="Count", title="Top 10 Passwords"
                )
                fig.update_layout(template="plotly_dark")
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No password data available")

    st.markdown("#### Top Username:Password Combinations")
    if combos:
        df_combos = pd.DataFrame(
            combos.most_common(20), columns=["Combination", "Count"]
        )
        st.dataframe(df_combos, use_container_width=True)
    else:
        st.info("No credential combinations available")

    st.markdown("#### Attempts per IP")
    if ip_attempts:
        df_ips = pd.DataFrame(
            ip_attempts.most_common(15), columns=["IP Address", "Attempts"]
        )
        st.dataframe(df_ips, use_container_width=True)


def render_ssh_fingerprints(sessions: List[Dict[str, Any]]) -> None:
    """Render SSH fingerprint insights page."""
    st.markdown("### SSH Fingerprint Insights")

    # Collect fingerprint data
    client_versions = Counter()
    client_types = Counter()
    kex_algorithms = Counter()
    ciphers = Counter()

    for sess in sessions:
        fp = sess.get("ssh_fingerprint", {})
        if fp:
            version = fp.get("client_version", "")
            if version:
                client_versions[version] += 1
                client_types[extract_ssh_client_type(version)] += 1

            for kex in fp.get("kex_algorithms", []):
                kex_algorithms[kex] += 1

            for cipher in fp.get("ciphers", []):
                ciphers[cipher] += 1

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Client Types")
        if client_types:
            if PLOTLY_AVAILABLE:
                fig = px.pie(
                    values=list(client_types.values()),
                    names=list(client_types.keys()),
                    title="SSH Client Distribution",
                )
                fig.update_layout(template="plotly_dark")
                st.plotly_chart(fig, use_container_width=True)
            else:
                df = pd.DataFrame(
                    client_types.most_common(), columns=["Client Type", "Count"]
                )
                st.dataframe(df, use_container_width=True)
        else:
            st.info("No client type data available")

    with col2:
        st.markdown("#### Client Versions")
        if client_versions:
            df_versions = pd.DataFrame(
                client_versions.most_common(10), columns=["Client Version", "Count"]
            )
            st.dataframe(df_versions, use_container_width=True)
        else:
            st.info("No client version data available")

    st.markdown("#### Key Exchange Algorithms")
    if kex_algorithms:
        df_kex = pd.DataFrame(
            kex_algorithms.most_common(10), columns=["Algorithm", "Count"]
        )
        st.dataframe(df_kex, use_container_width=True)

    st.markdown("#### Ciphers Used")
    if ciphers:
        df_ciphers = pd.DataFrame(ciphers.most_common(10), columns=["Cipher", "Count"])
        st.dataframe(df_ciphers, use_container_width=True)


def render_geoip_analytics(sessions: List[Dict[str, Any]]) -> None:
    """Render GeoIP mapping and analytics using free IP-API service."""
    st.markdown("### Geographic Analysis")

    if not sessions:
        st.info("No sessions available for geographic analysis.")
        return

    # Collect unique IPs
    unique_ips = list(
        set(
            sess.get("attacker_ip", "")
            for sess in sessions
            if sess.get("attacker_ip")
            and sess.get("attacker_ip") not in ("127.0.0.1", "::1", "localhost")
        )
    )

    if not unique_ips:
        st.info("No external IP addresses to analyze (only local connections).")
        return

    # Show loading status for API calls
    with st.spinner(f"Looking up {len(unique_ips)} IP addresses..."):
        # Use batch API for efficiency (cached for 1 hour)
        geo_data = batch_geolocate_ips(tuple(unique_ips))

    # Collect geo statistics
    countries: Counter = Counter()
    cities: Counter = Counter()
    locations = []

    for sess in sessions:
        ip = sess.get("attacker_ip", "")
        if ip and ip in geo_data:
            geo = geo_data[ip]
            if geo.get("country") and geo.get("country") not in ("Unknown", "Local"):
                countries[geo["country"]] += 1
                city_name = geo.get("city", "Unknown")
                if city_name and city_name != "Unknown":
                    cities[f"{city_name}, {geo['country']}"] += 1

                lat = geo.get("latitude", 0)
                lon = geo.get("longitude", 0)
                if lat and lon:
                    locations.append(
                        {
                            "lat": lat,
                            "lon": lon,
                            "ip": ip,
                            "country": geo["country"],
                            "city": geo.get("city", "Unknown"),
                        }
                    )

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Top Countries")
        if countries:
            df_countries = pd.DataFrame(
                countries.most_common(15), columns=["Country", "Sessions"]
            )
            st.dataframe(df_countries, use_container_width=True)

            if PLOTLY_AVAILABLE:
                fig = px.bar(
                    df_countries.head(10),
                    x="Country",
                    y="Sessions",
                    title="Top 10 Attacker Countries",
                )
                fig.update_layout(template="plotly_dark")
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No geographic data available")

    with col2:
        st.markdown("#### Top Cities")
        if cities:
            df_cities = pd.DataFrame(
                cities.most_common(15), columns=["City", "Sessions"]
            )
            st.dataframe(df_cities, use_container_width=True)

    # Map visualization using Streamlit's native st.map (lightweight, no extra deps)
    if locations:
        st.markdown("#### Attacker Map")

        # Use Plotly scatter_geo if available (prettier), else fall back to st.map
        if PLOTLY_AVAILABLE:
            df_loc = pd.DataFrame(locations)
            fig = px.scatter_geo(
                df_loc,
                lat="lat",
                lon="lon",
                hover_name="ip",
                hover_data=["country", "city"],
                title="Attacker Locations",
                projection="natural earth",
            )
            fig.update_layout(
                template="plotly_dark",
                geo=dict(
                    showland=True,
                    landcolor="rgb(30, 30, 30)",
                    showocean=True,
                    oceancolor="rgb(20, 20, 40)",
                ),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            # Fallback to Streamlit's built-in map
            df_loc = pd.DataFrame(locations)
            df_loc = df_loc.rename(columns={"lat": "latitude", "lon": "longitude"})
            st.map(df_loc)
            st.caption(
                "Install plotly for a better map visualization: `pip install plotly`"
            )

    # Show API usage info
    st.caption(
        f"Geographic data from ip-api.com (free tier, {len(unique_ips)} IPs looked up)"
    )


def render_analytics_charts(sessions: List[Dict[str, Any]]) -> None:
    """Render analytics charts page."""
    st.markdown("### Analytics & Charts")

    if not PLOTLY_AVAILABLE:
        st.warning("Plotly not installed. Run: `pip install plotly`")
        st.info("Charts require plotly for visualization.")
        return

    if not sessions:
        st.info("No session data available for charts.")
        return

    # Prepare data
    commands_per_session = []
    threat_scores = []
    all_commands = Counter()
    sessions_per_ip = Counter()
    sessions_by_date = defaultdict(int)
    high_risk_by_date = defaultdict(int)

    for sess in sessions:
        commands = sess.get("commands", [])
        commands_per_session.append(len(commands))
        sessions_per_ip[sess.get("attacker_ip", "unknown")] += 1

        login_time = parse_timestamp(sess.get("login_time", ""))
        if login_time:
            date_key = login_time.strftime("%Y-%m-%d")
            sessions_by_date[date_key] += 1

        for cmd in commands:
            score = cmd.get("threat_score", 0)
            threat_scores.append(score)

            command_text = (
                cmd.get("command", "").split()[0] if cmd.get("command") else ""
            )
            if command_text:
                all_commands[command_text] += 1

            if score >= 80 and login_time:
                high_risk_by_date[date_key] += 1

    # Charts layout
    col1, col2 = st.columns(2)

    with col1:
        # Commands over time
        st.markdown("#### Sessions Over Time")
        if sessions_by_date:
            df_time = pd.DataFrame(
                [
                    {"Date": k, "Sessions": v}
                    for k, v in sorted(sessions_by_date.items())
                ]
            )
            fig = px.line(df_time, x="Date", y="Sessions", title="Sessions per Day")
            fig.update_layout(template="plotly_dark")
            st.plotly_chart(fig, use_container_width=True)

        # Top commands
        st.markdown("#### Top Commands")
        if all_commands:
            df_cmds = pd.DataFrame(
                all_commands.most_common(10), columns=["Command", "Count"]
            )
            fig = px.bar(
                df_cmds, x="Command", y="Count", title="Most Frequent Commands"
            )
            fig.update_layout(template="plotly_dark")
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        # Threat score distribution
        st.markdown("#### Threat Score Distribution")
        if threat_scores:
            fig = px.histogram(
                threat_scores,
                nbins=20,
                title="Threat Score Histogram",
                labels={"value": "Threat Score", "count": "Frequency"},
            )
            fig.update_layout(template="plotly_dark")
            st.plotly_chart(fig, use_container_width=True)

        # Sessions per IP
        st.markdown("#### Top Attacker IPs")
        if sessions_per_ip:
            df_ips = pd.DataFrame(
                sessions_per_ip.most_common(10), columns=["IP", "Sessions"]
            )
            fig = px.bar(df_ips, x="IP", y="Sessions", title="Sessions per IP (Top 10)")
            fig.update_layout(template="plotly_dark")
            st.plotly_chart(fig, use_container_width=True)

    # High risk trend
    st.markdown("#### High Risk Commands Trend")
    if high_risk_by_date:
        df_risk = pd.DataFrame(
            [
                {"Date": k, "High Risk Commands": v}
                for k, v in sorted(high_risk_by_date.items())
            ]
        )
        fig = px.line(
            df_risk,
            x="Date",
            y="High Risk Commands",
            title="High Risk Commands per Day",
        )
        fig.update_layout(template="plotly_dark")
        st.plotly_chart(fig, use_container_width=True)


def render_session_inspector(session: Dict[str, Any], all_sessions: List[Dict]) -> None:
    """Render detailed session inspection view."""
    session_id = session.get("session_id", "unknown")

    st.markdown(f"## Session: `{session_id}`")

    # Session metadata
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Attacker IP", session.get("attacker_ip", "unknown"))
    with col2:
        st.metric("Duration", format_duration(session.get("duration_seconds")))
    with col3:
        st.metric("Commands", len(session.get("commands", [])))
    with col4:
        risk = get_session_risk_level(session)
        st.markdown(f"**Risk:** {risk_badge(risk)}", unsafe_allow_html=True)

    # Tabs for different views
    tabs = st.tabs(
        [
            "Risk Summary",
            "TTP Analysis",
            "Command Timeline",
            "Downloads",
            "SSH Info",
            "Raw JSON",
        ]
    )

    with tabs[0]:
        render_session_risk_summary(session)

    with tabs[1]:
        render_ttp_timeline(session)

    with tabs[2]:
        st.markdown("### Command Timeline")
        commands = session.get("commands", [])

        if not commands:
            st.info("No commands recorded.")
        else:
            for entry in commands:
                ts = entry.get("timestamp", "")[:19]
                cmd = entry.get("command", "")
                resp = entry.get("response", "")
                score = int(entry.get("threat_score", 0))
                delay = float(entry.get("delay_applied", 0.0))

                col1, col2, col3 = st.columns([2, 6, 2])
                with col1:
                    st.caption(ts)
                    st.code(cmd, language="bash")
                with col2:
                    if resp:
                        st.text_area(
                            "Response",
                            resp[:500],
                            height=100,
                            key=f"resp_{ts}_{hash(cmd)}",
                        )
                with col3:
                    color = threat_color(score)
                    st.markdown(
                        f"<div style='background-color:{color};padding:8px;border-radius:4px;'>"
                        f"Score: <b>{score}</b><br/>Delay: {delay:.2f}s"
                        f"</div>",
                        unsafe_allow_html=True,
                    )

    with tabs[3]:
        render_downloads_tab(session)

    with tabs[4]:
        st.markdown("### SSH Fingerprint")
        fp = session.get("ssh_fingerprint", {})
        if fp:
            st.json(fp)
        else:
            st.info("No SSH fingerprint data available.")

        st.markdown("### Authentication Info")
        auth = session.get("auth", {})
        if auth:
            st.json(auth)
        else:
            st.info("No authentication data available.")

        st.markdown("### PTY Info")
        pty = session.get("pty_info", {})
        if pty:
            st.json(pty)

    with tabs[5]:
        st.json(session)

    # Tagging
    st.markdown("### Session Tags")
    tags = load_session_tags()
    current_tags = tags.get(session_id, [])
    available_tags = [
        "Bot",
        "Human",
        "Recon",
        "Payload Dropper",
        "Brute Force",
        "Interesting",
        "False Positive",
    ]

    new_tags = st.multiselect(
        "Assign Tags",
        options=available_tags,
        default=current_tags,
        key=f"tags_{session_id}",
    )

    if new_tags != current_tags:
        tags[session_id] = new_tags
        save_session_tags(tags)
        st.success("Tags saved!")


# ============================================================================
# Main Application
# ============================================================================


def main() -> None:
    """Main dashboard entry point."""
    st.set_page_config(
        page_title="MiragePot Elite Dashboard",
        page_icon="",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Custom CSS for dark theme
    st.markdown(
        """
    <style>
    .stApp {
        background-color: #0e1117;
    }
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #00d9ff;
        margin-bottom: 0;
    }
    .sub-header {
        color: #888;
        font-size: 1rem;
        margin-top: 0;
    }
    .metric-card {
        background: #1a1a2e;
        padding: 20px;
        border-radius: 8px;
        border-left: 4px solid #00d9ff;
    }
    </style>
    """,
        unsafe_allow_html=True,
    )

    # Header
    st.markdown(
        '<p class="main-header">MiragePot Elite Dashboard</p>', unsafe_allow_html=True
    )
    st.markdown(
        '<p class="sub-header">AI-Driven Adaptive SSH Honeypot - Advanced Threat Analysis</p>',
        unsafe_allow_html=True,
    )

    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.radio(
        "Select Page",
        [
            "Overview",
            "Live Sessions",
            "Session Browser",
            "Credentials Analytics",
            "SSH Fingerprints",
            "Geographic Analysis",
            "Analytics Charts",
        ],
    )

    # Auto-refresh controls
    st.sidebar.markdown("---")
    st.sidebar.markdown("### Refresh")
    auto_refresh = st.sidebar.checkbox("Auto-refresh", value=False)
    refresh_interval = st.sidebar.selectbox(
        "Interval (seconds)", [5, 10, 30, 60], index=1
    )

    if st.sidebar.button("Refresh Now"):
        st.rerun()

    if auto_refresh:
        time.sleep(refresh_interval)
        st.rerun()

    # Load data
    sessions = load_session_logs()

    if not sessions:
        st.info("No session logs found yet. Run the honeypot and wait for connections.")
        st.markdown("""
        ### Quick Start
        1. Start Ollama: `ollama serve`
        2. Pull the model: `ollama pull phi3`
        3. Run MiragePot: `python -m miragepot`
        4. Connect: `ssh root@127.0.0.1 -p 2222` (any password works)
        """)
        return

    # Page routing
    if page == "Overview":
        # Statistics
        total_sessions = len(sessions)
        total_commands = sum(len(s.get("commands", [])) for s in sessions)
        unique_ips = len(set(s.get("attacker_ip", "") for s in sessions))
        high_risk_sessions = sum(
            1 for s in sessions if get_session_risk_level(s) in ("high", "critical")
        )
        total_downloads = sum(len(s.get("download_attempts", [])) for s in sessions)

        stat_cols = st.columns(5)
        stat_cols[0].metric("Total Sessions", total_sessions)
        stat_cols[1].metric("Total Commands", total_commands)
        stat_cols[2].metric("Unique IPs", unique_ips)
        stat_cols[3].metric("High Risk Sessions", high_risk_sessions)
        stat_cols[4].metric("Download Attempts", total_downloads)

        st.divider()

        # Live sessions panel
        render_live_sessions_panel(sessions)

        st.divider()

        # Recent sessions table
        st.markdown("### Recent Sessions")

        summary_rows = []
        for sess in sessions[:20]:
            commands = sess.get("commands", [])
            risk = get_session_risk_level(sess)
            summary_rows.append(
                {
                    "Session ID": sess.get("session_id", "unknown")[:30] + "...",
                    "IP": sess.get("attacker_ip", "unknown"),
                    "Login Time": sess.get("login_time", "")[:19],
                    "Duration": format_duration(sess.get("duration_seconds")),
                    "Commands": len(commands),
                    "Risk": risk.upper(),
                    "Downloads": len(sess.get("download_attempts", [])),
                }
            )

        df = pd.DataFrame(summary_rows)
        st.dataframe(df, use_container_width=True)

    elif page == "Live Sessions":
        render_live_sessions_panel(sessions)

        st.divider()

        # Show most active recent sessions
        st.markdown("### Most Active Recent Sessions")
        active_sessions = sorted(
            sessions, key=lambda s: len(s.get("commands", [])), reverse=True
        )[:10]

        for sess in active_sessions:
            with st.expander(
                f"{sess.get('attacker_ip', 'unknown')} - {len(sess.get('commands', []))} commands"
            ):
                render_session_risk_summary(sess)

    elif page == "Session Browser":
        # Filters
        filtered_sessions, filters = render_filters_panel(sessions)

        st.markdown(f"### Sessions ({len(filtered_sessions)} of {len(sessions)})")

        # Session selection
        session_ids = [s.get("session_id", "unknown") for s in filtered_sessions]

        if session_ids:
            selected_id = st.selectbox("Select a session to inspect", session_ids)
            selected = next(
                (s for s in filtered_sessions if s.get("session_id") == selected_id),
                None,
            )

            if selected:
                st.divider()
                render_session_inspector(selected, sessions)
        else:
            st.warning("No sessions match the current filters.")

    elif page == "Credentials Analytics":
        render_credentials_analytics(sessions)

    elif page == "SSH Fingerprints":
        render_ssh_fingerprints(sessions)

    elif page == "Geographic Analysis":
        render_geoip_analytics(sessions)

    elif page == "Analytics Charts":
        render_analytics_charts(sessions)


if __name__ == "__main__":
    main()
