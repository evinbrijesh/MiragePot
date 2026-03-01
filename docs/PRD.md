# Product Requirements Document — MiragePot

| Field | Details |
|---|---|
| **Document Version** | 1.1 |
| **Status** | Final |
| **Author** | Evin Brijesh |
| **Programme** | B.Tech Computer Science and Engineering, Semester 6 |
| **Institution** | Mar Athanasius College of Engineering, Kothamangalam |
| **Date** | 2026-02-28 |
| **Product Version** | 0.1.0 |

---

## Version History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-02-28 | Evin Brijesh | Initial draft |
| 1.1 | 2026-03-01 | Evin Brijesh | Expanded personas, added acceptance criteria, added constraints and assumptions, added glossary, improved formatting |

---

## Table of Contents

1. [Product Overview](#1-product-overview)
2. [Problem Statement](#2-problem-statement)
3. [Goals and Objectives](#3-goals-and-objectives)
4. [Target Users and Personas](#4-target-users-and-personas)
5. [Functional Requirements](#5-functional-requirements)
6. [Non-Functional Requirements](#6-non-functional-requirements)
7. [System Architecture Summary](#7-system-architecture-summary)
8. [Monitoring and Observability](#8-monitoring-and-observability)
9. [Configuration Reference](#9-configuration-reference)
10. [Deployment Requirements](#10-deployment-requirements)
11. [Technology Stack](#11-technology-stack)
12. [Constraints and Assumptions](#12-constraints-and-assumptions)
13. [Out of Scope (v0.1.0)](#13-out-of-scope-for-v010)
14. [Future Considerations](#14-future-considerations)
15. [Glossary](#15-glossary)

---

## 1. Product Overview

### 1.1 Product Summary

**MiragePot** is an AI-driven adaptive SSH honeypot. It presents attackers with a fully simulated Ubuntu 20.04 Linux server over SSH. When an attacker connects and begins issuing commands, MiragePot processes each command through a three-tier hybrid engine: an in-memory virtual filesystem, a static response cache, and a locally-running Large Language Model (Microsoft Phi-3 via Ollama) for all other commands.

No command entered by an attacker is ever executed on the host operating system. Every interaction is silently logged, scored against a threat keyword database, mapped to MITRE ATT&CK techniques, and surfaced in a real-time monitoring dashboard alongside a full Prometheus + Grafana observability stack.

### 1.2 Product Vision

> Enable security researchers, students, and SOC analysts to deploy an intelligent, self-contained SSH honeypot that captures high-fidelity attacker behaviour data — without static scripts, without cloud dependencies, and without exposing real infrastructure.

### 1.3 Academic Context

This product is developed as a B.Tech Computer Science and Engineering mini-project, demonstrating the intersection of:

- **Network security**: SSH protocol implementation, honeypot architecture, MITRE ATT&CK threat modelling
- **Systems programming**: PTY emulation, virtual filesystem design, rate limiting
- **Applied artificial intelligence**: local LLM inference, system prompt engineering, prompt injection defence, output validation

---

## 2. Problem Statement

### 2.1 Limitations of Static Honeypots

Traditional SSH honeypots (such as Cowrie and Kippo) operate by intercepting incoming SSH connections and returning pre-written, scripted responses from a fixed response table. This approach has a fundamental and well-known weakness: the response set is finite, deterministic, and publicly documented.

An experienced attacker — or an automated scanning tool — can fingerprint a static honeypot within seconds by:

- Issuing commands that produce atypical or suspiciously uniform responses
- Comparing observed `uname`, `hostname`, and `/proc/version` output against known honeypot signatures
- Observing response timing (static honeypots respond instantly and identically for all unknown commands)
- Checking banner strings against published fingerprint databases

Once identified as a honeypot, the attacker disconnects. The session produces no useful intelligence. The threat actor continues undetected.

### 2.2 The Intelligence Gap

Security professionals need honeypots that go beyond logging a connection IP and a handful of commands. Effective threat intelligence collection requires:

- **Attacker engagement**: the honeypot must be convincing enough to hold an attacker's attention and draw out their full post-exploitation behaviour
- **TTP visibility**: the specific sequence of commands an attacker runs reveals their toolchain, skill level, and intent
- **Credential access detection**: honeytokens embedded in realistic locations surface exactly when attackers find and attempt to use fake credentials
- **Privacy and containment**: all capture must happen locally; attacker commands must not be forwarded to third-party cloud APIs

### 2.3 How MiragePot Addresses These Problems

MiragePot replaces static response lookup with dynamic LLM inference, backed by a virtual filesystem and a structured session context. The result is a honeypot that:

- **Is non-deterministic**: no two sessions produce the same responses for the same command sequence
- **Maintains session consistency**: the LLM receives the session state (working directory, created files, active user) with every prompt, enabling it to maintain continuity across a long session
- **Is harder to fingerprint**: LLM-generated responses are grounded in real Ubuntu 20.04 behaviour and vary naturally with context
- **Captures richer intelligence**: all activity is logged in structured JSON, TTP-mapped, and accessible in a real-time dashboard

---

## 3. Goals and Objectives

### 3.1 Primary Goals

| Goal | Description |
|---|---|
| G-01 | Maximise attacker dwell time by providing believable, AI-powered responses to any SSH command |
| G-02 | Capture high-fidelity threat intelligence (command sequences, TTPs, download attempts, honeytoken triggers) |
| G-03 | Operate entirely on local infrastructure with no cloud dependencies |
| G-04 | Be deployable on a single machine with a single command (`docker compose up -d`) |
| G-05 | Provide real-time visibility into active sessions and threat activity via a monitoring dashboard |

### 3.2 Non-Goals

| Non-Goal | Rationale |
|---|---|
| NG-01 | Execute real commands on the host OS | Core safety boundary; must never be violated |
| NG-02 | Use cloud-hosted LLM APIs | Would transmit attacker input to third-party servers |
| NG-03 | Perform active retaliation against attackers | Out of scope; MiragePot is passive intelligence collection |
| NG-04 | Replace a production intrusion detection system | MiragePot is a deception layer, not a firewall |

---

## 4. Target Users and Personas

### 4.1 Security Researcher

**Background**: Graduate or professional researcher studying attacker behaviour, collecting indicators of compromise (IOCs), or mapping real-world threat actor TTPs to the MITRE ATT&CK framework.

**Goals with MiragePot**:
- Deploy on a cloud VM exposed to the internet to capture organic attack traffic
- Export session data for offline analysis and research publication
- Use Grafana dashboards to identify patterns across large numbers of sessions

**Key requirements**: structured session export (JSON), long session duration support, Prometheus metrics for time-series analysis, offline deployment capability

### 4.2 CS Student / Educator

**Background**: Undergraduate or postgraduate computer science student (the primary developer persona); also a lecturer using MiragePot as a teaching tool.

**Goals with MiragePot**:
- Demonstrate honeypot concepts, the SSH protocol, and applied AI in a hands-on lab setting
- Understand how MITRE ATT&CK maps to real attacker behaviour
- Run live demonstrations in classroom or conference settings

**Key requirements**: simple setup (Docker), offline deployment for air-gapped labs, interactive demonstration walkthrough guide, clear code structure for educational exploration

### 4.3 SOC Analyst

**Background**: Security operations centre analyst deploying MiragePot as an early-warning sensor on a DMZ, cloud perimeter, or internal network segment.

**Goals with MiragePot**:
- Detect attackers who have reached an internal network segment and are conducting post-exploitation reconnaissance
- Receive alerts when honeytokens are accessed (indicating credential theft)
- Integrate session data into a SIEM for correlation with other security events

**Key requirements**: honeytoken alerting, Prometheus metrics for alerting integration, JSON session logs, configurable rate limiting, low resource footprint

### 4.4 CTF Organiser

**Background**: Individual or team running a Capture the Flag competition and using MiragePot as an interactive challenge.

**Goals with MiragePot**:
- Create a realistic Linux SSH target with hidden flags (using the honeytoken system)
- Provide a safe, isolated environment where participants can practise post-exploitation techniques
- Monitor participant activity in real time via the dashboard

**Key requirements**: configurable honeytoken values, session replay, Docker deployment for easy reset between teams

---

## 5. Functional Requirements

### 5.1 SSH Honeypot Server

**Module:** `ssh_interface.py`, `server.py`

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| F-1.1 | The system shall accept SSH connections from any client on the configured port (default: 2222) | SSH client can connect and authenticate using any username and password combination |
| F-1.2 | Authentication shall accept all username and password combinations | `ssh root@localhost -p 2222` with any password opens an interactive session |
| F-1.3 | The system shall use a 4096-bit RSA host key, persistent across restarts | `data/host.key` exists after first run; the same fingerprint is presented on reconnection |
| F-1.4 | The system shall present a configurable SSH banner | Banner defaults to `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5`; configurable via `MIRAGEPOT_OS_*` env vars |
| F-1.5 | The system shall support full PTY/TTY emulation | Attacker's terminal responds to TERM type, window dimensions, and raw byte input |
| F-1.6 | The system shall log client SSH fingerprinting information | Session JSON includes client version string, negotiated KEX, ciphers, MACs, and compression |

### 5.2 Three-Tier Hybrid Command Engine

**Module:** `command_handler.py`

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| F-2.1 | The command engine shall process all input through a three-tier priority system | Tier 1 (filesystem) → Tier 2 (static cache) → Tier 3 (LLM) with no fallthrough to OS execution |
| F-2.2 | Tier 1 shall handle all filesystem-interactive commands in memory | `ls`, `cd`, `cat`, `mkdir`, `rm`, `touch`, `cp`, `mv`, `chmod`, `find`, `stat`, `pwd` all function correctly against the virtual filesystem |
| F-2.3 | Tier 2 shall return pre-written responses for common reconnaissance commands | `whoami`, `id`, `uname -a`, `ifconfig`, `env`, `hostname` return consistent, realistic output within 50 ms |
| F-2.4 | Tier 3 shall forward unrecognised commands to the configured LLM | Any command not handled by Tier 1 or 2 produces a response via Ollama |
| F-2.5 | The system shall never execute any attacker-supplied command on the host OS | No subprocess calls, shell invocations, or OS-level file access occur during session handling |

### 5.3 Virtual Filesystem

**Module:** `filesystem.py`, `command_handler.py`

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| F-3.1 | The virtual filesystem shall simulate an Ubuntu 20.04 directory tree | `/etc`, `/root`, `/home`, `/var`, `/proc`, `/tmp`, `/usr`, `/bin` directories are present and browseable |
| F-3.2 | The filesystem shall be seeded per-session with realistic file content | At session start, 300+ pre-seeded files are present including `/etc/passwd`, `.bash_history`, `auth.log`, `nginx.conf`, `.env` |
| F-3.3 | Filesystem state shall persist within a session | Files created, modified, or deleted within a session remain so for the duration of that session |
| F-3.4 | Path traversal and symlink attacks shall be handled safely | Paths like `../../etc/passwd` and symbolic link chains resolve to safe virtual paths without accessing the host |

### 5.4 Honeytoken System

**Module:** `honeytokens.py`

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| F-4.1 | The system shall generate 7 distinct honeytoken types per session | AWS key, Stripe API key, DB password, internal API key, JWT secret, GitHub PAT, and admin password are all present in the session filesystem |
| F-4.2 | Honeytoken values shall be unique per session | Two different sessions produce different token values; format is realistic for each token type |
| F-4.3 | The system shall detect and log honeytoken access events | Reading a file containing a honeytoken creates a log entry and increments the Prometheus counter |
| F-4.4 | Honeytoken events shall be surfaced in the dashboard | The Streamlit dashboard shows a real-time honeytoken alert feed |

### 5.5 MITRE ATT&CK TTP Detection

**Module:** `ttp_detector.py`

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| F-5.1 | The system shall map attacker commands to MITRE ATT&CK techniques | Each detected command produces a log entry with ATT&CK Technique ID, tactic name, and description |
| F-5.2 | The system shall support at least 150 single-command detection patterns | 151 compiled regex patterns are active across 10 attack stages |
| F-5.3 | The system shall detect multi-command attack chains | 12 chain patterns detect sequences of commands that together constitute a known TTP |
| F-5.4 | Detection results shall be available in the dashboard and Prometheus metrics | TTP detection counts are broken down by stage in Grafana; detected TTPs are shown in session detail view |

**Attack stages covered:**

| Stage | Example TTPs Detected |
|---|---|
| Initial Access | Post-brute-force discovery commands |
| Discovery | `whoami`, `id`, `uname`, `ps aux`, `netstat -an`, `cat /etc/passwd` |
| Privilege Escalation | `sudo -l`, SUID binary enumeration (`find / -perm -4000`), `su root` |
| Credential Access | `/etc/shadow` read, `~/.ssh` key access, `.env` credential extraction |
| Persistence | Crontab modification, `.bashrc` append, SSH key injection |
| Defence Evasion | Log file clearing (`> /var/log/auth.log`), history deletion (`history -c`) |
| Lateral Movement | SSH to internal hosts, internal IP range scanning |
| Collection | File staging, archiving (`tar czf`, `zip -r`) |
| Exfiltration | `scp`, `rsync`, `curl --upload-file` to external addresses |
| Command and Control | Reverse shell attempts (`bash -i`, `nc -e`, Python/Perl shells) |

### 5.6 Active Defence (Tarpit)

**Module:** `defense_module.py`

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| F-6.1 | The system shall assign a threat score to every command based on a keyword database | High-risk keywords (e.g. `/etc/shadow`, `nc -e`, `chmod 777`, `passwd`) increase the session threat score |
| F-6.2 | Sessions exceeding a threat score threshold shall receive artificial response delays | For cumulative score ≥ 40: delays of 1–5 seconds are inserted proportionally to the score |
| F-6.3 | Tarpit delays shall be logged | Each delayed response records the delay duration in the session JSON |

**Tarpit delay schedule:**

| Cumulative Threat Score | Response Delay |
|---|---|
| 0 – 39 | No delay |
| 40 – 79 | 1 – 2 seconds |
| 80 – 119 | 2 – 4 seconds |
| ≥ 120 | 3 – 5 seconds |

### 5.7 LLM Integration and Prompt Injection Protection

**Module:** `ai_interface.py`

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| F-7.1 | The system shall forward unrecognised commands to the locally-running Ollama LLM | A response is generated via `phi3` (or the configured model) for any Tier-3 command |
| F-7.2 | The LLM system prompt shall include the simulated server identity and current session state | The LLM receives hostname, OS details, current working directory, and active user with every request |
| F-7.3 | The system shall screen all LLM input for prompt injection attempts | 88 compiled regex patterns (72 direct + 16 encoded) block injection payloads before they reach the LLM |
| F-7.4 | Blocked injection attempts shall be logged and return a plausible terminal error | The attacker sees a `command not found`-style error; the attempt is recorded in the session log |
| F-7.5 | The system shall enforce an LLM response timeout | If Ollama does not respond within 30 seconds (configurable), a safe fallback response is returned and the session continues |

### 5.8 LLM Response Validation

**Module:** `response_validator.py`

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| F-8.1 | LLM responses that reveal the system is artificial shall be stripped | Text containing "As an AI", "I cannot execute real commands", or similar phrases is removed before the response is sent |
| F-8.2 | Markdown formatting in LLM responses shall be removed | No `**bold**`, `# headings`, or `` `code blocks` `` appear in the terminal output |
| F-8.3 | Incorrect date/year references shall be corrected | The validator removes or corrects LLM-generated dates that contradict the configured session context |

### 5.9 Rate Limiting

**Module:** `rate_limiter.py`

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| F-9.1 | The system shall limit concurrent connections per IP address | A single IP address can hold at most 3 simultaneous sessions (configurable) |
| F-9.2 | The system shall enforce a global concurrent session limit | No more than 50 sessions can be active simultaneously (configurable) |
| F-9.3 | IPs that exceed the per-IP limit shall be blocked temporarily | An IP exceeding the limit is blocked for 300 seconds (configurable) before new connections are accepted |

### 5.10 Download Capture

**Module:** `download_capture.py`

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| F-10.1 | The system shall detect and log download tool usage | Commands using `wget`, `curl`, `scp`, `rsync`, and `ftp` are recognised and the target URL/host/path is extracted and logged |
| F-10.2 | No download shall be executed | The parsed download command is logged only; no network connection is made to the target |

### 5.11 System State Simulation

**Module:** `system_state.py`

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| F-11.1 | The system shall produce realistic output for system introspection commands | `ps`, `top`, `netstat`, `ss`, `free`, `uptime`, `w`, `who`, `last`, `systemctl status` all return plausible output |
| F-11.2 | System state output shall be consistent with the configured server identity | Process list, hostname, kernel version, and network interface output reflect the configured `MIRAGEPOT_*` values |

### 5.12 Session Export and Replay

**Module:** `session_export.py`

| ID | Requirement | Acceptance Criteria |
|---|---|---|
| F-12.1 | Sessions shall be exportable in text, JSON, and HTML formats | `session_export.py` produces all three formats without error |
| F-12.2 | Session replay shall be available with configurable speed | HTML export includes a terminal replay with configurable speed multiplier and optional typing animation |

---

## 6. Non-Functional Requirements

| ID | Category | Requirement | Target |
|---|---|---|---|
| NF-1 | Privacy | LLM inference shall be local only | No external API calls; all data stays on the host machine |
| NF-2 | Performance | Response latency (Tier 1 and 2) | < 50 ms for filesystem and cached commands |
| NF-3 | Performance | Response latency (Tier 3 LLM) | ≤ 30 second configurable timeout; typical Phi-3 inference 5–20 seconds on CPU |
| NF-4 | Scalability | Concurrent sessions | The system shall support ≥ 50 simultaneous SSH sessions |
| NF-5 | Data integrity | Session log integrity | Session JSON files are append-only; no in-place modification after writing |
| NF-6 | Security | Host OS isolation | No attacker command shall result in any execution on the host operating system |
| NF-7 | Privacy | Password logging | Attacker passwords shall not be logged by default (`MIRAGEPOT_LOG_PASSWORDS = false`) |
| NF-8 | Portability | Platform support | The system shall run on Linux and macOS (native), and on any platform supporting Docker |
| NF-9 | Maintainability | Test coverage | The codebase shall maintain a unit test suite with zero failures; target: ≥ 500 tests |
| NF-10 | Usability | First-run setup | A new user shall be able to deploy the full stack without manual configuration beyond copying `.env.docker.example` |

---

## 7. System Architecture Summary

### 7.1 Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        External Network                         │
│                    (Attacker SSH client)                        │
└───────────────────────────┬─────────────────────────────────────┘
                            │ SSH (port 2222)
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                        MiragePot Core                           │
│                                                                 │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐    │
│  │SSH Interface │──►│Rate Limiter  │──►│Session           │    │
│  │(Paramiko)    │   │              │   │Orchestrator      │    │
│  └──────────────┘   └──────────────┘   │(server.py)       │    │
│                                        └────────┬─────────┘    │
│                                                 │              │
│                              ┌──────────────────▼────────────┐ │
│                              │  3-Tier Hybrid Command Engine  │ │
│                              │                                │ │
│                              │  Tier 1: Virtual Filesystem    │ │
│                              │  Tier 2: Static Cache          │ │
│                              │  Tier 3: Ollama LLM (Phi-3)    │ │
│                              └──────────────────┬────────────┘ │
│                                                 │              │
│         ┌───────────────────────────────────────┘              │
│         │                                                       │
│  ┌──────▼───────┐  ┌─────────────┐  ┌───────────┐             │
│  │TTP Detector  │  │Defense      │  │Honeytoken │             │
│  │(MITRE ATT&CK)│  │Module       │  │Monitor    │             │
│  └──────────────┘  └─────────────┘  └───────────┘             │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Session Logger                         │  │
│  │   data/logs/session_<id>.json · live_sessions.json       │  │
│  └──────────────┬───────────────────────────────────────────┘  │
└─────────────────┼───────────────────────────────────────────────┘
                  │
       ┌──────────┴──────────┐
       ▼                     ▼
Prometheus (9090)    Streamlit Dashboard (8501)
       │
       ▼
Grafana (3000)
```

### 7.2 Module Summary

| Module | File | Responsibility |
|---|---|---|
| SSH Interface | `ssh_interface.py` | Paramiko ServerInterface; authentication; PTY negotiation |
| Server | `server.py` | Session lifecycle; main connection loop; thread management |
| Command Handler | `command_handler.py` | 3-tier hybrid engine; 300+ pre-seeded file contents |
| AI Interface | `ai_interface.py` | Ollama/Phi-3 bridge; session state injection; prompt injection protection |
| Defense Module | `defense_module.py` | Keyword threat scoring; tarpit delay calculation |
| TTP Detector | `ttp_detector.py` | MITRE ATT&CK pattern matching; 163 patterns; chain detection |
| Honeytokens | `honeytokens.py` | 7 fake credential types; per-session generation; access detection |
| Filesystem | `filesystem.py` | Virtual filesystem operations (stat, chmod, chown, find, path normalisation) |
| System State | `system_state.py` | Realistic ps, top, netstat, ss, free, uptime, w, last, systemctl output |
| TTY Handler | `tty_handler.py` | Raw TTY input; line editing; command history; tab completion |
| Response Validator | `response_validator.py` | LLM output sanitisation; anti-hallucination rules |
| Download Capture | `download_capture.py` | wget, curl, scp, rsync, ftp detection and logging |
| Rate Limiter | `rate_limiter.py` | Per-IP and global connection limits; IP blocking |
| Metrics | `metrics.py` | Prometheus metrics exporter (~20 metric types) |
| Session Export | `session_export.py` | Export sessions as text, JSON, or HTML |
| Config | `config.py` | Typed configuration dataclasses; environment variable loading |
| Dashboard | `dashboard/app.py` | Streamlit real-time monitoring dashboard |
| Runner | `run.py` | Unified launcher for honeypot and dashboard subprocess |

---

## 8. Monitoring and Observability

### 8.1 Real-Time Dashboard

**Technology:** Streamlit | **Port:** 8501

| View | Description |
|---|---|
| Sessions Overview | All active and recent sessions: attacker IP, connection time, command count, threat score, detected TTPs |
| Session Detail | Full command history with threat-level colour coding and TTP annotations per command |
| Threat Heatmap | Visual breakdown of MITRE ATT&CK stages detected across all sessions |
| Honeytoken Alerts | Real-time feed of honeytoken access events with session ID and token type |
| Session Replay | Replay a recorded session at configurable speed with optional typing animation |

### 8.2 Prometheus Metrics

**Port:** 9090 (honeypot process) / 9091 (Prometheus UI in Docker stack)

Metrics exported (selected):

| Metric | Type | Description |
|---|---|---|
| `miragepot_connections_total` | Counter | Total connection attempts (labelled by result) |
| `miragepot_active_sessions` | Gauge | Currently active SSH sessions |
| `miragepot_session_duration_seconds` | Histogram | Session duration distribution |
| `miragepot_commands_total` | Counter | Commands processed (labelled by tier: filesystem / cache / llm) |
| `miragepot_llm_request_duration_seconds` | Histogram | LLM inference latency (p50, p95, p99) |
| `miragepot_ttp_detections_total` | Counter | TTP detections (labelled by ATT&CK stage) |
| `miragepot_honeytoken_triggers_total` | Counter | Honeytoken access events (labelled by token type) |
| `miragepot_threat_score` | Histogram | Threat score distribution across sessions |
| `miragepot_rate_limit_blocks_total` | Counter | IP addresses blocked by rate limiter |
| `miragepot_prompt_injection_blocks_total` | Counter | Prompt injection attempts blocked |

### 8.3 Grafana Dashboards

**Port:** 3000 | **Default credentials:** admin / admin

| Dashboard | Contents |
|---|---|
| MiragePot Overview | Active sessions, connection rate over time, top commands, threat score distribution, 24-hour unique attacker IPs |
| TTP Analysis | ATT&CK stage breakdown (bar chart), most-detected techniques (table), chain detection events, honeytoken trigger timeline |
| Performance | LLM inference latency (p50/p95/p99 over time), cache hit rate, tier distribution, error rate |

### 8.4 Session Logging

Per-session JSON files are written to `data/logs/session_<id>.json` and contain:

- Session metadata: session ID, attacker IP, port, connection time, disconnect time, duration
- SSH fingerprint data: client version string, negotiated algorithms
- Full command history: each entry includes timestamp, raw input, processed command, response, threat score, tarpit delay, current working directory, TTP detections, and honeytoken triggers
- Download attempt log: tool used, target URL, destination path
- Session summary: total commands, peak threat score, TTP stage list, honeytoken types accessed

A `live_sessions.json` file is maintained for real-time dashboard streaming (up to 50 active sessions, last 20 commands each).

---

## 9. Configuration Reference

All configuration is controlled via environment variables with the `MIRAGEPOT_` prefix. A `.env` file in the project root is automatically loaded.

| Group | Variable | Default | Description |
|---|---|---|---|
| **SSH** | `MIRAGEPOT_SSH_HOST` | `0.0.0.0` | SSH listen address |
| | `MIRAGEPOT_SSH_PORT` | `2222` | SSH listen port |
| | `MIRAGEPOT_HOST_KEY` | `data/host.key` | Path to RSA host key file |
| **LLM** | `MIRAGEPOT_LLM_MODEL` | `phi3` | Ollama model name |
| | `MIRAGEPOT_LLM_TIMEOUT` | `30` | LLM response timeout (seconds) |
| | `MIRAGEPOT_LLM_TEMPERATURE` | `0.7` | LLM sampling temperature |
| | `MIRAGEPOT_LLM_MAX_TOKENS` | `512` | Maximum tokens per LLM response |
| **Dashboard** | `MIRAGEPOT_DASHBOARD_HOST` | `localhost` | Dashboard listen address |
| | `MIRAGEPOT_DASHBOARD_PORT` | `8501` | Dashboard listen port |
| | `MIRAGEPOT_DASHBOARD_REFRESH` | `5` | Dashboard auto-refresh interval (seconds) |
| | `MIRAGEPOT_DASHBOARD_PASSWORD` | (none) | Optional password to protect dashboard access |
| **Logging** | `MIRAGEPOT_LOG_LEVEL` | `INFO` | Log verbosity (DEBUG / INFO / WARNING / ERROR) |
| | `MIRAGEPOT_LOG_FILE` | (none) | Optional log output file path |
| **Identity** | `MIRAGEPOT_HOSTNAME` | `miragepot` | Simulated server hostname (shown in prompt and system prompt) |
| | `MIRAGEPOT_OS_NAME` | `Ubuntu` | Simulated OS name (shown in SSH banner) |
| | `MIRAGEPOT_OS_VERSION` | `20.04.6 LTS` | Simulated OS version |
| | `MIRAGEPOT_KERNEL_VERSION` | `5.15.0-86-generic` | Simulated kernel version |
| **Security** | `MIRAGEPOT_MAX_CONNECTIONS_PER_IP` | `3` | Maximum concurrent connections per IP |
| | `MIRAGEPOT_MAX_TOTAL_CONNECTIONS` | `50` | Maximum global concurrent connections |
| | `MIRAGEPOT_BLOCK_DURATION` | `300` | IP block duration in seconds |
| | `MIRAGEPOT_MAX_SESSION_DURATION` | `3600` | Maximum session duration in seconds |
| | `MIRAGEPOT_LOG_PASSWORDS` | `false` | Whether to log attacker-supplied passwords |

---

## 10. Deployment Requirements

### 10.1 System Requirements

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Disk | 10 GB free | 20 GB free |
| OS | Linux (kernel 4.x+) or macOS 12+ | Ubuntu 22.04 LTS |
| Docker | Engine 20.x + Compose v2 | Latest stable |
| Python (local dev) | 3.10 | 3.11+ |

### 10.2 Deployment Modes

| Mode | Command | Services | RAM Required |
|---|---|---|---|
| Full Stack (recommended) | `cd docker && docker compose up -d` | honeypot + Ollama + Prometheus + Grafana + Alertmanager | ~5 GB |
| Simple Stack | `docker compose -f docker-compose-simple.yml up -d` | honeypot + Ollama + Streamlit | ~3 GB |
| Local Development | `python run.py` | honeypot + dashboard (Ollama separately) | ~4 GB |

### 10.3 Port Reference

| Port | Service |
|---|---|
| `2222` | SSH honeypot |
| `8501` | Streamlit dashboard |
| `9090` | Prometheus metrics (honeypot process) |
| `9091` | Prometheus UI |
| `9093` | Alertmanager |
| `3000` | Grafana |
| `11434` | Ollama API (internal Docker network only) |

### 10.4 First-Run Experience

```bash
# 1. Clone the repository
git clone https://github.com/evinbrijesh/MiragePot.git
cd MiragePot

# 2. Configure (optional — defaults work out of the box)
cp docker/.env.docker.example docker/.env.docker

# 3. Deploy (Phi-3 model downloads automatically on first run)
cd docker && docker compose up -d

# 4. Connect and test
ssh root@localhost -p 2222   # any password

# 5. Open monitoring
# Dashboard:  http://localhost:8501
# Grafana:    http://localhost:3000  (admin / admin)
```

---

## 11. Technology Stack

| Layer | Technology | Version | Justification |
|---|---|---|---|
| Core language | Python | 3.10+ | Mature SSH library availability (Paramiko); rapid prototyping; strong testing ecosystem |
| SSH protocol | Paramiko | ≥ 3.0.0 | Pure-Python SSH-2 implementation with full server-side support; widely used and actively maintained |
| LLM runtime | Ollama | ≥ 0.1.0 | Local-only inference; Docker-native; straightforward model management; REST API |
| LLM model | Microsoft Phi-3 | — | Strong instruction-following capability; fits within ~4 GB RAM; acceptable CPU inference speed |
| Dashboard | Streamlit | ≥ 1.30.0 | Python-native; requires no separate frontend framework; rapid iteration |
| Metrics | prometheus-client | ≥ 0.19.0 | Industry-standard metrics exposition format; native Grafana integration |
| Config | python-dotenv | ≥ 1.0.0 | Standard `.env` file support; twelve-factor app configuration pattern |
| Containerisation | Docker + Compose | v2.0+ | Reproducible deployment; service isolation; one-command stack management |
| Monitoring | Prometheus + Grafana | — | Industry-standard observability stack; pre-built dashboard provisioning |
| Testing | pytest + pytest-cov | ≥ 7.0.0 | Standard Python test framework; extensive plugin ecosystem |
| Formatting | black | ≥ 23.0.0 | Deterministic, zero-configuration code formatting |
| Linting | ruff | ≥ 0.1.0 | Fast, comprehensive Python linter |
| Type checking | mypy | ≥ 1.0.0 | Static type verification; catches type errors before runtime |
| Pre-commit hooks | pre-commit | ≥ 3.0.0 | Enforces quality checks automatically before every commit |

---

## 12. Constraints and Assumptions

### 12.1 Constraints

| ID | Constraint |
|---|---|
| C-1 | The system must never execute any command on the host operating system. This is an absolute safety boundary with no exceptions. |
| C-2 | All LLM inference must be local. Attacker input must not be transmitted to any external API or cloud service. |
| C-3 | The system is designed for single-node deployment. Multi-node or distributed operation is not supported in v0.1.0. |
| C-4 | The system targets SSH clients only. Other protocols (Telnet, RDP, HTTP) are out of scope. |
| C-5 | LLM response quality is bounded by the capabilities of Microsoft Phi-3. Responses may occasionally be inconsistent or non-realistic; this is an accepted trade-off for local-only operation. |

### 12.2 Assumptions

| ID | Assumption |
|---|---|
| A-1 | The deployment machine has sufficient RAM (≥ 8 GB) to run the Ollama model alongside the honeypot and monitoring stack. |
| A-2 | The operator has configured the host firewall appropriately to expose port 2222 to the intended audience (internet or test network). |
| A-3 | The operator accepts that running an internet-exposed honeypot may attract real malicious traffic. MiragePot is designed for this, but the operator retains responsibility for host security. |
| A-4 | The LLM model (Phi-3, ~2 GB) is downloadable on first run. For air-gapped deployments, the offline bundle must be used. |
| A-5 | Users of the monitoring dashboard are trusted; the dashboard is not intended to be internet-exposed without password protection. |

---

## 13. Out of Scope for v0.1.0

The following features are explicitly outside the scope of the current release:

| Feature | Rationale |
|---|---|
| Real command execution | Violates the core safety boundary; must never be implemented |
| Network-level deception (ARP spoofing, traffic redirection) | Requires privileged network access; beyond the SSH-layer scope |
| Windows attacker client emulation | SSH is a Unix-centric protocol; not part of the MVP threat model |
| Cloud-hosted LLM backends (OpenAI, Gemini, Anthropic) | Would transmit attacker commands to third-party servers |
| Multi-node honeypot clustering | Complexity not warranted for single-machine use cases |
| CI/CD pipeline | Planned for Phase 2 of production readiness |
| PyPI package publication (`pip install miragepot`) | Planned for a future version release |
| GeoIP enrichment | Requires external database; optional enhancement |
| SIEM integration (Splunk, Elastic) | Enterprise feature; deferred post-MVP |
| Automated threat report generation (PDF/HTML) | Useful enhancement; deferred to future version |
| Left/right arrow cursor movement in TTY | Non-trivial to implement; harmless omission for this release |

---

## 14. Future Considerations

### 14.1 Short-Term (Next Release)

| Feature | Description |
|---|---|
| CI/CD pipeline | GitHub Actions: automated pytest + mypy + ruff on every push; Docker image build to `ghcr.io`; auto GitHub Release on version tag |
| CHANGELOG.md | Formal version history document |
| Git version tag `v0.1.0` | First official release tag |
| TTY cursor movement | Implement left/right arrow key cursor positioning in `tty_handler.py` |

### 14.2 Medium-Term

| Feature | Description |
|---|---|
| Additional LLM backends | Support llama.cpp, vLLM, and OpenAI-compatible API specification |
| Additional OS profiles | CentOS, Debian, Alpine Linux personalities; configurable at deploy time |
| Red team mode | Web-based attack simulation interface to test the honeypot from the attacker's perspective |
| GeoIP enrichment | Enrich attacker IPs with geographic data; populate Grafana worldmap panel |

### 14.3 Long-Term

| Feature | Description |
|---|---|
| Automated threat reports | Generate PDF or HTML summaries from session data automatically after session close |
| SIEM integration | Export session data to Splunk, Elasticsearch, or any SIEM via syslog/CEF format |
| PyPI publication | `pip install miragepot` with a clean CLI entry point |
| Cloud deployment guide | Terraform/Ansible templates for one-command VM provisioning on AWS/GCP/Azure |

---

## 15. Glossary

| Term | Definition |
|---|---|
| **ATT&CK** | MITRE Adversarial Tactics, Techniques, and Common Knowledge — a knowledge base of real-world attacker behaviours used to classify threat intelligence |
| **Honeytoken** | A fake credential or secret embedded in a system specifically to detect unauthorised access; any access to a honeytoken is a high-confidence indicator of compromise |
| **Honeypot** | A security tool that presents an intentionally vulnerable or attractive fake system to attract and study malicious actors |
| **LLM** | Large Language Model — a machine learning model trained on large text corpora, capable of generating coherent text responses to arbitrary inputs |
| **MITRE ATT&CK** | See ATT&CK; MITRE is the non-profit organisation that maintains the framework |
| **Ollama** | An open-source tool for running LLM models locally; provides a REST API for inference |
| **Paramiko** | A pure-Python implementation of the SSH-2 protocol, used in MiragePot to implement the SSH server |
| **Phi-3** | A small language model released by Microsoft, optimised for instruction-following and deployable on consumer hardware |
| **Prompt injection** | An attack technique where malicious input attempts to override or manipulate the instructions given to an LLM, causing it to produce unintended outputs |
| **PTY** | Pseudo-Terminal — a software abstraction that emulates a hardware terminal, allowing applications to send and receive raw TTY I/O |
| **SOC** | Security Operations Centre — a team or facility responsible for monitoring and responding to security events in an organisation |
| **Tarpit** | A network or application technique that deliberately slows down malicious connections to waste attacker time and deter automated tools |
| **TTP** | Tactics, Techniques, and Procedures — the high-level behaviour patterns that characterise how a threat actor operates |
| **TTY** | TeleTYpewriter — the Linux abstraction for terminal I/O; in this context, refers to the raw byte stream of attacker keyboard input |
| **Virtual Filesystem** | An in-memory data structure that simulates a real filesystem's directory tree and file contents without touching the host OS |

---

*MiragePot — AI-Driven Adaptive SSH Honeypot*  
*Product Requirements Document v1.1*  
*B.Tech Computer Science and Engineering, Semester 6*  
*Mar Athanasius College of Engineering, Kothamangalam*  
*Evin Brijesh | 2026*
