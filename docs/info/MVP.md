# MiragePot — Minimum Viable Product (MVP) Document

**Project:** MiragePot — AI-Driven Adaptive SSH Honeypot  
**Version:** 0.2.0  
**Author:** Evin Brijesh  
**Programme:** B.Tech Computer Science and Engineering, Semester 6  
**Institution:** Mar Athanasius College of Engineering, Kothamangalam  
**Date:** 2026-02-28  
**Status:** Complete

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [MVP Definition and Goals](#3-mvp-definition-and-goals)
4. [Scope of v0.2.0](#4-scope-of-v020)
5. [System Architecture](#5-system-architecture)
6. [Feature Implementation](#6-feature-implementation)
7. [Technology Stack](#7-technology-stack)
8. [Testing and Validation](#8-testing-and-validation)
9. [Deployment](#9-deployment)
10. [Known Limitations](#10-known-limitations)
11. [Out of Scope for v0.2.0](#11-out-of-scope-for-v020)
12. [Future Roadmap](#12-future-roadmap)
13. [Summary](#13-summary)

---

## 1. Executive Summary

MiragePot is an AI-driven adaptive SSH honeypot that simulates a realistic Ubuntu 20.04 Linux server to attract, engage, and profile malicious actors. Unlike traditional honeypots that serve static, pre-scripted responses, MiragePot uses a locally-running Large Language Model (Microsoft Phi-3 via Ollama) to generate believable, context-aware replies to attacker commands in real time.

The current MVP baseline (v0.2.0) delivers a fully functional, deployable honeypot system with the following core capabilities:

- A working SSH server on port 2222 that accepts any credentials and simulates an interactive shell
- A three-tier hybrid command engine (virtual filesystem → static cache → LLM fallback)
- Real-time MITRE ATT&CK TTP detection across 38 technique IDs
- Honeytoken generation and access detection for 10 fake credential types
- An active defense system with threat scoring and tarpit delays
- A Streamlit-based live monitoring dashboard
- A full Prometheus + Grafana observability stack
- A complete Docker deployment with one-command setup (`docker compose up -d`)
- Unit tests included (run `pytest` to verify in your environment)

The project demonstrates the practical intersection of cybersecurity (honeypot design, attacker profiling, MITRE ATT&CK), network programming (SSH protocol, PTY emulation), and applied AI (local LLM inference, prompt injection protection, response validation).

---

## 2. Problem Statement

### 2.1 The Limitation of Static Honeypots

Traditional SSH honeypots (Cowrie, Kippo, and similar tools) operate by intercepting SSH connections and returning pre-scripted responses from a fixed lookup table. This design has a critical weakness: the response set is finite and static.

Experienced attackers and automated scanning tools fingerprint these honeypots within seconds by:

- Sending commands that no real system would respond to in a scripted way
- Observing timing patterns (immediate, identical responses for any unknown command)
- Comparing banner strings and error messages against known honeypot signatures
- Issuing `uname`, `hostname`, and `/proc/version` checks and comparing against known fakes

Once fingerprinted, the attacker terminates the session. The honeypot collects no useful intelligence. The threat actor proceeds undetected.

### 2.2 The Intelligence Gap

Security researchers and SOC analysts need honeypots that do more than log an IP address and a few commands. They need systems that:

- Keep attackers engaged long enough to reveal their full toolchain and intent
- Capture the sequence of commands (TTPs) used during post-exploitation
- Detect when known credentials or secrets are accessed (honeytoken triggers)
- Map attacker behaviour to the MITRE ATT&CK framework automatically
- Operate entirely on local infrastructure, with no cloud dependency that could leak attacker data

### 2.3 What MiragePot Solves

MiragePot addresses these gaps by replacing static response lookup with dynamic LLM inference. Because every response is generated in context, the honeypot is:

- **Non-deterministic**: no two sessions produce identical responses for the same command sequence
- **Self-consistent**: session state (working directory, file edits, created users) is tracked and injected into every LLM prompt
- **Harder to fingerprint**: responses are grounded in real Ubuntu 20.04 behaviour
- **Intelligence-rich**: all activity is logged, TTP-mapped, and surfaced in a real-time dashboard

---

## 3. MVP Definition and Goals

### 3.1 What an MVP Means for This Project

In the context of a cybersecurity research tool and academic project, the MVP is the smallest complete system that:

1. **Operates end-to-end**: attacker connects via SSH, issues commands, receives believable responses, and all activity is logged
2. **Provides intelligence value**: sessions are structured, TTP-mapped, and accessible via a dashboard
3. **Can be deployed**: works on a single machine using Docker without manual configuration beyond a single `.env` file
4. **Is demonstrable**: can be shown live in a classroom or conference setting within 15 minutes of setup

### 3.2 MVP Success Criteria

| Criterion | Target | Status |
|---|---|---|
| SSH server accepts connections | Any username / any password | Done |
| Commands produce believable responses | 3-tier engine operational | Done |
| LLM generates context-aware replies | Phi-3 via Ollama, <30s timeout | Done |
| All sessions logged to structured JSON | Per-session files in `data/logs/` | Done |
| MITRE ATT&CK mapping works | 38 technique IDs, 10 stages | Done |
| Honeytoken access detected | 10 credential types, per-session | Done |
| Dashboard displays live data | Streamlit, port 8501 | Done |
| One-command Docker deployment | `docker compose up -d` | Done |
| Test coverage | Unit tests included; run `pytest` to verify | Done |

### 3.3 Design Principles

The following principles guided all MVP decisions:

- **No real command execution**: nothing the attacker types is ever executed on the host OS
- **Local LLM only**: Phi-3 runs entirely via Ollama; no attacker data leaves the machine
- **Believable, not perfect**: responses need to be plausible enough to sustain engagement, not byte-for-byte identical to a real system
- **Fail safe**: LLM timeout or failure falls back to a generic but safe response; the session is never dropped
- **Observability first**: every event of interest generates a log entry, a Prometheus metric, and a dashboard update

---

## 4. Scope of v0.2.0

### 4.1 What Is Included

| Area | Description |
|---|---|
| SSH server | Full SSH-2 server via Paramiko; 4096-bit RSA host key; accepts all credentials; PTY emulation |
| 3-tier command engine | Virtual filesystem layer → static JSON cache → Ollama LLM fallback |
| Virtual filesystem | In-memory Ubuntu 20.04 directory tree; 250+ pre-seeded fake files |
| LLM integration | Microsoft Phi-3 via Ollama; system prompt with session state injection; 88-pattern prompt injection protection |
| Response validation | Post-LLM sanitisation; strips AI self-revelations, markdown, invalid dates |
| Honeytoken system | 10 fake credential types; per-session unique values; access detection and alerting |
| TTP detection | 38 MITRE ATT&CK technique IDs (62 single-command + 6 chain patterns); 10 attack stages |
| Active defence | Keyword-based threat scoring; tarpit delays of 1–5 seconds for threat score ≥ 40 |
| Rate limiting | 3 concurrent connections per IP; 50 global maximum; 300-second block duration |
| Download capture | Detects and logs wget, curl, scp, rsync, ftp commands without executing them |
| System state simulation | Realistic output for ps, top, netstat, ss, free, uptime, w, who, last, systemctl |
| TTY handling | Raw byte-by-byte input; command history (arrow keys); tab completion |
| Session export | Export to text, JSON, or HTML; configurable replay speed |
| Prometheus metrics | ~20 metric types: connections, sessions, commands, LLM latency, TTP detections, honeytoken triggers |
| Streamlit dashboard | Live sessions view, threat heatmap, TTP breakdown, honeytoken alerts, session replay |
| Grafana stack | 3 pre-built dashboards: Overview, TTP Analysis, Performance |
| Docker deployment | 5-container stack; auto-downloads Phi-3 model on first run |
| Offline deployment | Portable ~6–7 GB bundle with checksums for air-gapped demos |
| Configuration system | Fully environment-variable driven; typed dataclasses; `.env` file support |
| Test suite | Unit tests included; run `pytest` to verify |  |

### 4.2 Deliberate Exclusions

The following were considered and explicitly excluded from v0.2.0 to keep the MVP focused:

| Excluded Feature | Reason |
|---|---|
| Real command execution | Security boundary — must never execute attacker input on the host |
| Cloud LLM backends (OpenAI, Gemini) | Privacy — attacker commands would leave the machine |
| Multi-node honeypot clustering | Complexity — single-node is sufficient for the MVP use case |
| Network-level deception (ARP spoofing, port knocking) | Out of scope for SSH-focused MVP |
| Windows attacker client emulation | Not part of the SSH threat model |
| Left/right arrow cursor movement in TTY | Non-trivial to implement; harmless omission for MVP |
| CI/CD pipeline | Planned for Phase 2 of production readiness |
| PyPI publication | Planned for a later version release |
| GeoIP enrichment | Optional enhancement; requires external database |
| SIEM integration (Splunk, Elastic) | Enterprise feature deferred to post-MVP |

---

## 5. System Architecture

### 5.1 High-Level Overview

```
Attacker
   │
   ▼ SSH (port 2222)
┌─────────────────────────────────────────────────────────┐
│                    SSH Interface                         │
│              (Paramiko ServerInterface)                  │
│        Any-password auth · PTY negotiation              │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│                  Session Orchestrator                    │
│  Rate Limiter ─ Active Defence ─ TTP Detector           │
│  Honeytoken Monitor ─ Download Capture ─ Metrics        │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│              3-Tier Hybrid Command Engine                │
│                                                          │
│  Tier 1: Virtual Filesystem                              │
│    └─ stat, ls, cat, cp, mv, mkdir, rm, find, chmod …   │
│                                                          │
│  Tier 2: Static Response Cache (cache.json)              │
│    └─ whoami, id, uname, ifconfig, env, …               │
│                                                          │
│  Tier 3: Ollama LLM (Microsoft Phi-3)                   │
│    └─ Any command not handled by Tier 1 or 2            │
│    └─ Session state injected into system prompt          │
│    └─ Response validated and sanitised before return     │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│                   Session Logger                         │
│     Per-session JSON · live_sessions.json stream        │
└──────────────────────┬──────────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
  Prometheus (port 9090)    Streamlit Dashboard (port 8501)
          │
          ▼
  Grafana (port 3000)
```

### 5.2 Module Map

| Module | File | Lines | Responsibility |
|---|---|---|---|
| SSH Interface | `ssh_interface.py` | 298 | Paramiko ServerInterface, authentication, PTY negotiation |
| Server | `server.py` | 1,263 | Session lifecycle, main connection loop, thread management, attacker profiling |
| Command Handler | `command_handler.py` | 2,932 | 3-tier hybrid engine, 300+ pre-seeded file contents |
| AI Interface | `ai_interface.py` | 936 | Ollama/Phi-3 bridge, system prompt injection, prompt injection protection |
| Defense Module | `defense_module.py` | 103 | Keyword threat scoring, tarpit delay calculation |
| TTP Detector | `ttp_detector.py` | 1,701 | MITRE ATT&CK pattern matching, 38 technique IDs, chain detection |
| Honeytokens | `honeytokens.py` | 649 | 10 fake credential types, per-session generation, access detection |
| Filesystem | `filesystem.py` | 635 | Virtual filesystem operations (stat, chmod, chown, find, path normalisation) |
| System State | `system_state.py` | 794 | Realistic ps, top, netstat, ss, free, uptime, w, last, systemctl output |
| TTY Handler | `tty_handler.py` | 544 | Raw TTY input, line editing, command history, tab completion |
| Response Validator | `response_validator.py` | 566 | LLM output sanitisation, anti-hallucination rules |
| Download Capture | `download_capture.py` | 789 | wget, curl, scp, rsync, ftp detection and logging |
| Rate Limiter | `rate_limiter.py` | 302 | Per-IP and global connection limits, IP blocking |
| Metrics | `metrics.py` | 620 | Prometheus metrics exporter (~25 metric types) |
| Session Export | `session_export.py` | 609 | Export sessions as text, JSON, or HTML |
| Config | `config.py` | 255 | Typed configuration dataclasses, environment variable loading |
| Notifications | `notifications.py` | 572 | Real-time alerts via Discord and Telegram webhooks |
| Dashboard | `dashboard/app.py` | 1,995 | Streamlit real-time monitoring dashboard |
| Runner | `run.py` | — | Unified launcher for honeypot + dashboard subprocess |

**Total core package:** ~14,654 lines of Python

### 5.3 Data Flow — Command Processing

```
Raw bytes (SSH channel)
        │
        ▼
   TTY Handler
   (line editing, history, tab completion)
        │
        ▼
   Command Handler
        │
        ├─── Tier 1: Filesystem command? ──► Virtual Filesystem ──► Response
        │
        ├─── Tier 2: Cached command? ──────► cache.json lookup ──► Response
        │
        └─── Tier 3: LLM fallback ─────────►  AI Interface
                                                    │
                                                     ├─ Prompt injection check (88 patterns)
                                                    ├─ System prompt + session state
                                                    ├─ Ollama Phi-3 inference
                                                    └─ Response Validator ──► Response
        │
        ▼ (all paths converge here)
   Security Pipeline
        ├─ TTP Detector   (MITRE ATT&CK mapping)
        ├─ Defense Module (threat scoring + tarpit)
        ├─ Honeytoken Monitor (access detection)
        └─ Download Capture (tool detection)
        │
        ▼
   Session Logger ──► Prometheus Metrics ──► Dashboard
        │
        ▼
   Response sent to attacker via SSH channel
```

---

## 6. Feature Implementation

### 6.1 SSH Server

**Module:** `ssh_interface.py`, `server.py`

The SSH server is built on Paramiko, Python's SSH-2 protocol library. Key implementation details:

- **Authentication**: all username/password combinations are accepted. Rejecting credentials would immediately reveal the honeypot's nature.
- **Host key**: 4096-bit RSA key, generated once and persisted to `data/host.key`. This ensures the host key fingerprint remains consistent across restarts, as a real server's would.
- **PTY emulation**: full pseudo-terminal negotiation (TERM type, dimensions). The attacker's terminal behaves like a real interactive shell.
- **SSH banner**: configurable via `MIRAGEPOT_OS_NAME`, `MIRAGEPOT_OS_VERSION`, and `MIRAGEPOT_KERNEL_VERSION` environment variables. Defaults to Ubuntu 20.04.6 LTS.

### 6.2 Three-Tier Hybrid Command Engine

**Module:** `command_handler.py` (2,932 lines)

The command engine is the core of MiragePot. It processes every command through three tiers in order:

**Tier 1 — Virtual Filesystem**

Handles all commands that interact with the filesystem: `ls`, `cd`, `cat`, `cp`, `mv`, `mkdir`, `rm`, `touch`, `chmod`, `chown`, `find`, `stat`, `pwd`, `ln`, `echo` (redirected), and more. The filesystem is seeded at session start with 250+ realistic files including:

- `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/etc/crontab`
- `/etc/nginx/nginx.conf`, `/etc/mysql/my.cnf`
- `/home/ubuntu/.bash_history`, `/home/ubuntu/.ssh/authorized_keys`
- `/var/log/auth.log`, `/var/log/nginx/access.log`
- `.env` with database credentials (a honeytoken location)
- AWS credential files (`~/.aws/credentials`)

**Tier 2 — Static Response Cache**

A JSON file (`miragepot/cache.json`) maps commonly-used commands to realistic, pre-written responses. This covers commands where speed and consistency are more important than variability: `whoami`, `id`, `uname -a`, `ifconfig`, `ip addr`, `env`, `printenv`, `hostname`, etc.

**Tier 3 — LLM Fallback**

Any command not handled by Tiers 1 or 2 is forwarded to Ollama running Microsoft Phi-3. The LLM system prompt includes:

- The simulated OS identity (hostname, OS name, kernel version)
- The current session state (working directory, active user, recently created files)
- Instructions to respond as a real terminal, not an AI

### 6.3 LLM Integration and Prompt Injection Protection

**Module:** `ai_interface.py` (936 lines)

The AI interface bridges the command handler and Ollama. Key mechanisms:

- **Session state injection**: the working directory, current user, and session-created files are appended to every prompt. This gives the LLM the context it needs to maintain session consistency.
- **Prompt injection protection**: 88 compiled regex patterns (72 direct attack patterns + 16 encoded/obfuscated variants) screen every incoming command before it reaches the LLM. Commands matching these patterns are blocked and a generic "command not found" response is returned.
- **Timeout handling**: if Ollama does not respond within 30 seconds (configurable), the request is cancelled and a safe fallback response is returned. The session is not dropped.

### 6.4 Response Validation

**Module:** `response_validator.py` (566 lines)

LLM outputs are post-processed before being returned to the attacker. The validator:

- Strips any text where the model reveals it is an AI ("As an AI language model…", "I cannot execute real commands…")
- Removes markdown formatting (the attacker's terminal is not a web browser)
- Corrects obviously wrong dates or years
- Enforces length limits
- Ensures the response ends cleanly (no trailing LLM artefacts)

### 6.5 Honeytoken System

**Module:** `honeytokens.py` (649 lines)

Honeytokens are fake credentials and secrets embedded in the virtual filesystem. They are unique per session — generated with realistic formatting at session start. When an attacker reads a file containing a honeytoken, the event is logged, a Prometheus metric is incremented, and a dashboard alert is raised.

| Honeytoken Type | Location | Example Format |
|---|---|---|
| AWS Access Key | `~/.aws/credentials` | `AKIA...` (20-character key) |
| AWS Secret Key | `~/.aws/credentials` | 40-character secret |
| GitHub Personal Access Token | `~/.gitconfig`, `.env` | `ghp_...` format |
| Stripe API Key | `.env` | `sk_live_...` |
| JWT Secret | `.env` | 64-character hex string |
| Database Password | `.env`, `config.php` | Random 24-character string |
| Generic API Key | Various config files | UUID-format string |
| SSH Private Key | `~/.ssh/id_rsa` | RSA private key format |
| Slack Webhook | `.env` | `https://hooks.slack.com/...` |
| SendGrid API Key | `.env` | `SG....` format |

(10 distinct honeytoken types supported)

### 6.6 MITRE ATT&CK TTP Detection

**Module:** `ttp_detector.py` (1,701 lines)

Every command is analysed against a database of 38 MITRE ATT&CK technique IDs:

- **Single-command patterns**: regex-based, each mapped to a specific ATT&CK Technique ID, tactic, and description
- **Multi-command chain patterns**: detect sequences of commands that together constitute a known attack pattern (e.g. discovery followed by lateral movement)

**10 attack stages tracked:**

| Stage | Example Techniques |
|---|---|
| Initial Access | SSH brute-force follow-up commands |
| Discovery | `whoami`, `id`, `uname`, `ps aux`, `netstat` |
| Privilege Escalation | `sudo -l`, SUID binary enumeration, `su root` |
| Credential Access | `/etc/shadow` read, `.ssh` key exfiltration |
| Persistence | Crontab modification, `.bashrc` write, SSH key injection |
| Defence Evasion | Log clearing, history deletion, timestomping |
| Lateral Movement | SSH to other hosts, internal network scanning |
| Collection | File staging, archiving with `tar`, `zip` |
| Exfiltration | `scp`, `rsync`, `curl` to external IPs |
| Command and Control | Reverse shell attempts, netcat, Python shells |

### 6.7 Active Defence

**Module:** `defense_module.py` (103 lines)

The active defence system assigns threat scores to commands based on a keyword database. Commands that match high-severity keywords (e.g. `passwd`, `shadow`, `/etc/cron`, `nc -e`, `chmod 777`) accumulate a threat score for the session. When the session's cumulative score reaches or exceeds 40, artificial delays of 1–5 seconds (tarpit) are inserted before responses. This keeps high-threat attackers engaged longer while slowing down automated attack scripts.

### 6.8 Rate Limiting

**Module:** `rate_limiter.py` (302 lines)

- Maximum 3 concurrent SSH connections from the same IP address
- Maximum 50 total concurrent connections globally
- IPs that exceed the per-IP limit are blocked for 300 seconds (configurable)
- Prevents the honeypot from being overwhelmed by port scanners or brute-force tools

### 6.9 Monitoring and Observability

**Prometheus metrics (`metrics.py`, port 9090):**

Approximately 25 metric types exported, including:
- Total and active connection counts
- Session duration histograms
- Command counts (by tier: filesystem / cache / LLM)
- LLM inference latency histograms
- TTP detection counts (by stage)
- Honeytoken trigger counts (by type)
- Rate limiter block counts
- Prompt injection block counts

**Streamlit dashboard (`dashboard/app.py`, port 8501):**

- **Sessions overview**: all active and recent sessions with connection time, command count, threat score, and detected TTPs
- **Session detail**: full command history with threat-level highlighting and TTP annotations
- **Threat heatmap**: visual breakdown of TTP stages detected across all sessions
- **Honeytoken alerts**: real-time feed of honeytoken access events
- **Session replay**: replay a recorded session at configurable speed

**Grafana dashboards (port 3000):**

| Dashboard | Contents |
|---|---|
| MiragePot Overview | Active sessions, connection rate, top commands, threat score distribution |
| TTP Analysis | ATT&CK stage breakdown, most-detected techniques, chain detection events |
| Performance | LLM inference latency (p50/p95/p99), cache hit rate, error rate |

---

## 7. Technology Stack

| Component | Technology | Version | Justification |
|---|---|---|---|
| Core language | Python | 3.10+ | Mature SSH library (Paramiko) availability; rapid development; strong testing ecosystem |
| SSH protocol | Paramiko | ≥ 3.0.0 | Pure-Python SSH-2 implementation; full server-side support; active maintenance |
| LLM runtime | Ollama | ≥ 0.1.0 | Local-only inference; Docker-native; model management CLI; REST API |
| LLM model | Microsoft Phi-3 | — | Strong instruction-following; fits in ~4 GB RAM; fast inference on CPU |
| Dashboard | Streamlit | ≥ 1.30.0 | Rapid Python-native dashboarding; no separate frontend required |
| Metrics | prometheus-client | ≥ 0.19.0 | Industry-standard metrics format; native Grafana integration |
| Configuration | python-dotenv | ≥ 1.0.0 | Standard `.env` file support; twelve-factor app pattern |
| Containerisation | Docker + Compose | v2.0+ | Reproducible deployment; isolates Ollama, Prometheus, Grafana as separate services |
| Monitoring | Prometheus + Grafana | — | Industry-standard observability stack; pre-built dashboard support |
| Testing | pytest + pytest-cov | ≥ 7.0.0 | Standard Python test framework; coverage reporting |
| Formatting | black | ≥ 23.0.0 | Deterministic, zero-configuration code formatting |
| Linting | ruff | ≥ 0.1.0 | Fast Python linter; enforces code quality |
| Type checking | mypy | ≥ 1.0.0 | Static type verification |
| Pre-commit | pre-commit | ≥ 3.0.0 | Enforces quality checks before every commit |

---

## 8. Testing and Validation

### 8.1 Test Suite

| Test File | Module Tested | Tests |
|---|---|---|
| `test_command_handler.py` | `command_handler.py` | Command routing, tier selection, edge cases |
| `test_defense_module.py` | `defense_module.py` | Keyword scoring, tarpit thresholds |
| `test_download_capture.py` | `download_capture.py` | wget, curl, scp, rsync, ftp detection |
| `test_filesystem.py` | `filesystem.py` | Virtual filesystem operations, path normalisation |
| `test_honeytokens.py` | `honeytokens.py` | Token generation, format validity, access detection |
| `test_rate_limiter.py` | `rate_limiter.py` | Per-IP limits, global limits, IP blocking |
| `test_response_validator.py` | `response_validator.py` | AI self-revelation stripping, markdown removal |
| `test_session_export.py` | `session_export.py` | Text, JSON, HTML export formats |
| `test_ssh_interface.py` | `ssh_interface.py` | Authentication, PTY negotiation |
| `test_system_state.py` | `system_state.py` | ps, top, netstat, systemctl output correctness |
| `test_ttp_detector.py` | `ttp_detector.py` | Pattern matching, chain detection, stage mapping |
| `test_tty_handler.py` | `tty_handler.py` | Line editing, history, tab completion |

**Test counts and pass/fail status depend on the environment and installed dependencies.**

### 8.2 Test Strategy

- **Unit tests**: each module is tested in isolation with mocked dependencies
- **Edge cases**: empty commands, binary input, extremely long commands, Unicode, control characters
- **Security cases**: prompt injection patterns, oversized inputs, path traversal attempts
- **Regression coverage**: all 8 Phase 1 bug fixes are covered by tests to prevent reintroduction

### 8.3 Running the Tests

```bash
# Run full test suite
make test

# Run with coverage report
make test-cov

# Run a specific module's tests
pytest tests/test_ttp_detector.py -v
```

---

## 9. Deployment

### 9.1 Deployment Modes

| Mode | Command | Services | RAM Required |
|---|---|---|---|
| Full Stack (recommended) | `cd docker && docker compose up -d` | honeypot + Ollama + Prometheus + Grafana + Alertmanager | ~5 GB |
| Simple Stack | `docker compose -f docker-compose-simple.yml up -d` | honeypot + Ollama + Streamlit | ~3 GB |
| Local Development | `python run.py` | honeypot + dashboard (Ollama must be started separately) | ~4 GB |

### 9.2 First-Run Experience

1. Clone the repository
2. Copy `.env.docker.example` to `.env.docker` and edit as needed
3. Run `cd docker && docker compose up -d`
4. On first start, the Ollama container automatically downloads the Phi-3 model (~2 GB)
5. Once healthy, connect: `ssh root@localhost -p 2222` (any password)
6. Open dashboard: `http://localhost:8501`
7. Open Grafana: `http://localhost:3000` (admin / admin)

### 9.3 Port Reference

| Port | Service |
|---|---|
| 2222 | SSH honeypot |
| 8501 | Streamlit dashboard |
| 9090 | Prometheus metrics endpoint (honeypot) |
| 9091 | Prometheus UI |
| 9093 | Alertmanager |
| 3000 | Grafana |
| 11434 | Ollama API (internal only) |

### 9.4 Configuration

All configuration is controlled via environment variables with the `MIRAGEPOT_` prefix. Key variables:

| Variable | Default | Description |
|---|---|---|
| `MIRAGEPOT_SSH_PORT` | `2222` | SSH listen port |
| `MIRAGEPOT_LLM_MODEL` | `phi3` | Ollama model name |
| `MIRAGEPOT_LLM_TIMEOUT` | `30` | LLM response timeout (seconds) |
| `MIRAGEPOT_HOSTNAME` | `miragepot` | Simulated server hostname |
| `MIRAGEPOT_OS_NAME` | `Ubuntu` | Simulated OS name |
| `MIRAGEPOT_OS_VERSION` | `20.04.6 LTS` | Simulated OS version |
| `MIRAGEPOT_MAX_CONNECTIONS_PER_IP` | `3` | Rate limit per IP |
| `MIRAGEPOT_MAX_TOTAL_CONNECTIONS` | `50` | Global concurrent session limit |
| `MIRAGEPOT_LOG_PASSWORDS` | `false` | Whether to log attacker passwords |
| `MIRAGEPOT_DASHBOARD_PASSWORD` | (required) | Required password (dashboard refuses to start if unset) |

---

## 10. Known Limitations

The following limitations are documented and acknowledged in v0.2.0:

| Limitation | Impact | Notes |
|---|---|---|
| Left/right cursor movement in TTY | Attacker cannot move the cursor within a typed command | Harmless for typical attack sessions; up/down history works correctly |
| LLM inference latency | Some commands may take up to 30 seconds | Mitigated by Tier 1 and Tier 2 handling the most common commands |
| LLM consistency across long sessions | The LLM may occasionally contradict earlier session output | Mitigated by session state injection into every prompt |
| Single-node only | No clustering or distributed deployment | Sufficient for the MVP threat model |
| No real network topology | The simulated system cannot actually route packets | Consistent with the "no real execution" principle |
| No CHANGELOG.md | Version history is not formally documented yet | Planned for Phase 4 of the production roadmap |

---

## 11. Out of Scope for v0.2.0

The following features were considered and explicitly excluded from the MVP:

- **Real command execution** — violates the core safety boundary; must never be implemented
- **Cloud LLM backends** — would send attacker input to third-party servers
- **Multi-node clustering** — beyond the scope of a single-machine honeypot
- **Windows attacker client emulation** — SSH is a Unix-centric protocol; not part of the MVP threat model
- **CI/CD pipeline** — planned for Phase 2 of the production roadmap
- **PyPI package publication** — planned for a later version release
- **GeoIP enrichment** — optional Grafana enhancement; requires external database download
- **SIEM integration** — enterprise feature, deferred post-MVP
- **Automated threat report generation** — useful but not core to the MVP

---

## 12. Future Roadmap

### 12.1 Immediate Next Steps (Production Readiness)

These phases are planned and partially designed but not yet executed:

| Phase | Description | Status |
|---|---|---|
| Phase 2 | CI/CD pipeline — GitHub Actions for pytest, mypy, ruff on every push; Docker image builds; auto GitHub Release on version tag | Planned |
| Phase 3 | Security hardening — VM firewall rules, Docker resource limits, credential safety review | Planned |
| Phase 4 | Versioning and release — CHANGELOG.md, git tags, consistent version labelling | Planned |
| Phase 5 | Cloud deployment — VM provisioning, `deploy.sh` finalisation, automated backups | Planned |

### 12.2 Feature Roadmap

| Feature | Description | Priority |
|---|---|---|
| Additional LLM backends | Support llama.cpp, vLLM, and OpenAI-compatible APIs | High |
| Additional OS profiles | CentOS, Debian, Alpine Linux personalities | Medium |
| TTY cursor movement | Implement left/right arrow key cursor positioning in `tty_handler.py` | Medium |
| Red team mode | Web-based attack simulation interface to test the honeypot itself | Medium |
| GeoIP enrichment | Enrich attacker IPs with geographic data; Grafana worldmap panel | Medium |
| Automated threat reports | Generate PDF/HTML reports from session data | Low |
| SIEM integration | Export to Splunk, Elastic via syslog/CEF | Low |
| PyPI publication | `pip install miragepot` | Low |

---

## 13. Summary

MiragePot v0.2.0 is a complete, functional, and deployable AI-driven SSH honeypot. The MVP delivers on every core success criterion: any attacker connecting on port 2222 receives believable, AI-generated responses; all activity is logged, TTP-mapped, and surfaced in a real-time monitoring dashboard; the entire system deploys with a single `docker compose up -d` command.

The project demonstrates practical expertise across three domains:

- **Cybersecurity**: honeypot architecture, MITRE ATT&CK mapping, honeytoken design, active defence, prompt injection protection
- **Network programming**: SSH-2 protocol (Paramiko), PTY emulation, raw TTY handling, rate limiting
- **Applied AI**: local LLM inference (Ollama/Phi-3), system prompt engineering, response validation, prompt injection defence

The codebase is well-structured (18 modules, ~14,654 lines), includes a substantial unit test suite, and is fully documented. v0.2.0 is the foundation for subsequent production-readiness phases that will add CI/CD, security hardening, and formal versioning.

---

*MiragePot — AI-Driven Adaptive SSH Honeypot*  
*Version 0.2.0 | B.Tech Computer Science and Engineering, Semester 6*  
*Mar Athanasius College of Engineering, Kothamangalam*  
*Evin Brijesh | 2026*
