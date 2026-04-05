# How MiragePot Works

## What is MiragePot?

MiragePot is an **AI-driven adaptive SSH honeypot**. It pretends to be a real Ubuntu 20.04 server, accepts SSH connections from potential attackers, and uses a local LLM (Microsoft Phi-3 via Ollama) to generate believable terminal responses — all without running any real commands. Its goal is to trap, study, and log attacker behavior.

---

## How a Connection Works (End-to-End Flow)

```
Attacker SSH connects on port 2222
        ↓
Rate Limiter checks IP (rate_limiter.py)
  → too many connections? Block IP temporarily
        ↓
SSH Handshake via Paramiko (ssh_interface.py)
  → accepts ANY username/password (auth always succeeds)
  → rejects public key auth (forces password attempts for intel)
  → captures SSH fingerprint (client version, ciphers, KEX algos)
        ↓
Session spawned in new thread (server.py)
  → fake filesystem seeded with per-session honeytokens
  → PTY allocated (tty_handler.py for readline emulation)
        ↓
Attacker types commands in the fake shell
        ↓
Command Handler processes each command (command_handler.py)
  1. Prompt injection detection (safety guard)
  2. Check JSON cache (miragepot/cache.json) → fast pre-baked response
  3. If cache miss → send to Ollama LLM (ai_interface.py) → LLM generates response
  4. If LLM unavailable → static fallback response
  5. Response validated (response_validator.py)
        ↓
In parallel:
  - Defense Module scores threat level, applies tarpit delay (defense_module.py)
  - TTP Detector maps command to MITRE ATT&CK stage (ttp_detector.py)
  - Download Capture flags wget/curl attempts (download_capture.py)
  - Honeytokens tracks if attacker accessed fake credentials (honeytokens.py)
  - Metrics updated (metrics.py → Prometheus on port 9090)
        ↓
Response sent back to attacker
        ↓
Session ends → full JSON log written to data/logs/ and attacker profile written to data/profiles/
```

---

## Core Modules Explained

### `server.py` — The Heart
Runs the SSH server, listens on port 2222, spawns a new thread per connection. Manages session lifecycle start-to-finish and writes the final JSON log when a session ends.

### `ssh_interface.py` — The Doorman
A Paramiko `ServerInterface` subclass. Overrides `check_auth_password` to **always return `AUTH_SUCCESSFUL`** — meaning any attacker can get in. This is intentional: you want them inside so you can observe their behavior.

### `command_handler.py` — The Brain
The hybrid command engine. Has 154 fake filesystem files embedded directly (realistic `/etc/passwd`, nginx configs, AWS credential files, `.env` files, fake bash history, logs, etc.). For each command:
1. Checks a JSON cache first (instant, no LLM cost)
2. Falls back to the LLM for novel commands
3. Falls back to static strings if LLM is down

### `ai_interface.py` — The Actor
Wraps Ollama (Phi-3 model). Sends a system prompt telling the LLM to act as a real Ubuntu server, then feeds it the attacker's command. Cleans/validates the response so it doesn't look fake.

### `ttp_detector.py` — The Analyst
Maps every command to a **MITRE ATT&CK tactic** (Reconnaissance, Credential Access, Persistence, Privilege Escalation, Defense Evasion, Lateral Movement, Exfiltration, Impact). Tracks which stages the attacker has hit and calculates an overall risk level.

### `honeytokens.py` — The Trap
Generates per-session fake secrets: AWS keys, Stripe keys, GitHub tokens, JWT secrets, DB passwords. These are embedded in the fake filesystem (e.g., in `.env` files, `~/.aws/credentials`). If an attacker reads these files or tries to use the tokens, it's logged as a high-risk indicator.

### `defense_module.py` — The Slowdown
Scores each command based on threat keywords. Higher-scoring commands get an artificial **tarpit delay** (1–5 seconds) before responding — slowing down automated attack scripts.

### `rate_limiter.py` — The Bouncer
Limits connections per IP and total concurrent connections. Temporarily blocks IPs that exceed thresholds.

### `metrics.py` — The Reporter
Exposes Prometheus metrics (connection count, commands processed, threat scores, etc.) on port 9090. Used by Grafana for real-time dashboards.

### `dashboard/app.py` — The Window
A Streamlit web UI on port 8501 showing live session data, attacker IPs, commands run, TTP stages hit, and honeytoken accesses.

---

## The Fake Filesystem

The honeypot presents a fully believable Ubuntu filesystem. Key fake files that are seeded per-session:

| Path | What it contains |
|------|-----------------|
| `/etc/passwd`, `/etc/shadow` | Realistic user accounts |
| `~/.aws/credentials` | Fake AWS keys (honeytokens) |
| `~/.env` / `/var/www/.env` | Fake DB passwords, Stripe/GitHub tokens |
| `/etc/nginx/nginx.conf` | Realistic nginx config |
| `~/.bash_history` | Pre-seeded command history to look lived-in |
| `/var/log/auth.log` | Fake auth logs |
| `/proc/version`, `/etc/os-release` | Ubuntu 20.04 identity strings |

---

## Data Flow Summary

```
Attacker commands → command_handler
                         ↓
               [cache.json hit?] ──yes──→ cached response
                         ↓ no
               [Ollama/phi3 LLM] ──→ generated response
                         ↓ (if LLM down)
               [static fallback]
                         ↓
               response_validator (anti-hallucination)
                         ↓
               defense_module (threat score + delay)
               ttp_detector (MITRE ATT&CK mapping)
               honeytokens (access tracking)
               download_capture (wget/curl detection)
                         ↓
               response sent to attacker
                         ↓
               metrics.py (Prometheus)
               session log (data/logs/*.json)
               live_sessions.json (dashboard)
```

---

## Deployment

| Mode | How |
|------|-----|
| Local dev | `python run.py` (starts honeypot + dashboard) |
| Simple Docker | `docker-compose-simple.yml` (honeypot + Ollama + Streamlit) |
| Full Stack | `docker/docker-compose.yml` (+ Prometheus + Grafana + Alertmanager) |

---

## Port Reference

| Port | Service |
|------|---------|
| 2222 | SSH honeypot (what attackers connect to) |
| 8501 | Streamlit monitoring dashboard |
| 9090 | Prometheus metrics |
| 3000 | Grafana dashboards (full Docker only) |
| 11434 | Ollama LLM (internal) |

---

In short: an attacker SSH's in, thinks they're on a real server, runs commands, gets realistic responses generated by an LLM, and everything they do is silently logged, classified against MITRE ATT&CK, and tracked for honeytoken usage — all while the real system is completely untouched.
