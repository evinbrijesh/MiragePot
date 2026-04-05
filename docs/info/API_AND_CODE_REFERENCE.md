# MiragePot API and Code Reference

This document is a developer-facing index of MiragePot’s main modules and their roles. It is intentionally concise and points you to the right files.

## CLI

- `miragepot/__main__.py`
  - CLI entry point: start server, start dashboard, sessions subcommands
  - Commands: `miragepot sessions list|show|export|replay`

## Core Runtime

- `miragepot/server.py`
  - Session lifecycle orchestration
  - Live sessions tracking (`data/logs/live_sessions.json`)
  - Session log persistence (`data/logs/session_*.json`)
  - Attacker profile generation + persistence (`data/profiles/`)
  - Optional notifications integration

- `miragepot/ssh_interface.py`
  - Paramiko `ServerInterface` implementation
  - Auth attempt capture + SSH fingerprint extraction
  - Host key creation/loading

- `miragepot/command_handler.py`
  - Hybrid engine entry point (`handle_command`)
  - `init_session_state` + virtual filesystem seeding
  - Prompt injection screening
  - Cache tier (`miragepot/cache.json`)
  - LLM fallback integration (`ai_interface.query_llm`)

- `miragepot/ai_interface.py`
  - Ollama connectivity checks + model verification
  - System prompt loading (`miragepot/system_prompt.txt`)
  - Prompt building + query execution
  - In-session LLM cache

## Security + Intelligence

- `miragepot/defense_module.py`
  - Threat scoring + tarpit delay

- `miragepot/ttp_detector.py`
  - MITRE ATT&CK mapping and session-level summaries

- `miragepot/honeytokens.py`
  - Honeytoken generation
  - Access + exfiltration detection

- `miragepot/download_capture.py`
  - Detects and logs download/exfil attempts without executing them

- `miragepot/rate_limiter.py`
  - Per-IP and global connection limiting

## Observability

- `miragepot/metrics.py`
  - Prometheus metrics collector and HTTP exporter

- `miragepot/notifications.py`
  - `NotificationManager` orchestrates Discord/Telegram delivery
  - Rate limiting + JSON session log attachment support

## Dashboard

- `dashboard/app.py`
  - Streamlit dashboard
  - Auth gate via `MIRAGEPOT_DASHBOARD_PASSWORD`
  - Reads session logs from `data/logs/` and profiles from `data/profiles/`
