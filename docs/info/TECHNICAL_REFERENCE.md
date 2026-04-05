# MiragePot Technical Reference

This document is the “one place” reference for MiragePot’s runtime model: config, data layout, ports, and the major processing pipelines.

## Package vs Runtime Data

MiragePot deliberately separates packaged, read-only assets from runtime-generated data.

Packaged assets (ship with the Python package):

- `miragepot/cache.json` (static response cache)
- `miragepot/system_prompt.txt` (LLM system prompt template, supports `{hostname}` substitution)

Runtime data (generated while running; persisted under `data/` by default):

- `data/logs/` session logs (`session_*.json`) and `live_sessions.json`
- `data/profiles/` attacker profiles (JSON)
- `data/host.key` SSH host key (default; configurable via env)

Key constants:

- `miragepot/config.py`: `MIRAGEPOT_DIR` (package dir), `DATA_DIR` (runtime dir)
- `miragepot/command_handler.py`: `CACHE_PATH = MIRAGEPOT_DIR / "cache.json"`
- `miragepot/ai_interface.py`: `SYSTEM_PROMPT_PATH = MIRAGEPOT_DIR / "system_prompt.txt"`

## Ports

Default ports (local + Docker):

- `2222/tcp`: SSH honeypot
- `8501/tcp`: Streamlit dashboard
- `9090/tcp`: Prometheus metrics endpoint (`/metrics`)
- `9091/tcp`: Prometheus UI (full Docker stack)
- `3000/tcp`: Grafana UI (full Docker stack)
- `9093/tcp`: Alertmanager UI (full Docker stack)
- `11434/tcp`: Ollama API (typically internal Docker network)

## Configuration (Environment Variables)

Config is loaded from env into dataclasses in `miragepot/config.py`.

Common:

- `MIRAGEPOT_SSH_HOST` / `MIRAGEPOT_SSH_PORT`
- `MIRAGEPOT_HOST_KEY` (path to SSH host key; default `data/host.key`)
- `MIRAGEPOT_LLM_MODEL`, `MIRAGEPOT_LLM_TIMEOUT`, `MIRAGEPOT_LLM_TEMPERATURE`, `MIRAGEPOT_LLM_MAX_TOKENS`
- `MIRAGEPOT_HOSTNAME`, `MIRAGEPOT_OS_NAME`, `MIRAGEPOT_OS_VERSION`, `MIRAGEPOT_KERNEL_VERSION`
- `MIRAGEPOT_DASHBOARD_PASSWORD` (required; dashboard refuses to start if unset)

Notifications:

- `MIRAGEPOT_NOTIFICATIONS_ENABLED`
- `MIRAGEPOT_DISCORD_WEBHOOK_URL`
- `MIRAGEPOT_TELEGRAM_BOT_TOKEN`, `MIRAGEPOT_TELEGRAM_CHAT_ID`
- `MIRAGEPOT_NOTIFY_MIN_RISK`
- `MIRAGEPOT_NOTIFY_SESSION_END`, `MIRAGEPOT_NOTIFY_REALTIME`
- `MIRAGEPOT_NOTIFY_HONEYTOKENS_ACCESS`, `MIRAGEPOT_NOTIFY_HONEYTOKENS_EXFIL`
- `MIRAGEPOT_NOTIFY_INCLUDE_JSON`, `MIRAGEPOT_NOTIFY_INCLUDE_SUMMARY`
- `MIRAGEPOT_NOTIFY_RATE_LIMIT`

## End-to-End Command Processing Pipeline

At a high level (see `miragepot/server.py` + `miragepot/command_handler.py`):

1. SSH connection accepted (Paramiko server interface).
2. Session state initialized (`init_session_state()`), including:
   - in-memory filesystem structures
   - TTP tracking state
   - honeytoken set
   - simulated system state
   - tier usage counters (`filesystem`, `cache`, `llm`)
3. Each attacker input line is processed:
   - threat score calculated + optional tarpit delay
   - command handled via the hybrid engine:
     - Tier 1: built-in filesystem/system commands
     - Tier 2: static cache lookup (`miragepot/cache.json`)
     - Tier 3: LLM fallback (Ollama) + response validation
   - security pipeline updates (TTP mapping, honeytoken access/exfil detection, download attempt capture)
   - metrics emitted
4. On session end:
   - session log written to `data/logs/session_*.json`
   - attacker profile generated and saved to `data/profiles/`
   - optional notifications sent (session end summary / high-risk events)

## LLM System Prompt

- The system prompt is loaded from `miragepot/system_prompt.txt`.
- `{hostname}` placeholders are replaced at load time using `MIRAGEPOT_HOSTNAME`.

## Docker Notes

- `docker/Dockerfile` copies `miragepot/cache.json` and `miragepot/system_prompt.txt` into the image.
- `docker/docker-compose.yml` persists logs and profiles via bind mounts.
