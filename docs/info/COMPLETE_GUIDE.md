# MiragePot Complete Guide

This guide is the practical, end-to-end “how to run MiragePot” reference: local runs, Docker runs, demos, offline use, and common operational workflows.

## What MiragePot Is

MiragePot is an AI-driven SSH honeypot that emulates an interactive Linux shell without executing attacker commands on the host OS. It combines:

- An SSH server (Paramiko) that accepts credentials to maximize engagement.
- A hybrid command engine (virtual filesystem + static cache + local LLM fallback).
- A security/observability pipeline (threat scoring, MITRE ATT&CK mapping, honeytokens, download attempt capture, Prometheus metrics).
- A Streamlit dashboard for forensic review, plus optional Prometheus/Grafana stack in Docker.

## Quick Start (Local)

1. Install MiragePot in a virtualenv:

```bash
python -m venv venv
source venv/bin/activate
pip install -e .
```

2. Start Ollama (optional but recommended) and ensure your model exists:

```bash
ollama serve &
ollama pull phi3
```

3. Set required dashboard password (dashboard refuses to start if unset):

```bash
export MIRAGEPOT_DASHBOARD_PASSWORD='set-a-strong-password'
```

4. Run both backend + dashboard:

```bash
python run.py
```

5. Connect as an “attacker”:

```bash
ssh root@127.0.0.1 -p 2222
```

6. Open dashboard:

- http://localhost:8501

## Quick Start (Docker)

### Full Stack (Docker folder)

Runs: MiragePot + Ollama + Prometheus + Grafana + Alertmanager (+ Discord adapter).

```bash
cp .env.docker.example .env.docker
edit .env.docker  # set MIRAGEPOT_DASHBOARD_PASSWORD at minimum

cd docker
docker compose up -d
```

Key URLs (default bindings):

- SSH honeypot: `ssh root@localhost -p 2222`
- Streamlit dashboard: http://localhost:8501 (localhost only by default)
- Metrics endpoint: http://localhost:9090/metrics (localhost only by default)
- Prometheus UI: http://localhost:9091
- Grafana: http://localhost:3000

### Simple Stack (Repo root)

Runs: MiragePot + Ollama (dashboard is included in the MiragePot container).

```bash
cp .env.docker.example .env.docker
edit .env.docker  # set MIRAGEPOT_DASHBOARD_PASSWORD at minimum

docker compose -f docker-compose-simple.yml up -d
```

## Data, Paths, and Persistence

MiragePot splits “static assets shipped with the package” from “runtime data generated while running”:

- Packaged static assets (inside the Python package):
  - `miragepot/cache.json`
  - `miragepot/system_prompt.txt`
- Runtime data directory (default under repo root):
  - `data/logs/` (session logs + `live_sessions.json`)
  - `data/profiles/` (attacker profile JSON)
  - `data/host.key` (SSH host key, configurable)

In Docker, `docker/Dockerfile` copies the packaged assets into the image at `./miragepot/`.

## Required Security Setting: Dashboard Password

The Streamlit dashboard is an analyst UI over sensitive session data. It now refuses to start unless `MIRAGEPOT_DASHBOARD_PASSWORD` is set.

- Local run: export `MIRAGEPOT_DASHBOARD_PASSWORD` in your shell.
- Docker run: set it in `.env.docker`.

## Demo Workflows

### Demo: Generate Sample Data (No Live Attacker Needed)

Use the sample generator to populate realistic session logs and attacker profiles for the dashboard.

```bash
python scripts/generate_sample_data.py
```

### Demo: Simulated Attacker Session

```bash
python scripts/demo_session.py
```

### Demo: Cold Start (Makefile)

If your repo includes the demo target:

```bash
make demo
```

## Notifications (Discord/Telegram)

MiragePot can send real-time notifications for high-risk activity.

- Configure via env vars (see `docs/info/NOTIFICATIONS.md`).
- Implementation lives in `miragepot/notifications.py`.

## Common Operations

### List/Export Sessions from CLI

```bash
miragepot sessions list
miragepot sessions show <session_id_prefix>
miragepot sessions export <session_id_prefix> --format json
miragepot sessions replay <session_id_prefix>
```

### Where to Look for Outputs

- Session logs: `data/logs/session_*.json`
- Live dashboard stream: `data/logs/live_sessions.json`
- Attacker profiles: `data/profiles/session_*_*.json`

## Troubleshooting

Start with `docs/TROUBLESHOOTING.md`.

If the dashboard immediately exits, the most common cause is missing `MIRAGEPOT_DASHBOARD_PASSWORD`.
