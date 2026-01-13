# MiragePot User Manual

## Overview

MiragePot is an AI-driven SSH honeypot that simulates a Linux shell
using a local language model. It is intended as a B.Tech 6th semester
CS mini-project and should be run in an isolated environment.

## Components

- backend/server.py: SSH honeypot server
- backend/command_handler.py: command parsing and fake filesystem
- backend/ai_interface.py: interface to local Ollama LLM
- backend/defense_module.py: active defense and tarpit logic
- dashboard/app.py: Streamlit dashboard for viewing logs

## Running the System

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Ensure Ollama is installed, running, and the `phi3` model is pulled.

3. Start the honeypot backend:

```bash
python backend/server.py
```

4. Start the dashboard in another terminal:

```bash
streamlit run dashboard/app.py
```

5. Connect via SSH from a separate terminal or machine:

```bash
ssh root@127.0.0.1 -p 2222
```

Any username/password will be accepted.

## Logs

Per-session JSON logs are stored in `data/logs/` and consumed by the
dashboard for analysis.
