# MiragePot – AI-Driven Adaptive SSH Honeypot

MiragePot is a B.Tech-level mini-project that implements an SSH honeypot
which feels like a real Linux shell. Instead of executing real commands
on the host, it simulates a terminal by combining cached responses for
common commands with AI-generated output from a local LLM (Phi-3 via
Ollama).

## Features

- SSH server on port 2222 using Paramiko
- Accepts any username/password
- Hybrid command engine:
  - Fast cache for common commands (`ls`, `pwd`, `whoami`, `uname -a`, etc.)
  - AI fallback via Ollama for other commands
- In-memory fake filesystem per session (cwd, mkdir, cd, ls, touch, cat, rm)
- Basic active defense with threat scoring and tarpit delays
- Per-session JSON logs in `data/logs/`
- Streamlit dashboard to visualize attacker sessions

## Quick Start (Backend + Dashboard Together)

```bash
git clone https://github.com/<your-username>/MiragePot.git
cd MiragePot

python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

pip install -r requirements.txt

ollama pull phi3
ollama serve

python run.py
```

- SSH honeypot: `ssh root@127.0.0.1 -p 2222` (any password)
- Dashboard: open the URL printed by Streamlit (default `http://localhost:8501`)

## Running Components Manually

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Install and run Ollama, and pull the `phi3` model:

```bash
ollama pull phi3
ollama serve
```

3. Start the backend honeypot:

```bash
python backend/server.py
```

4. In a separate terminal, start the dashboard:

```bash
streamlit run dashboard/app.py
```

5. Connect via SSH from another terminal or machine:

```bash
ssh root@127.0.0.1 -p 2222
```

Any username/password combination will be accepted.

## Security Notes

- Run MiragePot only in an isolated environment (VM, lab network).
- It is meant for research and demonstration, not production defense.
- The honeypot does **not** execute real dangerous commands; everything
  is simulated and responses are generated logically or via an LLM.
