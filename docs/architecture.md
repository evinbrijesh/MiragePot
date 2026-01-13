# MiragePot Architecture and Design

## 1. High-Level Overview

MiragePot is an AI-driven SSH honeypot that emulates a Linux shell without
executing any real system commands on the host. The main idea is to lure
attackers into interacting with what appears to be a real Linux server,
while all command processing is safely simulated and heavily logged.

The architecture is split into three logical layers:

1. **Honeypot Backend (SSH + Command Engine)**  
   Accepts SSH connections, parses user commands, maintains a fake
   filesystem, and returns simulated terminal output.

2. **AI Integration Layer**  
   Uses a local Large Language Model (Phi-3 via Ollama) to generate
   realistic command output when no static or simulated response is
   available.

3. **Monitoring & Visualization Layer**  
   Stores per-session forensic logs and exposes them via a Streamlit
   dashboard for analysis and demonstration.

This separation keeps the design modular, easier to reason about, and
safer to operate in a lab environment.

---

## 2. Module-Level Architecture

### 2.1 `backend/server.py` – SSH Honeypot Orchestrator

**Responsibilities:**

- Starts a Paramiko-based SSH server on TCP port `2222`.
- Uses a persistent host key from `data/host.key` to appear as a stable
  SSH host across restarts.
- Handles incoming SSH connections and spawns a command-processing loop
  for each client.

**Workflow:**

1. **Startup**
   - Loads or generates the RSA host key via `ssh_interface.get_or_create_host_key()`.
   - Creates a listening socket via `ssh_interface.create_listening_socket()`.
   - Waits for incoming TCP connections on `0.0.0.0:2222`.

2. **Session Initialization**
   - For each new client, wraps the socket in a `paramiko.Transport`.
   - Uses `SSHServer` (from `ssh_interface.py`) as the `ServerInterface`.
   - Accepts any username/password (because this is a honeypot, not a
     secure SSH server).
   - Creates a new `session_state` using
     `command_handler.init_session_state()` to track a fake filesystem
     and working directory.
   - Initializes an in-memory `session_log` structure which will hold
     all commands and responses for that session.

3. **Command Loop**
   - Reads bytes from the SSH channel, decodes them as UTF-8, and
     accumulates into a line buffer.
   - On each newline / carriage return, extracts a full command line:
     - Strips whitespace.
     - Skips empty commands (just reprints the shell prompt).
   - Passes the command through the active defense layer:
     - Calls `defense_module.calculate_threat_score(command)`.
     - Calls `defense_module.apply_tarpit(score)` to optionally sleep
       based on the risk score.
   - Delegates the actual command handling to
     `command_handler.handle_command(command, session_state)`.
   - Sends the resulting response text back to the SSH client.
   - Appends a log entry to the in-memory `session_log`:
     - Timestamp
     - Command
     - Response
     - Threat score
     - Delay applied (seconds)
   - If the response is a special token (`"__MIRAGEPOT_EXIT__"`), the
     server sends a `logout` message, closes the SSH channel, and ends
     the session loop.

4. **Session Finalization**
   - On session end (client disconnect, error, or exit), writes
     `session_log` as pretty-printed JSON to
     `data/logs/session_<id>.json`.
   - Closes the transport and underlying socket, and waits for the next
     connection.

This module is the central orchestrator that ties together SSH
transport, command processing, active defense, and logging.

---

### 2.2 `backend/ssh_interface.py` – SSH Transport Layer

**Responsibilities:**

- Encapsulate Paramiko configuration and server behavior.
- Provide a simple API for the main server module to use.

**Key Components:**

- **`get_or_create_host_key()`**  
  - Tries to load `data/host.key` as an RSA private key.  
  - If missing or invalid, generates a new 2048-bit RSA key and writes
    it to `data/host.key`.  
  - This gives the honeypot a persistent SSH fingerprint which feels
    more realistic to attackers.

- **`SSHServer` (extends `paramiko.ServerInterface`)**
  - `check_auth_password`: always returns `paramiko.AUTH_SUCCESSFUL`,
    meaning any username/password is accepted.  
  - `check_channel_request`: allows only `"session"` channels.  
  - `check_channel_pty_request`: always grants PTY requests so the
    client feels like it has a real interactive shell.  
  - `check_channel_shell_request`: always accepts shell requests.

- **`create_listening_socket(host, port)`**  
  - Creates a TCP socket, sets `SO_REUSEADDR`, binds to the specified
    host/port, and starts listening.  
  - Used by `server.py` to accept incoming SSH connections.

By encapsulating Paramiko details here, the rest of the code can focus
on higher-level honeypot logic.

---

### 2.3 `backend/command_handler.py` – Hybrid Command Engine & Fake Filesystem

**Responsibilities:**

- Provide a single entry point: `handle_command(command, session_state)
  -> str`.
- Implement a hybrid processing strategy with three tiers:
  1. Built-in fake filesystem commands.
  2. Static cache responses (fast path).
  3. AI-backed responses (LLM) for everything else.

**Session State Design:**

For each SSH connection, `session_state` is a dictionary:

```python
{
    "cwd": "/root",                 # current working directory
    "directories": {"/", "/root"},  # fake directories (absolute paths)
    "files": {                        # fake files (absolute path -> content)
        "/root/notes.txt": "hello\nworld\n",
        # ...
    },
}
```

This state is stored in memory only and is never written to the real
filesystem.

**Built-in Commands (Simulated Only):**

- `pwd` – returns the current fake working directory (`cwd`).
- `cd <dir>` – normalizes and changes `cwd`; any visited directory is
  automatically added to the `directories` set to make navigation
  smoother.
- `mkdir <dir1> [dir2 ...]` – adds new directories to `directories` and
  returns errors if they already exist.
- `ls [path]` – lists children directories and files known under the
  target path based on `directories` and `files`.
- `touch <file1> [file2 ...]` – creates empty fake files (or updates
  their "mtime" conceptually).
- `cat <file1> [file2 ...]` – prints the content of fake files from the
  `files` dict, or `No such file or directory` if missing.
- `rm <name1> [name2 ...]` – removes files from `files`, and removes
  empty directories from `directories`. If a directory contains children
  it returns `Is a directory`, mimicking real `rm` behavior.
- `echo TEXT > file` and `echo TEXT >> file` – very simple redirection
  parser that writes or appends content to fake files.

All of these operations are carefully limited to in-memory structures so
no real files or directories are touched.

**Cache Fast Path (`data/cache.json`):**

Some common and low-risk commands are answered from a static JSON file
for speed and realism, for example:

- `whoami` → `root`
- `uname -a` → fake kernel string
- `id` → fake UID/GID

If an incoming command matches a key in `CACHE`, the cached value is
returned immediately, without involving the LLM.

**AI Fallback:**

If a command is not a built-in and not in the cache, the handler calls:

```python
query_llm(cmd, session_state)
```

from `ai_interface.py`. The LLM receives both the raw command and a
summary of the fake filesystem state, and is instructed to respond with
terminal-style output.

**Special Session Commands:**

- `exit` / `logout` – do not directly print output; instead they return
  a special token `"__MIRAGEPOT_EXIT__"` which signals `server.py` to
  cleanly close the SSH session.

---

### 2.4 `backend/ai_interface.py` – LLM Bridge (Ollama + Phi-3)

**Responsibilities:**

- Provide a thin abstraction over the Ollama API so that the rest of the
  code does not depend on Ollama-specific details.

**Key Functions:**

- `_load_system_prompt()`
  - Reads `data/system_prompt.txt` which defines how the model should
    behave (Ubuntu shell, no AI/self-references, short outputs, etc.).
  - If the file is missing or empty, falls back to a minimal hard-coded
    prompt and logs an error instead of crashing.

- `build_user_prompt(command, session_state)`
  - Serializes a subset of the `session_state` into JSON:
    - `cwd`, `directories`, and `files` (paths and contents).
  - Builds a text prompt that includes:
    - "Session state summary (JSON): ..."  
    - "User command: <command>"  
    - Instructions to output only what a real terminal would print.

- `query_llm(command, session_state)`
  - Calls `ollama.chat(model="phi3", messages=[...])` with the system
    and user prompts.
  - Extracts the `content` from the response and ensures a trailing
    newline so it looks like terminal output.
  - On any exception (e.g., Ollama not running), returns a generic shell
    error like `bash: internal emulation error` to avoid breaking the
    honeypot.

This module makes it easy to switch models or change prompts later
without impacting the core honeypot logic.

---

### 2.5 `backend/defense_module.py` – Active Defense & Tarpit

**Responsibilities:**

- Provide a simple but extensible framework for evaluating the risk of
  each command and slowing down obviously malicious behavior.

**Threat Scoring (`THREAT_KEYWORDS`):**

A dictionary of substrings to numeric scores. Examples:

- **Low / benign**
  - `"ls"`, `"pwd"`, `"whoami"`, `"id"` → small scores (5).

- **Medium / privilege and account changes**
  - `"sudo"`, `"chmod"`, `"chown"`, `"useradd"`, `"adduser"`,
    `"passwd"`, `"ssh"`, `"rsync"` → moderate scores.

- **High / recon and scanning tools**
  - `"wget"`, `"curl"`, `"scp"`, `"nc "`, `"netcat"`, `"nmap"`,
    `"masscan"`, `"telnet"` → high scores indicating networking,
    lateral movement, or reconnaissance.

- **Critical / destructive & persistence techniques**
  - `"rm -rf"`, `"mkfs"`, `"fdisk"`, `"dd "`, fork bombs (`":(){:|:&};:"`),
    and reverse shell patterns (`"bash -i"`, `"python -c"`, etc.).

The score is **additive**: a single command that contains multiple
suspicious keywords will accumulate multiple scores, resulting in a
higher total risk value.

**Functions:**

- `calculate_threat_score(command: str) -> int`
  - Lowercases the command.
  - Iterates over `THREAT_KEYWORDS` and sums values for all matches.
  - Returns an integer risk score.

- `compute_delay(score: int) -> float`
  - Maps a risk score to a time delay:
    - `score < 40`: no delay.
    - `40 <= score < 80`: ~1–2 seconds.
    - `80 <= score < 120`: ~2–4 seconds.
    - `score >= 120`: ~3–5 seconds.

- `apply_tarpit(score: int) -> float`
  - Calls `compute_delay(score)` to get a delay.
  - If delay > 0, sleeps for that amount of time.
  - Returns the actual delay applied (for logging and dashboard
    display).

This simple active defense mechanism introduces a realistic
"sluggishness" when attackers run clearly malicious commands, giving
defenders more time to observe and potentially react.

---

### 2.6 `dashboard/app.py` – Forensic Dashboard (Streamlit)

**Responsibilities:**

- Provide an easy-to-use web interface for viewing and analyzing attacker
  activity recorded by the honeypot.

**Data Source:**

- JSON files in `data/logs/`, one per session.
- Each file contains:
  - `session_id`
  - `attacker_ip`
  - `login_time`
  - `commands`: list of entries with timestamp, command, response,
    threat_score, and delay_applied.

**UI Features:**

1. **Sessions Overview Table**
   - Displays a list of all sessions with key fields:
     - Session ID
     - Attacker IP
     - Login time
     - Number of commands

2. **Session Detail View**
   - Users select a session from a dropdown.
   - For the selected session, a timeline is shown where each entry
     includes:
     - Timestamp
     - The command that was executed
     - The simulated/LLM output (shown in a text area)
     - Threat score and delay (with color-coded risk indicator)

3. **Threat Highlighting**
   - Threat scores are translated into simple colors:
     - Green: low
     - Yellow: medium
     - Red: high/critical
   - This quickly draws attention to the most dangerous actions in a
     session.

This dashboard is especially useful for demonstration to faculty and for
understanding attacker behavior over time.

---

### 2.7 `run.py` – Unified Runner

**Responsibilities:**

- Provide a single starting point to launch both the honeypot backend
  and the dashboard from one command.

**Behavior:**

- Uses Python's `subprocess.Popen` to start:
  - `python backend/server.py`
  - `streamlit run dashboard/app.py`
- Prints helpful messages indicating:
  - How to connect to the SSH honeypot
  - Where to access the dashboard in the browser
- Waits for the dashboard process to exit, and on `Ctrl+C`:
  - Gracefully terminates both the backend and dashboard processes.
  - Ensures no orphaned processes remain.

This greatly simplifies usage for anyone who clones the repository: they
only need to install dependencies, start Ollama, and run `python run.py`.

---

## 3. Data Flow and Logging

### 3.1 Command Flow

1. Attacker connects via SSH to port `2222`.
2. Paramiko (`ssh_interface.py` and `server.py`) accept the connection.
3. `server.py` initializes `session_state` and `session_log`.
4. For each command entered by the attacker:
   - The command is read from the SSH channel.
   - A threat score and tarpit delay are computed and applied.
   - `command_handler.handle_command()` is called.
   - The resulting output is sent back over SSH.
   - The command and response are appended to `session_log`.
5. On session end, `session_log` is written as JSON to `data/logs/`.

### 3.2 Security Flow

- Every command is inspected for suspicious patterns using the keyword
  map in `defense_module.py`.
- Potentially destructive or reconnaissance-related commands incur a
  higher score and therefore a longer delay before response.
- This delay can slow down automated tools and provide early warning of
  malicious behavior.

### 3.3 Logging Flow

- All data needed for forensic analysis and demonstration is stored in
  JSON:
  - Session metadata: ID, IP, login time.
  - Per-command records: command, response, threat_score,
    delay_applied, and timestamp.
- The dashboard reads these files and presents them in a human-friendly
  GUI for review.

---

## 4. Security Considerations by Design

- **No real shell execution:**  
  Commands are never executed on the real operating system. All logic
  runs inside Python and uses in-memory data structures or the local LLM
  for output.

- **Fake filesystem only:**  
  The project simulates `cd`, `ls`, `mkdir`, `touch`, `cat`, and `rm`
  using Python sets and dictionaries. No real files are created,
  modified, or deleted.

- **Local LLM usage:**  
  All AI queries are directed to a local Ollama instance running on the
  same machine. This allows the honeypot to function offline and avoids
  sending potentially sensitive attacker data to external cloud
  services.

- **Isolated deployment recommended:**  
  MiragePot is designed for educational and research use. It should be
  deployed in a virtual machine or isolated test network. The
  documentation strongly advises against running it directly on
  production servers.

- **Authentication always succeeds:**  
  Authentication is intentionally permissive to capture as many
  interactions as possible. This is appropriate for a honeypot but would
  not be acceptable for a real SSH server.

---

## 5. Summary

MiragePot combines classic honeypot design with modern generative AI
techniques. The architecture emphasizes:

- **Modularity** – clear separation of SSH transport, command handling,
  AI integration, and visualization.
- **Safety** – no real command execution or filesystem modification.
- **Observability** – detailed per-session logging and a dashboard for
  replaying attacker actions.

This makes it a suitable and instructive project for a B.Tech
6th-semester Computer Science mini-project, demonstrating practical
concepts in cybersecurity, network protocols, and applied AI.
