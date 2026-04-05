# MiragePot Internals

This document focuses on implementation internals: how MiragePot represents session state, how commands are routed, how safety/anti-fingerprinting measures work, and how attacker profiling is derived.

## Session State (In-Memory)

MiragePot maintains a per-connection `session_state` dict created by `miragepot/command_handler.py:init_session_state()`.

Core state elements (high-level):

- `cwd`: current working directory
- virtual filesystem:
  - `directories`: set of absolute directory paths
  - `files`: mapping of absolute file path -> file content
  - `file_metadata`: mapping of absolute file path -> metadata (mode/owner/timestamps)
- `system_state`: simulated system identity and command outputs (e.g. `ps`, `ss`, `uptime`)
- `ttp_state`: MITRE ATT&CK detection state for the session
- `honeytokens`: generated per-session honeytoken set + trigger tracking
- `tier_usage`: counters tracking how each command was served: `filesystem`, `cache`, `llm`

Nothing here touches the real host filesystem, except for writing session logs/profiles at session end.

## Hybrid Command Engine

Entry point: `miragepot/command_handler.py:handle_command(command, session_state) -> str`.

Routing behavior:

1. Input hardening and normalization:
   - command length cap (`MAX_COMMAND_LENGTH = 4096`)
   - path normalization and traversal prevention for filesystem operations
   - prompt-injection screening (direct and encoded patterns)
2. Tier 1: built-ins / virtual filesystem / simulated system commands.
3. Tier 2: static cache lookup (`miragepot/cache.json`) for common commands.
4. Tier 3: LLM fallback (`miragepot/ai_interface.py:query_llm`) + response validation.

Tier usage is incremented in session state and later included in attacker profiling.

## Prompt Injection Guard

`miragepot/command_handler.py` contains two pattern sets:

- `INJECTION_PATTERNS`: direct prompt-injection phrases and control attempts.
- `ENCODED_INJECTION_PATTERNS`: base64/hex/url-encoded indicators and common obfuscations.

At runtime, MiragePot normalizes attacker input (including Unicode normalization and whitespace normalization) and scans against compiled regex lists.

## LLM Bridge + Response Validation

`miragepot/ai_interface.py`:

- Loads system prompt from `miragepot/system_prompt.txt` (packaged asset).
- Substitutes `{hostname}` from `MIRAGEPOT_HOSTNAME`.
- Implements an in-session LLM response cache to avoid repeated inference for identical `(command, cwd)` within a session.
- Records metrics for latency and error paths.

After inference, responses are sanitized/validated to reduce obvious model artifacts.

## Timing Side-Channel Mitigation

LLM responses are much slower than cache/builtins. `miragepot/server.py` introduces a minimum delay + jitter for all responses (baseline 50ms, with jitter) to reduce the “fast vs slow path” fingerprint.

## Attacker Profiling

At session end, `miragepot/server.py`:

- Generates a session summary (TTP stages, honeytoken hits, download attempts).
- Computes a basic skill-level estimate using session behavior and tier usage ratios.
- Saves a JSON profile under `data/profiles/`.

The dashboard reads these profile JSON files directly to render the “Session Profiles” view.

## Dashboard Authentication Gate

`dashboard/app.py` requires `MIRAGEPOT_DASHBOARD_PASSWORD` to be set and uses constant-time comparison for password checks.

Operational implication: any docs or deployment examples that omit `MIRAGEPOT_DASHBOARD_PASSWORD` will result in the dashboard refusing to start.
