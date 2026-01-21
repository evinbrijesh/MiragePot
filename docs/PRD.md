# MiragePot Product Requirements Document (PRD)

**Product:** MiragePot (AI-driven adaptive SSH honeypot)

**Owner:** Project Maintainers

**Last updated:** 2026-01-21

## 1) Problem Statement

Commodity SSH attacks are constant (credential stuffing, recon, payload drops). Traditional honeypots are either too static (easy to fingerprint) or too risky/complex (accidentally executing attacker commands). Security teams need a safe, believable, low-friction SSH deception system that keeps attackers engaged and produces actionable telemetry.

MiragePot simulates an SSH-accessible Linux environment and responds to attacker commands using a hybrid engine (deterministic simulation + cached responses + local LLM fallback). It never executes attacker commands on the host.

## 2) Goals

- Provide a believable interactive SSH shell that accepts connections and keeps attackers engaged.
- Collect high-quality forensic data (commands, timing, fingerprints, download attempts, TTPs) with minimal operator setup.
- Minimize risk: no real command execution; run safely on a host/VM with configurable boundaries.
- Offer a usable dashboard for analysts to monitor sessions and quickly triage activity.
- Work offline or in restricted environments by using a local LLM via Ollama.

## 3) Non-Goals

- Full system emulation (kernel behaviors, real package installs, real networking).
- Exploit development sandboxing or malware detonation.
- Production hardening for internet-wide exposure without additional isolation controls.
- Perfect fidelity of every Linux distribution and every CLI tool output.

## 4) Target Users and Use Cases

### Personas

- Security analyst / SOC: monitors sessions, tags/highlights interesting activity, exports evidence.
- Detection engineer / threat hunter: uses logs to extract IOCs and attack sequences, maps to MITRE.
- Researcher / educator: demonstrates attacker behavior and common tactics in a controlled lab.

### Primary Use Cases

- Observe SSH intrusion behavior without risking the host.
- Collect command transcripts and attacker fingerprinting for later analysis.
- Identify payload download attempts and likely objectives (recon, lateral movement, exfiltration).
- Measure attacker dwell time and toolchains; export sessions for reporting.

## 5) Success Metrics

- Engagement: median session length and number of commands per session.
- Coverage: percentage of commands answered without obvious breakage (error loops, repeated "command not found").
- Telemetry quality: completeness of session logs (timestamped commands, response, threat score, fingerprint, downloads, TTPs).
- Analyst utility: time-to-triage (can an analyst find the top risky sessions quickly).
- Safety: zero instances of attacker input executed on the host.

## 6) Product Principles

- Safety first: simulated outputs only.
- Believability: outputs should look like a real Linux system (consistent users, paths, prompts).
- Determinism where it matters: filesystem and stateful commands should be consistent.
- Defense-in-depth: prompt-injection detection and response validation to keep the LLM "in character".
- Analyst-friendly: logs are structured; dashboard surfaces what matters.

## 7) Scope (What the Product Must Do)

### 7.1 SSH Honeypot Core

- Accept SSH connections and authenticate any username/password.
- Maintain per-session state (current directory, fake filesystem, terminal state).
- Provide a realistic shell prompt and interactive typing behavior (basic line editing, history, tab completion, control keys).
- Support multiple concurrent sessions.
- Capture SSH client fingerprint metadata (client version and negotiated algorithms) for each session.

### 7.2 Command Response Engine

- Parse and route commands.
- Provide fast responses via cached outputs for common commands.
- Provide deterministic simulation for filesystem and system-state commands (e.g., `ls`, `cat`, `ps`, `ss`).
- Fall back to local LLM (via Ollama) for unknown commands while keeping responses realistic.
- Maintain realism constraints (no chatbot-y phrasing, no policy disclosures).

### 7.3 Safety and Defensive Controls

- Never execute attacker-supplied commands on the host.
- Detect prompt injection attempts (including encoded variants) and block or neutralize them.
- Assign a threat score for each command and apply optional tarpit delays for higher risk activity.
- Detect MITRE ATT&CK techniques and maintain an attack-stage progression per session.

### 7.4 Telemetry and Logging

- Write a structured JSON session log per connection.
- Log every command with timestamp, response (or response metadata), threat score, and delays.
- Detect and log download attempts (wget/curl/scp/etc.) with parsed URLs and destinations.
- Track and log honeytoken accesses (decoy secrets, fake credentials, etc.).

### 7.5 Dashboard (Analyst UX)

- List sessions and provide drill-down into command timeline and key metadata.
- Provide live/active sessions visibility.
- Provide search/filtering and basic analytics (risk, TTPs, downloads, fingerprints).
- Support analyst tagging for sessions and persist tags.
- Provide export/replay options for reports and post-incident analysis.

## 8) Requirements

### 8.1 Functional Requirements

- FR-001: SSH server listens on configurable host/port.
- FR-002: Any credentials accepted; record provided username/password.
- FR-003: Per-session state is isolated; one session cannot affect another.
- FR-004: Built-in simulated commands support core navigation and discovery (`pwd`, `cd`, `ls`, `cat`, `find`, etc.).
- FR-005: System-state simulation supports common recon commands (`ps`, `top`, `uname`, `ss`, etc.).
- FR-006: Cached responses exist for common commands and are used when available.
- FR-007: LLM fallback generates outputs that resemble Linux command output.
- FR-008: Prompt injection attempts are detected and do not alter the system prompt or behavior.
- FR-009: Each command is assigned a threat score and optional delay.
- FR-010: Download attempts are detected, simulated, and logged.
- FR-011: TTPs are detected and summarized per session.
- FR-012: Dashboard displays sessions, per-session details, and live activity.
- FR-013: Session tags can be created/updated and persisted.
- FR-014: Sessions can be exported (at least transcript + structured JSON).

### 8.2 Non-Functional Requirements

- NFR-001: Safety: no execution on host; no reading arbitrary host files.
- NFR-002: Local-first: supports offline operation with Ollama; degrade gracefully when LLM unavailable.
- NFR-003: Performance: cached/deterministic commands should return quickly; LLM latency is acceptable but should not hang the session.
- NFR-004: Reliability: server should not crash on malformed input; per-session errors should be contained.
- NFR-005: Observability: log errors and startup checks; provide clear operator guidance when dependencies are missing.
- NFR-006: Portability: runs on Linux with Python 3.10+; minimal external services (Ollama optional but recommended).

## 9) User Stories

- As an analyst, I want to see active sessions and high-risk sessions first so I can triage quickly.
- As an analyst, I want to tag sessions ("botnet", "hands-on-keyboard") so I can cluster activity.
- As a threat hunter, I want to export a full session transcript and JSON so I can attach evidence.
- As an operator, I want to run MiragePot in a lab with a single command and minimal configuration.
- As a researcher, I want responses to remain consistent across commands (filesystem state does not reset mid-session).

## 10) Out of Scope for v1 (Candidate Backlog)

- SFTP/interactive file uploads (beyond detection/logging).
- Emulating additional services (HTTP, RDP) in the same product.
- Advanced VM-based "real execution" sandbox mode.
- Multi-node deployment and centralized fleet management.

## 11) Risks and Mitigations

- LLM prompt leakage / jailbreaks: mitigate with injection detection + response validation + strict system prompt.
- Fingerprinting: static banners and repeated output patterns can reduce believability; mitigate with variability and stateful simulation.
- Operator misconfiguration: exposing on the public internet without isolation; mitigate with explicit docs and warnings.
- Resource usage: LLM calls can be slow; mitigate with caching, timeouts, and graceful fallback responses.

## 12) Dependencies and Constraints

- Python 3.10+
- Paramiko (SSH)
- Ollama (optional but recommended) and a local model (e.g., Phi-3)
- Streamlit dashboard

## 13) Acceptance Criteria (Release Readiness)

- Can connect via SSH and interact with a stable prompt.
- Common recon and filesystem commands behave realistically and consistently.
- Unknown commands produce plausible output via LLM fallback (or a safe fallback if LLM offline).
- Logs are written per session and include: timestamps, commands, threat scores, SSH fingerprint metadata, download detection, and TTP summary.
- Dashboard loads and supports: session list, session drill-down, live activity, tagging, basic analytics.
- No attacker input is executed on the host; test suite passes.

## 14) References

- `README.md`
- `docs/MVP_BASELINE.md`
- `docs/architecture.md`
- `docs/USAGE.md`
