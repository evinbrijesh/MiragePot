# MiragePot Research Methodology

This document defines a paper-ready methodology for evaluating MiragePot.

## 1) Research Questions

- **RQ1 (Realism):** Does MiragePot maintain interactive realism during attacker sessions?
- **RQ2 (Detection):** How accurately does MiragePot detect and map attacker behavior to MITRE ATT&CK techniques?
- **RQ3 (Performance):** What is the runtime overhead (latency, resource usage) under realistic load?
- **RQ4 (Operational value):** Does MiragePot provide actionable telemetry for defenders?

## 2) System Under Study

- Honeypot: MiragePot SSH service (`miragepot/server.py`)
- Response engine: Filesystem + cache + LLM fallback (`miragepot/command_handler.py`, `miragepot/ai_interface.py`)
- Detection: TTP detector + threat scoring (`miragepot/ttp_detector.py`)
- Observability: Prometheus/Grafana + Streamlit dashboard (`miragepot/metrics.py`, `dashboard/app.py`)

## 3) Experimental Environment

Record exactly for reproducibility:

- Host OS: `<fill>`
- CPU / RAM / Storage: `<fill>`
- Docker version: `<fill>`
- Ollama version: `<fill>`
- MiragePot commit hash: `<fill>`
- Model: `phi3` (or `<fill if changed>`)
- Deployment mode: Full stack (`docker/docker-compose.yml`) unless otherwise stated

## 4) Study Design

### 4.1 Workload Types

Use three traffic classes:

1. **Benign baseline sessions**
   - Non-malicious admin-like command sequences
2. **Scripted attacker sessions**
   - Recon, credential access, persistence, exfiltration patterns
3. **Mixed/noisy sessions**
   - Interleaving benign and malicious commands

### 4.2 Session Generation

- Manual sessions via SSH for realism spot checks
- Scripted sessions for repeatable measurement
- Optional pre-generated sample logs only for UI demos (not main evaluation evidence)

### 4.3 Experimental Conditions (Ablation)

Run each scenario under:

- **C1:** Full MiragePot default config
- **C2:** LLM-disabled / fallback-heavy mode (cache/static emphasis)
- **C3:** Reduced security filters (only if safe and isolated)

Repeat each condition for `N >= 10` runs per scenario.

## 5) Metrics and Definitions

### 5.1 Detection Quality

- TTP precision / recall / F1
- Threat level classification accuracy
- Honeytoken detection rate

Ground truth should be created from known scripted attack steps.

### 5.2 Response Realism

- Human evaluator realism score (Likert 1–5)
- Session continuity consistency (cwd/files/user context stability)
- Obvious honeypot artifact rate

### 5.3 Performance

- P50 / P95 command response latency
- LLM request success/timeout/error rates
- Cache hit ratio
- CPU, memory, disk, and container-level overhead

### 5.4 Operational Utility

- Time-to-triage from dashboard/metrics
- Analyst usefulness score for logs and dashboards
- Alert signal-to-noise ratio

## 6) Data Collection Plan

Collect from:

- `data/logs/session_*.json`
- `data/profiles/*.json`
- Prometheus metrics snapshots (`/metrics`, query exports)
- Optional evaluator scoring sheets

Store immutable raw data per run with timestamp and scenario ID.

## 7) Analysis Plan

- Aggregate by scenario and condition
- Report mean, std, median, P95 where relevant
- Use non-parametric tests if distributions are skewed
- Include confidence intervals for key outcomes

## 8) Ethics and Safety

- Run in isolated lab network only
- No real malware execution on production assets
- No offensive use; defensive research intent only
- Redact sensitive data before publication

## 9) Deliverables for Paper

- Experimental setup table
- Metric definition table
- Results tables/figures per RQ
- Threats-to-validity section linked to `THREATS_TO_VALIDITY.md`
- Reproducibility appendix linked to `REPRODUCIBILITY_CHECKLIST.md`
