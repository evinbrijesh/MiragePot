# MiragePot Reproducibility Checklist

Use this checklist before submission to ensure another researcher can reproduce your results.

## 1) Version Pinning

- [ ] MiragePot git commit hash recorded
- [ ] Branch name recorded
- [ ] `pyproject.toml` dependency versions captured
- [ ] Docker image tags/digests captured
- [ ] Ollama version captured
- [ ] Model name and tag captured (e.g., `phi3`)

## 2) Environment Snapshot

- [ ] Host OS + kernel recorded
- [ ] CPU/RAM/disk specs recorded
- [ ] Docker + Compose versions recorded
- [ ] Network topology documented (isolated/local/public)

## 3) Configuration Snapshot

- [ ] `.env.docker` values archived (with secrets redacted)
- [ ] `MIRAGEPOT_DASHBOARD_PASSWORD` set and documented as required
- [ ] Any non-default limits/thresholds documented
- [ ] Model/runtime knobs (timeout, temperature, max tokens) documented

## 4) Data and Artifacts

- [ ] Raw session logs archived (`data/logs/session_*.json`)
- [ ] Attacker profiles archived (`data/profiles/*.json`)
- [ ] Metrics snapshots exported (Prometheus queries/raw scrape where used)
- [ ] Figure/table source data archived
- [ ] Derived datasets clearly separated from raw data

## 5) Procedure Reproducibility

- [ ] Exact deployment command(s) listed
- [ ] Exact workload-generation steps listed
- [ ] Run order and warm-up policy documented
- [ ] Number of repetitions per scenario documented
- [ ] Post-processing pipeline documented

## 6) Evaluation Reproducibility

- [ ] Metric formulas explicitly defined
- [ ] Ground-truth labeling method explained
- [ ] Statistical methods and thresholds declared
- [ ] Outlier handling policy declared

## 7) Security/Ethics Reproducibility

- [ ] Isolation and containment controls documented
- [ ] Data-retention and redaction policy documented
- [ ] Legal/ethical constraints statement included

## 8) Packaging for Artifact Release

- [ ] `docs/info/RESEARCH_METHODOLOGY.md` finalized
- [ ] `docs/info/EVALUATION_RESULTS_TEMPLATE.md` populated with final numbers
- [ ] `docs/info/THREATS_TO_VALIDITY.md` aligned with actual experiments
- [ ] README for artifacts includes “how to rerun” in <= 15 steps

## 9) Minimal Reproduction Script (Suggested)

At minimum, include the following command sequence in your paper appendix/artifact README:

1. Clone repository at exact commit hash
2. Copy `.env.docker.example` to `.env.docker` and apply documented values
3. Start full stack (`docker/docker-compose.yml`)
4. Confirm health for all services
5. Run workload scenarios (documented scripts/commands)
6. Export session logs and metric snapshots
7. Execute analysis notebook/script to regenerate tables and figures
