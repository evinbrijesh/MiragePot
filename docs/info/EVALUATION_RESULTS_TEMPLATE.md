# MiragePot Evaluation Results Template

Use this file as the canonical structure for the paper’s Evaluation section.

## 1) Experiment Summary

- Commit hash: `<fill>`
- Date range: `<fill>`
- Environment ID: `<fill>`
- Model used: `<fill>`
- Number of sessions: `<fill>`

## 2) Dataset / Scenario Breakdown

| Scenario ID | Type | Sessions | Description |
|---|---|---:|---|
| S1 | Benign baseline | `<n>` | `<fill>` |
| S2 | Recon-heavy attack | `<n>` | `<fill>` |
| S3 | Credential abuse | `<n>` | `<fill>` |
| S4 | Persistence/exfiltration | `<n>` | `<fill>` |
| S5 | Mixed/noisy | `<n>` | `<fill>` |

## 3) Detection Results (RQ2)

### 3.1 TTP Detection

| Metric | Value |
|---|---:|
| Precision | `<fill>` |
| Recall | `<fill>` |
| F1-score | `<fill>` |

### 3.2 Threat Classification

| Class | Precision | Recall | F1 |
|---|---:|---:|---:|
| Low | `<fill>` | `<fill>` | `<fill>` |
| Medium | `<fill>` | `<fill>` | `<fill>` |
| High | `<fill>` | `<fill>` | `<fill>` |
| Critical (if used) | `<fill>` | `<fill>` | `<fill>` |

## 4) Realism Results (RQ1)

| Metric | Value | Notes |
|---|---:|---|
| Human realism score (1–5) | `<fill>` | `<fill>` |
| Continuity consistency (%) | `<fill>` | `<fill>` |
| Obvious artifact rate (%) | `<fill>` | `<fill>` |

## 5) Performance Results (RQ3)

### 5.1 Latency

| Metric | C1 (default) | C2 (LLM-reduced) | C3 (alt config) |
|---|---:|---:|---:|
| Command latency P50 (ms) | `<fill>` | `<fill>` | `<fill>` |
| Command latency P95 (ms) | `<fill>` | `<fill>` | `<fill>` |
| LLM latency P50 (ms) | `<fill>` | `<fill>` | `<fill>` |
| LLM latency P95 (ms) | `<fill>` | `<fill>` | `<fill>` |

### 5.2 Reliability

| Metric | Value |
|---|---:|
| LLM success rate (%) | `<fill>` |
| LLM timeout rate (%) | `<fill>` |
| LLM error rate (%) | `<fill>` |
| Cache hit ratio (%) | `<fill>` |

### 5.3 Resource Use

| Resource | Mean | P95 | Max |
|---|---:|---:|---:|
| CPU (%) | `<fill>` | `<fill>` | `<fill>` |
| RAM (MB) | `<fill>` | `<fill>` | `<fill>` |
| Disk I/O (MB/s) | `<fill>` | `<fill>` | `<fill>` |

## 6) Operational Utility (RQ4)

| Metric | Value | Method |
|---|---:|---|
| Time-to-triage (min) | `<fill>` | analyst task timing |
| Alert precision (%) | `<fill>` | true alerts / total alerts |
| Analyst usefulness score (1–5) | `<fill>` | survey/rubric |

## 7) Statistical Testing

- Test used: `<fill>`
- Significance threshold: `<fill>`
- Effect size metric: `<fill>`
- Key statistically significant findings: `<fill>`

## 8) Key Findings (Paper-Ready)

1. `<fill>`
2. `<fill>`
3. `<fill>`

## 9) Figure/Table Mapping

| Paper Figure/Table | Source Data | Script/Query |
|---|---|---|
| Fig. 1 | `<fill>` | `<fill>` |
| Fig. 2 | `<fill>` | `<fill>` |
| Table 1 | `<fill>` | `<fill>` |
