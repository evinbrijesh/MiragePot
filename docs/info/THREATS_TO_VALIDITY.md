# MiragePot Threats to Validity

This document captures internal, external, construct, and conclusion validity risks for the MiragePot research paper.

## 1) Internal Validity

Potential confounders in observed outcomes:

- **Model warm-up effects:** first-run Ollama/model load can inflate early latency.
- **Cache-state bias:** prior runs may improve cache-hit metrics and lower latency.
- **Scenario scripting bias:** handcrafted attacker scripts can overfit detector patterns.
- **Environment drift:** background processes and host contention affect performance.

Mitigations:

- Discard warm-up runs or report separately.
- Reset cache and state between runs where required.
- Mix scripted and semi-randomized command sequences.
- Pin environment and collect host telemetry.

## 2) External Validity

Generalization limits:

- **Attack population mismatch:** lab traffic may not represent internet-scale adversaries.
- **Protocol scope:** results focus on SSH honeypot behavior; may not transfer to other protocols.
- **Model dependence:** findings may differ across LLM models/hardware.

Mitigations:

- Include internet-exposed pilot observations if ethically approved.
- Clearly scope claims to SSH and tested model configurations.
- Report model and hardware details for all experiments.

## 3) Construct Validity

Risk of measuring the wrong thing:

- **Realism proxies:** latency or textual variety alone does not fully represent human believability.
- **Detection metrics:** high TTP counts do not guarantee analyst usefulness.
- **Alert quality:** raw alert volume can be misleading without precision/recall context.

Mitigations:

- Combine automated metrics with blinded human ratings.
- Evaluate analyst task completion time and correctness.
- Report precision/recall and false-positive cost.

## 4) Conclusion Validity

Inference risks:

- **Small sample size:** insufficient sessions may produce unstable estimates.
- **Non-independent samples:** repeated command templates can reduce effective sample diversity.
- **Multiple comparisons:** many metrics increase false discovery risk.

Mitigations:

- Use adequate run counts per scenario (`N >= 10`, preferably higher).
- Ensure varied command/session generation.
- Apply corrected significance procedures where applicable.

## 5) Ethical and Operational Validity

- Honeypots can capture sensitive attacker-supplied data.
- Legal constraints vary by jurisdiction and deployment environment.
- Public deployment without isolation can create unintended risk.

Mitigations:

- Use isolated environments and strict access control.
- Redact identifiable data before sharing artifacts.
- Include legal/ethics statement in the paper.

## 6) Recommended Paper Wording

Use constrained claims:

- “Within our SSH-focused evaluation environment…”
- “Results are model- and configuration-dependent…”
- “Further validation on internet-scale traffic is future work…”
