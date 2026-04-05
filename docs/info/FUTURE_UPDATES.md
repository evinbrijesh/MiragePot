# MiragePot Future Updates & Roadmap

This document tracks planned features, enhancements, and architectural improvements for MiragePot.

**Current Version**: 0.2.0

---

## Completed Features (v0.2.0)

### ✅ Core Honeypot
- SSH server with Paramiko (RFC 4253 compliant)
- AI response generation with Ollama (Phi-3 model)
- Three-tier hybrid command engine:
  - Tier 1: Virtual filesystem with 50+ built-in handlers
  - Tier 2: Static response cache (`miragepot/cache.json`, 60+ entries)
  - Tier 3: LLM fallback for novel commands (10s timeout)
- Streamlit dashboard with authentication gate
- Session logging to JSON (`data/logs/session_*.json`)

### ✅ Threat Detection & Intelligence
- MITRE ATT&CK TTP detection (146 patterns across 12 tactics)
- Honeytoken system (7 credential types: AWS keys, SSH keys, API tokens, etc.)
- Threat scoring with configurable tarpit delays
- Download/exfiltration attempt capture (wget, curl, scp patterns)
- Prompt injection protection (direct + encoded patterns)

### ✅ Real-Time Notification System
**Implemented**: v0.2.0 (March 2026)

Full notification system for security team alerting:

- **Discord webhooks**: Rich embeds with color-coded risk levels, JSON session attachments
- **Telegram Bot API**: Markdown formatting, document uploads
- **Rate limiting**: Token bucket algorithm (default 10/minute) prevents spam
- **Risk-based filtering**: Only notify on configured minimum risk level
- **Event types supported**:
  - Session-end summaries (full TTP analysis, honeytoken activity, command history)
  - High-threat command alerts (score >= 80)
  - Honeytoken access alerts
  - Exfiltration attempt alerts

**Configuration** (environment variables):
```bash
MIRAGEPOT_NOTIFICATIONS_ENABLED=true
MIRAGEPOT_DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
MIRAGEPOT_TELEGRAM_BOT_TOKEN=...
MIRAGEPOT_TELEGRAM_CHAT_ID=...
MIRAGEPOT_NOTIFY_MIN_RISK=medium  # low, medium, high, critical
MIRAGEPOT_NOTIFY_SESSION_END=true
MIRAGEPOT_NOTIFY_REALTIME=true
MIRAGEPOT_NOTIFY_HONEYTOKENS_ACCESS=true
MIRAGEPOT_NOTIFY_HONEYTOKENS_EXFIL=true
MIRAGEPOT_NOTIFY_INCLUDE_JSON=true
MIRAGEPOT_NOTIFY_RATE_LIMIT=10
```

**Documentation**: See `docs/info/NOTIFICATIONS.md` for complete setup guide.

### ✅ Attacker Profiling System
**Implemented**: v0.2.0 (March 2026)

- Automatic skill-level estimation based on session behavior
- Tier usage tracking (filesystem vs cache vs LLM responses)
- Profile JSON saved to `data/profiles/` per session
- Dashboard integration for viewing profiles

### ✅ Observability Stack
- Prometheus metrics endpoint (`/metrics` on port 9090)
- 20+ metric types (connections, commands, LLM latency, TTPs, notifications)
- Pre-built Grafana dashboards
- Alertmanager integration (Docker full stack)

### ✅ Deployment Options
- Local Python installation
- Docker simple stack (honeypot + Ollama)
- Docker full stack (honeypot + Ollama + Prometheus + Grafana + Alertmanager)
- Offline deployment bundle (~6-7 GB) for air-gapped environments

---

## High Priority: Future Features

### Threat Intelligence Integration
**Status**: Planned  
**Priority**: High  
**Estimated Effort**: 1-2 weeks

Integrate with external threat intelligence feeds to automatically enrich session logs:

- **AbuseIPDB**: IP reputation scores, abuse confidence percentage
- **GreyNoise**: Identify mass scanners vs targeted attacks
- **Shodan**: Historical data on attacker IPs
- Automatic geographic threat data (country, ASN, ISP)
- Known botnet membership detection

**Value**: Distinguish targeted human attacks from automated scanning without manual lookup.

### Multi-Model LLM Support
**Status**: Planned  
**Priority**: High  
**Estimated Effort**: 1 week

Dynamic model selection based on command type:

- Route code execution attempts to code-specialized models (CodeLlama, DeepSeek Coder)
- Route general shell interactions to general-purpose models (Phi-3, Mistral)
- Configurable model routing rules
- Fallback chain if primary model unavailable

**Value**: Improved response realism across different attacker behaviors.

### Automated MITRE ATT&CK Reporting
**Status**: Planned  
**Priority**: High  
**Estimated Effort**: 3-5 days

Generate structured ATT&CK Navigator layer files:

- Per-session `.json` layer files for ATT&CK Navigator
- Aggregated layers across multiple sessions
- Export to STIX 2.1 format for threat intel platforms
- Integration with SIEM/SOAR tools

**Value**: Seamless integration with enterprise SOC workflows.

---

## Medium Priority: Future Features

### Attacker Fingerprinting and Clustering
**Status**: Planned  
**Priority**: Medium  
**Estimated Effort**: 2-3 weeks

Apply machine learning to accumulated session logs:

- Automatically group sessions by behavioral similarity
- Distinguish automated scanners from skilled human operators
- Identify coordinated campaigns from multiple source IPs
- Track recurring attacker profiles over time
- Clustering algorithms: DBSCAN, hierarchical clustering on command sequences

**Value**: Threat hunting and campaign attribution.

### Dynamic Filesystem Content Generation
**Status**: Planned  
**Priority**: Medium  
**Estimated Effort**: 2 weeks

LLM-generated file contents on demand:

- Plausible source code files (Python, PHP, config files)
- Web application configurations with realistic credentials
- Database dump files tailored to attacker's apparent target
- Dynamic `/var/log/` entries that reference attacker activity

**Value**: Extended engagement duration, harder to distinguish from real servers.

### Enhanced Notification Channels
**Status**: Planned  
**Priority**: Medium  
**Estimated Effort**: 1 week

Expand notification platform support:

- Slack webhook integration
- Microsoft Teams webhook integration
- Email (SMTP) support
- PagerDuty integration for on-call alerting
- Generic webhook (custom endpoint)

---

## Low Priority: Future Features

### Multi-Protocol Honeypot Support
**Status**: Concept  
**Priority**: Low  
**Estimated Effort**: 3-4 weeks per protocol

Extend beyond SSH to additional protocols:

- HTTP/HTTPS honeypot module (fake web apps, login pages)
- FTP honeypot module
- Telnet honeypot module
- LDAP honeypot module
- SMB honeypot module

Each with LLM-backed response generation and unified logging.

**Value**: Comprehensive view of multi-vector attack campaigns.

### Post-Quantum SSH Compatibility
**Status**: Concept  
**Priority**: Low  
**Estimated Effort**: 1 week

Modern SSH clients advertise post-quantum key exchange algorithms:

- Handle PQ key exchange gracefully (no warnings/fallback messages)
- Support hybrid classical+PQ modes
- Maintain deception integrity as cryptographic landscape evolves

### Cloud-Native Deployment
**Status**: Concept  
**Priority**: Low  
**Estimated Effort**: 2-3 weeks

Production-ready cloud deployment:

- Kubernetes manifests (Helm chart)
- Terraform configurations for AWS/GCP/Azure
- Multi-region honeypot deployment
- Centralized log aggregation (Loki, Elasticsearch)
- Global threat intelligence collection

**Value**: Geographically distributed threat intelligence at scale.

### Machine Learning Attack Classification
**Status**: Concept  
**Priority**: Low  
**Estimated Effort**: 4-6 weeks

- Train ML model on labeled attack patterns
- Real-time attacker skill level classification
- Anomaly detection for zero-day techniques
- Behavioral prediction (next likely command)

---

## Rejected Features

### ❌ Real Command Execution
**Reason**: Security risk — honeypot must remain isolated. No attacker command is ever executed on the host.  
**Date**: Project inception

### ❌ Cryptocurrency Mining Detection
**Reason**: Out of scope — focus on SSH attack patterns, not post-exploitation payloads.  
**Date**: 2026-03-15

### ❌ Cloud-Based LLM (OpenAI, Anthropic)
**Reason**: Privacy and security — attacker input must never leave the local network. All inference is local-only via Ollama.  
**Date**: Project inception

---

## Feature Request Template

When proposing new features, include:

```markdown
### Feature Name
**Status**: Proposed  
**Priority**: High/Medium/Low  
**Estimated Effort**: X days/weeks  
**Proposed By**: Name (Date)

#### Problem Statement
What problem does this solve?

#### Proposed Solution
How should it work?

#### Technical Approach
Implementation details

#### Success Metrics
How do we measure success?

#### Dependencies
What else needs to be done first?
```

---

**Last Updated**: 2026-04-05  
**Version**: 0.2.0  
**Maintainer**: Evin Brijesh
