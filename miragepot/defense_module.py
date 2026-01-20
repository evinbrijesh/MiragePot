"""Defense module for MiragePot.

Provides basic active defense capabilities:
- Keyword-based threat scoring for SSH commands.
- Decision logic for whether to delay (tarpit) a response.
- Delay application with randomized sleep, used to slow down attackers.

This is intentionally simple and rule-based for a teaching/demo project.
"""

from __future__ import annotations

import random
import time


# Simple keyword-based scoring. In a real system, this might be
# data-driven or configurable via external rules.
THREAT_KEYWORDS = {
    # Low / benign commands
    "ls": 5,
    "pwd": 5,
    "whoami": 5,
    "id": 5,
    # Medium risk / privilege changes
    "sudo": 30,
    "chmod": 25,
    "chown": 25,
    "useradd": 25,
    "adduser": 25,
    "passwd": 25,
    "ssh": 25,
    "rsync": 40,
    # High risk network / recon tools
    "wget": 60,
    "curl": 60,
    "scp": 60,
    "nc ": 70,
    "ncat": 70,
    "netcat": 70,
    "nmap": 70,
    "masscan": 80,
    "telnet": 40,
    # Reverse shells / interpreters
    "bash -i": 90,
    "sh -i": 90,
    "python -c": 80,
    "perl -e": 80,
    "php -r": 80,
    # Critical / destructive
    "rm -rf": 120,
    "mkfs": 100,
    "dd ": 90,
    "mkfs.": 100,
    "fdisk": 100,
    ":(){:|:&};:": 150,
}


def calculate_threat_score(command: str) -> int:
    """Return a basic threat score based on command content.

    The score is additive across all matching substrings in THREAT_KEYWORDS.
    """
    cmd_lower = command.lower()
    score = 0
    for keyword, value in THREAT_KEYWORDS.items():
        if keyword in cmd_lower:
            score += value
    return score


def should_delay(score: int) -> bool:
    """Return True if a response should be delayed based on the score."""
    return score >= 40


def compute_delay(score: int) -> float:
    """Compute a delay duration based on the threat score.

    - score < 40:  no delay
    - 40-79:      random 1-2 seconds
    - 80-119:     random 2-4 seconds
    - >=120:      random 3-5 seconds
    """
    if score < 40:
        return 0.0
    if score < 80:
        return random.uniform(1.0, 2.0)
    if score < 120:
        return random.uniform(2.0, 4.0)
    return random.uniform(3.0, 5.0)


def apply_tarpit(score: int) -> float:
    """Apply a tarpit delay based on score.

    Returns the actual delay applied (in seconds).
    """
    delay = compute_delay(score)
    if delay > 0:
        time.sleep(delay)
    return delay
