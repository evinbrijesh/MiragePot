# MiragePot Enhancement Roadmap

## Overview

This document describes the documentation accuracy audit and TTP enhancement initiative completed as part of the Strategy B implementation plan.

## Background

During preparation for a comprehensive project report, a thorough audit revealed significant discrepancies between documented statistics and actual implementation. This roadmap was created to:

1. **Correct all documentation** to reflect actual implementation
2. **Enhance TTP detection** by implementing 12 additional MITRE ATT&CK techniques
3. **Establish a single source of truth** for all project statistics

## Phase 1: Documentation Audit & Correction (Completed)

### Issues Discovered

| Metric | Original Documentation | Actual Implementation |
|--------|------------------------|----------------------|
| MITRE ATT&CK Techniques | 163-191 | 38 |
| Honeytoken Types | 7-17 | 10 |
| Prompt Injection Patterns | 104 | 88 |
| Filesystem Entries | 300+ | ~258 |
| Telegram Notifications | "Fully implemented" | Config-only (planned) |

### Files Corrected

1. **MVP.md** - Fixed all inflated statistics
2. **PRD.md** - Aligned with MVP.md corrections
3. **HOW_IT_WORKS.md** - Corrected filesystem entry count
4. **NOTIFICATIONS.md** - Clarified Telegram status as planned feature

### New Documentation Created

- **STATISTICS.md** - Single source of truth for all project metrics

## Phase 2: TTP Enhancement (Completed)

### New Techniques Implemented (12 total)

| Technique ID | Name | Category |
|--------------|------|----------|
| T1033 | System Owner/User Discovery | Discovery |
| T1049 | System Network Connections Discovery | Discovery |
| T1018 | Remote System Discovery | Discovery |
| T1007 | System Service Discovery | Discovery |
| T1069 | Permission Groups Discovery | Discovery |
| T1222 | File and Directory Permissions Modification | Defense Evasion |
| T1036 | Masquerading | Defense Evasion |
| T1119 | Automated Collection | Collection |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1555 | Credentials from Password Stores | Credential Access |
| T1490 | Inhibit System Recovery | Impact |
| T1074 | Data Staged | Collection |

### Implementation Details

- **~60 new detection patterns** added to `ttp_detector.py`
- **44 unit tests** written covering all new techniques
- All tests pass successfully

### Final Statistics (Post-Enhancement)

| Metric | Count |
|--------|-------|
| MITRE ATT&CK Techniques | **50** |
| Honeytoken Types | 10 |
| Prompt Injection Patterns | 88 (72 direct + 16 encoded) |
| Filesystem Entries | ~258 |

## Phase 3: Future Enhancements (Planned)

### Potential Additional Techniques

The following techniques could be added in future iterations:

1. **T1078** - Valid Accounts (detect use of discovered credentials)
2. **T1098** - Account Manipulation
3. **T1136** - Create Account
4. **T1543** - Create or Modify System Process
5. **T1053** - Scheduled Task/Job
6. **T1547** - Boot or Logon Autostart Execution
7. **T1059.006** - Python scripting detection
8. **T1059.007** - JavaScript/Node.js scripting detection

### Infrastructure Improvements

1. **Telegram Integration** - Complete implementation of notification system
2. **SIEM Integration** - Add support for Splunk, ELK, QRadar
3. **Real-time Dashboard** - Web UI for monitoring honeypot activity

## Verification Commands

```bash
# Count unique MITRE ATT&CK technique IDs
grep -oE "T[0-9]{4}(\.[0-9]+)?" miragepot/ttp_detector.py | sort -u | wc -l

# Run TTP detector tests
python -m pytest tests/test_ttp_detector.py -v

# Count honeytoken types
grep -c "HoneytokenType\." miragepot/honeytokens.py | head -1
```

## Quality Assurance

### Principles Established

1. **No aspirational documentation** - Only document implemented features
2. **Single source of truth** - All statistics reference STATISTICS.md
3. **Test coverage** - All new TTP patterns have unit tests
4. **Accurate counts** - Use automated scripts to verify statistics

### Documentation Review Process

Before any report or documentation update:

1. Run verification commands to get actual counts
2. Cross-reference with STATISTICS.md
3. Update STATISTICS.md first if counts change
4. Update other docs to reference STATISTICS.md

---

*Last Updated: April 2025*
*Status: Phase 1 & 2 Complete*
